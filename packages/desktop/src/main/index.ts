import { app, BrowserWindow, ipcMain, shell } from "electron";
import * as fs from "node:fs/promises";
import * as path from "path";
import * as os from "node:os";
import type {
  AskRequest,
  ChatMessage,
  ChatSession,
  CreateProjectRequest,
  CreateSessionRequest,
  DeleteProjectRequest,
  DeleteSessionRequest,
  HuntSession,
  HuntSessionConfig,
  IngestProjectKnowledgeRequest,
  KnowledgeSourceType,
  Project,
  ProjectKnowledgeItem,
  RagSearchChunk,
  RagSearchRequest,
  RenameProjectRequest,
  RenameSessionRequest,
  SessionProjectAssignment,
  ToolInvokeRequest,
} from "@hexguard/shared";
import { askHexStrike, getToolHealth, readGeminiConfig, writeGeminiConfig, hexstrikeTool, hexstrikeSmartScan, hexstrikeAnalyzeTarget, hexstrikeBugBountyRecon, hexstrikeBugBountyComprehensive, hexstrikeListProcesses, hexstrikeTerminateProcess, hexstrikeTelemetry, hexstrikeExtractText, hexstrikePost } from "./services/mcpClient";
import { getHexStrikeDiagnostics, runPreflightChecks, restartHexStrike, shutdownHexStrike } from "./services/startupManager";
import { buildReport, reportsDir } from "./services/reportBuilder";
import { ffufAdapter } from "./adapters/ffuf";
import { sqlmapAdapter } from "./adapters/sqlmap";
import { zapAdapter } from "./adapters/zap";
import { validateRunConfig } from "./services/policyEngine";
import {
  initSessionManager,
  startHunt,
  submitDecision,
  pauseHunt,
  resumeHunt,
  endHunt,
  getCurrentHunt,
  startAutonomousHunt,
  stopAutonomousHunt,
} from "./services/sessionManager";

// Linux environments without a usable GPU stack can crash Electron at startup.
// Keep this enabled by default; set HEXGUARD_SAFE_GPU_MODE=0 to opt out.
if (process.platform === "linux" && process.env.HEXGUARD_SAFE_GPU_MODE !== "0") {
  app.disableHardwareAcceleration();
  app.commandLine.appendSwitch("disable-gpu");
  app.commandLine.appendSwitch("disable-gpu-compositing");
  app.commandLine.appendSwitch("disable-dev-shm-usage");
  app.commandLine.appendSwitch("use-gl", "swiftshader");
  app.commandLine.appendSwitch("enable-unsafe-swiftshader");
  // Ensure the MediaStream API (microphone/camera) is available despite GPU workarounds.
  app.commandLine.appendSwitch("enable-features", "MediaStreamAPI");

  // Some Linux setups (containers/WSL/restricted namespaces) fail sandbox zygote startup.
  // Keep this guarded so it can be turned off via HEXGUARD_DISABLE_SANDBOX_FALLBACK=0.
  if (process.env.HEXGUARD_DISABLE_SANDBOX_FALLBACK !== "0") {
    app.commandLine.appendSwitch("no-sandbox");
    app.commandLine.appendSwitch("disable-setuid-sandbox");
  }
}

const sessions = new Map<string, ChatSession>();
const projects = new Map<string, Project>();

// Module-level reference so the BrowserWindow is never GC'd while the app runs
let mainWindow: BrowserWindow | null = null;

interface RagManifest {
  projectId: string;
  schemaVersion: 1;
  updatedAt: string;
  items: ProjectKnowledgeItem[];
}

function dataRoot(): string {
  return path.join(app.getPath("userData"), "projects");
}

function sessionsDir(): string {
  return path.join(app.getPath("userData"), "hexguard-sessions");
}

async function persistSession(s: ChatSession): Promise<void> {
  await ensureDir(sessionsDir());
  await writeJson(path.join(sessionsDir(), `${s.id}.json`), s);
}

async function loadSessionsFromDisk(): Promise<void> {
  await ensureDir(sessionsDir());
  const entries = await fs.readdir(sessionsDir(), { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const s = await readJson<ChatSession | null>(path.join(sessionsDir(), entry.name), null);
    if (s) sessions.set(s.id, s);
  }
}

function projectDir(projectId: string): string {
  return path.join(dataRoot(), projectId);
}

function ragDir(projectId: string): string {
  return path.join(projectDir(projectId), "rag");
}

function ragManifestPath(projectId: string): string {
  return path.join(ragDir(projectId), "manifest.json");
}

function nowIso(): string {
  return new Date().toISOString();
}

async function ensureDir(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function writeJson(filePath: string, data: unknown): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
}

function makeProject(req: CreateProjectRequest): Project {
  const now = nowIso();
  return {
    id: `project-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    name: req.name.trim(),
    description: req.description?.trim() || undefined,
    createdAt: now,
    updatedAt: now
  };
}

async function initializeProjectStorage(project: Project): Promise<void> {
  const pDir = projectDir(project.id);
  await ensureDir(path.join(pDir, "rag", "raw"));
  await ensureDir(path.join(pDir, "rag", "items"));
  await writeJson(path.join(pDir, "project.json"), project);
  const manifest: RagManifest = {
    projectId: project.id,
    schemaVersion: 1,
    updatedAt: nowIso(),
    items: []
  };
  await writeJson(ragManifestPath(project.id), manifest);
}

async function loadProjectsFromDisk(): Promise<void> {
  await ensureDir(dataRoot());
  const entries = await fs.readdir(dataRoot(), { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const pJson = path.join(dataRoot(), entry.name, "project.json");
    const project = await readJson<Project | null>(pJson, null);
    if (project) projects.set(project.id, project);
  }
}

async function listKnowledge(projectId: string, sessionId?: string): Promise<ProjectKnowledgeItem[]> {
  const manifest = await readJson<RagManifest>(ragManifestPath(projectId), {
    projectId,
    schemaVersion: 1,
    updatedAt: nowIso(),
    items: []
  });
  // No session filter → return all items (used by "show all" mode)
  if (!sessionId) return manifest.items;
  // Session-scoped: strictly return only items tagged to this session
  return manifest.items.filter(i => i.sessionId === sessionId);
}

function tokenizeForSearch(input: string): string[] {
  return input
    .toLowerCase()
    .split(/[^a-z0-9_/-]+/)
    .map(t => t.trim())
    .filter(t => t.length >= 2);
}

async function searchKnowledge(projectId: string, query: string, limit = 6, sessionId?: string): Promise<RagSearchChunk[]> {
  const knowledge = await listKnowledge(projectId, sessionId);
  if (knowledge.length === 0) return [];

  const terms = tokenizeForSearch(query);
  if (terms.length === 0) return [];

  const results: RagSearchChunk[] = [];
  for (const item of knowledge) {
    const ragItem = await readJson<{
      id: string;
      title: string;
      chunks?: Array<{ id: string; text: string }>;
    } | null>(item.ragJsonPath, null);
    if (!ragItem || !Array.isArray(ragItem.chunks)) continue;

    for (const chunk of ragItem.chunks) {
      const text = chunk.text ?? "";
      if (!text) continue;
      const lowered = text.toLowerCase();
      const titleLowered = item.title.toLowerCase();
      let score = 0;
      for (const term of terms) {
        if (titleLowered.includes(term)) score += 3;
        if (lowered.includes(term)) score += 1;
      }
      if (score <= 0) continue;

      results.push({
        knowledgeId: item.id,
        chunkId: chunk.id,
        title: item.title,
        text: text.slice(0, 1200),
        score,
      });
    }
  }

  return results
    .sort((a, b) => b.score - a.score)
    .slice(0, Math.max(1, Math.min(limit, 12)));
}

function chunkText(text: string): string[] {
  const cleaned = text.replace(/\r\n/g, "\n").trim();
  const chunkSize = 800;
  const overlap = 120;
  const chunks: string[] = [];
  let start = 0;
  while (start < cleaned.length) {
    const end = Math.min(cleaned.length, start + chunkSize);
    chunks.push(cleaned.slice(start, end));
    if (end === cleaned.length) break;
    start = Math.max(0, end - overlap);
  }
  return chunks;
}

function extractPathsFromText(text: string): string[] {
  const matches = text.match(/\/[a-zA-Z0-9._~!$&'()*+,;=:@\/-]*/g) ?? [];
  const cleaned = new Set<string>();
  for (const m of matches) {
    if (!m || m === "/") continue;
    if (m.length < 3) continue;
    if (!m.startsWith("/")) continue;
    cleaned.add(m.replace(/\/+$/, ""));
  }
  return [...cleaned];
}

function buildHuntKnowledgeText(session: HuntSession): string {
  const ctx = session.context;
  const date = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const findingsText = ctx.findings.length === 0
    ? "No confirmed findings."
    : ctx.findings.map(f => [
        `### [${f.severity.toUpperCase()}] ${f.title}`,
        `- Endpoint: ${f.endpoint}`,
        `- Evidence: ${f.evidence}`,
        `- Tool: ${f.tool}`,
        `- Time: ${f.timestamp}`,
      ].join("\n")).join("\n\n");

  const endpointsText = ctx.visitedEndpoints.length === 0
    ? "None discovered."
    : ctx.visitedEndpoints.slice(0, 60).map(e => `- ${e}`).join("\n");

  const decisionTrail = session.history.map((action, i) => {
    const proposal = i === 0 ? ctx.lastProposal : undefined;
    const optionsList = proposal?.options.map(o =>
      `  - [${o.rank}] ${o.title} (risk: ${o.riskLevel})${o.id === action.chosenOptionId ? " ← CHOSEN" : ""}`
    ).join("\n") ?? "";
    return [
      `### Decision ${i + 1} — ${action.chosenOptionTitle}`,
      optionsList ? `Options presented:\n${optionsList}` : "",
      `Chosen: ${action.chosenOptionTitle}`,
      `Result: ${action.state} · ${action.findings.length} finding(s)`,
      action.durationMs ? `Duration: ${(action.durationMs / 1000).toFixed(1)}s` : "",
    ].filter(Boolean).join("\n");
  }).join("\n\n");

  const toolOutputs = ctx.toolResults.map(r =>
    `- ${r.tool}: ${r.summary}`
  ).join("\n");

  const warnings = ctx.events
    .filter(e => e.level !== "info")
    .slice(0, 20)
    .map(e => `- [${e.level}] ${e.title}: ${e.detail}`)
    .join("\n");

  return [
    `# Hunt Report — ${ctx.target} — ${date}`,
    `Session ID: ${session.id}  |  Profile: ${session.config.profile}  |  State: ${session.state}`,
    "",
    `## Executive Summary`,
    ctx.lastProposal?.contextSummary ?? "Session completed.",
    "",
    `## Findings (${ctx.findings.length} total)`,
    findingsText,
    "",
    `## Endpoints Discovered (${ctx.visitedEndpoints.length})`,
    endpointsText,
    "",
    `## Decision Trail (${session.history.length} decisions)`,
    decisionTrail || "No actions taken.",
    "",
    `## Tool Results`,
    toolOutputs || "No tool results.",
    "",
    `## Events & Warnings`,
    warnings || "No warnings.",
  ].join("\n");
}

async function persistProjectKnowledge(
  project: Project,
  title: string,
  text: string,
  source: Record<string, unknown>,
  sourceType?: KnowledgeSourceType,
  fileType?: string,
  sessionId?: string,
): Promise<ProjectKnowledgeItem> {
  const id = `rag-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  const createdAt = nowIso();
  const baseRagDir = ragDir(project.id);
  const rawTextPath = path.join(baseRagDir, "raw", `${id}.txt`);
  const ragJsonPath = path.join(baseRagDir, "items", `${id}.json`);

  await ensureDir(path.dirname(rawTextPath));
  await ensureDir(path.dirname(ragJsonPath));
  await fs.writeFile(rawTextPath, text, "utf8");

  const chunks = chunkText(text).map((chunk, idx) => ({
    id: `${id}-chunk-${idx + 1}`,
    text: chunk,
    metadata: {
      projectId: project.id,
      ...(sessionId ? { sessionId } : {}),
      knowledgeId: id,
      title,
      order: idx + 1,
      tokenEstimate: Math.ceil(chunk.length / 4)
    }
  }));

  await writeJson(ragJsonPath, {
    id,
    projectId: project.id,
    ...(sessionId ? { sessionId } : {}),
    title,
    createdAt,
    updatedAt: createdAt,
    source: {
      ...source,
      rawTextPath,
    },
    chunks
  });

  const item: ProjectKnowledgeItem = {
    id,
    projectId: project.id,
    ...(sessionId ? { sessionId } : {}),
    title,
    rawTextPath,
    ragJsonPath,
    charCount: text.length,
    createdAt,
    updatedAt: createdAt,
    ...(sourceType ? { sourceType } : {}),
    ...(fileType ? { fileType } : {}),
  };

  const manifest = await readJson<RagManifest>(ragManifestPath(project.id), {
    projectId: project.id,
    schemaVersion: 1,
    updatedAt: createdAt,
    items: []
  });
  manifest.items = [item, ...manifest.items];
  manifest.updatedAt = nowIso();
  await writeJson(ragManifestPath(project.id), manifest);

  project.updatedAt = nowIso();
  await writeJson(path.join(projectDir(project.id), "project.json"), project);
  projects.set(project.id, project);

  return item;
}

function makeSession(req?: CreateSessionRequest): ChatSession {
  const now = nowIso();
  return {
    id: `session-${Date.now()}`,
    title: "New Security Session",
    projectId: req?.projectId ?? null,
    createdAt: now,
    updatedAt: now,
    messages: []
  };
}

async function bootstrap(): Promise<void> {
  await loadProjectsFromDisk();
  await loadSessionsFromDisk();
  if (sessions.size === 0) {
    const s = makeSession();
    s.title = "Getting Started";
    const intro: ChatMessage = {
      id: `sys-${Date.now()}`, role: "system",
      content: "HexGuard Hunt is ready.\n\nASK mode: send cybersecurity queries for structured guidance.\nAutonomous mode: configure and run supervised simulation workflows.",
      timestamp: nowIso(), state: "complete"
    };
    s.messages.push(intro);
    sessions.set(s.id, s);
    await persistSession(s);
  }
}

function registerHandlers(win: BrowserWindow): void {
  // Initialise session manager with window reference and RAG search function
  initSessionManager(win, (projectId, query, limit, sessionId) => searchKnowledge(projectId, query, limit ?? 6, sessionId));

  // ── Window chrome controls ────────────────────────────────────────────
  ipcMain.handle("window:minimize",  () => win.minimize());
  ipcMain.handle("window:maximize",  () => { win.isMaximized() ? win.unmaximize() : win.maximize(); });
  ipcMain.handle("window:close",     () => win.close());

  ipcMain.handle("tool-health:list", () => getToolHealth());

  ipcMain.handle("tool:invoke", async (_e, req: ToolInvokeRequest) => {
    // Policy check before spawning any subprocess
    const policy = validateRunConfig({
      target: req.target,
      scope: req.target,
      profile: "passive",
      maxRequestsPerMinute: 30,
    });
    if (!policy.allowed) throw new Error(`Policy blocked: ${policy.reason}`);

    const outDir = path.join(os.tmpdir(), `hexguard-${Date.now()}`);
    await fs.mkdir(outDir, { recursive: true });

    try {
      switch (req.tool) {
        case "ffuf":
          return await ffufAdapter.invoke({ target: req.target, outputDir: outDir, extraArgs: req.extraArgs, wordlistPath: req.wordlistPath });
        case "sqlmap":
          return await sqlmapAdapter.invoke({ target: req.target, outputDir: outDir, extraArgs: req.extraArgs });
        case "zap":
          return await zapAdapter.invoke({ target: req.target, outputDir: outDir, extraArgs: req.extraArgs });
        default:
          throw new Error(`Unknown tool: ${String(req.tool)}`);
      }
    } finally {
      await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
    }
  });
  ipcMain.handle("project:list", () => Array.from(projects.values()));
  ipcMain.handle("project:create", async (_e, req: CreateProjectRequest) => {
    const name = req?.name?.trim();
    if (!name) throw new Error("Project name is required");
    const project = makeProject({ name, description: req.description });
    projects.set(project.id, project);
    await initializeProjectStorage(project);
    return project;
  });
  ipcMain.handle("project:rename", async (_e, req: RenameProjectRequest) => {
    const p = projects.get(req.projectId);
    if (!p) throw new Error("Project not found");
    p.name = req.name.trim() || p.name;
    if (req.description !== undefined) p.description = req.description?.trim() || undefined;
    p.updatedAt = nowIso();
    await writeJson(path.join(projectDir(p.id), "project.json"), p);
    projects.set(p.id, p);
    return p;
  });
  ipcMain.handle("project:delete", async (_e, req: DeleteProjectRequest) => {
    if (!projects.has(req.projectId)) throw new Error("Project not found");
    projects.delete(req.projectId);
    // Orphan sessions that belonged to this project
    const orphaned = Array.from(sessions.values()).filter(s => s.projectId === req.projectId);
    for (const s of orphaned) {
      s.projectId = null;
      s.updatedAt = nowIso();
      await persistSession(s);
    }
    await fs.rm(projectDir(req.projectId), { recursive: true, force: true }).catch(() => {});
  });
  ipcMain.handle("chat:list-sessions", () => Array.from(sessions.values()));
  ipcMain.handle("chat:create-session", async (_e, req?: CreateSessionRequest) => {
    const s = makeSession(req);
    sessions.set(s.id, s);
    await persistSession(s);
    return s;
  });
  ipcMain.handle("chat:assign-project", async (_e, req: SessionProjectAssignment) => {
    const s = sessions.get(req.sessionId);
    if (!s) throw new Error("Session not found");
    if (req.projectId && !projects.has(req.projectId)) throw new Error("Project not found");
    s.projectId = req.projectId;
    s.updatedAt = nowIso();
    await persistSession(s);
    return s;
  });
  ipcMain.handle("chat:rename-session", async (_e, req: RenameSessionRequest) => {
    const s = sessions.get(req.sessionId);
    if (!s) throw new Error("Session not found");
    s.title = req.title.trim() || s.title;
    s.updatedAt = nowIso();
    await persistSession(s);
    return s;
  });
  ipcMain.handle("chat:delete-session", async (_e, req: DeleteSessionRequest) => {
    sessions.delete(req.sessionId);
    await fs.unlink(path.join(sessionsDir(), `${req.sessionId}.json`)).catch(() => {});
  });
  ipcMain.handle("chat:ask", async (_e, req: AskRequest) => {
    const s = sessions.get(req.sessionId);
    if (!s) throw new Error("Session not found");
    const user: ChatMessage = { id: `user-${Date.now()}`, role: "user", content: req.prompt, timestamp: nowIso(), state: "complete" };
    s.messages.push(user);

    let knowledgeContext = "";
    if (s.projectId) {
      const chunks = await searchKnowledge(s.projectId, req.prompt, 6, s.id);
      if (chunks.length > 0) {
        const contextLines = chunks.map((c, idx) => {
          return `Source ${idx + 1} (${c.title}, score=${c.score}):\n${c.text}`;
        });
        knowledgeContext = contextLines.join("\n\n---\n\n");
      }
    }

    const res = await askHexStrike({
      ...req,
      projectId: s.projectId ?? null,
      knowledgeContext,
    });
    s.messages.push(res.message);
    s.updatedAt = nowIso();
    await persistSession(s);
    return res;
  });
  ipcMain.handle("rag:list", async (_e, projectId: string, sessionId?: string) => {
    if (!projects.has(projectId)) throw new Error("Project not found");
    return listKnowledge(projectId, sessionId);
  });
  ipcMain.handle("rag:read-raw", async (_e, projectId: string, itemId: string) => {
    if (!projects.has(projectId)) throw new Error("Project not found");
    const items = await listKnowledge(projectId);
    const item = items.find(i => i.id === itemId);
    if (!item) throw new Error("Knowledge item not found");
    return fs.readFile(item.rawTextPath, "utf8");
  });
  ipcMain.handle("rag:delete", async (_e, projectId: string, itemId: string) => {
    const project = projects.get(projectId);
    if (!project) throw new Error("Project not found");
    const manifest = await readJson<RagManifest>(ragManifestPath(projectId), {
      projectId, schemaVersion: 1, updatedAt: nowIso(), items: []
    });
    const item = manifest.items.find(i => i.id === itemId);
    if (!item) throw new Error("Knowledge item not found");
    // Remove files (best-effort)
    await fs.unlink(item.rawTextPath).catch(() => {});
    await fs.unlink(item.ragJsonPath).catch(() => {});
    // Update manifest
    manifest.items = manifest.items.filter(i => i.id !== itemId);
    manifest.updatedAt = nowIso();
    await writeJson(ragManifestPath(projectId), manifest);
  });
  ipcMain.handle("rag:search", async (_e, req: RagSearchRequest) => {
    if (!projects.has(req.projectId)) throw new Error("Project not found");
    return searchKnowledge(req.projectId, req.query, req.limit ?? 6, req.sessionId);
  });
  ipcMain.handle("rag:ingest", async (_e, req: IngestProjectKnowledgeRequest) => {
    const project = projects.get(req.projectId);
    if (!project) throw new Error("Project not found");
    const title = req.title?.trim();
    const text = req.text?.trim();
    if (!title) throw new Error("Knowledge title is required");
    if (!text) throw new Error("Knowledge text is required");

    return persistProjectKnowledge(
      project, title, text,
      { type: req.sourceType ?? "manual-text" },
      req.sourceType ?? "manual-text",
      req.fileType,
      req.sessionId,
    );
  });

  ipcMain.handle("rag:ingest-file", async (_e, projectId: string, filePath: string, title?: string, sessionId?: string) => {
    const project = projects.get(projectId);
    if (!project) throw new Error("Project not found");

    const ext = filePath.split(".").pop()?.toLowerCase() ?? "";
    const resolvedTitle = title?.trim() || path.basename(filePath, path.extname(filePath));
    let text = "";

    if (ext === "txt" || ext === "md") {
      text = await fs.readFile(filePath, "utf8");
    } else if (ext === "json") {
      const raw = await fs.readFile(filePath, "utf8");
      try { text = JSON.stringify(JSON.parse(raw), null, 2); } catch { text = raw; }
    } else if (ext === "html" || ext === "htm") {
      const raw = await fs.readFile(filePath, "utf8");
      text = raw.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
               .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
               .replace(/<[^>]+>/g, " ")
               .replace(/\s{2,}/g, " ")
               .trim();
    } else if (ext === "pdf" || ext === "docx") {
      // Delegate extraction to HexStrike Python backend
      const fileBytes = await fs.readFile(filePath);
      const extracted = await hexstrikeExtractText(fileBytes, ext, resolvedTitle);
      text = extracted ?? "";
    } else {
      // Fallback: try reading as utf8
      text = await fs.readFile(filePath, "utf8");
    }

    if (!text.trim()) throw new Error("No text could be extracted from the file");

    return persistProjectKnowledge(
      project, resolvedTitle, text,
      { type: "manual-file", originalPath: filePath },
      "manual-file",
      ext,
      sessionId,
    );
  });

  // ── Hunt (HITL Decision Engine) ──────────────────────────────────────────────
  ipcMain.handle("hunt:start", async (_e, config: HuntSessionConfig) => {
    return startHunt(config);
  });

  ipcMain.handle("hunt:submit-decision", async (_e, optionId: string, overrideParams?: Record<string, unknown>) => {
    return submitDecision(optionId, overrideParams);
  });

  ipcMain.handle("hunt:pause",  async () => pauseHunt());
  ipcMain.handle("hunt:resume", async () => resumeHunt());
  ipcMain.handle("hunt:end",    async () => endHunt());
  ipcMain.handle("hunt:get-state", () => getCurrentHunt());

  ipcMain.handle("hunt:start-autonomous", async (_e, config: HuntSessionConfig) => {
    return startAutonomousHunt(config);
  });

  ipcMain.handle("hunt:stop-autonomous", async () => {
    return stopAutonomousHunt();
  });

  ipcMain.handle("report:export", async (_e, _rendererSession: HuntSession, chatSessionId?: string) => {
    // Use the authoritative in-memory session rather than the renderer's IPC-serialized
    // copy, which may have stale or stripped context fields (e.g. visitedEndpoints).
    const session = getCurrentHunt();
    if (!session) throw new Error("No active hunt session to export");
    const bundle = await buildReport(session);
    // Write a full knowledge document to project RAG if project is linked.
    // Tag with the renderer's active chat session ID so it appears in session-filtered view.
    if (session.config.projectId && projects.has(session.config.projectId)) {
      const project = projects.get(session.config.projectId)!;
      const docText = buildHuntKnowledgeText(session);
      const reportTitle = `Hunt Report — ${session.context.target} — ${new Date().toLocaleDateString()}`;
      await persistProjectKnowledge(
        project, reportTitle, docText,
        { type: "hunt-report", huntSessionId: session.id, target: session.context.target },
        "hunt-report",
        undefined,
        chatSessionId ?? session.id,
      ).catch(err => console.error("[HexGuard] RAG writeback failed:", err));
    }
    await shell.openExternal(`file://${bundle.htmlPath}`);
    return bundle;
  });

  ipcMain.handle("report:open-folder", async () => {
    const dir = reportsDir();
    await fs.mkdir(dir, { recursive: true });
    await shell.openPath(dir);
  });

  // ── Voice transcription via local Whisper (hexstrike /voice/transcribe) ──────
  ipcMain.handle("voice:transcribe", async (_e, audioBase64: string, mimeType: string) => {
    const result = await hexstrikePost<{ transcript?: string; error?: string }>(
      "/voice/transcribe",
      { audio_b64: audioBase64, mime_type: mimeType },
      30_000 // up to 30 s for model inference
    );
    if (!result?.transcript) {
      throw new Error(result?.error ?? "Transcription returned no text");
    }
    return result.transcript;
  });

  ipcMain.handle("gemini:get-config", () => readGeminiConfig());
  ipcMain.handle("gemini:set-config", async (_e, cfg) => writeGeminiConfig(cfg));

  ipcMain.handle("startup:preflight", () => {
    return runPreflightChecks(check => {
      if (!win.isDestroyed()) win.webContents.send("startup:check-update", check);
    });
  });

  ipcMain.handle("startup:retry-hexstrike", async () => {
    await restartHexStrike();
  });

  ipcMain.handle("startup:hexstrike-diagnostics", () => {
    return getHexStrikeDiagnostics();
  });

  // ── HexStrike Intelligence & Tool API ─────────────────────────────────────
  ipcMain.handle("hexstrike:smart-scan", async (_e, target: string, objective?: string) => {
    return hexstrikeSmartScan(target, objective ?? "comprehensive");
  });

  ipcMain.handle("hexstrike:analyze-target", async (_e, target: string) => {
    return hexstrikeAnalyzeTarget(target);
  });

  ipcMain.handle("hexstrike:run-tool", async (_e, toolName: string, params: Record<string, unknown>) => {
    return hexstrikeTool(toolName, params);
  });

  ipcMain.handle("hexstrike:bugbounty-recon", async (_e, domain: string, scope?: string[]) => {
    return hexstrikeBugBountyRecon(domain, scope);
  });

  ipcMain.handle("hexstrike:bugbounty-comprehensive", async (_e, domain: string, scope?: string[]) => {
    return hexstrikeBugBountyComprehensive(domain, scope);
  });

  ipcMain.handle("hexstrike:list-processes", async () => {
    return hexstrikeListProcesses();
  });

  ipcMain.handle("hexstrike:terminate-process", async (_e, pid: number) => {
    return hexstrikeTerminateProcess(pid);
  });

  ipcMain.handle("hexstrike:telemetry", async () => {
    return hexstrikeTelemetry();
  });
}

async function createWindow(): Promise<void> {
  const iconPath = path.join(__dirname, "../../../icons/Logo-Emblem.png");
  const win = new BrowserWindow({
    width: 1500, height: 940, minWidth: 1200, minHeight: 760,
    backgroundColor: "#060d1a", title: "HexGuard Hunt",
    // frame: false gives a clean frameless window on all platforms.
    // titleBarStyle hidden removes the native title bar while keeping
    // the window draggable via -webkit-app-region: drag in CSS.
    frame: false,
    titleBarStyle: "hidden",
    icon: iconPath,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true, nodeIntegration: false
    }
  });

  mainWindow = win;

  // Grant microphone and media permissions so webkitSpeechRecognition and
  // MediaRecorder can access the system microphone inside Electron's sandbox.
  win.webContents.session.setPermissionRequestHandler((_wc, permission, callback) => {
    callback(["media", "microphone", "audioCapture"].includes(permission));
  });
  win.webContents.session.setPermissionCheckHandler((_wc, permission) => {
    return (["media", "microphone", "audioCapture"] as string[]).includes(permission);
  });

  win.on("closed", () => { mainWindow = null; });

  // Reopen on macOS dock click
  app.on("activate", () => { if (mainWindow === null) void createWindow(); });

  // Prevent crash loops: attempt limited auto-reloads, then keep process stable.
  let crashCount = 0;
  let windowMsStart = Date.now();
  win.webContents.on("render-process-gone", (_e, details) => {
    console.error("[HexGuard] Renderer crashed:", details.reason, details.exitCode);
    const now = Date.now();
    if (now - windowMsStart > 15_000) {
      windowMsStart = now;
      crashCount = 0;
    }
    crashCount += 1;
    if (!win.isDestroyed() && crashCount <= 2) {
      win.reload();
      return;
    }
    console.error("[HexGuard] Renderer crash loop detected; auto-reload disabled for this window");
  });
  win.webContents.on("unresponsive", () => {
    console.error("[HexGuard] Renderer unresponsive — reloading");
    if (!win.isDestroyed()) win.reload();
  });

  registerHandlers(win);

  try {
    if (process.env["VITE_DEV_SERVER_URL"]) {
      await win.loadURL(process.env["VITE_DEV_SERVER_URL"]);
    } else {
      await win.loadFile(path.join(__dirname, "../../renderer/dist/index.html"));
    }
  } catch (err) {
    console.error("[HexGuard] loadURL failed:", err);
    // Retry once after a short delay
    await new Promise(r => setTimeout(r, 1500));
    try {
      if (process.env["VITE_DEV_SERVER_URL"]) {
        await win.loadURL(process.env["VITE_DEV_SERVER_URL"]);
      } else {
        await win.loadFile(path.join(__dirname, "../../renderer/dist/index.html"));
      }
    } catch (err2) {
      console.error("[HexGuard] loadURL retry failed:", err2);
    }
  }
}

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", () => shutdownHexStrike());

app.whenReady().then(async () => {
  await bootstrap();
  await createWindow();
});
