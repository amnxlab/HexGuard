import { contextBridge, ipcRenderer } from "electron";
import type {
  AskRequest,
  ChatSession,
  ConsoleLogLine,
  CreateProjectRequest,
  CreateSessionRequest,
  DeleteProjectRequest,
  DeleteSessionRequest,
  GeminiConfig,
  HexStrikeDiagnostics,
  HexguardApi,
  HuntSession,
  HuntSessionConfig,
  IngestProjectKnowledgeRequest,
  PreflightCheck,
  PreflightReport,
  Project,
  ProjectKnowledgeItem,
  RagSearchChunk,
  RagSearchRequest,
  ReportBundle,
  RenameProjectRequest,
  RenameSessionRequest,
  SessionProjectAssignment,
  ToolAdapterResult,
  ToolHealth,
  ToolInvokeRequest,
} from "@hexguard/shared";

const api: HexguardApi = {
  getToolHealth: () => ipcRenderer.invoke("tool-health:list") as Promise<ToolHealth[]>,
  listProjects: () => ipcRenderer.invoke("project:list") as Promise<Project[]>,
  createProject: (req: CreateProjectRequest) => ipcRenderer.invoke("project:create", req) as Promise<Project>,
  renameProject: (req: RenameProjectRequest) => ipcRenderer.invoke("project:rename", req) as Promise<Project>,
  deleteProject: (req: DeleteProjectRequest) => ipcRenderer.invoke("project:delete", req) as Promise<void>,
  listSessions: () => ipcRenderer.invoke("chat:list-sessions") as Promise<ChatSession[]>,
  createSession: (req?: CreateSessionRequest) => ipcRenderer.invoke("chat:create-session", req) as Promise<ChatSession>,
  assignSessionProject: (req: SessionProjectAssignment) => ipcRenderer.invoke("chat:assign-project", req) as Promise<ChatSession>,
  renameSession: (req: RenameSessionRequest) => ipcRenderer.invoke("chat:rename-session", req) as Promise<ChatSession>,
  deleteSession: (req: DeleteSessionRequest) => ipcRenderer.invoke("chat:delete-session", req) as Promise<void>,
  listProjectKnowledge: (projectId: string, sessionId?: string) => ipcRenderer.invoke("rag:list", projectId, sessionId) as Promise<ProjectKnowledgeItem[]>,
  readRawKnowledge: (projectId: string, itemId: string) => ipcRenderer.invoke("rag:read-raw", projectId, itemId) as Promise<string>,
  deleteProjectKnowledge: (projectId: string, itemId: string) => ipcRenderer.invoke("rag:delete", projectId, itemId) as Promise<void>,
  searchProjectKnowledge: (request: RagSearchRequest) => ipcRenderer.invoke("rag:search", request) as Promise<RagSearchChunk[]>,
  ingestProjectKnowledge: (req: IngestProjectKnowledgeRequest) => ipcRenderer.invoke("rag:ingest", req) as Promise<ProjectKnowledgeItem>,
  ingestFile: (projectId: string, filePath: string, title?: string, sessionId?: string) =>
    ipcRenderer.invoke("rag:ingest-file", projectId, filePath, title, sessionId) as Promise<ProjectKnowledgeItem>,
  ask: (req: AskRequest) => ipcRenderer.invoke("chat:ask", req),
  // ── Hunt ────────────────────────────────────────────────────────────────────
  startHunt: (cfg: HuntSessionConfig) => ipcRenderer.invoke("hunt:start", cfg) as Promise<HuntSession>,
  submitDecision: (optionId: string, overrideParams?: Record<string, unknown>) =>
    ipcRenderer.invoke("hunt:submit-decision", optionId, overrideParams) as Promise<HuntSession>,
  pauseHunt:  () => ipcRenderer.invoke("hunt:pause") as Promise<HuntSession>,
  resumeHunt: () => ipcRenderer.invoke("hunt:resume") as Promise<HuntSession>,
  endHunt:    () => ipcRenderer.invoke("hunt:end") as Promise<HuntSession>,
  getCurrentHunt: () => ipcRenderer.invoke("hunt:get-state") as Promise<HuntSession | null>,
  startAutonomousHunt: (cfg: HuntSessionConfig) => ipcRenderer.invoke("hunt:start-autonomous", cfg) as Promise<HuntSession>,
  stopAutonomousHunt:  () => ipcRenderer.invoke("hunt:stop-autonomous") as Promise<HuntSession>,
  onHuntUpdate: (listener: (session: HuntSession) => void) => {
    const sub = (_e: unknown, session: HuntSession) => listener(session);
    ipcRenderer.on("hunt:update", sub);
    return () => ipcRenderer.removeListener("hunt:update", sub);
  },
  onHuntConsole: (listener: (line: ConsoleLogLine) => void) => {
    const sub = (_e: unknown, line: ConsoleLogLine) => listener(line);
    ipcRenderer.on("hunt:console", sub);
    return () => ipcRenderer.removeListener("hunt:console", sub);
  },
  invokeTool: (req: ToolInvokeRequest) => ipcRenderer.invoke("tool:invoke", req) as Promise<ToolAdapterResult>,
  exportReport: (session: HuntSession, chatSessionId?: string) => ipcRenderer.invoke("report:export", session, chatSessionId) as Promise<ReportBundle>,
  openReportsFolder: () => ipcRenderer.invoke("report:open-folder") as Promise<void>,
  transcribeAudio: (audioBase64: string, mimeType: string) =>
    ipcRenderer.invoke("voice:transcribe", audioBase64, mimeType) as Promise<string>,
  getGeminiConfig: () => ipcRenderer.invoke("gemini:get-config") as Promise<GeminiConfig | null>,
  setGeminiConfig: (cfg: GeminiConfig) => ipcRenderer.invoke("gemini:set-config", cfg) as Promise<void>,
  runPreflight: () => ipcRenderer.invoke("startup:preflight") as Promise<PreflightReport>,
  retryHexStrike: () => ipcRenderer.invoke("startup:retry-hexstrike") as Promise<void>,
  getHexStrikeDiagnostics: () => ipcRenderer.invoke("startup:hexstrike-diagnostics") as Promise<HexStrikeDiagnostics>,
  onStartupUpdate: (listener: (check: PreflightCheck) => void) => {
    const sub = (_e: unknown, check: PreflightCheck) => listener(check);
    ipcRenderer.on("startup:check-update", sub);
    return () => ipcRenderer.removeListener("startup:check-update", sub);
  },
  // ── HexStrike extended API ──────────────────────────────────────────────────
  hexstrikeSmartScan: (target: string, objective?: string) =>
    ipcRenderer.invoke("hexstrike:smart-scan", target, objective) as Promise<unknown>,
  hexstrikeAnalyzeTarget: (target: string) =>
    ipcRenderer.invoke("hexstrike:analyze-target", target) as Promise<unknown>,
  hexstrikeRunTool: (toolName: string, params: Record<string, unknown>) =>
    ipcRenderer.invoke("hexstrike:run-tool", toolName, params) as Promise<unknown>,
  hexstrikeBugBountyRecon: (domain: string, scope?: string[]) =>
    ipcRenderer.invoke("hexstrike:bugbounty-recon", domain, scope) as Promise<unknown>,
  hexstrikeBugBountyComprehensive: (domain: string, scope?: string[]) =>
    ipcRenderer.invoke("hexstrike:bugbounty-comprehensive", domain, scope) as Promise<unknown>,
  hexstrikeListProcesses: () =>
    ipcRenderer.invoke("hexstrike:list-processes") as Promise<unknown>,
  hexstrikeTerminateProcess: (pid: number) =>
    ipcRenderer.invoke("hexstrike:terminate-process", pid) as Promise<unknown>,
  hexstrikeTelemetry: () =>
    ipcRenderer.invoke("hexstrike:telemetry") as Promise<unknown>,
  // ── Window chrome ───────────────────────────────────────────────────────────
  windowMinimize: () => ipcRenderer.invoke("window:minimize") as Promise<void>,
  windowMaximize: () => ipcRenderer.invoke("window:maximize") as Promise<void>,
  windowClose:    () => ipcRenderer.invoke("window:close") as Promise<void>,
};

contextBridge.exposeInMainWorld("hexguard", api);
