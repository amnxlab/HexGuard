import * as http from "node:http";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { app } from "electron";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AskRequest, AskResponse, DecisionProposal, ExploitResult, Finding, GeminiConfig, GeminiModel, HttpCapture, RagSearchChunk, SessionContext, TechFingerprint, ToolHealth } from "@hexguard/shared";

const execFileAsync = promisify(execFile);

const HEXSTRIKE_PORT = 8888;
const ZAP_PORT  = 8090;

// ─── Config file ──────────────────────────────────────────────────────────────

function geminiConfigPath(): string {
  return path.join(app.getPath("userData"), "hexguard-gemini.json");
}

export async function readGeminiConfig(): Promise<GeminiConfig | null> {
  try {
    const raw = await fs.readFile(geminiConfigPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<GeminiConfig>;
    if (typeof parsed.apiKey === "string" && parsed.apiKey && typeof parsed.model === "string") {
      return { apiKey: parsed.apiKey, model: (parsed.model as GeminiModel) };
    }
    return null;
  } catch {
    return null;
  }
}

export async function writeGeminiConfig(config: GeminiConfig): Promise<void> {
  // Only store apiKey and model — nothing else
  const safe = { apiKey: config.apiKey.trim(), model: config.model };
  await fs.writeFile(geminiConfigPath(), JSON.stringify(safe, null, 2), { encoding: "utf8", mode: 0o600 });
}

// ─── Dynamic tool health detection ───────────────────────────────────────────

async function whichExists(bin: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync("which", [bin], { timeout: 3000 });
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

interface JsonRequestResult<T> {
  ok: boolean;
  data?: T;
  statusCode?: number;
  errorKind?: "offline" | "timeout" | "http" | "invalid-json";
  errorMessage?: string;
}

function httpHealthCheck(port: number, p = "/"): Promise<boolean> {
  return new Promise(resolve => {
    const req = http.get({ hostname: "127.0.0.1", port, path: p, timeout: 2000 }, res => {
      resolve(res.statusCode !== undefined && res.statusCode < 500);
      res.resume();
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => { req.destroy(); resolve(false); });
  });
}

// ─── Generic HexStrike HTTP helper ───────────────────────────────────────────

export function isHexStrikeAvailable(): Promise<boolean> {
  return httpHealthCheck(HEXSTRIKE_PORT, "/health");
}

async function hexstrikeJsonRequest<T>(
  urlPath: string,
  method: "GET" | "POST",
  body?: Record<string, unknown>,
  timeoutMs = 10_000
): Promise<JsonRequestResult<T>> {
  try {
    const payload = body ? JSON.stringify(body) : undefined;
    return await new Promise<JsonRequestResult<T>>(resolve => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: HEXSTRIKE_PORT,
          path: urlPath,
          method,
          timeout: timeoutMs,
          headers: payload
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(payload),
              }
            : undefined,
        },
        res => {
          let data = "";
          res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
          res.on("end", () => {
            const statusCode = res.statusCode ?? 0;
            try {
              const parsed = data.length > 0 ? JSON.parse(data) as T : ({} as T);
              if (statusCode >= 200 && statusCode < 300) {
                resolve({ ok: true, data: parsed, statusCode });
                return;
              }

              const msg = typeof (parsed as { error?: unknown }).error === "string"
                ? (parsed as { error: string }).error
                : `HTTP ${statusCode}`;
              resolve({ ok: false, statusCode, errorKind: "http", errorMessage: msg, data: parsed });
            } catch {
              resolve({ ok: false, statusCode, errorKind: "invalid-json", errorMessage: "Invalid JSON response" });
            }
          });
        }
      );

      req.on("error", () => resolve({ ok: false, errorKind: "offline", errorMessage: "HexStrike is unreachable" }));
      req.on("timeout", () => {
        req.destroy();
        resolve({ ok: false, errorKind: "timeout", errorMessage: "HexStrike request timed out" });
      });

      if (payload) req.write(payload);
      req.end();
    });
  } catch {
    return { ok: false, errorKind: "offline", errorMessage: "HexStrike request failed before dispatch" };
  }
}

/**
 * POST JSON to a HexStrike endpoint and return parsed response.
 * Returns null on any network/parse error so callers can fall back gracefully.
 */
export async function hexstrikePost<T>(
  urlPath: string,
  body: Record<string, unknown>,
  timeoutMs = 60_000
): Promise<T | null> {
  try {
    const payload = JSON.stringify(body);
    return await new Promise<T>((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: HEXSTRIKE_PORT,
          path: urlPath,
          method: "POST",
          timeout: timeoutMs,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
          },
        },
        res => {
          let data = "";
          res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
          res.on("end", () => {
            try { resolve(JSON.parse(data) as T); }
            catch { reject(new Error("JSON parse error")); }
          });
        }
      );
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
      req.write(payload);
      req.end();
    });
  } catch {
    return null;
  }
}

/**
 * GET from a HexStrike endpoint and return parsed response.
 */
export async function hexstrikeGet<T>(urlPath: string, timeoutMs = 10_000): Promise<T | null> {
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = http.get(
        { hostname: "127.0.0.1", port: HEXSTRIKE_PORT, path: urlPath, timeout: timeoutMs },
        res => {
          let data = "";
          res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
          res.on("end", () => {
            try { resolve(JSON.parse(data) as T); }
            catch { reject(new Error("JSON parse error")); }
          });
        }
      );
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    });
  } catch {
    return null;
  }
}

// ─── HexStrike Intelligence API ───────────────────────────────────────────────

/** AI-powered target analysis — returns target profile, risk, recommended tools */
export async function hexstrikeAnalyzeTarget(target: string, analysisType = "comprehensive") {
  return hexstrikePost("/api/intelligence/analyze-target", { target, analysis_type: analysisType });
}

/** Intelligent tool selection based on target profile */
export async function hexstrikeSelectTools(target: string, objective = "comprehensive") {
  return hexstrikePost("/api/intelligence/select-tools", { target, objective });
}

/** AI-driven comprehensive scan — runs the full HexStrike smart scan pipeline */
export async function hexstrikeSmartScan(
  target: string,
  objective = "comprehensive",
  maxTools = 8
) {
  return hexstrikePost(
    "/api/intelligence/smart-scan",
    { target, objective, max_tools: maxTools },
    300_000 // 5 min — smart scan is long-running
  );
}

/** Technology stack detection */
export async function hexstrikeTechDetection(target: string) {
  return hexstrikePost("/api/intelligence/technology-detection", { target });
}

/** Create an AI attack chain for a target */
export async function hexstrikeAttackChain(target: string, objective = "comprehensive") {
  return hexstrikePost("/api/intelligence/create-attack-chain", { target, objective });
}

// ─── HexStrike Tool Execution API ─────────────────────────────────────────────

/** Run any specific HexStrike tool by name */
export async function hexstrikeTool(
  toolName: string,
  params: Record<string, unknown>,
  timeoutMs = 120_000
) {
  return hexstrikePost(`/api/tools/${toolName}`, params, timeoutMs);
}

/** Execute ffuf through HexStrike */
export async function hexstrikeFfuf(url: string, wordlist?: string, mode = "directory") {
  return hexstrikeTool("ffuf", { url, wordlist, mode }, 120_000);
}

/** Execute sqlmap through HexStrike */
export async function hexstrikeSqlmap(url: string, data?: string, additionalArgs?: string) {
  return hexstrikeTool("sqlmap", { url, data, additional_args: additionalArgs }, 180_000);
}

/** Execute nmap through HexStrike */
export async function hexstrikeNmap(target: string, scanType = "quick") {
  return hexstrikeTool("nmap", { target, scan_type: scanType }, 120_000);
}

/** Execute nuclei through HexStrike */
export async function hexstrikeNuclei(target: string, severity = "medium,high,critical") {
  return hexstrikeTool("nuclei", { target, severity }, 180_000);
}

/** Execute gobuster through HexStrike */
export async function hexstrikeGobuster(target: string, mode = "dir") {
  return hexstrikeTool("gobuster", { target, mode }, 120_000);
}

/** Run arbitrary command through HexStrike (for advanced use) */
export async function hexstrikeCommand(command: string) {
  return hexstrikePost("/api/command", { command }, 60_000);
}

// ─── HexStrike Bug Bounty Workflows ──────────────────────────────────────────

export async function hexstrikeBugBountyRecon(domain: string, scope: string[] = []) {
  return hexstrikePost("/api/bugbounty/reconnaissance-workflow", { domain, scope }, 300_000);
}

export async function hexstrikeBugBountyVulnHunt(domain: string) {
  return hexstrikePost("/api/bugbounty/vulnerability-hunting-workflow", { domain }, 300_000);
}

export async function hexstrikeBugBountyComprehensive(domain: string, scope: string[] = []) {
  return hexstrikePost("/api/bugbounty/comprehensive-assessment", { domain, scope }, 600_000);
}

// ─── HexStrike Process Management ────────────────────────────────────────────

export async function hexstrikeListProcesses() {
  return hexstrikeGet("/api/processes/list");
}

export async function hexstrikeTerminateProcess(pid: number) {
  return hexstrikePost(`/api/processes/terminate/${pid}`, {});
}

export async function hexstrikeTelemetry() {
  return hexstrikeGet("/api/telemetry");
}

// ─── Tool health detection ─────────────────────────────────────────────────

export async function getToolHealth(): Promise<ToolHealth[]> {
  const [hexstrikeUp, zapUp, hasFfuf, hasSqlmap, geminiCfg] = await Promise.all([
    httpHealthCheck(HEXSTRIKE_PORT, "/health"),
    httpHealthCheck(ZAP_PORT, "/JSON/core/view/version/"),
    whichExists("ffuf"),
    whichExists("sqlmap"),
    readGeminiConfig(),
  ]);

  // When HexStrike is up, pull its tool inventory for richer status
  let hexstrikeToolCount = 0;
  let modelsReachable = false;
  let healthMode: "online" | "degraded" | "offline" = hexstrikeUp ? "online" : "offline";
  let healthReason = "";
  if (hexstrikeUp) {
    const [toolsHealth, modelsHealth] = await Promise.all([
      hexstrikeGet<{ total_tools_available?: number }>("/health/tools", 15_000),
      hexstrikeGet<{ models?: unknown[] }>("/models", 5_000),
    ]);
    if (toolsHealth && typeof (toolsHealth as { total_tools_available?: number }).total_tools_available === "number") {
      hexstrikeToolCount = (toolsHealth as { total_tools_available: number }).total_tools_available;
    }
    if (modelsHealth) {
      modelsReachable = true;
    }

    if (!modelsReachable) {
      healthMode = "degraded";
      healthReason = "model endpoint unreachable";
    } else if (hexstrikeToolCount === 0) {
      healthMode = "degraded";
      healthReason = "tool inventory unavailable";
    }
  }

  const localToolsStatus: ToolHealth["status"] =
    hasFfuf && hasSqlmap ? "online" : hasFfuf || hasSqlmap ? "degraded" : "offline";

  const localToolsDetail =
    hasFfuf && hasSqlmap ? "ffuf + sqlmap detected"
    : hasFfuf ? "ffuf detected, sqlmap not found"
    : hasSqlmap ? "sqlmap detected, ffuf not found"
    : "Neither ffuf nor sqlmap found on PATH";

  // ZAP role: active web vulnerability scanner — spiders targets, runs active
  // injection/XSS/auth probes, and populates the alert list consumed by the
  // autonomous engine's reportBuilder step.
  const zapDetail = zapUp
    ? "ZAP active scanner online · web vulnerability probing enabled"
    : "ZAP offline · active web scans will be skipped (start: zaproxy -daemon -port 8090 -config api.disablekey=true)";

  return [
    {
      id: "mcp-local",
      label: "HexStrike Local",
      status: healthMode,
      detail: hexstrikeUp
        ? `hexstrike_server.py ready on port ${HEXSTRIKE_PORT}${hexstrikeToolCount > 0 ? ` · ${hexstrikeToolCount} tools` : ""}${healthReason ? ` · ${healthReason}` : ""}`
        : "Start hexstrike_server.py to enable tool orchestration",
    },
    {
      id: "mcp-remote",
      label: "HexStrike AI",
      status: hexstrikeUp && geminiCfg && modelsReachable ? "online" : geminiCfg || hexstrikeUp ? "degraded" : "offline",
      detail: hexstrikeUp && geminiCfg
        ? `Gemini connected · model: ${geminiCfg.model}`
        : geminiCfg
        ? "API key configured — start hexstrike_server.py to activate"
        : "Add your API key in Settings, then start hexstrike_server.py",
    },
    {
      id: "local-tools",
      label: "Local Toolchain",
      status: zapUp ? localToolsStatus : localToolsStatus === "online" ? "degraded" : localToolsStatus,
      detail: `${localToolsDetail} · ${zapDetail}`,
    },
  ];
}

// ─── HexStrike /ask chat ──────────────────────────────────────────────────────

async function askHexStrikeDetailed(
  request: AskRequest,
  model = "gemini-2.0-flash",
): Promise<{ reply: string | null; modelUsed: string | null; error: string | null; kind: "offline" | "timeout" | "rate-limited" | "server" | "invalid" }> {
  const res = await hexstrikeJsonRequest<{ content?: string; response?: string; message?: string; model?: string; error?: string }>(
    "/ask",
    "POST",
    {
      prompt: request.prompt,
      sessionId: request.sessionId,
      projectId: request.projectId,
      knowledge_context: request.knowledgeContext,
      history: request.history ?? [],
      model,
    },
    20_000,
  );

  if (res.ok && res.data) {
    const content = res.data.content ?? res.data.response ?? res.data.message ?? null;
    const modelUsed = res.data.model ?? null;
    return { reply: content, modelUsed, error: null, kind: "server" };
  }

  if (res.errorKind === "timeout") {
    return { reply: null, modelUsed: null, error: "HexStrike AI timed out while generating a response.", kind: "timeout" };
  }
  if (res.errorKind === "offline") {
    return { reply: null, modelUsed: null, error: "HexStrike AI server is not reachable on 127.0.0.1:8888.", kind: "offline" };
  }
  if (res.errorKind === "http") {
    const msg = res.errorMessage ?? "Unknown server error";
    if (res.statusCode === 429 || /too many requests|quota|rate limit/i.test(msg)) {
      return {
        reply: null,
        modelUsed: null,
        error: "Gemini API quota limit reached.",
        kind: "rate-limited",
      };
    }
    return {
      reply: null,
      modelUsed: null,
      error: `HexStrike /ask failed (${res.statusCode ?? "n/a"}): ${msg}`,
      kind: "server",
    };
  }
  return { reply: null, modelUsed: null, error: "HexStrike AI returned an invalid response format.", kind: "invalid" };
}

export async function askHexStrike(request: AskRequest): Promise<AskResponse> {
  const start = Date.now();

  // Read the configured model once — passed to the server so it uses the right Gemini model.
  const cfg = await readGeminiConfig();
  const configuredModel = cfg?.model ?? "gemini-2.0-flash";

  // Route through HexStrike server — it owns the Gemini connection
  const { reply: serverReply, modelUsed, error, kind } = await askHexStrikeDetailed(request, configuredModel);
  if (serverReply) {
    return {
      transport: "remote",
      latencyMs: Date.now() - start,
      message: {
        id: `assistant-${Date.now()}`,
        role: "assistant",
        content: serverReply,
        timestamp: new Date().toISOString(),
        state: "complete",
        source: "hexstrike",
        model: modelUsed ?? configuredModel,
        kind: "normal",
      },
    };
  }

  // ── Error recovery ────────────────────────────────────────────────────────
  const hasCfg = cfg !== null;
  const recovery = (() => {
    if (kind === "rate-limited") {
      return "**What to do:**\n1. Wait 30–90 seconds and retry\n2. Switch to a lighter model in **Settings** (e.g. `gemini-2.0-flash-lite` — 30 RPM)\n3. Reduce rapid repeated requests";
    }
    if (kind === "timeout") {
      return "The model request timed out. Try again in a few seconds, or switch to a faster model in Settings.";
    }
    if (kind === "offline") {
      return "Start it with:\n```\ncd hexstrike-ai && python3 hexstrike_server.py\n```";
    }
    return hasCfg
      ? "HexStrike server is reachable but Ask failed. Check backend logs and Gemini quota/model health."
      : "1. Open **Settings** and paste your Google AI Studio API key\n2. Start the server: `cd hexstrike-ai && python3 hexstrike_server.py`\n\nGet a free key at: [aistudio.google.com](https://aistudio.google.com)";
  })();

  const isQuota = kind === "rate-limited";
  return {
    transport: "local",
    latencyMs: Date.now() - start,
    message: {
      id: `assistant-${Date.now()}`,
      role: "assistant",
      content: isQuota
        ? `**Gemini API Quota Limit Reached**\n\nAll models in the fallback chain returned 429 (Too Many Requests). The free tier has per-minute rate limits:\n\n| Model | Free RPM |\n|---|---|\n| gemini-2.5-flash | 10 |\n| gemini-2.5-flash-lite | 30 |\n| gemini-2.0-flash | 15 |\n| gemini-2.0-flash-lite | 30 |\n\n${recovery}`
        : `${error ?? "Unknown error."}\n\n${recovery}`,
      timestamp: new Date().toISOString(),
      state: "complete",
      source: "hexguard",
      kind: isQuota ? "quota" : "error",
    },
  };
}

// ─── Decision Engine API ──────────────────────────────────────────────────────

interface HexStrikeProposalResponse {
  options?: DecisionProposal["options"];
  contextSummary?: string;
  ragChunksUsed?: string[];
}

/**
 * Ask HexStrike to propose the next 2-4 ranked actions for the current hunt
 * session. Prior RAG knowledge chunks are included so HexStrike can reason over
 * them before proposing.
 *
 * Returns null if HexStrike is unreachable — callers fall back to local rules.
 */
export async function hexstrikeProposeDecisions(
  context: SessionContext,
  priorKnowledge: RagSearchChunk[] = [],
): Promise<HexStrikeProposalResponse | null> {
  // Compute per-tool run counts from phaseHints so Gemini knows what's been done
  const toolRunCounts: Record<string, number> = {
    ffuf:       context.phaseHints.filter(h => h === "discovery_done").length,
    sqlmap:     context.phaseHints.filter(h => h === "sqlmap_run").length,
    zap:        context.phaseHints.filter(h => h === "zap_run").length,
    hexstrike:  context.phaseHints.filter(h => h === "hexstrike_run").length,
  };

  return hexstrikePost<HexStrikeProposalResponse>(
    "/api/decision/propose",
    {
      target:             context.target,
      context_summary:    context.toolResults.map(r => `${r.tool}: ${r.summary}`).join("; "),
      findings:           context.findings.map(f => ({ title: f.title, severity: f.severity, endpoint: f.endpoint })),
      visited_endpoints:  context.visitedEndpoints,
      phase_hints:        context.phaseHints,
      tool_run_counts:    toolRunCounts,
      last_action:        context.lastAction ? {
        title:  context.lastAction.chosenOptionTitle,
        state:  context.lastAction.state,
        tool:   context.lastAction.toolParams,
      } : null,
      prior_knowledge: priorKnowledge.map(c => ({
        title: c.title,
        text:  c.text.slice(0, 1200),
        score: c.score,
      })),
    },
    60_000,
  );
}

// ─── Pipeline AI Analysis API ─────────────────────────────────────────────────

/**
 * Send a batch of HttpCapture objects to HexStrike for AI vulnerability analysis.
 * Returns a structured findings list or null if HexStrike is unavailable.
 */
export async function hexstrikeAnalyzeHttp(
  captures: HttpCapture[],
  existingFindings: Finding[],
  tech?: TechFingerprint,
): Promise<unknown | null> {
  // Trim payload: cap body previews at 1 KB each to stay within context limits
  const trimmedCaptures = captures.slice(0, 30).map(c => ({
    url:         c.url,
    method:      c.method,
    statusCode:  c.statusCode,
    contentType: c.contentType,
    timingMs:    c.timingMs,
    headers:     c.headers,
    bodyPreview: c.bodyPreview.slice(0, 1024),
  }));

  return hexstrikePost<unknown>(
    "/api/analyze-http",
    {
      captures:         trimmedCaptures,
      existing_findings: existingFindings.map(f => ({ title: f.title, severity: f.severity, endpoint: f.endpoint })),
      tech_fingerprint: tech ?? null,
    },
    90_000,
  );
}

/**
 * Ask HexStrike to detect technology stack from response headers and an HTML snippet.
 * Returns tech fingerprint data or null if HexStrike is unavailable.
 */
export async function hexstrikeFingerprint(
  headers: Record<string, string>,
  htmlSnippet: string,
): Promise<unknown | null> {
  return hexstrikePost<unknown>(
    "/api/fingerprint",
    {
      headers,
      html_snippet: htmlSnippet.slice(0, 4096),
    },
    30_000,
  );
}

// ─── PoC + Report synthesis ───────────────────────────────────────────────────

/**
 * Ask HexStrike to generate a proof-of-concept and CVSS score for a confirmed finding.
 */
export async function hexstrikeGeneratePoc(
  finding: Finding,
  target: string,
): Promise<ExploitResult | null> {
  const res = await hexstrikePost<Record<string, unknown>>(
    "/api/generate-poc",
    { finding, target },
    60_000,
  );
  if (!res) return null;
  return {
    findingId:        finding.id,
    pocCurl:          String(res["poc_curl"] ?? ""),
    pocDescription:   String(res["poc_description"] ?? ""),
    remediationSteps: Array.isArray(res["remediation_steps"])
      ? (res["remediation_steps"] as unknown[]).map(String)
      : [],
    cvssScore:  Number(res["cvss_score"] ?? 0),
    cvssVector: String(res["cvss_vector"] ?? ""),
  };
}

/**
 * Ask HexStrike to synthesize all findings into CVSS scores, attack chains,
 * and an executive summary.
 */
export async function hexstrikeSynthesizeReport(
  findings: Finding[],
  target: string,
  tech?: TechFingerprint,
): Promise<unknown | null> {
  return hexstrikePost<unknown>(
    "/api/synthesize-report",
    {
      findings: findings.map(f => ({
        id: f.id, title: f.title, severity: f.severity,
        endpoint: f.endpoint, evidence: f.evidence.slice(0, 300), tool: f.tool,
      })),
      target,
      tech: tech ?? null,
    },
    120_000,
  );
}

// ─── File Text Extraction ─────────────────────────────────────────────────────

/**
 * Send a file's raw bytes to HexStrike for text extraction (PDF / DOCX).
 * Returns the extracted plain text, or null if extraction fails.
 */
export async function hexstrikeExtractText(
  fileBytes: Buffer,
  fileType: string,
  filename: string,
): Promise<string | null> {
  try {
    const boundary = `----HexGuardBoundary${Date.now()}`;
    const nl = "\r\n";
    const preamble = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="file"; filename="${filename}.${fileType}"`,
      `Content-Type: application/octet-stream`,
      "",
      "",
    ].join(nl);
    const epilogue = `${nl}--${boundary}--${nl}`;
    const preambleBuffer = Buffer.from(preamble, "utf8");
    const epilogueBuffer = Buffer.from(epilogue, "utf8");
    const body = Buffer.concat([preambleBuffer, fileBytes, epilogueBuffer]);

    return await new Promise<string | null>((resolve) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: HEXSTRIKE_PORT,
          path: "/api/extract-text",
          method: "POST",
          timeout: 30_000,
          headers: {
            "Content-Type": `multipart/form-data; boundary=${boundary}`,
            "Content-Length": body.length,
          },
        },
        res => {
          let data = "";
          res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
          res.on("end", () => {
            try {
              const parsed = JSON.parse(data) as { text?: string };
              resolve(typeof parsed.text === "string" ? parsed.text : null);
            } catch {
              resolve(null);
            }
          });
        }
      );
      req.on("error", () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.write(body);
      req.end();
    });
  } catch {
    return null;
  }
}

// ─── Autonomous Mode API ──────────────────────────────────────────────────────

/**
 * Ask HexStrike to select the single best next action for the autonomous hunt loop.
 * Sends full session context, already-tried exclusions, and the action graph.
 * Returns a HexstrikeActionProposal or null if HexStrike is unreachable.
 */
export async function hexstrikeSelectNextAction(
  session: import("@hexguard/shared").HuntSession,
  exclusions: string[],
  actionGraph: import("@hexguard/shared").AutonomousActionRecord[],
): Promise<import("@hexguard/shared").HexstrikeActionProposal | null> {
  const ctx = session.context;
  const raw = await hexstrikePost<Record<string, unknown>>(
    "/api/autonomous/select-action",
    {
      target:            ctx.target,
      findings:          ctx.findings.map(f => ({ title: f.title, severity: f.severity, endpoint: f.endpoint })),
      visited_endpoints: ctx.visitedEndpoints.slice(0, 50),
      tech_fingerprint:  ctx.techFingerprint ?? null,
      current_strategy:  ctx.currentStrategy ?? "recon",
      termination_score: ctx.terminationScore ?? 0,
      exploit_paths:     ctx.exploitPaths ?? [],
      action_graph:      actionGraph.slice(-20).map(a => ({
        actionType: a.actionType, tool: a.tool, rationale: a.rationale,
        findingsCount: a.findingsCount, durationMs: a.durationMs,
      })),
      exclusions: exclusions.slice(-100),
    },
    60_000,
  );
  if (!raw) return null;
  return {
    actionType:       String(raw["action_type"] ?? "recon") as import("@hexguard/shared").AutonomousActionType,
    tool:             String(raw["tool"] ?? "http-recon"),
    toolParams:       (raw["tool_params"] as Record<string, unknown>) ?? {},
    rationale:        String(raw["rationale"] ?? ""),
    aiConfidence:     Number(raw["ai_confidence"] ?? 0.5),
    terminationScore: raw["termination_score"] != null ? Number(raw["termination_score"]) : undefined,
    parentActionId:   raw["parent_action_id"] != null ? String(raw["parent_action_id"]) : undefined,
    skipIfTried:      raw["skip_if_tried"] === true,
  };
}

/**
 * Ask HexStrike to evaluate overall assessment completeness.
 * Returns a score 0–100; ≥ terminationThreshold means the hunt should end.
 */
export async function hexstrikeEvaluateTermination(
  session: import("@hexguard/shared").HuntSession,
  actionGraph: import("@hexguard/shared").AutonomousActionRecord[],
): Promise<number> {
  const ctx = session.context;
  const raw = await hexstrikePost<{ termination_score?: number }>(
    "/api/autonomous/termination-score",
    {
      target:            ctx.target,
      findings:          ctx.findings.map(f => ({ title: f.title, severity: f.severity, endpoint: f.endpoint })),
      visited_endpoints: ctx.visitedEndpoints.length,
      action_count:      actionGraph.length,
      high_critical_count: ctx.findings.filter(f => f.severity === "high" || f.severity === "critical").length,
      exploit_paths:     (ctx.exploitPaths ?? []).map(p => ({ title: p.title, status: p.status })),
    },
    30_000,
  );
  return raw && typeof raw.termination_score === "number" ? raw.termination_score : 0;
}
