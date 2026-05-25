/**
 * startupManager.ts — Manages the HexStrike server child process and
 * runs all pre-flight checks at application startup.
 *
 * Responsibilities:
 *   1. Spawn hexstrike_server.py (inside its venv if present)
 *   2. Poll /health until the server is ready (max 20 s)
 *   3. Run 6 dependency checks in parallel (python, hexstrike, gemini-cfg,
 *      ffuf, sqlmap, burp)
 *   4. Emit live PreflightCheck updates via a callback (forwarded to IPC)
 *   5. SIGTERM the child process on app quit
 *
 * Layer contract:
 *   - This module is pure Node.js / Electron main-process code.
 *   - It does NOT import from workflowEngine or any scan engine.
 */

import * as http from "node:http";
import * as path from "node:path";
import * as fs from "node:fs";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import { app } from "electron";
import type { HexStrikeDiagnostics, PreflightCheck, PreflightCheckId, PreflightReport } from "@hexguard/shared";
import { readGeminiConfig } from "./mcpClient";
import { tryAutoInstall } from "../adapters/toolInstaller";

const execFileAsync = promisify(execFile);

// ─── Constants ─────────────────────────────────────────────────────────────────

const HEXSTRIKE_PORT   = 8888;
const POLL_INTERVAL_MS = 500;
const POLL_MAX_MS      = 20_000;

// ─── State ─────────────────────────────────────────────────────────────────────

let hexstrikeProcess: ChildProcess | null = null;
let launchState: HexStrikeDiagnostics = {
  status: "stopped",
  pid: null,
  python: "",
  script: "",
  cwd: "",
  lastExitCode: null,
  lastSignal: null,
  lastError: null,
  recentStdout: [],
  recentStderr: [],
  launchedAt: null,
};

function trimLogs(lines: string[], line: string): string[] {
  const next = [...lines, line].slice(-50);
  return next;
}

function onLogChunk(kind: "stdout" | "stderr", chunk: Buffer | string): void {
  const text = chunk.toString();
  const rows = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  for (const row of rows) {
    if (kind === "stdout") {
      launchState.recentStdout = trimLogs(launchState.recentStdout, row);
    } else {
      launchState.recentStderr = trimLogs(launchState.recentStderr, row);
    }
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function backendDir(): string {
  // Try multiple candidate paths — different launch modes resolve differently.
  // hexstrike_server.py existence is used to verify the candidate before returning.
  //
  // Directory layout (dev):
  //   repo-root/
  //     hexstrike-ai/hexstrike_server.py       ← target
  //     packages/desktop/
  //       package.json                         ← app.getAppPath() points here
  //       dist/main/services/startupManager.js ← __dirname is HERE (5 levels deep)
  //
  const candidates = [
    // 1. pnpm sets INIT_CWD to the directory where the user ran pnpm (repo root)
    ...(process.env.INIT_CWD ? [path.join(process.env.INIT_CWD, "hexstrike-ai")] : []),
    // 2. app.getAppPath() = packages/desktop/ → go 2 levels up
    path.join(app.getAppPath(), "..", "..", "hexstrike-ai"),
    // 3. __dirname = packages/desktop/dist/main/services/ → 5 levels up to repo root
    path.join(__dirname, "..", "..", "..", "..", "..", "hexstrike-ai"),
    // 4. __dirname → 4 levels up (covers alternate build layouts)
    path.join(__dirname, "..", "..", "..", "..", "hexstrike-ai"),
    // 5. process.cwd() might be repo root (e.g., when run from root with pnpm dev)
    path.join(process.cwd(), "hexstrike-ai"),
    // 6. process.cwd() = packages/desktop/ → 2 levels up
    path.join(process.cwd(), "..", "..", "hexstrike-ai"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, "hexstrike_server.py"))) {
      console.error("[HexGuard] backendDir →", candidate);
      return candidate;
    }
  }
  // Log all attempted paths to help diagnose future failures
  console.error("[HexGuard] backendDir: none of the candidates contained hexstrike_server.py:");
  for (const c of candidates) console.error("  tried:", c);
  return candidates[1]; // fall back to the getAppPath-based guess
}

function venvPython(): string | null {
  const candidate = path.join(backendDir(), "hexstrike-env", "bin", "python3");
  return fs.existsSync(candidate) ? candidate : null;
}

function httpCheck(port: number, urlPath = "/"): Promise<boolean> {
  return new Promise(resolve => {
    const req = http.get(
      { hostname: "127.0.0.1", port, path: urlPath, timeout: 2_000 },
      res => { resolve((res.statusCode ?? 0) < 500); res.resume(); }
    );
    req.on("error",   () => resolve(false));
    req.on("timeout", () => { req.destroy(); resolve(false); });
  });
}

async function whichExists(bin: string): Promise<boolean> {
  // Import the full whichBinary helper so ~/go/bin, ~/.local/bin, /snap/bin
  // etc. are probed in addition to the standard PATH.
  const { whichBinary } = await import("../adapters/base.js");
  return (await whichBinary(bin)) !== null;
}

/** Poll /health until up or timeout */
async function waitForHexStrike(): Promise<boolean> {
  const deadline = Date.now() + POLL_MAX_MS;
  let attempts = 0;
  while (Date.now() < deadline) {
    // Bail early if our managed process died before becoming ready.
    // If hexstrikeProcess is null but status is "running" it means we adopted
    // an existing external process — keep polling in that case.
    if (!hexstrikeProcess && launchState.status !== "running") {
      console.error(`[HexStrike] waitForHexStrike: early exit — process gone, status=${launchState.status}`);
      return false;
    }
    const up = await httpCheck(HEXSTRIKE_PORT, "/health");
    attempts++;
    if (up) {
      console.error(`[HexStrike] waitForHexStrike: /health OK after ${attempts} attempts`);
      return true;
    }
    if (attempts === 1 || attempts % 10 === 0) {
      console.error(`[HexStrike] waitForHexStrike: attempt ${attempts}, status=${launchState.status}, pid=${launchState.pid}, stderr=${launchState.recentStderr.slice(-1)[0] ?? "none"}`);
    }
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
  }
  console.error(`[HexStrike] waitForHexStrike: 20s timeout, status=${launchState.status}, lastExit=${launchState.lastExitCode}, lastErr=${launchState.lastError}, stderr=${launchState.recentStderr.slice(-2).join(" | ")}`);
  return false;
}

async function probeHexStrikeCapabilities(): Promise<{ toolsOk: boolean; modelsOk: boolean }> {
  const [toolsOk, modelsOk] = await Promise.all([
    httpCheck(HEXSTRIKE_PORT, "/health/tools"),
    httpCheck(HEXSTRIKE_PORT, "/models"),
  ]);
  return { toolsOk, modelsOk };
}

// ─── Launch ─────────────────────────────────────────────────────────────────────

/**
 * Kill any process currently binding the given TCP port so the next spawn can
 * claim it. Uses `fuser -k` (Linux). Swallows all errors — if nothing is on
 * the port, fuser exits non-zero and we ignore it.
 */
async function freePort(port: number): Promise<void> {
  try {
    await execFileAsync("fuser", ["-k", `${port}/tcp`], { timeout: 3_000 });
    // Brief pause so the OS fully releases the socket before the next bind.
    await new Promise(r => setTimeout(r, 600));
  } catch {
    // fuser not found, or no process on port — both are fine.
  }
}

/**
 * Spawn hexstrike_server.py.
 * Uses the venv python if found; falls back to system python3.
 * Reads the stored Gemini API key and injects it as GEMINI_API_KEY so the
 * server can authenticate with Google AI Studio without any separate config.
 * Safe to call multiple times — kills existing process first.
 * Serialised via mutex — concurrent calls wait for the first to complete.
 */
let _launchMutex: Promise<void> | null = null;

export async function launchHexStrike(): Promise<void> {
  // Serialise concurrent callers: if a launch is already in progress, wait
  // for it to complete then return — the server will be up (or failed).
  if (_launchMutex) {
    console.error("[HexStrike] launchHexStrike: another launch in progress, waiting...");
    await _launchMutex;
    console.error(`[HexStrike] launchHexStrike: resumed after wait, status=${launchState.status}`);
    return;
  }

  let _resolve!: () => void;
  _launchMutex = new Promise<void>(r => { _resolve = r; });

  try {
    await _doLaunchHexStrike();
  } finally {
    _launchMutex = null;
    _resolve();
  }
}

async function _doLaunchHexStrike(): Promise<void> {
  // If a HexStrike-compatible server is already answering on the port (e.g. a
  // stale process from a previous session), adopt it instead of trying to bind
  // again — which would fail with "Port 8888 is in use".
  const alreadyUp = await httpCheck(HEXSTRIKE_PORT, "/health");
  console.error(`[HexStrike] launchHexStrike: alreadyUp=${alreadyUp}`);
  if (alreadyUp) {
    // A healthy HexStrike is already on the port (stale process from a prior
    // session). Adopt it — no need to spawn.
    launchState.status = "running";
    launchState.pid = null; // external process, PID unknown to us
    return;
  }

  // Port may be held by a dead/zombie process that isn't responding to HTTP.
  // Evict it so our new spawn can bind successfully.
  await freePort(HEXSTRIKE_PORT);

  if (hexstrikeProcess && !hexstrikeProcess.killed) {
    hexstrikeProcess.kill("SIGTERM");
    hexstrikeProcess = null;
  }

  const dir    = backendDir();
  const py     = venvPython() ?? "python3";
  const script = path.join(dir, "hexstrike_server.py");

  console.error(`[HexStrike] spawn: dir=${dir} py=${py} scriptExists=${fs.existsSync(script)}`);
  if (!fs.existsSync(script)) return; // backend not present — checked separately

  // Read the stored Gemini config and pass it to the server process as env vars
  let geminiEnv: Record<string, string> = {};
  try {
    const cfgPath = path.join(app.getPath("userData"), "hexguard-gemini.json");
    const raw = fs.readFileSync(cfgPath, "utf8");
    const cfg = JSON.parse(raw) as { apiKey?: string; model?: string };
    if (cfg.apiKey) {
      geminiEnv["GEMINI_API_KEY"] = cfg.apiKey;
    }
    if (cfg.model) {
      geminiEnv["GEMINI_MODEL"] = cfg.model;
    }
  } catch {
    // Config not yet written — server will start without key (shows error on /ask)
  }

  hexstrikeProcess = spawn(py, [script, "--port", String(HEXSTRIKE_PORT)], {
    cwd: dir,
    stdio: ["ignore", "pipe", "pipe"],
    detached: false,
    env: { ...process.env, ...geminiEnv },
  });

  launchState = {
    status: "starting",
    pid: hexstrikeProcess.pid ?? null,
    python: py,
    script,
    cwd: dir,
    lastExitCode: null,
    lastSignal: null,
    lastError: null,
    recentStdout: [],
    recentStderr: [],
    launchedAt: new Date().toISOString(),
  };

  hexstrikeProcess.stdout?.on("data", chunk => onLogChunk("stdout", chunk));
  hexstrikeProcess.stderr?.on("data", chunk => onLogChunk("stderr", chunk));

  hexstrikeProcess.on("error", (err) => {
    launchState.lastError = err.message;
    launchState.status = "stopped";
    hexstrikeProcess = null;
  });
  hexstrikeProcess.on("spawn", () => {
    launchState.status = "running";
  });
  hexstrikeProcess.on("exit", (code, signal) => {
    launchState.lastExitCode = code;
    launchState.lastSignal = signal;
    launchState.status = "stopped";
    hexstrikeProcess = null;
  });
}

export function shutdownHexStrike(): void {
  if (hexstrikeProcess && !hexstrikeProcess.killed) {
    hexstrikeProcess.kill("SIGTERM");
    hexstrikeProcess = null;
  }
  launchState.status = "stopped";
}

export async function restartHexStrike(): Promise<void> {
  // Force kill any existing managed process before relaunching.
  if (hexstrikeProcess && !hexstrikeProcess.killed) {
    hexstrikeProcess.kill("SIGTERM");
    hexstrikeProcess = null;
    // Brief pause so the OS releases the port before we try to bind again.
    await new Promise(r => setTimeout(r, 800));
  }
  await launchHexStrike();
  await waitForHexStrike();
}

export function getHexStrikeDiagnostics(): HexStrikeDiagnostics {
  return { ...launchState };
}

// ─── Preflight checks ──────────────────────────────────────────────────────────

const INITIAL_CHECKS: PreflightCheck[] = [
  { id: "python",     label: "Python 3",        critical: true,  status: "pending", detail: "Checking python3..." },
  { id: "hexstrike",  label: "HexStrike Server", critical: true,  status: "pending", detail: "Starting hexstrike_server.py..." },
  { id: "gemini-cfg", label: "API Key",          critical: false, status: "pending", detail: "Reading config file..." },
  { id: "ffuf",       label: "ffuf",             critical: false, status: "pending", detail: "Checking ffuf on PATH..." },
  { id: "sqlmap",     label: "sqlmap",           critical: false, status: "pending", detail: "Checking sqlmap on PATH..." },
  { id: "zap",        label: "OWASP ZAP",        critical: false, status: "pending", detail: "Probing ZAP REST API on port 8090..." },
  { id: "wafw00f",     label: "wafw00f",           critical: true,  status: "pending", detail: "Checking wafw00f on PATH..." },
  { id: "nuclei",      label: "Nuclei",            critical: false, status: "pending", detail: "Checking nuclei on PATH..." },
  { id: "nikto",       label: "nikto",             critical: false, status: "pending", detail: "Checking nikto on PATH..." },
  { id: "wapiti",      label: "wapiti",            critical: true,  status: "pending", detail: "Checking wapiti on PATH..." },
  { id: "h2csmuggler", label: "h2csmuggler",       critical: false, status: "pending", detail: "Checking h2csmuggler on PATH..." },
  { id: "surf",        label: "surf",              critical: false, status: "pending", detail: "Checking surf on PATH..." },
];

export async function runPreflightChecks(
  onUpdate: (check: PreflightCheck) => void
): Promise<PreflightReport> {
  const checks = new Map<PreflightCheckId, PreflightCheck>(
    INITIAL_CHECKS.map(c => [c.id, { ...c }])
  );

  function push(id: PreflightCheckId, status: PreflightCheck["status"], detail: string): void {
    const c = checks.get(id)!;
    c.status = status;
    c.detail = detail;
    onUpdate({ ...c });
  }

  // Mark all as "checking"
  for (const c of checks.values()) push(c.id, "checking", c.detail);

  // ── python ────────────────────────────────────────────────────────────────
  const pythonCheck = whichExists("python3").then(ok => {
    push("python", ok ? "pass" : "fail",
      ok ? "python3 found on PATH" : "python3 not found — install Python 3.10+ to run HexStrike");
  });

  // ── hexstrike ─────────────────────────────────────────────────────────────
  const hexstrikeCheck = (async () => {
    const script = path.join(backendDir(), "hexstrike_server.py");
    if (!fs.existsSync(script)) {
      push("hexstrike", "fail", "hexstrike_server.py not found — check hexstrike-ai/ directory");
      return;
    }
    await launchHexStrike();
    const up = await waitForHexStrike();
    if (!up) {
      const diag = getHexStrikeDiagnostics();
      const lastErr = diag.lastError
        ?? diag.recentStderr[diag.recentStderr.length - 1]
        ?? (diag.lastExitCode !== null ? `Process exited with code ${diag.lastExitCode}` : "no startup diagnostics available");
      push("hexstrike", "fail", `HexStrike did not become ready: ${lastErr}`);
      return;
    }

    const caps = await probeHexStrikeCapabilities();
    push("hexstrike", up ? "pass" : "fail",
      caps.toolsOk && caps.modelsOk
        ? `HexStrike server ready on port ${HEXSTRIKE_PORT}`
        : `HexStrike online with degraded capabilities (${!caps.toolsOk ? "tools" : "models"} probe failed)`);
  })();

  // ── gemini-cfg ────────────────────────────────────────────────────────────
  const configCheck = readGeminiConfig().then(cfg => {
    push("gemini-cfg", cfg ? "pass" : "warn",
      cfg
        ? `API key configured · model: ${cfg.model}`
        : "No API key found — open Settings and paste your Google AI Studio key");
  });

  // ── non-critical tools (parallel, independent) ────────────────────────────
  const ffufCheck   = whichExists("ffuf").then(ok =>
    push("ffuf",   ok ? "pass" : "warn", ok ? "ffuf found on PATH" : "ffuf not found — endpoint discovery will use fallback path list"));
  const sqlmapCheck = whichExists("sqlmap").then(ok =>
    push("sqlmap", ok ? "pass" : "warn", ok ? "sqlmap found on PATH" : "sqlmap not found — injection testing will be skipped"));
  const zapCheck    = (async () => {
    const daemonUp = await httpCheck(8090, "/JSON/core/view/version/");
    if (daemonUp) {
      push("zap", "pass", "OWASP ZAP daemon online on port 8090 · active scanner ready");
      return;
    }
    const installed = await whichExists("zaproxy") || await whichExists("zap.sh");
    if (!installed) {
      push("zap", "warn", "OWASP ZAP not found — active web scan step will be skipped (install: snap install zaproxy --classic)");
      return;
    }
    // ZAP is installed but daemon is not running — spawn it automatically
    push("zap", "checking", "Launching ZAP daemon...");
    const zapBin = await whichExists("zaproxy") ? "zaproxy" : "zap.sh";
    try {
      const { spawn } = await import("node:child_process");
      spawn(zapBin, ["-daemon", "-port", "8090", "-config", "api.disablekey=true"], {
        detached: true, stdio: "ignore",
      }).unref();
    } catch {
      push("zap", "warn", "Failed to auto-launch ZAP — start manually: zaproxy -daemon -port 8090 -config api.disablekey=true");
      return;
    }
    // Wait up to 15 s for ZAP to bind its port
    let up = false;
    for (let i = 0; i < 15; i++) {
      await new Promise(r => setTimeout(r, 1_000));
      up = await httpCheck(8090, "/JSON/core/view/version/");
      if (up) break;
    }
    push("zap", up ? "pass" : "warn",
      up
        ? "OWASP ZAP daemon launched and ready on port 8090 · active scanner ready"
        : "ZAP launched but did not respond in time — active scans may be unavailable");
  })();

  // ── wafw00f ───────────────────────────────────────────────────────────────
  const consoleFn = (tag: "info" | "warn" | "err" | "out", text: string) =>
    console.error(`[preflight:${tag}] ${text}`);

  const wafw00fCheck = (async () => {
    push("wafw00f", "checking", "Checking wafw00f…");
    const already = await whichExists("wafw00f");
    if (already) { push("wafw00f", "pass", "wafw00f found on PATH · WAF detection ready"); return; }
    push("wafw00f", "checking", "wafw00f not found — attempting auto-install via pipx/pip3…");
    const ok = await tryAutoInstall({ binary: "wafw00f", method: "pip3", packageName: "wafw00f" }, consoleFn);
    push("wafw00f", ok ? "pass" : "warn",
      ok
        ? "wafw00f installed successfully · WAF detection ready"
        : "wafw00f not installed — run: pipx install wafw00f (or: pip3 install wafw00f)");
  })();

  // ── nuclei ─────────────────────────────────────────────────────────────────────────
  const nucleiCheck = (async () => {
    push("nuclei", "checking", "Checking nuclei…");
    const already = await whichExists("nuclei");
    if (already) { push("nuclei", "pass", "nuclei found on PATH · vulnerability scanner ready"); return; }
    push("nuclei", "checking", "nuclei not found — attempting auto-install via go install…");
    const ok = await tryAutoInstall(
      { binary: "nuclei", method: "go-install", packageName: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
      consoleFn,
    );
    push("nuclei", ok ? "pass" : "warn",
      ok
        ? "Nuclei installed successfully · vulnerability scanner ready"
        : "Nuclei not installed — requires Go. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest (https://go.dev/dl/)");
  })();

  // ── wapiti ────────────────────────────────────────────────────────────────
  const wapitiCheck = (async () => {
    push("wapiti", "checking", "Checking wapiti…");
    const already = await whichExists("wapiti");
    if (already) { push("wapiti", "pass", "wapiti found on PATH · vulnerability scanner ready"); return; }
    push("wapiti", "checking", "wapiti not found — attempting auto-install via pipx/pip3…");
    const ok = await tryAutoInstall({ binary: "wapiti", method: "pip3", packageName: "wapiti3" }, consoleFn);
    push("wapiti", ok ? "pass" : "warn",
      ok
        ? "wapiti installed successfully · vulnerability scanner ready"
        : "wapiti not installed — run: pipx install wapiti3");
  })();

  // ── nikto ─────────────────────────────────────────────────────────────────────────
  const niktoCheck = (async () => {
    push("nikto", "checking", "Checking nikto…");
    const already = await whichExists("nikto");
    if (already) { push("nikto", "pass", "nikto found on PATH · web server scanner ready"); return; }
    push("nikto", "checking", "nikto not found — requesting system install via pkexec…");
    const ok = await tryAutoInstall({ binary: "nikto", method: "apt-pkexec", packageName: "nikto" }, consoleFn);
    push("nikto", ok ? "pass" : "warn",
      ok
        ? "nikto installed successfully · web server scanner ready"
        : "nikto not installed — run: sudo apt install nikto");
  })();

  // ── h2csmuggler ───────────────────────────────────────────────────────────────────
  const h2cSmugglerCheck = (async () => {
    push("h2csmuggler", "checking", "Checking h2csmuggler…");
    const already = await whichExists("h2csmuggler");
    if (already) { push("h2csmuggler", "pass", "h2csmuggler found on PATH · H2C smuggling detection ready"); return; }
    push("h2csmuggler", "checking", "h2csmuggler not found — attempting auto-install via go install…");
    const ok = await tryAutoInstall(
      { binary: "h2csmuggler", method: "go-install", packageName: "github.com/assetnote/h2csmuggler@latest" },
      consoleFn,
    );
    push("h2csmuggler", ok ? "pass" : "warn",
      ok
        ? "h2csmuggler installed successfully · H2C smuggling detection ready"
        : "h2csmuggler not installed — requires Go. Install: go install github.com/assetnote/h2csmuggler@latest (https://go.dev/dl/)");
  })();

  // ── surf ─────────────────────────────────────────────────────────────────────────────────
  const surfCheck = (async () => {
    push("surf", "checking", "Checking surf…");
    const already = await whichExists("surf");
    if (already) { push("surf", "pass", "surf found on PATH · SSRF candidate detection ready"); return; }
    push("surf", "checking", "surf not found — attempting auto-install via go install…");
    const ok = await tryAutoInstall(
      { binary: "surf", method: "go-install", packageName: "github.com/assetnote/surf@latest" },
      consoleFn,
    );
    push("surf", ok ? "pass" : "warn",
      ok
        ? "surf installed successfully · SSRF candidate detection ready"
        : "surf not installed — requires Go. Install: go install github.com/assetnote/surf@latest (https://go.dev/dl/)");
  })();

  await Promise.all([pythonCheck, hexstrikeCheck, configCheck, ffufCheck, sqlmapCheck, zapCheck, wafw00fCheck, niktoCheck, nucleiCheck, wapitiCheck, h2cSmugglerCheck, surfCheck]);

  const all = Array.from(checks.values());
  const allCriticalPass = all.filter(c => c.critical).every(c => c.status === "pass");
  return { checks: all, allCriticalPass };
}
