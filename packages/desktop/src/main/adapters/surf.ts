/**
 * surf.ts — Adapter for surf (Assetnote SSRF escalation tool).
 *
 * surf filters a list of discovered URLs/hosts to identify viable SSRF
 * candidates — endpoints that can be coerced into making outbound requests
 * to cloud metadata services (AWS IMDSv1, GCP, Azure), internal services,
 * or open redirects that chain into SSRF.
 *
 * Input:  session.context.visitedEndpoints piped to stdin (newline-delimited)
 * Output: lines with URLs that are viable SSRF candidates
 *
 * Runs: surf   (reads stdin, writes stdout)
 *
 * Install: go install github.com/assetnote/surf@latest
 *
 * Security: spawn() with explicit args array — no shell interpolation.
 * Only runs in active/autonomous/simulation profiles (not passive).
 * Requires visitedEndpoints to be populated by a prior discovery phase.
 */

import { spawn } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import { whichBinary } from "./base";
import { tryAutoInstall } from "./toolInstaller";
import type { Finding, HuntSession, PhaseResult } from "@hexguard/shared";

type ConsoleFn = (tag: "info" | "warn" | "err" | "res" | "out", text: string) => void;

interface AdapterResult {
  success: boolean;
  exitCode: number;
  error?: string;
  durationMs: number;
}

export interface SurfResult extends AdapterResult {
  tool: "surf";
  candidates: string[]; // URLs identified as SSRF-viable
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

let _idCounter = 0;
function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${(++_idCounter).toString(36)}`;
}
function nowIso(): string {
  return new Date().toISOString();
}

/** Extra PATH locations where Go installs binaries. */
const GO_BIN_PATHS = [
  path.join(os.homedir(), "go", "bin"),
  path.join(os.homedir(), ".local", "bin"),
  "/usr/local/bin",
  "/usr/local/go/bin",
  "/snap/bin",
];

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const surfAdapter = {
  toolName: "surf" as const,

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("surf")) !== null;
  },

  async invoke(options: {
    urls:       string[];   // list of candidate URLs to check
    timeoutMs?: number;
    onConsole?: ConsoleFn;
  }): Promise<SurfResult> {
    const start = Date.now();
    const log   = options.onConsole ?? (() => {});

    if (options.urls.length === 0) {
      return {
        tool: "surf", success: true, exitCode: 0,
        durationMs: Date.now() - start, candidates: [],
      };
    }

    if (!(await this.isAvailable())) {
      log("info", "[surf] not found — attempting auto-install via go install…");
      const installed = await tryAutoInstall(
        { binary: "surf", method: "go-install", packageName: "github.com/assetnote/surf@latest" },
        log,
      );
      if (!installed) {
        log("warn", "[surf] Auto-install failed — skipping SSRF analysis. Install: go install github.com/assetnote/surf@latest");
        return {
          tool: "surf", success: false, exitCode: -1,
          error: "surf not found", durationMs: Date.now() - start, candidates: [],
        };
      }
    }

    log("info", `[surf] Analysing ${options.urls.length} endpoint(s) for SSRF viability…`);

    const augmentedPath = [...GO_BIN_PATHS, process.env["PATH"] ?? ""].join(":");
    const input = options.urls.join("\n") + "\n";

    return new Promise(resolve => {
      let stdout = "";
      let settled = false;
      const timeout = options.timeoutMs ?? 120_000; // 2 min

      const proc = spawn("surf", [], {
        shell: false,
        env: { ...process.env, PATH: augmentedPath },
      });

      const timer = setTimeout(() => {
        if (!settled) { settled = true; proc.kill("SIGTERM"); }
      }, timeout);

      // Write all URLs to stdin then close
      proc.stdin.write(input);
      proc.stdin.end();

      proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on("data", (d: Buffer) => {
        const line = d.toString().trim();
        if (line) log("info", `[surf] ${line.slice(0, 200)}`);
      });

      proc.on("close", code => {
        clearTimeout(timer);
        settled = true;
        const candidates = stdout
          .split("\n")
          .map(l => l.trim())
          .filter(l => l.length > 0 && (l.startsWith("http://") || l.startsWith("https://")));

        log(
          candidates.length > 0 ? "res" : "out",
          `[surf] ${candidates.length} viable SSRF candidate(s) identified (exit ${code ?? "?"})`,
        );
        resolve({
          tool: "surf", success: true,
          exitCode: code ?? -1, durationMs: Date.now() - start,
          candidates,
        });
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        settled = true;
        const msg = err.code === "ENOENT"
          ? "surf not found in PATH — install: go install github.com/assetnote/surf@latest"
          : `Failed to spawn surf: ${err.message}`;
        log("err", `[surf] ${msg}`);
        resolve({
          tool: "surf", success: false, exitCode: -1,
          error: msg, durationMs: Date.now() - start, candidates: [],
        });
      });
    });
  },
};

// ─── Phase runner ─────────────────────────────────────────────────────────────

export async function runSurfPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  if (session.config.profile === "passive") {
    onConsole("info", "[surf] Skipping SSRF analysis in passive profile");
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const endpoints = session.context.visitedEndpoints ?? [];
  if (endpoints.length === 0) {
    onConsole("info", "[surf] No discovered endpoints yet — skipping SSRF analysis");
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const res = await surfAdapter.invoke({
    urls:      endpoints,
    onConsole,
    timeoutMs: 120_000,
  });

  if (res.candidates.length === 0) {
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const findings: Finding[] = res.candidates.map(url => ({
    id:        makeId("finding-surf"),
    timestamp: nowIso(),
    title:     `SSRF candidate: ${url}`,
    severity:  "medium" as Finding["severity"],
    endpoint:  url,
    evidence:
      "surf identified this endpoint as a viable SSRF candidate. " +
      "The endpoint may be used to coerce the server into making outbound requests " +
      "to cloud metadata services (AWS IMDSv1, GCP, Azure) or internal network resources.\n\n" +
      `Candidate URL: ${url}`,
    tool: "surf",
  }));

  onConsole(
    "res",
    `[surf] ${findings.length} SSRF candidate(s) — verify manually for cloud metadata exfiltration`,
  );
  return { findings, captures: [], visitedEndpoints: [] };
}
