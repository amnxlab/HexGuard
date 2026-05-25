/**
 * h2csmuggler.ts — Adapter for h2csmuggler (HTTP/2 Cleartext Smuggling detector).
 *
 * h2csmuggler (by Assetnote) checks whether a target accepts HTTP/1.1 → HTTP/2
 * cleartext (h2c) upgrade requests. Servers and reverse proxies that pass the
 * Upgrade header to a backend that speaks h2c allow request-smuggling attacks
 * that can bypass security controls (WAFs, auth middleware, ACLs).
 *
 * Runs: h2csmuggler -x <target>
 *   -x: proxy/target URL to check for h2c upgrade support
 *
 * Install: go install github.com/assetnote/h2csmuggler@latest
 *
 * Security: spawn() with explicit args array — no shell interpolation.
 * Only runs in active/autonomous/simulation profiles (not passive).
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

export interface H2cSmugglerResult extends AdapterResult {
  tool: "h2csmuggler";
  vulnerable: boolean;
  evidence: string;
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

// ─── Vulnerability indicators in h2csmuggler output ──────────────────────────

const VULN_PATTERNS = [
  /h2c upgrade.*successful/i,
  /upgrade.*successful/i,
  /connection upgraded/i,
  /h2c is supported/i,
  /vulnerable/i,
  /smuggling.*possible/i,
  /\[!\]/,              // h2csmuggler uses [!] for positive findings
  /smuggl/i,
];

function isVulnerable(output: string): boolean {
  return VULN_PATTERNS.some(p => p.test(output));
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const h2cSmugglerAdapter = {
  toolName: "h2csmuggler" as const,

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("h2csmuggler")) !== null;
  },

  async invoke(options: {
    target:     string;
    timeoutMs?: number;
    onConsole?: ConsoleFn;
  }): Promise<H2cSmugglerResult> {
    const start = Date.now();
    const log   = options.onConsole ?? (() => {});

    if (!(await this.isAvailable())) {
      log("info", "[h2csmuggler] not found — attempting auto-install via go install…");
      const installed = await tryAutoInstall(
        { binary: "h2csmuggler", method: "go-install", packageName: "github.com/assetnote/h2csmuggler@latest" },
        log,
      );
      if (!installed) {
        log("warn", "[h2csmuggler] Auto-install failed — skipping H2C check. Install: go install github.com/assetnote/h2csmuggler@latest");
        return {
          tool: "h2csmuggler", success: false, exitCode: -1,
          error: "h2csmuggler not found", durationMs: Date.now() - start,
          vulnerable: false, evidence: "",
        };
      }
    }

    const args = ["-x", options.target];

    log("info", `[h2csmuggler] Checking H2C upgrade: h2csmuggler ${args.join(" ")}`);

    const augmentedPath = [...GO_BIN_PATHS, process.env["PATH"] ?? ""].join(":");

    return new Promise(resolve => {
      let stdout = "";
      let stderr = "";
      let settled = false;
      const timeout = options.timeoutMs ?? 60_000; // 1 min

      const proc = spawn("h2csmuggler", args, {
        shell: false,
        env: { ...process.env, PATH: augmentedPath },
      });

      const timer = setTimeout(() => {
        if (!settled) { settled = true; proc.kill("SIGTERM"); }
      }, timeout);

      proc.stdout.on("data", (d: Buffer) => {
        stdout += d.toString();
        const line = d.toString().trim();
        if (line) log("out", `[h2csmuggler] ${line.slice(0, 200)}`);
      });
      proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

      proc.on("close", code => {
        clearTimeout(timer);
        settled = true;
        const combined = stdout + "\n" + stderr;
        const vulnerable = isVulnerable(combined);
        log(
          vulnerable ? "res" : "out",
          `[h2csmuggler] H2C check complete — ${vulnerable ? "VULNERABLE (h2c upgrade accepted)" : "not vulnerable"} (exit ${code ?? "?"})`,
        );
        resolve({
          tool: "h2csmuggler", success: true,
          exitCode: code ?? -1, durationMs: Date.now() - start,
          vulnerable, evidence: combined.trim().slice(0, 1000),
        });
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        settled = true;
        const msg = err.code === "ENOENT"
          ? "h2csmuggler not found in PATH — install: go install github.com/assetnote/h2csmuggler@latest"
          : `Failed to spawn h2csmuggler: ${err.message}`;
        log("err", `[h2csmuggler] ${msg}`);
        resolve({
          tool: "h2csmuggler", success: false, exitCode: -1,
          error: msg, durationMs: Date.now() - start,
          vulnerable: false, evidence: "",
        });
      });
    });
  },
};

// ─── Phase runner ─────────────────────────────────────────────────────────────

export async function runH2cSmugglerPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  if (session.config.profile === "passive") {
    onConsole("info", "[h2csmuggler] Skipping H2C check in passive profile");
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const res = await h2cSmugglerAdapter.invoke({
    target:    session.config.target,
    onConsole,
    timeoutMs: 60_000,
  });

  if (!res.vulnerable) {
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const findings: Finding[] = [{
    id:        makeId("finding-h2c"),
    timestamp: nowIso(),
    title:     "HTTP/2 Cleartext (H2C) Smuggling — Upgrade Accepted",
    severity:  "high",
    endpoint:  session.config.target,
    evidence:
      "The target accepted an HTTP/1.1 → HTTP/2 cleartext (h2c) upgrade request. " +
      "This may allow an attacker to bypass WAFs, authentication middleware, and ACLs " +
      "by smuggling requests through a front-end proxy that strips the Upgrade header.\n\n" +
      "Tool output:\n" + res.evidence,
    tool: "h2csmuggler",
  }];

  onConsole("res", `[h2csmuggler] HIGH: H2C smuggling attack surface confirmed on ${session.config.target}`);
  return { findings, captures: [], visitedEndpoints: [] };
}
