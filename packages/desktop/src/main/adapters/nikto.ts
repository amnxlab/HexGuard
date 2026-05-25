/**
 * nikto.ts — Adapter for the Nikto web server scanner.
 *
 * Nikto scans for outdated server software, dangerous files/scripts,
 * misconfigurations, and known CVEs against web servers. It complements
 * Nuclei: Nikto focuses on server-level issues (CGI, headers, server banners)
 * while Nuclei covers template-based CVE + misconfiguration detection.
 *
 * Runs: nikto -h <target> -Format json -output <outfile> -nointeractive -timeout 10
 *
 * Security: spawn() with explicit args array — no shell interpolation.
 * Install: sudo apt install nikto
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
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

// ─── Nikto JSON output shapes ─────────────────────────────────────────────────

interface NiktoItem {
  id?: string;
  OSVDB?: string;
  url?: string;
  uri?: string;
  method?: string;
  msg?: string;
  description?: string;
  namelink?: string;
}

interface NiktoJson {
  host?: string;
  port?: string;
  vulnerabilities?: NiktoItem[];
  items?: NiktoItem[];
}

export interface NiktoFinding {
  id: string;
  url: string;
  method: string;
  description: string;
  osvdb?: string;
  severity: "high" | "medium" | "low" | "info";
}

export interface NiktoResult extends AdapterResult {
  tool: "nikto";
  findings: NiktoFinding[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

let _idCounter = 0;
function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${(++_idCounter).toString(36)}`;
}
function nowIso(): string {
  return new Date().toISOString();
}

// ─── Parser ───────────────────────────────────────────────────────────────────

function parseJson(raw: string): NiktoFinding[] {
  const out: NiktoFinding[] = [];
  try {
    const parsed = JSON.parse(raw) as NiktoJson;
    const items: NiktoItem[] = parsed.vulnerabilities ?? parsed.items ?? [];
    for (const item of items) {
      const desc = item.msg ?? item.description ?? item.namelink ?? "Nikto finding";
      const url  = item.url ?? item.uri ?? "";
      const sev: NiktoFinding["severity"] =
        /dangerous|remote code|shell|upload|arbitrary/i.test(desc)              ? "high"
        : /default file|outdated|deprecated|exposure|disclose|cgi/i.test(desc) ? "medium"
        : "low";
      out.push({
        id:          item.id ?? item.OSVDB ?? makeId("nikto-item"),
        url,
        method:      item.method ?? "GET",
        description: desc,
        osvdb:       item.OSVDB,
        severity:    sev,
      });
    }
  } catch {
    // Fallback: parse nikto text output (+ prefix lines)
    for (const line of raw.split("\n")) {
      const m = /^\+ (.+)/.exec(line);
      if (!m) continue;
      const desc = m[1]!.trim();
      if (!desc || desc.startsWith("-") || /^Target|^Start Time|^End Time|^\d+ item/i.test(desc)) continue;
      out.push({
        id:          makeId("nikto-text"),
        url:         "",
        method:      "GET",
        description: desc,
        severity:    /dangerous|shell|upload/i.test(desc) ? "high" : "low",
      });
    }
  }
  return out;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const niktoAdapter = {
  toolName: "nikto" as const,

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("nikto")) !== null;
  },

  async invoke(options: {
    target:     string;
    outputDir:  string;
    timeoutMs?: number;
    onConsole?: ConsoleFn;
  }): Promise<NiktoResult> {
    const start   = Date.now();
    const log     = options.onConsole ?? (() => {});
    const outFile = path.join(options.outputDir, "nikto-output.json");

    if (!(await whichBinary("nikto"))) {
      const installed = await tryAutoInstall(
        { binary: "nikto", method: "apt-pkexec", packageName: "nikto" },
        log,
      );
      if (!installed) {
        log("warn", "[nikto] nikto not found — skipping web server scan");
        return {
          tool: "nikto", success: false, exitCode: -1,
          error: "nikto not found", durationMs: Date.now() - start, findings: [],
        };
      }
    }

    const args = [
      "-h", options.target,
      "-Format", "json",
      "-output", outFile,
      "-nointeractive",
      "-timeout", "10",
    ];

    log("info", `[nikto] Starting scan: nikto ${args.join(" ")}`);

    return new Promise(resolve => {
      let lastLogTime = 0;
      const timeout = options.timeoutMs ?? 300_000; // 5 min

      const proc = spawn("nikto", args, { shell: false });
      const timer = setTimeout(() => { proc.kill("SIGTERM"); }, timeout);

      proc.stdout.on("data", (d: Buffer) => {
        const now = Date.now();
        if (now - lastLogTime > 2_000) {
          const line = d.toString().trim().split("\n").pop()?.trim() ?? "";
          if (line.startsWith("+") || line.startsWith("-")) {
            log("out", `[nikto] ${line}`);
            lastLogTime = now;
          }
        }
      });
      proc.stderr.on("data", () => {/* suppress */});

      proc.on("close", async code => {
        clearTimeout(timer);
        const durationMs = Date.now() - start;
        let findings: NiktoFinding[] = [];
        try {
          const raw = await fs.readFile(outFile, "utf8");
          findings = parseJson(raw);
        } catch {/* no output file — nothing found or timed out */}

        log(
          findings.length > 0 ? "warn" : "out",
          `[nikto] ${findings.length} finding(s) (${(durationMs / 1000).toFixed(1)}s, exit ${code ?? -1})`,
        );
        resolve({
          tool: "nikto", success: code === 0 || findings.length > 0,
          exitCode: code ?? -1, durationMs, findings,
        });
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        const msg = err.code === "ENOENT"
          ? "nikto not found in PATH — install: sudo apt install nikto"
          : `Failed to spawn nikto: ${err.message}`;
        log("err", `[nikto] ${msg}`);
        resolve({
          tool: "nikto", success: false, exitCode: -1, error: msg,
          durationMs: Date.now() - start, findings: [],
        });
      });
    });
  },
};

// ─── Phase runner ─────────────────────────────────────────────────────────────

export async function runNiktoPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  if (session.config.profile === "passive") {
    onConsole("info", "[nikto] Skipping web server scan in passive profile");
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const outDir = `/tmp/hexguard-nikto-${Date.now()}`;
  await fs.mkdir(outDir, { recursive: true });

  try {
    const res = await niktoAdapter.invoke({
      target:    session.config.target,
      outputDir: outDir,
      onConsole,
      timeoutMs: 300_000,
    });

    const findings: Finding[] = res.findings.map(f => ({
      id:        makeId("finding-nikto"),
      timestamp: nowIso(),
      title:     f.description.slice(0, 120),
      severity:  (f.severity === "info" ? "low" : f.severity) as Finding["severity"],
      endpoint:  f.url || session.config.target,
      evidence:  f.description + (f.osvdb ? `\nOSVDB: ${f.osvdb}` : ""),
      tool:      "nikto",
    }));

    if (findings.length > 0) {
      onConsole("res", `[nikto] ${findings.length} finding(s)`);
    }

    return { findings, captures: [], visitedEndpoints: [] };
  } finally {
    await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}
