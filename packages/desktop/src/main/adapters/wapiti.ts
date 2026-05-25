/**
 * wapiti.ts — Adapter for the Wapiti3 web application vulnerability scanner.
 *
 * Wapiti is a Python-based scanner (pip: wapiti3) that covers misconfigurations,
 * exposed files, SSL/TLS issues, open redirects, cookie flags, CSP, and more.
 * It is the primary replacement for nuclei in HexGuard Hunt — no Go required.
 *
 * CLI invoked:
 *   wapiti -u <target> -f json -o <outFile>
 *          --no-bugreport --scope domain -d 2
 *          --timeout 15 --max-scan-time 240
 *          -m backup,cms,cookieflags,csp,http_headers,
 *             https_redirect,methods,redirect,ssl,wapp,htaccess
 *
 * Modules chosen are non-destructive (no brute-force, no active injection).
 * Scope is limited to --scope domain -d 2 to prevent runaway crawling.
 *
 * Security: spawn() with explicit argument array — no shell interpolation.
 * Install: pipx install wapiti3
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { whichBinary } from "./base";
import { tryAutoInstall } from "./toolInstaller";

type ConsoleFn = (tag: "info" | "warn" | "err" | "res" | "out", text: string) => void;

interface AdapterResult {
  success: boolean;
  exitCode: number;
  error?: string;
  durationMs: number;
}

// ─── Wapiti JSON output shape ─────────────────────────────────────────────────

interface WapitiEntry {
  method: string;
  path: string;
  info: string;
  level: number;         // 0–5 — higher = more severe
  parameter?: string;
  module?: string;
  http_request?: string;
  curl_command?: string;
  wstg?: string;
}

interface WapitiJsonOutput {
  vulnerabilities?: Record<string, WapitiEntry[]>;
  anomalies?: Record<string, WapitiEntry[]>;
  additionals?: Record<string, WapitiEntry[]>;
  infos?: {
    scan_start?: string;
    scan_end?: string;
    target?: string;
  };
}

export interface WapitiFinding {
  module: string;
  severity: "critical" | "high" | "medium" | "low";
  url: string;
  info: string;
  method: string;
  parameter: string;
  httpRequest: string;
  curlCommand: string;
  wstg: string;
}

export interface WapitiResult extends AdapterResult {
  tool: "wapiti";
  findings: WapitiFinding[];
}

// ─── Severity normalizer ──────────────────────────────────────────────────────

function levelToSeverity(level: number): WapitiFinding["severity"] {
  if (level >= 5) return "critical";
  if (level >= 4) return "high";
  if (level >= 3) return "medium";
  return "low";
}

// ─── Parser ───────────────────────────────────────────────────────────────────

function parseOutput(raw: string, target: string): WapitiFinding[] {
  const findings: WapitiFinding[] = [];
  let data: WapitiJsonOutput;
  try {
    data = JSON.parse(raw) as WapitiJsonOutput;
  } catch {
    return findings;
  }

  const sections: Array<Record<string, WapitiEntry[]>> = [
    data.vulnerabilities ?? {},
    data.anomalies ?? {},
    data.additionals ?? {},
  ];

  for (const section of sections) {
    for (const [moduleName, entries] of Object.entries(section)) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        const urlPath = entry.path ?? "";
        const url = urlPath.startsWith("http") ? urlPath : new URL(urlPath || "/", target).href;
        findings.push({
          module:      moduleName,
          severity:    levelToSeverity(entry.level ?? 0),
          url,
          info:        entry.info ?? "",
          method:      entry.method ?? "GET",
          parameter:   entry.parameter ?? "",
          httpRequest: entry.http_request ?? "",
          curlCommand: entry.curl_command ?? "",
          wstg:        entry.wstg ?? "",
        });
      }
    }
  }

  return findings;
}

// ─── Safe module list (non-destructive) ──────────────────────────────────────

const SAFE_MODULES = [
  "backup",           // exposed backup files/archives
  "cms",              // CMS detection (WP, Drupal, Joomla)
  "cookieflags",      // missing Secure/HttpOnly flags
  "csp",              // CSP policy evaluation
  "http_headers",     // security header checks
  "https_redirect",   // HTTPS enforcement
  "methods",          // dangerous HTTP methods (PUT, DELETE…)
  "redirect",         // open redirects
  "ssl",              // SSL/TLS configuration
  "wapp",             // web tech fingerprinting + CVE mapping
  "htaccess",         // .htaccess misconfigurations
].join(",");

// ─── Adapter ─────────────────────────────────────────────────────────────────

export const wapitiAdapter = {
  toolName: "wapiti" as const,

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("wapiti")) !== null;
  },

  async invoke(options: {
    target: string;
    outputDir: string;
    timeoutMs?: number;
    onConsole?: ConsoleFn;
  }): Promise<WapitiResult> {
    const start   = Date.now();
    const log     = options.onConsole ?? (() => {});
    const outFile = path.join(options.outputDir, "wapiti-report.json");

    if (!(await whichBinary("wapiti"))) {
      const installed = await tryAutoInstall(
        { binary: "wapiti", method: "pip3", packageName: "wapiti3" },
        log,
      );
      if (!installed) {
        log("warn", "wapiti not found — skipping vulnerability scan (run: pipx install wapiti3)");
        return {
          tool: "wapiti", success: false, exitCode: -1,
          error: "wapiti not found",
          durationMs: Date.now() - start,
          findings: [],
        };
      }
    }

    const args = [
      "-u", options.target,
      "-f", "json",
      "-o", outFile,
      "--no-bugreport",
      "--scope", "domain",
      "-d", "2",
      "--timeout", "15",
      "--max-scan-time", "240",
      "-m", SAFE_MODULES,
    ];

    log("info", `[cmd] wapiti ${args.join(" ")}`);

    return new Promise(resolve => {
      const timeout  = options.timeoutMs ?? 300_000; // 5 min hard cap
      let   stdout   = "";
      let   stderr   = "";

      const proc  = spawn("wapiti", args, { shell: false });
      const timer = setTimeout(() => {
        proc.kill("SIGTERM");
        log("warn", "wapiti: timed out — partial results may be available");
      }, timeout);

      proc.stdout?.on("data", (d: Buffer) => {
        const line = d.toString();
        stdout += line;
        for (const row of line.split("\n").filter(Boolean)) {
          log("out", row);
        }
      });

      proc.stderr?.on("data", (d: Buffer) => {
        const line = d.toString();
        stderr += line;
        for (const row of line.split("\n").filter(Boolean)) {
          log("warn", row);
        }
      });

      proc.on("close", async code => {
        clearTimeout(timer);
        const durationMs = Date.now() - start;

        // Try to read the JSON report wapiti wrote to disk
        let findings: WapitiFinding[] = [];
        try {
          const raw = await fs.readFile(outFile, "utf8");
          findings = parseOutput(raw, options.target);
        } catch {
          // wapiti may also print JSON to stdout if -o points to a path it
          // couldn't write — attempt to parse stdout as fallback
          if (stdout.trim().startsWith("{")) {
            findings = parseOutput(stdout, options.target);
          }
        }

        const success = code === 0 || findings.length > 0;
        log(
          success ? "res" : "warn",
          `wapiti: finished (exit ${code}) — ${findings.length} finding(s) in ${Math.round(durationMs / 1000)}s`,
        );

        resolve({
          tool: "wapiti",
          success,
          exitCode: code ?? -1,
          error: success ? undefined : (stderr.slice(-200) || "wapiti returned non-zero"),
          durationMs,
          findings,
        });
      });

      proc.on("error", err => {
        clearTimeout(timer);
        log("err", `wapiti spawn error: ${err.message}`);
        resolve({
          tool: "wapiti", success: false, exitCode: -1,
          error: err.message,
          durationMs: Date.now() - start,
          findings: [],
        });
      });
    });
  },
};
