/**
 * ffuf.ts — Adapter for ffuf endpoint discovery.
 *
 * Runs: ffuf -u <target>/FUZZ -w <wordlist> -o <file> -of json -mc all -fc 404
 *
 * Security: spawn() is used with an explicit argument array.
 * No shell interpolation is performed on user-supplied target strings.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { app } from "electron";
import type { FfufEndpoint, FfufResult } from "@hexguard/shared";
import type { ToolInvokeOptions } from "./base";
import { whichBinary } from "./base";
import { hexstrikeFfuf, isHexStrikeAvailable } from "../services/mcpClient";

type ConsoleFn = (tag: "info"|"warn"|"err"|"res"|"out", text: string) => void;

// Lazily computed once app is ready — points to <repo-root>/wordlists/
function repoWordlistDir(): string {
  // app.getAppPath() → packages/desktop  (where packages/desktop/package.json lives)
  // Two levels up from there is the repo root.
  return path.join(app.getAppPath(), "../../wordlists");
}

// ─── ffuf JSON output types ───────────────────────────────────────────────────

interface FfufJsonResult {
  input?: Record<string, string>;
  status: number;
  length: number;
  words: number;
  lines: number;
  "content-type"?: string;
  redirectlocation?: string;
  url: string;
  duration?: number;
}

interface FfufJsonOutput {
  commandline?: string;
  results: FfufJsonResult[];
}

// ─── Wordlist resolution ──────────────────────────────────────────────────────

// System-level fallbacks (Kali / parrot distros)
const SYSTEM_WORDLISTS = [
  "/usr/share/wordlists/dirb/common.txt",
  "/usr/share/seclists/Discovery/Web-Content/common.txt",
  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
];

async function resolveWordlist(provided?: string): Promise<string | null> {
  if (provided) {
    try { await fs.access(provided); return provided; } catch { return null; }
  }

  // ── 1. Repo-bundled wordlists (highest priority) ──────────────────────────
  const repoDir = repoWordlistDir();
  const repoCandidates = [
    path.join(repoDir, "common.txt"),
    path.join(repoDir, "raft-medium-directories.txt"),
    path.join(repoDir, "big.txt"),
    path.join(repoDir, "api-endpoints.txt"),
  ];
  for (const wl of repoCandidates) {
    try { await fs.access(wl); return wl; } catch { continue; }
  }

  // ── 2. System wordlists (Kali / Parrot) ──────────────────────────────────
  for (const wl of SYSTEM_WORDLISTS) {
    try { await fs.access(wl); return wl; } catch { continue; }
  }

  return null;
}

// ─── Parser ───────────────────────────────────────────────────────────────────

function parseOutput(raw: string): FfufEndpoint[] {
  try {
    const parsed = JSON.parse(raw) as FfufJsonOutput;
    return (parsed.results ?? []).map(r => ({
      url: r.url,
      method: "GET",
      statusCode: r.status,
      contentLength: r.length,
      words: r.words,
      lines: r.lines,
      redirectLocation: r.redirectlocation ?? "",
    }));
  } catch {
    return [];
  }
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const ffufAdapter = {
  toolName: "ffuf",

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("ffuf")) !== null;
  },

  async invoke(options: ToolInvokeOptions & { wordlistPath?: string; onConsole?: ConsoleFn }): Promise<FfufResult> {
    const start = Date.now();
    const log = options.onConsole ?? (() => {});

    // ── Try HexStrike first ──────────────────────────────────────────────────
    if (await isHexStrikeAvailable()) {
      log("info", "ffuf: routing through HexStrike MCP…");
      const result = await hexstrikeFfuf(options.target, options.wordlistPath) as Record<string, unknown> | null;
      if (result && !result["error"]) {
        // Parse HexStrike's output field into endpoints
        const rawOutput = String(result["output"] ?? result["stdout"] ?? "");
        const endpoints: FfufEndpoint[] = [];
        for (const line of rawOutput.split("\n")) {
          const m = line.match(/\[Status:\s*(\d+).*?\]\s+\[Length:\s*(\d+).*?\]\s+(.+)/);
          if (m) {
            endpoints.push({
              url: m[3]?.trim() ?? "",
              method: "GET",
              statusCode: parseInt(m[1], 10),
              contentLength: parseInt(m[2], 10),
              words: 0,
              lines: 0,
              redirectLocation: "",
            });
          }
        }
        return {
          tool: "ffuf",
          success: true,
          exitCode: 0,
          durationMs: Date.now() - start,
          endpoints,
          totalRequests: endpoints.length,
        };
      }
    }

    // ── Fall back to direct spawn ────────────────────────────────────────────
    const outputFile = path.join(options.outputDir, "ffuf-output.json");
    const wordlist = await resolveWordlist(options.wordlistPath);

    if (!(await whichBinary("ffuf"))) {
      log("warn", "ffuf not found in PATH — install with: sudo apt install ffuf");
      // Fall through to the built-in path prober below
    }

    if (!wordlist) {
      // No wordlist available — fall back to probing a known-useful set of paths
      const COMMON_PATHS = [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/login",
        "/admin", "/login", "/register", "/dashboard", "/health",
        "/status", "/version", "/config", "/.env", "/backup",
        "/graphql", "/swagger.json", "/openapi.json", "/api-docs",
        "/wp-admin", "/wp-login.php", "/phpmyadmin",
      ];
      const base = options.target.replace(/\/$/, "");
      const discovered: FfufEndpoint[] = [];
      await Promise.allSettled(
        COMMON_PATHS.map(async p => {
          try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 5000);
            const res = await fetch(`${base}${p}`, {
              method: "GET",
              signal: controller.signal,
              redirect: "manual",
            });
            clearTimeout(timer);
            if (res.status !== 404 && res.status !== 403) {
              discovered.push({
                url: `${base}${p}`,
                method: "GET",
                statusCode: res.status,
                contentLength: parseInt(res.headers.get("content-length") ?? "0", 10),
                words: 0,
                lines: 0,
                redirectLocation: res.headers.get("location") ?? "",
              });
            }
          } catch { /* skip unreachable */ }
        })
      );
      return {
        tool: "ffuf",
        success: true,
        exitCode: 0,
        durationMs: Date.now() - start,
        endpoints: discovered,
        totalRequests: COMMON_PATHS.length,
      };
    }

    // Build the FUZZ target URL: append /FUZZ if not already present
    const targetUrl = options.target.includes("FUZZ")
      ? options.target
      : options.target.replace(/\/$/, "") + "/FUZZ";

    const args = [
      "-u", targetUrl,
      "-w", wordlist,
      "-o", outputFile,
      "-of", "json",
      "-mc", "all",
      "-fc", "404",
      "-ac",
      "-t", "10",
      "-timeout", "10",
      ...(options.extraArgs ?? []),
    ];

    log("info", `[cmd] ffuf ${args.join(" ")}`);

    return new Promise(resolve => {
      let stdout = "";
      let stderr = "";
      let lastLogTime = 0;
      const timeout = options.timeoutMs ?? 300_000;

      const proc = spawn("ffuf", args, { shell: false });
      const timer = setTimeout(() => { proc.kill("SIGTERM"); }, timeout);

      proc.stdout.on("data", (d: Buffer) => {
        stdout += d.toString();
        const now = Date.now();
        if (now - lastLogTime > 2000) {
          const lines = d.toString().split("\n").map(l => l.trim()).filter(l => l.startsWith("["));
          if (lines.length) { log("out", `[ffuf] ${lines[lines.length - 1]}`); lastLogTime = now; }
        }
      });
      proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

      proc.on("close", async (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - start;
        try {
          const raw = await fs.readFile(outputFile, "utf8");
          const endpoints = parseOutput(raw);
          const parsed = JSON.parse(raw) as FfufJsonOutput;
          log("out", `ffuf: ${endpoints.length} endpoint(s) found (${(durationMs / 1000).toFixed(1)}s)`);
          resolve({
            tool: "ffuf", success: code === 0, exitCode: code ?? -1,
            durationMs, endpoints, totalRequests: parsed.results?.length ?? 0,
          });
        } catch {
          log("warn", `ffuf: no output file — ${stderr || "no output"}`);
          resolve({
            tool: "ffuf", success: false, exitCode: code ?? -1,
            error: stderr || stdout || "ffuf produced no output file",
            durationMs, endpoints: [], totalRequests: 0,
          });
        }
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        const msg = err.code === "ENOENT"
          ? "ffuf not found in PATH — install with: sudo apt install ffuf"
          : `Failed to spawn ffuf: ${err.message}`;
        log("err", msg);
        resolve({
          tool: "ffuf", success: false, exitCode: -1, error: msg,
          durationMs: Date.now() - start, endpoints: [], totalRequests: 0,
        });
      });
    });
  },
};
