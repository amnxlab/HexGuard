/**
 * sqlmap.ts — Adapter for sqlmap SQL injection detection.
 *
 * Runs: sqlmap -u <target> --batch --level=<N> --risk=<N> --output-dir <dir>
 *
 * Output is parsed from the captured stdout/stderr stream.
 * sqlmap writes structured log data to the output directory; we parse
 * both the live stream and the resulting log file.
 *
 * Security: spawn() with explicit args array — no shell interpolation.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { SqlmapFinding, SqlmapResult } from "@hexguard/shared";
import type { ToolInvokeOptions } from "./base";
import { whichBinary } from "./base";

type ConsoleFn = (tag: "info"|"warn"|"err"|"res"|"out", text: string) => void;
import { hexstrikeSqlmap, isHexStrikeAvailable } from "../services/mcpClient";

// ─── Output parser ────────────────────────────────────────────────────────────

/**
 * Parse sqlmap stdout for injection findings.
 * sqlmap outputs structured text; we extract parameter + type + title lines.
 */
function parseOutput(output: string): SqlmapFinding[] {
  const findings: SqlmapFinding[] = [];
  const lines = output.split("\n");

  let currentParam = "";
  let currentType = "";
  let currentTitle = "";
  let currentDbms = "";

  for (const line of lines) {
    // Extract DBMS info
    const dbmsMatch = /the back-end DBMS is (.+)/i.exec(line);
    if (dbmsMatch) currentDbms = dbmsMatch[1].trim();

    // Parameter line: "Parameter: id (GET)"
    const paramMatch = /^\s*Parameter:\s*(\S+)\s*\((\w+)\)/i.exec(line);
    if (paramMatch) {
      if (currentParam && currentTitle) {
        findings.push({
          parameter: currentParam,
          injectionType: currentType,
          title: currentTitle,
          dbms: currentDbms,
          confidence: "high",
        });
      }
      currentParam = paramMatch[1];
      currentType = "";
      currentTitle = "";
    }

    // Type line: "    Type: boolean-based blind"
    const typeMatch = /^\s+Type:\s*(.+)$/i.exec(line);
    if (typeMatch && currentParam) {
      currentType = typeMatch[1].trim();
    }

    // Title line: "    Title: AND boolean-based blind - WHERE..."
    const titleMatch = /^\s+Title:\s*(.+)$/i.exec(line);
    if (titleMatch && currentParam) {
      currentTitle = titleMatch[1].trim();
    }

    // Explicit "is vulnerable" marker
    const vulnMatch = /parameter '([^']+)' is vulnerable/i.exec(line);
    if (vulnMatch && !findings.some(f => f.parameter === vulnMatch[1])) {
      findings.push({
        parameter: vulnMatch[1],
        injectionType: currentType || "unknown",
        title: currentTitle || `${vulnMatch[1]} is vulnerable`,
        dbms: currentDbms,
        confidence: "high",
      });
    }
  }

  // Push the last captured finding
  if (currentParam && currentTitle && !findings.some(f => f.parameter === currentParam && f.title === currentTitle)) {
    findings.push({
      parameter: currentParam,
      injectionType: currentType,
      title: currentTitle,
      dbms: currentDbms,
      confidence: "medium",
    });
  }

  return findings;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const sqlmapAdapter = {
  toolName: "sqlmap",

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("sqlmap")) !== null;
  },

  async invoke(
    options: ToolInvokeOptions & { level?: number; risk?: number; onConsole?: ConsoleFn },
  ): Promise<SqlmapResult> {
    const start = Date.now();
    const log = options.onConsole ?? (() => {});
    const level = options.level ?? 2;
    const risk  = options.risk  ?? 1;

    // ── Try HexStrike first ──────────────────────────────────────────────────
    if (await isHexStrikeAvailable()) {
      log("info", "sqlmap: routing through HexStrike MCP…");
      const result = await hexstrikeSqlmap(
        options.target,
        undefined,
        options.extraArgs?.join(" ")
      ) as Record<string, unknown> | null;

      if (result && !result["error"]) {
        const rawOutput = String(result["output"] ?? result["stdout"] ?? "");
        const findings = parseOutput(rawOutput);
        log("out", `sqlmap (HexStrike): ${findings.length} injection(s) found`);
        return {
          tool: "sqlmap",
          success: true,
          exitCode: 0,
          durationMs: Date.now() - start,
          findings,
          isVulnerable: findings.length > 0,
        };
      }
    }

    // ── Check binary is present ──────────────────────────────────────────────
    if (!(await whichBinary("sqlmap"))) {
      log("warn", "sqlmap not found in PATH — install with: sudo apt install sqlmap");
      return {
        tool: "sqlmap",
        success: false,
        exitCode: -1,
        error: "sqlmap not found",
        durationMs: Date.now() - start,
        findings: [],
        isVulnerable: false,
      };
    }

    // ── Fall back to direct spawn ────────────────────────────────────────────
    const outputDir = path.join(options.outputDir, "sqlmap");

    const args = [
      "-u", options.target,
      "--batch",
      `--level=${level}`,
      `--risk=${risk}`,
      "--output-dir", outputDir,
      "--forms",
      "--random-agent",
      ...(options.extraArgs ?? []),
    ];

    // Log the exact command that will run
    log("info", `[cmd] sqlmap ${args.join(" ")}`);

    return new Promise(resolve => {
      let output = "";
      let lastLogLine = "";
      let lastLogTime = 0;
      const timeout = options.timeoutMs ?? 600_000;

      const proc = spawn("sqlmap", args, { shell: false });
      const timer = setTimeout(() => { proc.kill("SIGTERM"); }, timeout);

      const onData = (d: Buffer) => {
        const chunk = d.toString();
        output += chunk;
        // Throttle console output — emit at most 1 unique line per 1.5s
        const now = Date.now();
        const lines = chunk.split("\n").map(l => l.trim()).filter(Boolean);
        for (const line of lines) {
          if (line === lastLogLine) continue;
          if (now - lastLogTime < 1500) continue;
          // Filter sqlmap boilerplate
          if (/^\[\d{2}:\d{2}:\d{2}\] \[INFO\]/.test(line) || /^\[\d{2}:\d{2}:\d{2}\] \[WARNING\]/.test(line)) {
            log("out", `[sqlmap] ${line}`);
            lastLogLine = line;
            lastLogTime = now;
          }
        }
      };

      proc.stdout.on("data", onData);
      proc.stderr.on("data", onData);

      proc.on("close", async (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - start;

        try {
          const targetHost = new URL(options.target).hostname;
          const logFile = path.join(outputDir, targetHost, "log");
          const logContent = await fs.readFile(logFile, "utf8");
          output += "\n" + logContent;
        } catch { /* log file not available */ }

        const findings = parseOutput(output);
        log(
          findings.length > 0 ? "warn" : "out",
          `sqlmap: ${findings.length} injection(s) found (${(durationMs / 1000).toFixed(1)}s, exit ${code ?? -1})`,
        );
        resolve({
          tool: "sqlmap",
          success: code === 0,
          exitCode: code ?? -1,
          durationMs,
          findings,
          isVulnerable: findings.length > 0,
        });
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        const msg = err.code === "ENOENT"
          ? "sqlmap not found in PATH — install with: sudo apt install sqlmap"
          : `Failed to spawn sqlmap: ${err.message}`;
        log("err", msg);
        resolve({
          tool: "sqlmap",
          success: false,
          exitCode: -1,
          error: msg,
          durationMs: Date.now() - start,
          findings: [],
          isVulnerable: false,
        });
      });
    });
  },
};
