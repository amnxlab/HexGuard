import * as fs from "node:fs/promises";
import * as path from "path";
import { spawn } from "node:child_process";
import type { SqlmapFinding, SqlmapResult } from "@hexguard/shared";

const HEXSTRIKE_BASE = "http://localhost:8888";
const TIMEOUT_MS = 90_000;

interface InvokeOptions {
  target: string;
  outputDir: string;
  bearerToken?: string;
  extraArgs?: string[];
  simulation?: boolean;
  param?: string;
}

// Agreement constraint: level=1 risk=1 — HARDCODED, not configurable
const SQLMAP_LEVEL = "1";
const SQLMAP_RISK = "1";

async function tryHexStrike(target: string, bearerToken?: string): Promise<SqlmapFinding[] | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    const res = await fetch(`${HEXSTRIKE_BASE}/api/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        command: "sqlmap",
        args: ["--url", target, `--level=${SQLMAP_LEVEL}`, `--risk=${SQLMAP_RISK}`, "--batch"],
        tool: "sqlmap",
        params: { target, bearerToken, level: SQLMAP_LEVEL, risk: SQLMAP_RISK },
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json() as { findings?: SqlmapFinding[]; vulnerabilities?: SqlmapFinding[] };
    if (Array.isArray(data?.findings)) return data.findings;
    if (Array.isArray(data?.vulnerabilities)) return data.vulnerabilities;
    return null;
  } catch {
    return null;
  }
}

function parseSqlmapOutput(stdout: string): SqlmapFinding[] {
  const findings: SqlmapFinding[] = [];
  // sqlmap prints lines like: "Parameter: id (GET)\n   Type: boolean-based blind\n   Title: ..."
  const paramMatches = stdout.matchAll(/Parameter:\s*(.+?)\s*\((\w+)\)/g);
  for (const match of paramMatches) {
    const paramName = match[1].trim();
    const typeMatch = stdout.match(/Type:\s*(.+)/);
    const titleMatch = stdout.match(/Title:\s*(.+)/);
    const dbmsMatch = stdout.match(/web application technology:\s*(.+)/i) ??
      stdout.match(/back-end DBMS:\s*(.+)/i);
    findings.push({
      parameter: paramName,
      injectionType: typeMatch?.[1]?.trim() ?? "unknown",
      title: titleMatch?.[1]?.trim() ?? "SQL Injection",
      dbms: dbmsMatch?.[1]?.trim() ?? "unknown",
      confidence: "medium",
    });
  }
  // Fallback: if output contains injection keywords but no structured match
  if (findings.length === 0) {
    if (stdout.includes("is vulnerable") || stdout.includes("injection found")) {
      findings.push({
        parameter: "unknown",
        injectionType: "union-based",
        title: "SQL Injection Detected",
        dbms: "unknown",
        confidence: "low",
      });
    }
  }
  return findings;
}

function simulateSqlmapResult(target: string): SqlmapFinding[] {
  // In simulation mode: only report findings if target URL has injectable-looking params
  const url = target.toLowerCase();
  if (url.includes("id=") || url.includes("user=") || url.includes("item=")) {
    return [{
      parameter: "id",
      injectionType: "boolean-based blind",
      title: "Boolean-Based Blind SQL Injection",
      dbms: "MySQL",
      confidence: "medium",
    }];
  }
  return [];
}

async function runSqlmapProcess(
  target: string,
  outputDir: string,
  bearerToken: string | undefined,
  extraArgs: string[],
): Promise<{ findings: SqlmapFinding[]; rawOutput: string }> {
  const args: string[] = [
    "--url", target,
    `--level=${SQLMAP_LEVEL}`,
    `--risk=${SQLMAP_RISK}`,
    "--batch",
    "--output-dir", outputDir,
    ...extraArgs,
  ];

  if (bearerToken) {
    args.push("--headers", `Authorization: Bearer ${bearerToken}`);
  }

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    const proc = spawn("sqlmap", args, { timeout: TIMEOUT_MS });
    const timer = setTimeout(() => { proc.kill(); resolve({ findings: parseSqlmapOutput(stdout), rawOutput: stdout }); }, TIMEOUT_MS);

    proc.stdout?.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });

    proc.on("close", () => {
      clearTimeout(timer);
      resolve({ findings: parseSqlmapOutput(stdout), rawOutput: stdout + stderr });
    });

    proc.on("error", () => {
      clearTimeout(timer);
      resolve({ findings: [], rawOutput: "" });
    });
  });
}

export const sqlmapAdapter = {
  async invoke(opts: InvokeOptions): Promise<SqlmapResult> {
    const start = Date.now();
    const { target, outputDir, bearerToken, extraArgs = [], simulation = false } = opts;

    if (simulation) {
      const findings = simulateSqlmapResult(target);
      return {
        tool: "sqlmap",
        success: true,
        exitCode: 0,
        findings,
        isVulnerable: findings.length > 0,
        durationMs: Date.now() - start,
      };
    }

    // 1) Try HexStrike first
    const hexstrikeFindings = await tryHexStrike(target, bearerToken);
    if (hexstrikeFindings !== null) {
      return {
        tool: "sqlmap",
        success: true,
        exitCode: 0,
        findings: hexstrikeFindings,
        isVulnerable: hexstrikeFindings.length > 0,
        durationMs: Date.now() - start,
      };
    }

    // 2) Spawn sqlmap locally
    try {
      await fs.mkdir(outputDir, { recursive: true });
    } catch { /* ok */ }

    const { findings, rawOutput } = await runSqlmapProcess(target, outputDir, bearerToken, extraArgs);

    return {
      tool: "sqlmap",
      success: true,
      exitCode: 0,
      findings,
      isVulnerable: findings.length > 0,
      error: findings.length === 0 ? (rawOutput.includes("not injectable") ? "No injection points found" : undefined) : undefined,
      durationMs: Date.now() - start,
    };
  },
};
