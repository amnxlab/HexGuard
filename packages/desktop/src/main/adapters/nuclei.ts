/**
 * nuclei.ts — Adapter for the Nuclei template-based vulnerability scanner.
 *
 * Runs: nuclei -u <target> -t exposures/,misconfiguration/ -j -o <outfile> -silent
 *
 * Nuclei uses community-maintained YAML templates. We restrict to safe,
 * informational template categories:
 *   - exposures/    → leaked files, tokens, keys
 *   - misconfiguration/ → misconfigured services, headers, etc.
 *
 * Security: spawn() with explicit args array — no shell interpolation.
 * Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { whichBinary } from "./base";
import { tryAutoInstall } from "./toolInstaller";
import type { Finding, HuntSession } from "@hexguard/shared";
import type { PhaseResult } from "../engine/pipelineEngine";

type ConsoleFn = (tag: "info"|"warn"|"err"|"res"|"out", text: string) => void;

interface AdapterResult {
  success: boolean;
  exitCode: number;
  error?: string;
  durationMs: number;
}

// ─── Nuclei JSONL output shape ────────────────────────────────────────────────

interface NucleiJsonLine {
  template?: string;
  "template-id"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    tags?: string[];
  };
  matched?: string;
  host?: string;
  type?: string;
  "matched-at"?: string;
  curl?: string;
  request?: string;
  response?: string;
}

export interface NucleiFinding {
  templateId: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  url: string;
  description: string;
  tags: string[];
}

export interface NucleiResult extends AdapterResult {
  tool: "nuclei";
  findings: NucleiFinding[];
}

// ─── Severity normalizer ──────────────────────────────────────────────────────

function normalizeSev(raw: string): NucleiFinding["severity"] {
  const s = (raw ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high")     return "high";
  if (s === "medium")   return "medium";
  return "low"; // covers "low" + "info"
}

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

// ─── Parser ───────────────────────────────────────────────────────────────────

/** Parse nuclei JSONL output (one JSON object per line). */
function parseJsonl(raw: string): NucleiFinding[] {
  const findings: NucleiFinding[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const item = JSON.parse(trimmed) as NucleiJsonLine;
      findings.push({
        templateId:  item["template-id"] ?? item.template ?? "unknown",
        name:        item.info?.name ?? item["template-id"] ?? "Nuclei finding",
        severity:    normalizeSev(item.info?.severity ?? "info"),
        url:         item["matched-at"] ?? item.matched ?? item.host ?? "",
        description: item.info?.description ?? "",
        tags:        item.info?.tags ?? [],
      });
    } catch { /* skip malformed lines */ }
  }
  return findings;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

/** Tags to include — safe, non-destructive templates. */
const SAFE_TEMPLATE_TAGS = "cve,exposure,misconfiguration,default-login,tech";
/** Tags to always exclude — destructive or fuzzing templates. */
const EXCLUDE_TAGS = "dos,fuzzing,intrusive";

export const nucleiAdapter = {
  toolName: "nuclei" as const,

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("nuclei")) !== null;
  },

  async invoke(options: {
    target: string;
    outputDir: string;
    timeoutMs?: number;
    templateTags?: string;
    onConsole?: ConsoleFn;
  }): Promise<NucleiResult> {
    const start   = Date.now();
    const log     = options.onConsole ?? (() => {});
    const outFile = path.join(options.outputDir, "nuclei-output.jsonl");
    const tags    = options.templateTags ?? SAFE_TEMPLATE_TAGS;

    if (!(await whichBinary("nuclei"))) {
      const installed = await tryAutoInstall(
        { binary: "nuclei", method: "go-install", packageName: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
        log,
      );
      if (!installed) {
        log("warn", "nuclei not found — skipping template scan (install Go and run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)");
        return {
          tool: "nuclei", success: false, exitCode: -1,
          error: "nuclei not found",
          durationMs: Date.now() - start,
          findings: [],
        };
      }
    }

    const args = [
      "-u", options.target,
      "-tags",          tags,
      "-exclude-tags",  EXCLUDE_TAGS,
      "-severity",      "critical,high,medium,low",
      "-j",                       // JSONL output
      "-o", outFile,
      "-silent",                  // suppress banner noise
      "-no-color",
      "-timeout",      "10",      // per-request timeout (seconds)
      "-rate-limit",   "50",      // requests per second
      "-c",            "10",      // concurrent templates
    ];

    log("info", `[nuclei] Starting scan: nuclei ${args.join(" ")}`);

    return new Promise(resolve => {
      let stderr = "";
      let lastLogTime = 0;
      const timeout = options.timeoutMs ?? 300_000; // 5 min

      const augmentedPath = [
        ...GO_BIN_PATHS,
        process.env["PATH"] ?? "",
      ].join(":");

      const proc = spawn("nuclei", args, {
        shell: false,
        env: { ...process.env, PATH: augmentedPath },
      });
      const timer = setTimeout(() => { proc.kill("SIGTERM"); }, timeout);

      proc.stdout.on("data", (d: Buffer) => {
        const now = Date.now();
        if (now - lastLogTime > 2000) {
          const lines = d.toString().split("\n").filter(l => l.trim().startsWith("["));
          if (lines.length) {
            log("out", `[nuclei] ${lines[lines.length - 1]!.trim()}`);
            lastLogTime = now;
          }
        }
      });
      proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

      proc.on("close", async (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - start;
        let findings: NucleiFinding[] = [];

        try {
          const raw = await fs.readFile(outFile, "utf8");
          findings = parseJsonl(raw);
        } catch { /* no output file */ }

        log(
          findings.length > 0 ? "warn" : "out",
          `nuclei: ${findings.length} finding(s) (${(durationMs / 1000).toFixed(1)}s, exit ${code ?? -1})`,
        );
        resolve({
          tool: "nuclei", success: code === 0 || findings.length > 0,
          exitCode: code ?? -1, durationMs, findings,
        });
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        const msg = err.code === "ENOENT"
          ? "nuclei not found in PATH — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
          : `Failed to spawn nuclei: ${err.message}`;
        log("err", `[nuclei] ${msg}`);
        resolve({
          tool: "nuclei", success: false, exitCode: -1, error: msg,
          durationMs: Date.now() - start, findings: [],
        });
      });
    });
  },
};

// ─── Phase runner ─────────────────────────────────────────────────────────────

/**
 * Run nuclei as a PhaseResult-returning phase function.
 * Called from pipelineEngine.runDeepScanPhase() and autonomousEngine.executeAction().
 */
export async function runNucleiPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  if (session.config.profile === "passive") {
    onConsole("info", "[nuclei] Skipping vulnerability scan in passive profile");
    return { findings: [], captures: [], visitedEndpoints: [] };
  }

  const outDir = `/tmp/hexguard-nuclei-${Date.now()}`;
  await fs.mkdir(outDir, { recursive: true });

  try {
    const res = await nucleiAdapter.invoke({
      target:    session.config.target,
      outputDir: outDir,
      onConsole,
      timeoutMs: 600_000, // 10 min — first run downloads ~50 MB templates
    });

    const findings: Finding[] = res.findings.map(f => ({
      id:        makeId("finding-nuclei"),
      timestamp: nowIso(),
      title:     f.name.slice(0, 120),
      severity:  f.severity as Finding["severity"],
      endpoint:  f.url || session.config.target,
      evidence:  [
        f.description,
        `Template: ${f.templateId}`,
        f.tags.length ? `Tags: ${f.tags.join(", ")}` : "",
      ].filter(Boolean).join("\n"),
      tool: "nuclei",
    }));

    if (findings.length > 0) {
      const hiCrit = findings.filter(f => f.severity === "critical" || f.severity === "high").length;
      onConsole("res", `[nuclei] ${findings.length} finding(s) — ${hiCrit} high/critical`);
    }

    return { findings, captures: [], visitedEndpoints: [] };
  } finally {
    await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
  }
}
