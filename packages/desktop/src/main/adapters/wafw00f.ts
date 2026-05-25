/**
 * wafw00f.ts — Adapter for WAF (Web Application Firewall) detection.
 *
 * Runs: wafw00f <target> -a -o <outfile> -f json
 *
 * Detects which WAF (if any) is protecting the target, and returns
 * the WAF vendor/product name as a tech fingerprint enrichment.
 *
 * Security: spawn() with explicit args array — no shell interpolation.
 * Install: pip install wafw00f  /  sudo apt install wafw00f
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { whichBinary } from "./base";
import { tryAutoInstall } from "./toolInstaller";

type ConsoleFn = (tag: "info"|"warn"|"err"|"res"|"out", text: string) => void;

interface AdapterResult {
  success: boolean;
  exitCode: number;
  error?: string;
  durationMs: number;
}

// ─── wafw00f JSON output shape ────────────────────────────────────────────────

interface Waf00fJsonEntry {
  url?: string;
  detected?: boolean;
  firewalls?: string[];
  manufacturer?: string;
  firewall?: string;
}

export interface WafResult extends AdapterResult {
  tool: "wafw00f";
  detected: boolean;
  firewalls: string[];
  manufacturer?: string;
}

// ─── Parser ───────────────────────────────────────────────────────────────────

function parseOutput(raw: string): { detected: boolean; firewalls: string[]; manufacturer?: string } {
  // Try JSON first
  try {
    const entries = JSON.parse(raw) as Waf00fJsonEntry[] | Waf00fJsonEntry;
    const list = Array.isArray(entries) ? entries : [entries];
    const firewalls: string[] = [];
    let manufacturer: string | undefined;
    for (const e of list) {
      if (e.firewalls) firewalls.push(...e.firewalls);
      if (e.firewall)  firewalls.push(e.firewall);
      if (e.manufacturer) manufacturer = e.manufacturer;
    }
    return { detected: firewalls.length > 0, firewalls: [...new Set(firewalls)], manufacturer };
  } catch { /* fall through to text parse */ }

  // Text output fallback: "The site http://... is behind <WAF name> WAF"
  const firewalls: string[] = [];
  for (const line of raw.split("\n")) {
    const m = /is behind (.+?) WAF/i.exec(line) ?? /Detected WAF: (.+)/i.exec(line);
    if (m) firewalls.push(m[1]!.trim());
    if (/No WAF detected/i.test(line)) return { detected: false, firewalls: [] };
  }
  return { detected: firewalls.length > 0, firewalls: [...new Set(firewalls)] };
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const wafw00fAdapter = {
  toolName: "wafw00f" as const,

  async isAvailable(): Promise<boolean> {
    return (await whichBinary("wafw00f")) !== null;
  },

  async invoke(options: {
    target: string;
    outputDir: string;
    timeoutMs?: number;
    onConsole?: ConsoleFn;
  }): Promise<WafResult> {
    const start   = Date.now();
    const log     = options.onConsole ?? (() => {});
    const outFile = path.join(options.outputDir, "wafw00f-output.json");

    if (!(await whichBinary("wafw00f"))) {
      const installed = await tryAutoInstall(
        { binary: "wafw00f", method: "pip3", packageName: "wafw00f" },
        log,
      );
      if (!installed) {
        log("warn", "wafw00f not found — skipping WAF detection");
        return {
          tool: "wafw00f", success: false, exitCode: -1,
          error: "wafw00f not found",
          durationMs: Date.now() - start,
          detected: false, firewalls: [],
        };
      }
    }

    const args = [
      options.target,
      "-a",              // try all detection techniques
      "-o", outFile,
      "-f", "json",
    ];

    log("info", `[cmd] wafw00f ${args.join(" ")}`);

    return new Promise(resolve => {
      let stdout = "";
      const timeout = options.timeoutMs ?? 60_000; // 1 min — WAF detection is fast

      const proc = spawn("wafw00f", args, { shell: false });
      const timer = setTimeout(() => { proc.kill("SIGTERM"); }, timeout);

      proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on("data", (d: Buffer) => { stdout += d.toString(); });

      proc.on("close", async (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - start;

        // Try reading output file first; fall back to stdout
        let raw = "";
        try { raw = await fs.readFile(outFile, "utf8"); } catch { raw = stdout; }

        const { detected, firewalls, manufacturer } = parseOutput(raw);

        if (detected) {
          log("warn", `WAF detected: ${firewalls.join(", ")}${manufacturer ? ` (${manufacturer})` : ""}`);
        } else {
          log("out", "wafw00f: no WAF detected");
        }

        resolve({
          tool: "wafw00f", success: true, exitCode: code ?? 0, durationMs,
          detected, firewalls, manufacturer,
        });
      });

      proc.on("error", (err: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        const msg = err.code === "ENOENT"
          ? "wafw00f not found in PATH — install with: pip install wafw00f"
          : `Failed to spawn wafw00f: ${err.message}`;
        log("err", msg);
        resolve({
          tool: "wafw00f", success: false, exitCode: -1, error: msg,
          durationMs: Date.now() - start, detected: false, firewalls: [],
        });
      });
    });
  },
};
