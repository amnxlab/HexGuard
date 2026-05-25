/**
 * base.ts — Abstract interface for all tool adapters.
 *
 * Security invariant: adapters MUST use spawn() with an argument array,
 * never exec() or shell interpolation — prevents command injection from
 * user-supplied target strings.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const execFileAsync = promisify(execFile);

export interface ToolInvokeOptions {
  target: string;
  outputDir: string;
  extraArgs?: string[];
  timeoutMs?: number;
}

export interface ToolAdapter<TResult> {
  readonly toolName: string;
  isAvailable(): Promise<boolean>;
  invoke(options: ToolInvokeOptions): Promise<TResult>;
}

/**
 * Well-known binary directories that may not be in Electron's stripped PATH.
 * Checked in order after `which` fails.
 */
function extraBinDirs(): string[] {
  const home = os.homedir();
  return [
    path.join(home, "go", "bin"),          // go install default (GOPATH/bin)
    path.join(home, ".local", "bin"),       // pipx / pip --user installs
    "/usr/local/bin",
    "/usr/local/go/bin",
    "/snap/bin",                            // snap packages (zaproxy, etc.)
    "/opt/homebrew/bin",                    // macOS Homebrew (Apple Silicon)
  ];
}

/**
 * Check if a binary exists on PATH using `which`, then fall back to
 * probing well-known install directories that Electron's stripped PATH
 * may omit (e.g. ~/go/bin for nuclei, ~/.local/bin for pipx tools).
 * Returns the resolved path, or null if not found.
 */
export async function whichBinary(name: string): Promise<string | null> {
  // 1. Standard PATH lookup
  try {
    const { stdout } = await execFileAsync("which", [name], { timeout: 3000 });
    const result = stdout.trim();
    if (result) return result;
  } catch {
    // not on PATH — fall through to directory probes
  }

  // 2. Probe well-known directories directly
  for (const dir of extraBinDirs()) {
    const candidate = path.join(dir, name);
    if (fs.existsSync(candidate)) return candidate;
  }

  return null;
}
