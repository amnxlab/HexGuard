/**
 * toolInstaller.ts — Automatic tool installation helper.
 *
 * Attempts to install missing security tools before giving up.
 * Strategy per tool type:
 *   • pip tools  (wafw00f)  → pip3 install --user <pkg>  (no sudo)
 *   • apt tools  (nikto)    → pkexec apt-get install -y <pkg>
 *                             pkexec pops the system PolicyKit dialog — the
 *                             user approves with their own password in a native
 *                             OS prompt, no password is ever handled in code.
 *   • go/binary (nuclei)    → go install <path>@latest  (if Go is available)
 *
 * Security: all invocations use spawn() with explicit arg arrays.
 */

import { spawn } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import { whichBinary } from "./base";

export type InstallMethod = "pip3" | "apt-pkexec" | "go-install";

export interface InstallSpec {
  /** Binary name to check with `which` after install. */
  binary: string;
  method: InstallMethod;
  /** Package/module name passed to the package manager. */
  packageName: string;
}

type LogFn = (tag: "info" | "warn" | "err" | "out", text: string) => void;

/**
 * Try to install a tool. Returns true if the binary is available after
 * the attempt (either it was already there, or install succeeded).
 */
export async function tryAutoInstall(
  spec: InstallSpec,
  log: LogFn,
): Promise<boolean> {
  // Already installed — nothing to do.
  if ((await whichBinary(spec.binary)) !== null) return true;

  log("info", `[installer] ${spec.binary} not found — attempting auto-install…`);

  const ok = await runInstall(spec, log);
  if (ok) {
    // Verify the binary is now reachable.
    const found = (await whichBinary(spec.binary)) !== null;
    if (found) {
      log("out", `[installer] ${spec.binary} installed successfully`);
    } else {
      log("warn", `[installer] install command succeeded but ${spec.binary} still not in PATH`);
    }
    return found;
  }

  return false;
}

async function runInstall(spec: InstallSpec, log: LogFn): Promise<boolean> {
  switch (spec.method) {
    case "pip3": {
      // 1st attempt: pipx (handles externally-managed Python environments)
      const hasPipx = await (async () => {
        const { execFile } = await import("node:child_process");
        const { promisify } = await import("node:util");
        try { await promisify(execFile)("which", ["pipx"]); return true; } catch { return false; }
      })();

      if (hasPipx) {
        const ok = await runCommand("pipx", ["install", spec.packageName], log, `pipx install ${spec.packageName}`);
        if (ok) return true;
      }

      // 2nd attempt: pip3 --user (standard)
      const ok2 = await runCommand(
        "pip3", ["install", "--user", spec.packageName],
        log, `pip3 install --user ${spec.packageName}`,
      );
      if (ok2) return true;

      // 3rd attempt: pip3 --user --break-system-packages (Debian/Ubuntu PEP668 guard)
      log("warn", `[installer] Retrying with --break-system-packages…`);
      return runCommand(
        "pip3", ["install", "--user", "--break-system-packages", spec.packageName],
        log, `pip3 install --user --break-system-packages ${spec.packageName}`,
      );
    }

    case "apt-pkexec":
      // pkexec pops the system PolicyKit (polkit) password dialog —
      // the password is never passed through our process.
      log("info", `[installer] Requesting system authorisation to install ${spec.packageName} — a system dialog will appear`);
      return runCommand(
        "pkexec", ["apt-get", "install", "-y", spec.packageName],
        log,
        `pkexec apt-get install -y ${spec.packageName}`,
      );

    case "go-install":
      return runCommand(
        "go", ["install", spec.packageName],
        log,
        `go install ${spec.packageName}`,
      );
  }
}

function runCommand(
  cmd: string,
  args: string[],
  log: LogFn,
  label: string,
): Promise<boolean> {
  // Augment PATH so tools installed outside Electron's stripped environment
  // are reachable: ~/go/bin (nuclei), ~/.local/bin (pipx tools), /snap/bin (go).
  const home = os.homedir();
  const extraPaths = [
    path.join(home, "go", "bin"),
    path.join(home, ".local", "bin"),
    "/snap/bin",
    "/usr/local/go/bin",
    "/usr/local/bin",
  ];
  const augmentedPath = [...extraPaths, process.env.PATH ?? ""].join(path.delimiter);

  return new Promise(resolve => {
    log("info", `[cmd] ${label}`);
    const child = spawn(cmd, args, {
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      env: {
        ...process.env,
        PATH: augmentedPath,
        DEBIAN_FRONTEND: "noninteractive",
        GOPATH: process.env.GOPATH ?? path.join(home, "go"),
      },
    });

    child.stdout?.on("data", (d: Buffer) => {
      const line = d.toString().trim();
      if (line) log("out", `[installer] ${line}`);
    });
    child.stderr?.on("data", (d: Buffer) => {
      const line = d.toString().trim();
      if (line) log("warn", `[installer] ${line}`);
    });

    child.on("close", code => {
      if (code === 0) {
        resolve(true);
      } else {
        log("warn", `[installer] ${cmd} exited with code ${code}`);
        resolve(false);
      }
    });
    child.on("error", err => {
      log("warn", `[installer] could not run ${cmd}: ${err.message}`);
      resolve(false);
    });
  });
}
