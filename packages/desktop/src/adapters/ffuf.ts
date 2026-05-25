import * as fs from "node:fs/promises";
import * as path from "path";
import { spawn } from "node:child_process";
import type { FfufEndpoint, FfufResult } from "@hexguard/shared";

const HEXSTRIKE_BASE = "http://localhost:8888";
const TIMEOUT_MS = 60_000;

interface InvokeOptions {
  target: string;
  outputDir: string;
  wordlistPath?: string;
  bearerToken?: string;
  extraArgs?: string[];
  simulation?: boolean;
}

// Common paths for API and web endpoint discovery
const BUILTIN_PATHS = [
  "/", "/api", "/api/v1", "/api/v2", "/admin", "/login", "/logout",
  "/register", "/user", "/users", "/profile", "/dashboard", "/health",
  "/status", "/config", "/debug", "/robots.txt", "/sitemap.xml",
  "/.env", "/.git/config", "/swagger.json", "/openapi.json",
  "/api/users", "/api/login", "/api/auth", "/api/config",
  "/api/admin", "/api/debug", "/api/health", "/api/status",
  "/api/v1/users", "/api/v1/auth", "/api/v1/admin",
  "/graphql", "/graphiql", "/.well-known/security.txt",
  "/actuator", "/actuator/health", "/actuator/env",
];

async function probeSpecialPaths(
  target: string,
  bearerToken?: string,
): Promise<FfufEndpoint[]> {
  const base = target.replace(/\/$/, "");
  const headers: Record<string, string> = { "User-Agent": "HexGuard-Hunt/1.0" };
  if (bearerToken) headers["Authorization"] = `Bearer ${bearerToken}`;

  const specials = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"];
  const found: FfufEndpoint[] = [];

  for (const p of specials) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`${base}${p}`, {
        method: "GET",
        headers,
        signal: controller.signal,
        redirect: "manual",
      });
      clearTimeout(timer);
      if (res.status < 500) {
        found.push({
          url: `${base}${p}`,
          method: "GET",
          statusCode: res.status,
          contentLength: parseInt(res.headers.get("content-length") ?? "0", 10),
          words: 0,
          lines: 0,
          redirectLocation: res.headers.get("location") ?? "",
        });
      }
    } catch {
      // silently skip
    }
  }
  return found;
}

async function tryHexStrike(target: string, bearerToken?: string): Promise<FfufEndpoint[] | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    const res = await fetch(`${HEXSTRIKE_BASE}/api/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        command: "ffuf",
        args: ["-u", `${target}/FUZZ`, "-w", "-", "-of", "json"],
        tool: "ffuf",
        params: { target, bearerToken },
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json() as { results?: FfufEndpoint[]; endpoints?: FfufEndpoint[] };
    if (Array.isArray(data?.results)) return data.results;
    if (Array.isArray(data?.endpoints)) return data.endpoints;
    return null;
  } catch {
    return null;
  }
}

function simulateEndpoints(target: string): FfufEndpoint[] {
  const base = target.replace(/\/$/, "");
  const endpoints: FfufEndpoint[] = [
    { url: `${base}/api/v1/users`, method: "GET", statusCode: 200, contentLength: 1247, words: 38, lines: 12, redirectLocation: "" },
    { url: `${base}/api/v1/users/1`, method: "GET", statusCode: 200, contentLength: 342, words: 12, lines: 6, redirectLocation: "" },
    { url: `${base}/api/v1/auth/login`, method: "POST", statusCode: 200, contentLength: 189, words: 8, lines: 4, redirectLocation: "" },
    { url: `${base}/api/v1/admin`, method: "GET", statusCode: 403, contentLength: 67, words: 4, lines: 2, redirectLocation: "" },
    { url: `${base}/api/v1/profile`, method: "GET", statusCode: 200, contentLength: 521, words: 18, lines: 9, redirectLocation: "" },
    { url: `${base}/api/v1/products`, method: "GET", statusCode: 200, contentLength: 4320, words: 142, lines: 48, redirectLocation: "" },
    { url: `${base}/api/v1/orders`, method: "GET", statusCode: 401, contentLength: 45, words: 3, lines: 2, redirectLocation: "" },
    { url: `${base}/api/v1/config`, method: "GET", statusCode: 200, contentLength: 198, words: 11, lines: 7, redirectLocation: "" },
    { url: `${base}/robots.txt`, method: "GET", statusCode: 200, contentLength: 88, words: 6, lines: 4, redirectLocation: "" },
    { url: `${base}/api/v2/users`, method: "GET", statusCode: 200, contentLength: 1247, words: 38, lines: 12, redirectLocation: "" },
    { url: `${base}/admin`, method: "GET", statusCode: 302, contentLength: 0, words: 0, lines: 0, redirectLocation: `${base}/login` },
    { url: `${base}/health`, method: "GET", statusCode: 200, contentLength: 32, words: 2, lines: 1, redirectLocation: "" },
  ];
  return endpoints;
}

async function runFfufProcess(
  target: string,
  wordlistPath: string | undefined,
  bearerToken: string | undefined,
  outFile: string,
  extraArgs: string[],
): Promise<FfufEndpoint[]> {
  const targetFuzz = `${target.replace(/\/$/, "")}/FUZZ`;
  const wl = wordlistPath ?? "/usr/share/wordlists/dirb/common.txt";

  const args: string[] = [
    "-u", targetFuzz,
    "-w", wl,
    "-o", outFile,
    "-of", "json",
    "-mc", "200,201,204,301,302,307,401,403,405",
    "-t", "20",
    ...extraArgs,
  ];

  if (bearerToken) {
    args.push("-H", `Authorization: Bearer ${bearerToken}`);
  }

  return new Promise((resolve) => {
    const proc = spawn("ffuf", args, { timeout: TIMEOUT_MS });
    const timer = setTimeout(() => { proc.kill(); resolve([]); }, TIMEOUT_MS);

    proc.on("close", async () => {
      clearTimeout(timer);
      try {
        const raw = await fs.readFile(outFile, "utf8");
        const json = JSON.parse(raw) as { results?: FfufEndpoint[] };
        resolve(Array.isArray(json?.results) ? json.results : []);
      } catch {
        resolve([]);
      }
    });

    proc.on("error", () => {
      clearTimeout(timer);
      resolve([]);
    });
  });
}

export const ffufAdapter = {
  async invoke(opts: InvokeOptions): Promise<FfufResult> {
    const start = Date.now();
    const { target, outputDir, wordlistPath, bearerToken, extraArgs = [], simulation = false } = opts;

    if (simulation) {
      const endpoints = simulateEndpoints(target);
      return {
        tool: "ffuf",
        success: true,
        exitCode: 0,
        endpoints,
        totalRequests: endpoints.length * 2,
        durationMs: Date.now() - start,
      };
    }

    // 1) Try HexStrike server first
    const hexstrikeResult = await tryHexStrike(target, bearerToken);
    if (hexstrikeResult !== null && hexstrikeResult.length > 0) {
      const special = await probeSpecialPaths(target, bearerToken);
      return {
        tool: "ffuf",
        success: true,
        exitCode: 0,
        endpoints: [...hexstrikeResult, ...special],
        totalRequests: hexstrikeResult.length + special.length,
        durationMs: Date.now() - start,
      };
    }

    // 2) Try spawning ffuf locally
    const outFile = path.join(outputDir, "ffuf-out.json");
    const spawnedEndpoints = await runFfufProcess(target, wordlistPath, bearerToken, outFile, extraArgs);

    // 3) Always probe special paths
    const special = await probeSpecialPaths(target, bearerToken);
    const allEndpoints = [...spawnedEndpoints, ...special];

    // 4) If nothing found at all, use built-in path list to probe
    const results = allEndpoints.length > 0 ? allEndpoints : await (async () => {
      const base = target.replace(/\/$/, "");
      const headers: Record<string, string> = { "User-Agent": "HexGuard-Hunt/1.0" };
      if (bearerToken) headers["Authorization"] = `Bearer ${bearerToken}`;
      const found: FfufEndpoint[] = [];
      for (const p of BUILTIN_PATHS) {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 5000);
          const res = await fetch(`${base}${p}`, { method: "GET", headers, signal: controller.signal, redirect: "manual" });
          clearTimeout(timer);
          if (res.status < 500) {
            found.push({
              url: `${base}${p}`,
              method: "GET",
              statusCode: res.status,
              contentLength: parseInt(res.headers.get("content-length") ?? "0", 10),
              words: 0,
              lines: 0,
              redirectLocation: res.headers.get("location") ?? "",
            });
          }
        } catch { /* skip */ }
      }
      return found;
    })();

    return {
      tool: "ffuf",
      success: true,
      exitCode: 0,
      endpoints: results,
      totalRequests: results.length + BUILTIN_PATHS.length,
      durationMs: Date.now() - start,
    };
  },
};
