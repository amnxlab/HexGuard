/**
 * zap.ts — Adapter for OWASP ZAP (Zed Attack Proxy) REST API.
 *
 * ZAP is the free, open-source replacement for Burp Suite Professional.
 * Start ZAP as a daemon before running scans:
 *   zap.sh -daemon -port 8090 -host 127.0.0.1 -config api.disablekey=true
 *
 * API: http://127.0.0.1:8090
 *   GET /JSON/ascan/action/scan/      → start active scan, returns { scan }
 *   GET /JSON/ascan/view/status/      → poll progress (0-100)
 *   GET /JSON/core/view/alerts/       → fetch found alerts
 *   GET /JSON/core/view/version/      → health check
 *
 * Documentation: https://www.zaproxy.org/docs/api/
 */

import * as http from "node:http";
import type { ZapAlert, ZapScanResult } from "@hexguard/shared";
import type { ToolInvokeOptions } from "./base";

type ConsoleFn = (tag: "info"|"warn"|"err"|"res"|"out", text: string) => void;

const ZAP_BASE        = "http://127.0.0.1:8090";
const POLL_INTERVAL_MS = 3_000;
const DEFAULT_TIMEOUT_MS = 300_000; // 5 min

// ─── ZAP API response shapes ──────────────────────────────────────────────────

interface ZapScanStartResponse {
  scan: string; // scan ID as string
}

interface ZapStatusResponse {
  status: string; // "0" – "100"
}

interface ZapAlertRaw {
  alertRef?: string;
  alert: string;
  risk: string;
  confidence: string;
  url: string;
  description: string;
  solution: string;
}

interface ZapAlertsResponse {
  alerts: ZapAlertRaw[];
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function zapGet(urlPath: string): Promise<{ status: number; data: string }> {
  return new Promise((resolve, reject) => {
    const url = new URL(ZAP_BASE + urlPath);
    const options: http.RequestOptions = {
      hostname: url.hostname,
      port: Number(url.port) || 8090,
      path: url.pathname + url.search,
      method: "GET",
      timeout: 10_000,
      headers: { "Accept": "application/json" },
    };
    const req = http.request(options, res => {
      let data = "";
      res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, data }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("ZAP request timed out")); });
    req.end();
  });
}

// ─── Risk/confidence normalizers ──────────────────────────────────────────────

function normalizeRisk(raw: string): ZapAlert["risk"] {
  const r = raw.trim();
  if (r === "High")          return "High";
  if (r === "Medium")        return "Medium";
  if (r === "Low")           return "Low";
  return "Informational";
}

function normalizeConfidence(raw: string): ZapAlert["confidence"] {
  const r = raw.trim();
  if (r === "High")          return "High";
  if (r === "Medium")        return "Medium";
  if (r === "False Positive") return "False Positive";
  return "Low";
}

function parseAlerts(raw: ZapAlertRaw[]): ZapAlert[] {
  return raw.map(a => ({
    alertRef:   a.alertRef ?? "",
    name:       a.alert,
    risk:       normalizeRisk(a.risk),
    confidence: normalizeConfidence(a.confidence),
    url:        a.url,
    description: a.description,
    solution:   a.solution,
  }));
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

export const zapAdapter = {
  toolName: "zap" as const,

  async isAvailable(): Promise<boolean> {
    try {
      const res = await zapGet("/JSON/core/view/version/");
      return res.status === 200;
    } catch {
      return false;
    }
  },

  async invoke(
    options: ToolInvokeOptions & { onConsole?: ConsoleFn }
  ): Promise<ZapScanResult> {
    const start   = Date.now();
    const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const log = options.onConsole ?? (() => {});

    // If ZAP is offline, return a graceful empty result (non-fatal — it's optional)
    if (!(await this.isAvailable())) {
      log("warn", "ZAP daemon not running — start with: zap.sh -daemon -port 8090 -config api.disablekey=true");
      return {
        tool: "zap",
        success: true,
        exitCode: 0,
        durationMs: Date.now() - start,
        alerts: [],
        scanStatus: "succeeded",
        error: "ZAP daemon not running — active scan skipped",
      };
    }

    log("info", `[cmd] ZAP active scan → ${options.target}`);

    const encoded = encodeURIComponent(options.target);

    // 0. Seed ZAP's site tree — accessUrl + quick spider so ascan has a target node.
    //    Without this, ZAP returns HTTP 400 ("URL not found in scan tree") on the first run.
    try {
      await zapGet(`/JSON/core/action/accessUrl/?url=${encoded}&followRedirects=true`);
      log("info", "ZAP: seeding site tree via accessUrl…");
    } catch { /* non-fatal */ }

    try {
      const spiderRes = await zapGet(
        `/JSON/spider/action/scan/?url=${encoded}&maxChildren=5&recurse=false&subtreeOnly=false`,
      );
      if (spiderRes.status === 200) {
        const spiderId = (JSON.parse(spiderRes.data) as { scan: string }).scan;
        log("info", `ZAP: quick spider started (id=${spiderId}) — waiting up to 30s…`);
        const spiderDeadline = Date.now() + 30_000;
        while (Date.now() < spiderDeadline) {
          await new Promise(r => setTimeout(r, 2_000));
          try {
            const ss = await zapGet(`/JSON/spider/view/status/?scanId=${spiderId}`);
            if ((JSON.parse(ss.data) as { status: string }).status === "100") break;
          } catch { /* keep polling */ }
        }
        log("info", "ZAP: spider complete — starting active scan");
      }
    } catch { /* non-fatal — proceed to ascan anyway */ }

    // 1. Start active scan
    let scanId: string;
    try {
      const res = await zapGet(`/JSON/ascan/action/scan/?url=${encoded}&recurse=true&inScopeOnly=false`);
      if (res.status !== 200) {
        log("err", `ZAP scan start returned HTTP ${res.status}`);
        return {
          tool: "zap",
          success: false,
          exitCode: res.status,
          error: `ZAP scan start returned HTTP ${res.status}: ${res.data}`,
          durationMs: Date.now() - start,
          alerts: [],
          scanStatus: "failed",
        };
      }
      const parsed = JSON.parse(res.data) as ZapScanStartResponse;
      scanId = parsed.scan;
      log("info", `ZAP active scan started (id=${scanId}) — polling…`);
    } catch (err) {
      log("err", `Failed to start ZAP scan: ${(err as Error).message}`);
      return {
        tool: "zap",
        success: false,
        exitCode: -1,
        error: `Failed to start ZAP scan: ${(err as Error).message}`,
        durationMs: Date.now() - start,
        alerts: [],
        scanStatus: "failed",
      };
    }

    // 2. Poll until 100% or timeout
    let lastPct = -1;
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      try {
        const statusRes = await zapGet(`/JSON/ascan/view/status/?scanId=${scanId}`);
        const statusData = JSON.parse(statusRes.data) as ZapStatusResponse;
        const pct = parseInt(statusData.status, 10);
        if (pct !== lastPct && pct % 20 === 0) {
          log("info", `ZAP scan progress: ${pct}%`);
          lastPct = pct;
        }
        if (statusData.status === "100") break;
      } catch { /* transient error — keep polling */ }
    }

    // 3. Fetch alerts
    try {
      const alertRes = await zapGet(`/JSON/core/view/alerts/?baseurl=${encodeURIComponent(options.target)}`);
      const alertData = JSON.parse(alertRes.data) as ZapAlertsResponse;
      const alerts = parseAlerts(alertData.alerts ?? []);
      const highCount = alerts.filter(a => a.risk === "High" || a.risk === "Medium").length;
      log(highCount > 0 ? "warn" : "out",
        `ZAP: ${alerts.length} alert(s) (${highCount} high/medium) in ${((Date.now() - start) / 1000).toFixed(1)}s`);
      return {
        tool: "zap",
        success: true,
        exitCode: 0,
        durationMs: Date.now() - start,
        alerts,
        scanStatus: "succeeded",
      };
    } catch (err) {
      log("err", `Failed to fetch ZAP alerts: ${(err as Error).message}`);
      return {
        tool: "zap",
        success: false,
        exitCode: -1,
        error: `Failed to fetch ZAP alerts: ${(err as Error).message}`,
        durationMs: Date.now() - start,
        alerts: [],
        scanStatus: "failed",
      };
    }
  },
};
