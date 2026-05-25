import type { ZapAlert, ZapScanResult } from "@hexguard/shared";

const ZAP_BASE = "http://localhost:8090";
const POLL_INTERVAL_MS = 3_000;
const SCAN_TIMEOUT_MS = 120_000;

interface InvokeOptions {
  target: string;
  outputDir: string;
  extraArgs?: string[];
  simulation?: boolean;
}

async function zapFetch<T>(path: string): Promise<T | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);
    const res = await fetch(`${ZAP_BASE}${path}`, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function isZapRunning(): Promise<boolean> {
  const r = await zapFetch<unknown>("/JSON/core/view/version/");
  return r !== null;
}

async function startActiveScan(target: string): Promise<string | null> {
  const encoded = encodeURIComponent(target);
  const r = await zapFetch<{ scan?: string }>(`/JSON/ascan/action/scan/?url=${encoded}&recurse=true`);
  return r?.scan ?? null;
}

async function getScanProgress(scanId: string): Promise<number> {
  const r = await zapFetch<{ status?: string }>(`/JSON/ascan/view/status/?scanId=${scanId}`);
  return parseInt(r?.status ?? "0", 10);
}

async function getAlerts(baseUrl: string): Promise<ZapAlert[]> {
  const encoded = encodeURIComponent(baseUrl);
  const r = await zapFetch<{ alerts?: Array<{
    alertRef?: string;
    name?: string;
    risk?: string;
    confidence?: string;
    url?: string;
    description?: string;
    solution?: string;
  }> }>(`/JSON/core/view/alerts/?baseurl=${encoded}`);

  if (!Array.isArray(r?.alerts)) return [];

  return r.alerts.map(a => ({
    alertRef: a.alertRef ?? "0",
    name: a.name ?? "Unknown",
    risk: (a.risk ?? "Informational") as ZapAlert["risk"],
    confidence: (a.confidence ?? "Low") as ZapAlert["confidence"],
    url: a.url ?? baseUrl,
    description: a.description ?? "",
    solution: a.solution ?? "",
  }));
}

function simulateAlerts(target: string): ZapAlert[] {
  return [
    {
      alertRef: "10038",
      name: "Content Security Policy (CSP) Header Not Set",
      risk: "Medium",
      confidence: "High",
      url: target,
      description: "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.",
      solution: "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.",
    },
    {
      alertRef: "10036",
      name: "Server Leaks Version Information via Server HTTP Response Header Field",
      risk: "Low",
      confidence: "High",
      url: target,
      description: "The web/application server is leaking version information via the Server HTTP response header.",
      solution: "Ensure that your web server, application server, load balancer, etc. is configured to suppress the Server header.",
    },
    {
      alertRef: "10055",
      name: "CSP: Wildcard Directive",
      risk: "Medium",
      confidence: "Medium",
      url: `${target}/api/v1/users`,
      description: "Content Security Policy (CSP) header contains a wildcard directive. This allows any source for that directive.",
      solution: "Review the wildcard directives in CSP. Consider replacing them with specific origins.",
    },
    {
      alertRef: "90033",
      name: "Loosely Scoped Cookie",
      risk: "Informational",
      confidence: "Low",
      url: `${target}/api/v1/auth/login`,
      description: "Cookie has a broad domain scope.",
      solution: "Ensure that cookies set for a specific hostname do not include a domain attribute that covers a broader scope.",
    },
  ];
}

export const zapAdapter = {
  async invoke(opts: InvokeOptions): Promise<ZapScanResult> {
    const start = Date.now();
    const { target, simulation = false } = opts;

    if (simulation) {
      const alerts = simulateAlerts(target);
      return {
        tool: "zap",
        success: true,
        exitCode: 0,
        alerts,
        scanStatus: "succeeded",
        durationMs: Date.now() - start,
      };
    }

    // Graceful degradation if ZAP is not running
    const running = await isZapRunning();
    if (!running) {
      return {
        tool: "zap",
        success: false,
        exitCode: 1,
        error: "ZAP proxy not running on port 8090. Start OWASP ZAP to enable active scan validation.",
        alerts: [],
        scanStatus: "failed",
        durationMs: Date.now() - start,
      };
    }

    // Start active scan
    const scanId = await startActiveScan(target);
    if (!scanId) {
      return {
        tool: "zap",
        success: false,
        exitCode: 1,
        error: "Failed to start ZAP active scan.",
        alerts: [],
        scanStatus: "failed",
        durationMs: Date.now() - start,
      };
    }

    // Poll until completion
    const deadline = Date.now() + SCAN_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      const progress = await getScanProgress(scanId);
      if (progress >= 100) break;
    }

    const alerts = await getAlerts(target);

    return {
      tool: "zap",
      success: true,
      exitCode: 0,
      alerts,
      scanStatus: "succeeded",
      durationMs: Date.now() - start,
    };
  },
};
