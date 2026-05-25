/**
 * pipelineEngine.ts — Seven-phase autonomous vulnerability scan pipeline.
 *
 * Phases run autonomously.  High-risk phases (active_probing, deep_scan)
 * pause and emit a confirmation card before executing.
 *
 * Phase order:
 *   recon → fingerprint → passive_audit → discovery →
 *   ai_analysis → active_probing → deep_scan → ended
 */

import * as os from "node:os";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { app } from "electron";
import type {
  Finding,
  HttpCapture,
  HuntSession,
  ScanPhase,
  SecurityAuditResult,
  TechFingerprint,
  ConsoleLogLine,
} from "@hexguard/shared";
import { httpFetch, httpFetchCorsProbe } from "../recon/httpClient";
import { RateLimiter } from "../recon/rateLimiter";
import { auditCaptures } from "../recon/passiveAuditor";
import { detectTech } from "../recon/techFingerprinter";
import { probeWithWordlist } from "../recon/concurrentProber";
import { ffufAdapter } from "../adapters/ffuf";
import { sqlmapAdapter } from "../adapters/sqlmap";
import { zapAdapter } from "../adapters/zap";
import { runNucleiPhase } from "../adapters/nuclei";
import { runNiktoPhase } from "../adapters/nikto";
import { runH2cSmugglerPhase } from "../adapters/h2csmuggler";
import { runSurfPhase } from "../adapters/surf";
import { wapitiAdapter } from "../adapters/wapiti";
import { wafw00fAdapter } from "../adapters/wafw00f";
import {
  hexstrikeAnalyzeHttp,
  hexstrikeFingerprint,
  hexstrikeGeneratePoc,
  hexstrikeSynthesizeReport,
} from "../services/mcpClient";
import { extractFormsFromCaptures } from "../recon/formExtractor";
import { extractLinks, parseRobotsTxt, parseSitemap } from "../recon/linkExtractor";
import {
  XSS_PAYLOADS,
  SQLI_PAYLOADS,
  TRAVERSAL_PAYLOADS,
  SSRF_PAYLOADS,
  AUTH_BYPASS_PAIRS,
  AUTH_BYPASS_SQLI,
  idorProbeIds,
  URL_PARAM_NAMES,
  FILE_PARAM_NAMES,
  PASSWD_PATTERN,
  SQLI_ERROR_PATTERN,
} from "./vulnPayloads";

// ─── Phase metadata ───────────────────────────────────────────────────────────

export const PHASE_ORDER: ScanPhase[] = [
  "recon",
  "fingerprint",
  "passive_audit",
  "discovery",
  "ai_analysis",
  "active_probing",
  "deep_scan",
  "vuln_assessment",
  "exploitation",
  "report_synthesis",
  "ended",
];

export function nextPhase(current: ScanPhase): ScanPhase {
  const idx = PHASE_ORDER.indexOf(current);
  return idx >= 0 && idx < PHASE_ORDER.length - 1
    ? PHASE_ORDER[idx + 1]!
    : "ended";
}

export function phaseLabel(phase: ScanPhase): string {
  const labels: Record<ScanPhase, string> = {
    recon:            "Reconnaissance",
    fingerprint:      "Tech Fingerprinting",
    passive_audit:    "Passive Security Audit",
    discovery:        "Endpoint Discovery",
    ai_analysis:      "AI Response Analysis",
    active_probing:   "Active Vulnerability Probing",
    deep_scan:        "Deep Scan (SQLi / ZAP)",
    vuln_assessment:  "Vulnerability Assessment (OWASP Top 10)",
    exploitation:     "Exploitation & PoC Generation",
    report_synthesis: "Report Synthesis",
    ended:            "Complete",
  };
  return labels[phase] ?? phase;
}

export function phaseNeedsConfirmation(phase: ScanPhase): boolean {
  return (
    phase === "active_probing" ||
    phase === "deep_scan" ||
    phase === "vuln_assessment" ||
    phase === "exploitation"
  );
}

// ─── Phase result type ────────────────────────────────────────────────────────

export interface PhaseResult {
  findings:         Finding[];
  captures:         HttpCapture[];
  visitedEndpoints: string[];
  techFingerprint?: TechFingerprint;
  securityAudit?:   SecurityAuditResult;
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

type ConsoleFn = (tag: ConsoleLogLine["tag"], text: string) => void;

/** Build a rate limiter from session config. Falls back to 30 req/min. */
function makeRl(session: HuntSession): RateLimiter {
  return new RateLimiter(session.config.maxRequestsPerMinute ?? 30);
}

// ─── Phase 1: RECON ───────────────────────────────────────────────────────────

export async function runReconPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const base    = session.config.target.replace(/\/$/, "");
  const bearer  = session.config.bearerToken;
  const probeUrls = [
    base,
    `${base}/robots.txt`,
    `${base}/sitemap.xml`,
    `${base}/.well-known/security.txt`,
    `${base}/favicon.ico`,
  ];

  onConsole("info", "Fetching root page and well-known resources…");

  const rl = makeRl(session);
  const captures: HttpCapture[] = [];
  for (const url of probeUrls) {
    const cap = await httpFetch(url, { bearerToken: bearer, timeoutMs: 12_000, rateLimiter: rl });
    if (cap) {
      captures.push(cap);
      if (cap.statusCode < 400) {
        onConsole("res", `${cap.statusCode} ${url} (${cap.timingMs}ms, ${cap.contentType})`);
      }
    }
  }

  onConsole("out", `Recon: ${captures.filter(c => c.statusCode < 400).length}/${probeUrls.length} resources fetched`);
  return { findings: [], captures, visitedEndpoints: [] };
}

// ─── Phase 2: FINGERPRINT ─────────────────────────────────────────────────────

export async function runFingerprintPhase(
  session: HuntSession,
  existingCaptures: HttpCapture[],
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  onConsole("info", "Detecting technology stack…");

  let tech = detectTech(existingCaptures);

  // Enrich with HexStrike if available
  try {
    const root = existingCaptures.find(c => {
      try { return new URL(c.url).pathname === "/"; } catch { return false; }
    }) ?? existingCaptures[0];

    if (root) {
      const res = await hexstrikeFingerprint(root.headers, root.bodyPreview.slice(0, 4096));
      if (res && typeof res === "object") {
        const r = res as Record<string, unknown>;
        if (r["framework"] && !tech.framework) tech.framework = String(r["framework"]);
        if (r["cms"]       && !tech.cms)       tech.cms       = String(r["cms"]);
        if (r["language"]  && !tech.language)  tech.language  = String(r["language"]);
        if (r["suggestedWordlist"]) tech.suggestedWordlist = String(r["suggestedWordlist"]);
      }
    }
  } catch { /* non-fatal */ }

  const stackParts = [tech.cms, tech.framework, tech.language, tech.server].filter(Boolean);
  onConsole("out", `Tech stack: ${stackParts.join(" / ") || "undetected"} (confidence ${tech.confidence}%)`);

  // ── WAF detection (non-fatal) ─────────────────────────────────────────
  const findings: Finding[] = [];
  try {
    onConsole("info", "Running WAF detection…");
    const outDir = path.join(os.tmpdir(), `hexguard-fp-${Date.now()}`);
    await fs.mkdir(outDir, { recursive: true });
    const wafRes = await wafw00fAdapter.invoke({
      target: session.config.target,
      outputDir: outDir,
      timeoutMs: 60_000,
      onConsole,
    });
    await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
    if (wafRes.detected && wafRes.firewalls.length > 0) {
      // Annotate tech fingerprint
      tech.waf = wafRes.firewalls.join(", ");
      findings.push({
        id:        `finding-waf-${Date.now()}`,
        timestamp: new Date().toISOString(),
        title:     `WAF detected: ${wafRes.firewalls.join(", ")}`,
        severity:  "low",
        endpoint:  session.config.target,
        evidence:  `Web Application Firewall (${wafRes.firewalls.join(", ")}) is protecting this target. Payloads may be filtered.`,
        tool:      "wafw00f",
      });
    }
  } catch { /* non-fatal */ }

  return { findings, captures: [], visitedEndpoints: [], techFingerprint: tech };
}

// ─── Phase 3: PASSIVE AUDIT ───────────────────────────────────────────────────

export async function runPassiveAuditPhase(
  session: HuntSession,
  existingCaptures: HttpCapture[],
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  onConsole("info", "Running passive security audit (headers, CORS, cookies, info-disclosure)…");

  // Probe with evil Origin header to test CORS
  const rl = makeRl(session);
  const corsCapture = await httpFetchCorsProbe(session.config.target, {
    bearerToken: session.config.bearerToken,
    timeoutMs:   8_000,
    rateLimiter: rl,
  });
  const allCaptures = [...existingCaptures, ...(corsCapture ? [corsCapture] : [])];

  const { findings: headerFindings, audit } = auditCaptures(allCaptures, session.config.target);
  const findings = [...headerFindings];

  // ── Active CSP analysis ───────────────────────────────────────────────
  const root = allCaptures.find(c => {
    try { return new URL(c.url).pathname === "/"; } catch { return false; }
  }) ?? allCaptures[0];
  if (root) {
    const csp = root.headers["content-security-policy"];
    if (csp) {
      const issues: string[] = [];
      if (csp.includes("'unsafe-inline'")) issues.push("unsafe-inline scripts allowed");
      if (csp.includes("'unsafe-eval'"))  issues.push("unsafe-eval allowed");
      if (/default-src\s+\*|script-src\s+\*/i.test(csp)) issues.push("wildcard source in CSP");
      if (csp.includes("data:"))          issues.push("data: URI allowed as source");
      if (issues.length > 0) {
        findings.push({
          id: `finding-csp-${Date.now()}`, timestamp: new Date().toISOString(),
          title: "Content-Security-Policy is weak",
          severity: "medium",
          endpoint: root.url,
          evidence: `CSP is present but has weaknesses:\n${issues.map(i => `  • ${i}`).join("\n")}\nFull header: ${csp.slice(0, 300)}`,
          tool: "passive-auditor",
        });
        onConsole("warn", `CSP weaknesses: ${issues.join("; ")}`);
      } else {
        onConsole("out", "CSP is present and appears well-configured");
      }
    }
    const hsts = root.headers["strict-transport-security"];
    if (hsts) {
      const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]!, 10) : 0;
      if (maxAge < 31536000) {
        findings.push({
          id: `finding-hsts-${Date.now()}`, timestamp: new Date().toISOString(),
          title: "HSTS max-age is too short",
          severity: "low",
          endpoint: root.url,
          evidence: `Strict-Transport-Security: ${hsts}\nmax-age ${maxAge}s is below the recommended 31536000s (1 year).`,
          tool: "passive-auditor",
        });
      }
      if (!hsts.includes("includeSubDomains")) {
        onConsole("warn", "HSTS does not include includeSubDomains");
      }
    }
  }

  // ── Active CORS verification (send crafted Origin, check reflection) ───────
  try {
    const testOrigin = "https://evil-cors-test.hexguard.internal";
    const corsTest = await httpFetch(session.config.target, {
      bearerToken: session.config.bearerToken,
      timeoutMs: 6_000,
      headers: { "Origin": testOrigin },
      rateLimiter: rl,
    });
    if (corsTest) {
      const acao = corsTest.headers["access-control-allow-origin"] ?? "";
      const acac = corsTest.headers["access-control-allow-credentials"] === "true";
      if (acao === testOrigin || acao === "*") {
        const sev = (acao === testOrigin && acac) ? "high" : "medium";
        findings.push({
          id: `finding-cors-active-${Date.now()}`, timestamp: new Date().toISOString(),
          title: acao === testOrigin && acac
            ? "CORS reflects arbitrary origin with credentials (active verification)"
            : "CORS reflects arbitrary origin (active verification)",
          severity: sev,
          endpoint: session.config.target,
          evidence: `Active probe sent Origin: ${testOrigin}\nResponse header: Access-Control-Allow-Origin: ${acao}` +
            (acac ? "\nAccess-Control-Allow-Credentials: true" : ""),
          tool: "passive-auditor",
        });
        onConsole("warn", `CORS misconfiguration confirmed (active): ACAO=${acao}, credentials=${acac}`);
      }
    }
  } catch { /* non-fatal */ }

  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] ?? 0) + 1;

  onConsole(
    findings.length > 0 ? "warn" : "out",
    `Passive audit: ${findings.length} finding(s) — ` +
    `critical:${sev.critical} high:${sev.high} medium:${sev.medium} low:${sev.low}`,
  );

  return { findings, captures: [], visitedEndpoints: [], securityAudit: audit };
}

// ─── Phase 4: DISCOVERY ───────────────────────────────────────────────────────

export async function runDiscoveryPhase(
  session: HuntSession,
  tech: TechFingerprint | undefined,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const target  = session.config.target;
  const bearer  = session.config.bearerToken;
  const base    = target.replace(/\/$/, "");
  const outDir  = path.join(os.tmpdir(), `hexguard-disc-${Date.now()}`);
  await fs.mkdir(outDir, { recursive: true });

  const discovered: HttpCapture[] = [];
  // Passive endpoints (URLs without a full HttpCapture — gathered from HTML, robots, sitemap)
  const passiveUrls = new Set<string>();

  // ── Step 1: Passive crawl — extract links from previously captured pages ──
  const prevCaptures = session.context.capturedResponses ?? [];
  for (const cap of prevCaptures) {
    if (cap.contentType.includes("html") && cap.bodyPreview) {
      for (const link of extractLinks(cap.bodyPreview, cap.url)) {
        passiveUrls.add(link);
      }
    }
  }
  // Always include the base URL itself
  passiveUrls.add(base);
  if (passiveUrls.size > 1) {
    onConsole("info", `Passive crawl: ${passiveUrls.size} link(s) extracted from captured pages`);
  }

  const rl = makeRl(session);
  // ── Step 2: robots.txt ────────────────────────────────────────────────────
  const robotsCap = await httpFetch(`${base}/robots.txt`, { timeoutMs: 8_000, bearerToken: bearer, rateLimiter: rl });
  if (robotsCap) {
    discovered.push(robotsCap);
    if (robotsCap.statusCode === 200 && robotsCap.bodyPreview.toLowerCase().includes("user-agent")) {
      const paths = parseRobotsTxt(robotsCap.bodyPreview, base);
      onConsole("info", `robots.txt: ${paths.length} path(s) found`);
      for (const p of paths) passiveUrls.add(p);
    }
  }

  // ── Step 3: sitemap.xml ───────────────────────────────────────────────────
  const sitemapCap = await httpFetch(`${base}/sitemap.xml`, { timeoutMs: 8_000, bearerToken: bearer, rateLimiter: rl });
  if (sitemapCap) {
    discovered.push(sitemapCap);
    if (sitemapCap.statusCode === 200 && sitemapCap.bodyPreview.includes("<loc")) {
      const locs = parseSitemap(sitemapCap.bodyPreview, base);
      onConsole("info", `sitemap.xml: ${locs.length} URL(s) found`);
      for (const u of locs) passiveUrls.add(u);
    }
  }

  // ── Step 4: Active wordlist probe (ffuf → built-in prober fallback) ───────
  // Resolve wordlist directory relative to the compiled output location so
  // it works on any machine regardless of install prefix.
  // Compiled path:  packages/desktop/dist/main/engine/pipelineEngine.js
  // Repo root:      ../../../../.. (5 levels up)
  const repoWordlistDir = path.resolve(__dirname, "../../../../../wordlists");
  const candidates = [
    // Repo-bundled — highest priority, always present when running from source
    path.join(repoWordlistDir, "raft-medium-directories.txt"),
    path.join(repoWordlistDir, "common.txt"),
    path.join(repoWordlistDir, "big.txt"),
    path.join(repoWordlistDir, "api-endpoints.txt"),
    // Fallback: app.getAppPath() variant (packaged app or unusual launch)
    path.join(app.getAppPath(), "../../wordlists/raft-medium-directories.txt"),
    path.join(app.getAppPath(), "../../wordlists/common.txt"),
    // System SecLists
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
  ];
  let wordlistPath: string | null = null;
  for (const p of candidates) {
    try { await fs.access(p); wordlistPath = p; break; } catch { continue; }
  }

  let usedFfuf = false;
  // All URLs discovered by ffuf (regardless of whether they were httpFetch'd)
  const ffufUrls: string[] = [];

  if (wordlistPath) {
    onConsole("info", `Starting ffuf with wordlist: ${path.basename(wordlistPath)}`);
    try {
      const res = await ffufAdapter.invoke({ target, outputDir: outDir, wordlistPath, onConsole });
      if (res.success && res.endpoints && res.endpoints.length > 0) {
        // WAF baseline filter: if >70% of results share the same status code
        // and response length, they're likely a WAF block page — remove them.
        const statusCounts = new Map<number, number>();
        for (const ep of res.endpoints) statusCounts.set(ep.statusCode, (statusCounts.get(ep.statusCode) ?? 0) + 1);
        const topStatus = [...statusCounts.entries()].sort((a, b) => b[1] - a[1])[0];
        const wafBaseline = topStatus && topStatus[1] / res.endpoints.length > 0.70 && topStatus[0] !== 200;
        const filtered = wafBaseline
          ? res.endpoints.filter(ep => ep.statusCode !== topStatus[0])
          : res.endpoints;

        if (wafBaseline) {
          onConsole("warn", `WAF baseline detected (${topStatus[0]} ×${topStatus[1]}) — filtered from results`);
        }

        if (filtered.length > 0) {
          onConsole("out", `ffuf: ${filtered.length} endpoint(s) found`);
          // Track ALL ffuf-discovered URLs so they all appear in the report,
          // even those beyond the httpFetch cap.
          for (const ep of filtered) ffufUrls.push(ep.url);
          const caps = await Promise.all(
            filtered.slice(0, 60).map(ep =>
              httpFetch(ep.url, { timeoutMs: 6_000, bearerToken: bearer }),
            ),
          );
          discovered.push(...caps.filter(Boolean) as HttpCapture[]);
          usedFfuf = true;
        }
      }
    } catch { /* fall through to prober */ }
  }

  if (!usedFfuf) {
    if (wordlistPath) {
      onConsole("info", "ffuf produced no output — using built-in concurrent prober…");
    } else {
      onConsole("warn", "No system wordlist found — using built-in prober with common paths");
      wordlistPath = path.join(outDir, "builtin.txt");
      const builtinPaths = [
        // Auth & accounts
        "login","logout","register","signup","signin","forgot-password",
        "reset-password","change-password","account","profile","user","users",
        // Admin
        "admin","admin/login","admin/dashboard","administration","manage",
        "manager","panel","control","controlpanel",
        // API
        "api","api/v1","api/v2","api/v3","rest","graphql","query",
        "api/users","api/login","api/register","api/auth","api/token",
        // Discovery
        "robots.txt","sitemap.xml","sitemap_index.xml",".well-known/security.txt",
        ".well-known/change-password","humans.txt","ads.txt",
        // Config & secrets
        ".env",".env.local",".env.production","config","configuration",
        "settings","app.config.js","web.config","config.json","config.yaml",
        // Dev & debug
        "debug","test","testing","dev","development","health","healthcheck",
        "status","ping","version","info","metrics","monitor",
        // Backup & upload
        "backup","bak","old","upload","uploads","files","file","download",
        "downloads","media","static","assets",
        // Docs
        "swagger.json","swagger.yaml","openapi.json","openapi.yaml",
        "api-docs","docs","documentation",
        // CMS
        "wp-admin","wp-login.php","wp-json","wp-json/wp/v2/users",
        "phpmyadmin","phpinfo.php","info.php","xmlrpc.php",
        // Common paths
        "dashboard","home","index","search","contact","about","help",
        "setup","install","update","upgrade","feed","rss",
      ];
      await fs.writeFile(wordlistPath, builtinPaths.join("\n"), "utf8");
    }

    const rpm = Math.max(6, session.config.maxRequestsPerMinute);
    const concurrency = Math.min(20, Math.floor(rpm / 3));

    const caps = await probeWithWordlist(target, wordlistPath, {
      concurrency,
      bearerToken: bearer,
      timeoutMs:   7_000,
      onProgress: ({ probed, total, found }) => {
        onConsole("info", `[probe] ${probed}/${total} paths · ${found} found`);
      },
    });
    discovered.push(...caps);
  }

  await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});

  // ── Merge all sources ────────────────────────────────────────────────────
  const allUrls = new Set<string>(passiveUrls);
  for (const ep  of ffufUrls)   allUrls.add(ep);
  for (const cap of discovered) allUrls.add(cap.url);

  const visitedEndpoints = [...allUrls];
  onConsole(
    "out",
    `Discovery: ${visitedEndpoints.length} endpoint(s) found ` +
    `(${ffufUrls.length} ffuf, ${discovered.length} probed, ${passiveUrls.size} passive)`,
  );

  return { findings: [], captures: discovered, visitedEndpoints };
}

// ─── Phase 5: AI ANALYSIS ─────────────────────────────────────────────────────

export async function runAiAnalysisPhase(
  session: HuntSession,
  allCaptures: HttpCapture[],
  existingFindings: Finding[],
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const capCount = Math.min(allCaptures.length, 30);
  onConsole("info", `Sending ${capCount} response(s) to HexStrike AI for analysis…`);

  try {
    const res = await hexstrikeAnalyzeHttp(
      allCaptures.slice(0, 30),
      existingFindings,
      session.context.techFingerprint,
    );
    if (!res) {
      onConsole("warn", "AI analysis: HexStrike unavailable, skipping");
      return { findings: [], captures: [], visitedEndpoints: [] };
    }

    const r = res as Record<string, unknown>;
    const candidates = r["findings"] as unknown[] | undefined;
    const aiFindings: Finding[] = [];

    if (Array.isArray(candidates)) {
      for (const item of candidates) {
        if (!item || typeof item !== "object") continue;
        const f = item as Record<string, unknown>;
        aiFindings.push({
          id:        makeId("finding-ai"),
          timestamp: nowIso(),
          title:     String(f["title"] ?? "AI-identified finding"),
          severity:  (["low","medium","high","critical"].includes(
            String(f["severity"] ?? "").toLowerCase())
              ? String(f["severity"]).toLowerCase()
              : "medium") as Finding["severity"],
          endpoint:  String(f["endpoint"] ?? f["url"] ?? session.config.target),
          evidence:  String(f["evidence"] ?? f["description"] ?? "").slice(0, 500),
          tool:      "ai-analysis",
        });
      }
    }

    onConsole("out", `AI analysis: ${aiFindings.length} finding(s) identified`);
    return { findings: aiFindings, captures: [], visitedEndpoints: [] };
  } catch (err) {
    onConsole("warn", `AI analysis error (non-fatal): ${String(err)}`);
    return { findings: [], captures: [], visitedEndpoints: [] };
  }
}

// ─── Phase 6: ACTIVE PROBING ──────────────────────────────────────────────────

export async function runActiveProbingPhase(
  session: HuntSession,
  endpoints: string[],
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const findings: Finding[] = [];
  const bearer = session.config.bearerToken;
  const rl = makeRl(session);
  // Limit scope — test up to 15 endpoints
  const targets = endpoints.slice(0, 15);

  // ── Open redirect ──
  onConsole("info", "Testing for open redirects…");
  const evilUrl = "https://evil.com/hexguard-redirect-test";
  for (const ep of targets) {
    try {
      const params = `url=${encodeURIComponent(evilUrl)}&redirect=${encodeURIComponent(evilUrl)}&next=${encodeURIComponent(evilUrl)}`;
      const testUrl = ep.includes("?") ? `${ep}&${params}` : `${ep}?${params}`;
      const cap = await httpFetch(testUrl, { timeoutMs: 5_000, followRedirects: false, bearerToken: bearer, rateLimiter: rl });
      if (cap && [301, 302, 303, 307, 308].includes(cap.statusCode)) {
        const loc = cap.headers["location"] ?? "";
        if (loc.includes("evil.com")) {
          findings.push({
            id: makeId("finding-active"), timestamp: nowIso(),
            title: "Open Redirect",
            severity: "medium",
            endpoint: ep,
            evidence: `Redirects to controlled URL.\nHeader: Location: ${loc}\nTest URL: ${testUrl}`,
            tool: "active-probing",
          });
        }
      }
    } catch { /* continue */ }
  }

  // ── XSS reflection ──
  onConsole("info", "Testing for reflected XSS…");
  const xssTag = `HGXSSProbe${Math.random().toString(36).slice(2, 7)}`;
  for (const ep of targets) {
    try {
      const payload = encodeURIComponent(`<${xssTag}>`);
      const testUrl = ep.includes("?") ? `${ep}&q=${payload}&s=${payload}` : `${ep}?q=${payload}`;
      const cap = await httpFetch(testUrl, { timeoutMs: 5_000, bearerToken: bearer, rateLimiter: rl });
      if (cap?.bodyPreview.includes(`<${xssTag}>`)) {
        findings.push({
          id: makeId("finding-active"), timestamp: nowIso(),
          title: "Reflected XSS — unencoded input in response",
          severity: "high",
          endpoint: ep,
          evidence: `Payload <${xssTag}> reflected verbatim in the response body.\nTest URL: ${testUrl}`,
          tool: "active-probing",
        });
      }
    } catch { /* continue */ }
  }

  // ── Path traversal ──
  onConsole("info", "Testing for path traversal…");
  const traversalPayloads = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
  ];
  for (const ep of targets.slice(0, 5)) {
    for (const payload of traversalPayloads) {
      try {
        const testUrl = ep.includes("?")
          ? `${ep}&file=${payload}&path=${payload}`
          : `${ep}?file=${payload}`;
        const cap = await httpFetch(testUrl, { timeoutMs: 5_000, bearerToken: bearer, rateLimiter: rl });
        if (cap?.bodyPreview.match(/root:.*:0:0:|daemon:.*:1:1:/)) {
          findings.push({
            id: makeId("finding-active"), timestamp: nowIso(),
            title: "Path Traversal — local file read",
            severity: "critical",
            endpoint: ep,
            evidence: `Traversal payload read /etc/passwd.\nPayload: ${payload}`,
            tool: "active-probing",
          });
          break; // one finding per endpoint is enough
        }
      } catch { /* continue */ }
    }
  }

  onConsole("out", `Active probing: ${findings.length} finding(s)`);
  return { findings, captures: [], visitedEndpoints: [] };
}

// ─── Phase 7: DEEP SCAN ───────────────────────────────────────────────────────

export async function runDeepScanPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const findings: Finding[] = [];
  const outDir  = path.join(os.tmpdir(), `hexguard-deep-${Date.now()}`);
  await fs.mkdir(outDir, { recursive: true });

  const paramEndpoints = session.context.visitedEndpoints.filter(u => u.includes("?"));
  // Also test non-parameterized endpoints with --forms (sqlmap will discover form params)
  const formEndpoints  = session.context.visitedEndpoints.filter(u => !u.includes("?"));

  // ── sqlmap ──
  const sqlmapTargets = [...paramEndpoints.slice(0, 2), ...formEndpoints.slice(0, 2)];
  // Derive level/risk from hunt profile
  const sqlLevel = session.config.profile === "active" ? 3 : 2;
  const sqlRisk  = session.config.profile === "active" ? 2 : 1;
  if (sqlmapTargets.length > 0) {
    onConsole("info", `sqlmap: testing ${sqlmapTargets.length} endpoint(s) at level=${sqlLevel}/risk=${sqlRisk}…`);
    for (const ep of sqlmapTargets) {
      try {
        const res = await sqlmapAdapter.invoke({
          target: ep,
          outputDir: outDir,
          level: sqlLevel,
          risk: sqlRisk,
          onConsole,
        });
        if (res.isVulnerable && res.findings) {
          for (const f of res.findings) {
            findings.push({
              id: makeId("finding-sqlmap"), timestamp: nowIso(),
              title:    f.title || "SQL Injection",
              severity: f.confidence === "high" ? "high" : "medium",
              endpoint: ep,
              evidence: `Parameter: ${f.parameter}, Type: ${f.injectionType}, DBMS: ${f.dbms}`,
              tool:     "sqlmap",
            });
          }
        }
      } catch { /* continue */ }
    }
  } else {
    onConsole("info", "sqlmap: no endpoints to test — skipping");
  }

  // ── ZAP (optional — only if daemon is running) ──
  onConsole("info", "ZAP active scan (skipped if daemon not running)…");
  const [nucleiSettled, niktoSettled, h2cSettled, wapitiSettled, zapSettled] = await Promise.allSettled([
    // ── Nuclei ──
    (async () => {
      onConsole("info", "nuclei: starting template-based vulnerability scan…");
      return runNucleiPhase(session, onConsole);
    })(),
    // ── Nikto ──
    (async () => {
      onConsole("info", "nikto: starting web server vulnerability scan…");
      return runNiktoPhase(session, onConsole);
    })(),
    // ── h2csmuggler ──
    (async () => {
      onConsole("info", "h2csmuggler: checking for HTTP/2 cleartext upgrade vulnerability…");
      return runH2cSmugglerPhase(session, onConsole);
    })(),
    // ── Wapiti ──
    (async () => {
      onConsole("info", "wapiti: scanning for misconfigurations, exposed files, SSL/TLS issues…");
      return wapitiAdapter.invoke({ target: session.config.target, outputDir: outDir, onConsole });
    })(),
    // ── ZAP ──
    zapAdapter.invoke({ target: session.config.target, outputDir: outDir, onConsole }),
  ]);

  // Nuclei findings
  if (nucleiSettled.status === "fulfilled" && nucleiSettled.value.findings.length > 0) {
    findings.push(...nucleiSettled.value.findings);
  }

  // Nikto findings
  if (niktoSettled.status === "fulfilled" && niktoSettled.value.findings.length > 0) {
    findings.push(...niktoSettled.value.findings);
  }

  // h2csmuggler findings
  if (h2cSettled.status === "fulfilled" && h2cSettled.value.findings.length > 0) {
    findings.push(...h2cSettled.value.findings);
  }

  // Wapiti findings
  if (wapitiSettled.status === "fulfilled" && wapitiSettled.value.findings.length > 0) {
    for (const f of wapitiSettled.value.findings) {
      findings.push({
        id: makeId("finding-wapiti"), timestamp: nowIso(),
        title:    `[${f.module}] ${f.info.slice(0, 100)}`,
        severity: f.severity,
        endpoint: f.url || session.config.target,
        evidence: f.info + (f.parameter ? `\nParameter: ${f.parameter}` : "") + (f.wstg ? `\nWSTG: ${f.wstg}` : ""),
        tool:     "wapiti",
      });
    }
  }

  // ZAP findings
  if (zapSettled.status === "fulfilled" && zapSettled.value.success && zapSettled.value.alerts) {
    for (const a of zapSettled.value.alerts.filter((al: { risk: string }) => al.risk === "High" || al.risk === "Medium")) {
      findings.push({
        id: makeId("finding-zap"), timestamp: nowIso(),
        title:    a.name,
        severity: a.risk === "High" ? "high" : "medium",
        endpoint: a.url,
        evidence: a.description.slice(0, 300),
        tool:     "zap",
      });
    }
    onConsole("out", `ZAP: ${zapSettled.value.alerts.length} alert(s)`);
  }

  await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
  onConsole("out", `Deep scan: ${findings.length} finding(s)`);
  return { findings, captures: [], visitedEndpoints: [] };
}

// ─── Phase 8: VULNERABILITY ASSESSMENT ───────────────────────────────────────

export async function runVulnAssessmentPhase(
  session: HuntSession,
  allCaptures: HttpCapture[],
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const findings: Finding[] = [];
  const bearer  = session.config.bearerToken;
  const target  = session.config.target;
  const rl = makeRl(session);
  const outDir  = path.join(os.tmpdir(), `hexguard-va-${Date.now()}`);
  await fs.mkdir(outDir, { recursive: true });

  // ── surf: SSRF candidate detection across all discovered endpoints ──────────────────
  const surfResult = await runSurfPhase(session, onConsole);
  if (surfResult.findings.length > 0) {
    findings.push(...surfResult.findings);
  }

  // ── Extract forms from all captured HTML ──
  onConsole("info", "Extracting forms and input fields from captured HTML…");
  const forms = extractFormsFromCaptures(allCaptures);
  onConsole("out", `Found ${forms.length} unique form(s) to test`);

  // ── XSS fuzzing on form inputs ──
  onConsole("info", "XSS fuzzing on form fields…");
  for (const form of forms.slice(0, 5)) {
    for (const payload of XSS_PAYLOADS.slice(0, 8)) {
      try {
        const body = new URLSearchParams();
        for (const field of form.fields) {
          body.set(field.name, field.type === "submit" ? field.value || "Submit" : payload);
        }
        const isPost = form.method === "POST";
        const url = isPost ? form.action : `${form.action}?${body.toString()}`;
        const cap = await httpFetch(url, {
          timeoutMs: 6_000,
          bearerToken: bearer,
          rateLimiter: rl,
          method:  isPost ? "POST" : "GET",
          body:    isPost ? body.toString() : undefined,
          headers: isPost ? { "content-type": "application/x-www-form-urlencoded" } : undefined,
        });
        if (cap?.bodyPreview.includes(payload) && !cap.bodyPreview.includes("&lt;")) {
          const fieldName = form.fields.find(f => f.type !== "submit")?.name ?? "input";
          findings.push({
            id: makeId("finding-va"), timestamp: nowIso(),
            title:    `Reflected XSS in form field '${fieldName}'`,
            severity: "high",
            endpoint: form.action,
            evidence: `Payload reflected unencoded in response body.\nForm: ${form.method} ${form.action}\nPayload: ${payload.slice(0, 80)}`,
            tool:     "vuln-assessment",
          });
          break; // one finding per form
        }
      } catch { /* continue */ }
    }
  }

  // ── XSS on URL params already in discovered endpoints ──
  // When no parameterized endpoints are found, probe clean endpoints with common param names
  // to discover parameter-accepting surfaces.
  const existingParamUrls = session.context.visitedEndpoints.filter(u => u.includes("?")).slice(0, 10);
  const SYNTH_PARAMS = ["id", "q", "search", "page", "cat", "item", "user", "ref", "name", "type"];
  const syntheticParamUrls: string[] = [];
  if (existingParamUrls.length === 0) {
    onConsole("info", "No parameterized endpoints found — probing clean endpoints with common params…");
    const cleanEndpoints = [target, ...session.context.visitedEndpoints.filter(u => !u.includes("?"))].slice(0, 8);
    for (const ep of cleanEndpoints) {
      try {
        const u = new URL(ep);
        // Append up to 3 common params to each clean endpoint
        for (const paramName of SYNTH_PARAMS.slice(0, 3)) {
          const testU = new URL(ep);
          testU.searchParams.set(paramName, "1");
          // Quick probe to see if endpoint responds — if it does, use it for injection testing
          const probe = await httpFetch(testU.toString(), { timeoutMs: 5_000, bearerToken: bearer, rateLimiter: rl });
          if (probe && probe.statusCode < 400) {
            syntheticParamUrls.push(testU.toString());
            break; // one synthetic param per endpoint is enough
          }
          void u; // suppress unused warning
        }
      } catch { /* continue */ }
    }
    onConsole("out", `Parameter discovery: ${syntheticParamUrls.length} injectable surface(s) found`);
  }
  const paramUrls = [...existingParamUrls, ...syntheticParamUrls];
  for (const ep of paramUrls) {
    try {
      const u = new URL(ep);
      const firstParam = [...u.searchParams.keys()][0];
      if (!firstParam) continue;
      const xssPayload = XSS_PAYLOADS[0]!;
      u.searchParams.set(firstParam, xssPayload);
      const cap = await httpFetch(u.toString(), { timeoutMs: 5_000, bearerToken: bearer, rateLimiter: rl });
      if (cap?.bodyPreview.includes(xssPayload) && !cap.bodyPreview.includes("&lt;")) {
        findings.push({
          id: makeId("finding-va"), timestamp: nowIso(),
          title:    `Reflected XSS in URL parameter '${firstParam}'`,
          severity: "high",
          endpoint: ep,
          evidence: `Payload reflected unencoded.\nTest URL: ${u.toString().slice(0, 200)}`,
          tool:     "vuln-assessment",
        });
      }
    } catch { /* continue */ }
  }

  // ── SQLi error-based test on form inputs ──
  onConsole("info", "SQLi error-detection on form fields…");
  for (const form of forms.slice(0, 5)) {
    for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
      try {
        const body = new URLSearchParams();
        for (const field of form.fields) {
          body.set(field.name, field.type === "submit" ? field.value || "Submit" : payload);
        }
        const isPost = form.method === "POST";
        const url = isPost ? form.action : `${form.action}?${body.toString()}`;
        const cap = await httpFetch(url, {
          timeoutMs: 6_000,
          bearerToken: bearer,
          rateLimiter: rl,
          method:  isPost ? "POST" : "GET",
          body:    isPost ? body.toString() : undefined,
          headers: isPost ? { "content-type": "application/x-www-form-urlencoded" } : undefined,
        });
        if (cap && SQLI_ERROR_PATTERN.test(cap.bodyPreview)) {
          const fieldName = form.fields.find(f => f.type !== "submit")?.name ?? "input";
          findings.push({
            id: makeId("finding-va"), timestamp: nowIso(),
            title:    `SQL Injection error in form field '${fieldName}'`,
            severity: "high",
            endpoint: form.action,
            evidence: `SQL error pattern detected in response.\nPayload: ${payload}\nMatch: ${cap.bodyPreview.slice(0, 200)}`,
            tool:     "vuln-assessment",
          });
          break;
        }
      } catch { /* continue */ }
    }
  }

  // ── SSRF on URL-type params ──
  onConsole("info", "SSRF surface testing on URL parameters…");
  const allEndpoints = [target, ...session.context.visitedEndpoints].slice(0, 8);
  for (const ep of allEndpoints) {
    try {
      const u = new URL(ep);
      for (const paramName of URL_PARAM_NAMES) {
        if (!u.searchParams.has(paramName)) continue;
        const ssrfPayload = SSRF_PAYLOADS[0]!; // 127.0.0.1
        u.searchParams.set(paramName, ssrfPayload);
        const cap = await httpFetch(u.toString(), { timeoutMs: 5_000, bearerToken: bearer, followRedirects: false, rateLimiter: rl });
        // SSRF is indicated by connection to loopback or unusual redirect
        if (cap && cap.statusCode < 400 && (cap.bodyPreview.includes("127.0.0.1") || cap.bodyPreview.includes("localhost"))) {
          findings.push({
            id: makeId("finding-va"), timestamp: nowIso(),
            title:    `Potential SSRF in parameter '${paramName}'`,
            severity: "high",
            endpoint: ep,
            evidence: `Parameter accepted internal URL; response may indicate SSRF.\nTest: ${u.toString().slice(0, 200)}`,
            tool:     "vuln-assessment",
          });
        }
      }
    } catch { /* continue */ }
  }

  // ── Path traversal on file params in forms ──
  onConsole("info", "Path traversal testing on file parameters…");
  for (const form of forms.slice(0, 5)) {
    const fileFields = form.fields.filter(f => FILE_PARAM_NAMES.includes(f.name.toLowerCase()));
    if (fileFields.length === 0) continue;
    for (const payload of TRAVERSAL_PAYLOADS.slice(0, 5)) {
      try {
        const body = new URLSearchParams();
        for (const field of form.fields) {
          body.set(field.name, fileFields.some(ff => ff.name === field.name) ? payload : field.value || "x");
        }
        const isPost = form.method === "POST";
        const url = isPost ? form.action : `${form.action}?${body.toString()}`;
        const cap = await httpFetch(url, {
          timeoutMs: 6_000, bearerToken: bearer,
          rateLimiter: rl,
          method: isPost ? "POST" : "GET",
          body: isPost ? body.toString() : undefined,
          headers: isPost ? { "content-type": "application/x-www-form-urlencoded" } : undefined,
        });
        if (cap && PASSWD_PATTERN.test(cap.bodyPreview)) {
          findings.push({
            id: makeId("finding-va"), timestamp: nowIso(),
            title:    "Path Traversal — local file read via form parameter",
            severity: "critical",
            endpoint: form.action,
            evidence: `Traversal payload read /etc/passwd.\nPayload: ${payload}`,
            tool:     "vuln-assessment",
          });
          break;
        }
      } catch { /* continue */ }
    }
  }

  // ── Auth bypass on login forms ──
  onConsole("info", "Auth bypass testing on login forms…");
  const loginForms = forms.filter(f =>
    f.action.toLowerCase().includes("login") ||
    f.action.toLowerCase().includes("signin") ||
    f.fields.some(ff => ff.type === "password"),
  );
  for (const form of loginForms.slice(0, 2)) {
    const userField = form.fields.find(f => ["username", "user", "email", "login", "name"].includes(f.name.toLowerCase()));
    const passField = form.fields.find(f => f.type === "password");
    if (!userField || !passField) continue;

    // Try SQLi auth bypass in username field
    for (const sqliPayload of AUTH_BYPASS_SQLI.slice(0, 3)) {
      try {
        const body = new URLSearchParams();
        for (const field of form.fields) {
          if (field.name === userField.name)  body.set(field.name, sqliPayload);
          else if (field.name === passField.name) body.set(field.name, "anything");
          else body.set(field.name, field.value || "");
        }
        const cap = await httpFetch(form.action, {
          timeoutMs: 6_000, bearerToken: bearer,
          method: "POST", body: body.toString(),
          headers: { "content-type": "application/x-www-form-urlencoded" },
          followRedirects: false,
          rateLimiter: rl,
        });
        // Successful bypass indicated by redirect (302) or welcome content
        if (cap && (cap.statusCode === 302 || /welcome|dashboard|logout|signed in/i.test(cap.bodyPreview))) {
          findings.push({
            id: makeId("finding-va"), timestamp: nowIso(),
            title:    "Authentication Bypass via SQL Injection",
            severity: "critical",
            endpoint: form.action,
            evidence: `Login bypass using SQLi in '${userField.name}' field.\nPayload: ${sqliPayload}`,
            tool:     "vuln-assessment",
          });
          break;
        }
      } catch { /* continue */ }
    }
  }

  // ── Time-based blind SQLi on URL parameters ──
  onConsole("info", "Time-based blind SQLi testing on URL parameters…");
  // Use the already-built paramUrls (includes synthetic ones) rather than re-filtering visitedEndpoints
  const sqliUrlEndpoints = paramUrls.slice(0, 10);
  const BLIND_SQLI_PAYLOADS = [
    "1' AND SLEEP(3)-- -",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))A)-- -",
    "1; WAITFOR DELAY '0:0:3'-- -",          // MSSQL
    "1' AND 3=BENCHMARK(3000000,SHA1(1))-- -", // MySQL CPU-based
  ];
  for (const ep of sqliUrlEndpoints) {
    try {
      const u = new URL(ep);
      if (u.searchParams.size === 0) continue;

      // Establish baseline response time
      const t0 = Date.now();
      await httpFetch(ep, { timeoutMs: 8_000, bearerToken: bearer, rateLimiter: rl });
      const baseline = Date.now() - t0;

      for (const [paramName, origValue] of u.searchParams.entries()) {
        for (const payload of BLIND_SQLI_PAYLOADS.slice(0, 2)) {
          try {
            const testUrl = new URL(ep);
            testUrl.searchParams.set(paramName, payload);
            const t1 = Date.now();
            await httpFetch(testUrl.toString(), { timeoutMs: 12_000, bearerToken: bearer, rateLimiter: rl });
            const elapsed = Date.now() - t1;

            // Flag if response took ≥2.5× baseline and ≥2500ms
            if (elapsed >= 2500 && elapsed >= baseline * 2.5) {
              findings.push({
                id: makeId("finding-blind-sqli"), timestamp: nowIso(),
                title:    `Time-based Blind SQLi in parameter '${paramName}'`,
                severity: "high",
                endpoint: ep,
                evidence:
                  `Payload caused response delay of ${elapsed}ms (baseline: ${baseline}ms).\n` +
                  `Parameter: ${paramName}=${origValue}\nPayload: ${payload}\n` +
                  `URL: ${testUrl.toString().slice(0, 300)}`,
                tool:     "vuln-assessment",
              });
              onConsole("warn", `Blind SQLi confirmed in '${paramName}' (${elapsed}ms delay)`);
              break; // One confirmed finding per parameter
            }
          } catch { /* timeout or connection error */ }
        }
      }
    } catch { /* skip non-URL endpoints */ }
  }

  // ── WAF detection heuristic ──
  // If more than 40% of probes returned 403, likely behind a WAF
  let probeCount = 0;
  let blockedCount = 0;
  // Count from last 30 captures in context
  for (const cap of allCaptures.slice(-30)) {
    if (cap.statusCode === 403 || cap.statusCode === 429) blockedCount++;
    probeCount++;
  }
  if (probeCount >= 5 && blockedCount / probeCount > 0.4) {
    findings.push({
      id: makeId("finding-va"), timestamp: nowIso(),
      title:    "WAF / Rate-limiter detected — probes may be blocked",
      severity: "low",
      endpoint: target,
      evidence: `${blockedCount} of ${probeCount} recent requests returned 403/429. Active testing results may be incomplete.`,
      tool:     "vuln-assessment",
    });
  }

  await fs.rm(outDir, { recursive: true, force: true }).catch(() => {});
  onConsole("out", `Vulnerability assessment: ${findings.length} finding(s)`);
  return { findings, captures: [], visitedEndpoints: [] };
}

// ─── Phase 9: EXPLOITATION ────────────────────────────────────────────────────

export async function runExploitationPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const findings: Finding[] = [];
  const target  = session.config.target;
  const bearer  = session.config.bearerToken;
  const rl = makeRl(session);

  const highFindings = session.context.findings.filter(
    f => f.severity === "high" || f.severity === "critical",
  ).slice(0, 5); // limit to 5 to keep runtime reasonable

  onConsole("info", `Generating PoC for ${highFindings.length} high/critical finding(s)…`);

  for (const finding of highFindings) {
    try {
      const exploit = await hexstrikeGeneratePoc(finding, target);
      if (exploit && (exploit.pocCurl || exploit.pocDescription)) {
        // Annotate the original finding's evidence with PoC
        finding.evidence = [
          finding.evidence,
          `\n── PoC ──`,
          exploit.pocCurl ? `$ ${exploit.pocCurl}` : "",
          exploit.pocDescription,
          exploit.remediationSteps.length > 0
            ? `Remediation: ${exploit.remediationSteps.slice(0, 2).join(" | ")}`
            : "",
          exploit.cvssScore > 0 ? `CVSS: ${exploit.cvssScore} ${exploit.cvssVector}` : "",
        ].filter(Boolean).join("\n");

        onConsole("out", `PoC generated for: ${finding.title} (CVSS ${exploit.cvssScore})`);
      }
    } catch { /* non-fatal */ }
  }

  // ── IDOR probe on numeric-ID endpoints ──
  onConsole("info", "Testing for IDOR on numeric-ID endpoints…");
  const numericIdRe = /\/(\d+)(?:\/|$|\?)/;
  const idEndpoints = session.context.visitedEndpoints.filter(u => numericIdRe.test(u)).slice(0, 5);

  for (const ep of idEndpoints) {
    const match = numericIdRe.exec(ep);
    if (!match) continue;
    const originalId = parseInt(match[1]!, 10);
    const probeIds = idorProbeIds(originalId).slice(0, 3);
    const originalCap = await httpFetch(ep, { timeoutMs: 5_000, bearerToken: bearer, rateLimiter: rl }).catch(() => null);
    if (!originalCap) continue;

    for (const probeId of probeIds) {
      if (probeId === originalId) continue;
      const probeUrl = ep.replace(`/${originalId}`, `/${probeId}`);
      const probeCap = await httpFetch(probeUrl, { timeoutMs: 5_000, bearerToken: bearer, rateLimiter: rl }).catch(() => null);
      if (
        probeCap && probeCap.statusCode === 200 &&
        probeCap.bodyPreview.length > 50 &&
        probeCap.bodyPreview !== originalCap.bodyPreview
      ) {
        findings.push({
          id: makeId("finding-exploit"), timestamp: nowIso(),
          title:    `Potential IDOR — resource accessible without ownership check`,
          severity: "high",
          endpoint: ep,
          evidence: `Fetching ${probeUrl} returned 200 with different content.\nOriginal ID: ${originalId}, Probe ID: ${probeId}`,
          tool:     "exploitation",
        });
        break; // one finding per endpoint
      }
    }
  }

  // ── Session fixation check ──
  onConsole("info", "Checking for session fixation…");
  try {
    const cap1 = await httpFetch(target, { timeoutMs: 6_000, rateLimiter: rl });
    const cap2 = await httpFetch(target, { timeoutMs: 6_000, rateLimiter: rl });
    if (cap1 && cap2) {
      const sid1 = Object.entries(cap1.headers)
        .filter(([k]) => k === "set-cookie")
        .flatMap(([, v]) => v.split(";")[0] ?? "")
        .join("");
      const sid2 = Object.entries(cap2.headers)
        .filter(([k]) => k === "set-cookie")
        .flatMap(([, v]) => v.split(";")[0] ?? "")
        .join("");
      if (sid1 && sid1 === sid2) {
        findings.push({
          id: makeId("finding-exploit"), timestamp: nowIso(),
          title:    "Session Fixation — server issues identical session token on repeated requests",
          severity: "medium",
          endpoint: target,
          evidence: `Two unauthenticated requests received the same Set-Cookie value:\n${sid1}`,
          tool:     "exploitation",
        });
      }
    }
  } catch { /* non-fatal */ }

  onConsole("out", `Exploitation: ${findings.length} new finding(s), PoC data added to ${highFindings.length} existing finding(s)`);
  return { findings, captures: [], visitedEndpoints: [] };
}

// ─── Phase 10: REPORT SYNTHESIS ───────────────────────────────────────────────

export async function runReportSynthesisPhase(
  session: HuntSession,
  onConsole: ConsoleFn,
): Promise<PhaseResult> {
  const findings: Finding[] = [];
  const allFindings = session.context.findings;
  const target = session.config.target;

  onConsole("info", `Sending ${allFindings.length} finding(s) to HexStrike for report synthesis…`);

  try {
    const res = await hexstrikeSynthesizeReport(allFindings, target, session.context.techFingerprint);
    if (!res) {
      onConsole("warn", "HexStrike unavailable — report synthesis skipped");
      return { findings: [], captures: [], visitedEndpoints: [] };
    }

    const r = res as Record<string, unknown>;
    const summary      = String(r["executive_summary"] ?? "");
    const overallRisk  = String(r["overall_risk"] ?? "medium");
    const topPriorities = Array.isArray(r["top_priorities"])
      ? (r["top_priorities"] as unknown[]).map(String).slice(0, 5)
      : [];

    // Back-fill CVSS scores onto existing findings
    const cvssEntries = Array.isArray(r["findings_with_cvss"])
      ? (r["findings_with_cvss"] as Array<Record<string, unknown>>)
      : [];
    for (const entry of cvssEntries) {
      const id = String(entry["id"] ?? "");
      const score = Number(entry["cvss_score"] ?? 0);
      const vector = String(entry["cvss_vector"] ?? "");
      if (id && score > 0) {
        const existing = allFindings.find(f => f.id === id);
        if (existing && !existing.evidence.includes("CVSS:")) {
          existing.evidence += `\nCVSS: ${score} ${vector}`;
        }
      }
    }

    // Emit a synthesis finding as a record of the AI report
    if (summary) {
      findings.push({
        id:        makeId("finding-synthesis"),
        timestamp: nowIso(),
        title:     `Report Synthesis — Overall Risk: ${overallRisk.toUpperCase()}`,
        severity:  (["low","medium","high","critical"].includes(overallRisk) ? overallRisk : "medium") as Finding["severity"],
        endpoint:  target,
        evidence:  [
          summary,
          topPriorities.length > 0 ? `\nTop priorities:\n${topPriorities.map((p, i) => `${i+1}. ${p}`).join("\n")}` : "",
          Array.isArray(r["attack_chains"])
            ? `\nAttack chains: ${(r["attack_chains"] as Array<Record<string,unknown>>).map(c => c["name"]).join(", ")}`
            : "",
        ].filter(Boolean).join(""),
        tool: "report-synthesis",
      });
      onConsole("out", `Report synthesis complete — overall risk: ${overallRisk.toUpperCase()}`);
    }
  } catch (err) {
    onConsole("warn", `Report synthesis error (non-fatal): ${String(err)}`);
  }

  return { findings, captures: [], visitedEndpoints: [] };
}
