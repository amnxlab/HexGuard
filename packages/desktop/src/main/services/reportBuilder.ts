/**
 * reportBuilder.ts — Converts a completed HuntSession into a rich JSON + HTML report.
 *
 * Writes files to <repo-root>/reports/<sessionId>/
 * Returns a ReportBundle with the absolute paths.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { app } from "electron";
import type {
  Finding,
  HuntAction,
  HuntSession,
  HttpCapture,
  ReportBundle,
  ReportSummary,
  RunEvent,
  SecurityAuditResult,
  TechFingerprint,
} from "@hexguard/shared";

export function reportsDir(): string {
  return path.resolve(app.getAppPath(), "..", "..", "reports");
}

function sessionDir(sessionId: string): string {
  return path.join(reportsDir(), sessionId.replace(/[^a-zA-Z0-9_-]/g, "_"));
}

// ─── Escaping ─────────────────────────────────────────────────────────────────

function esc(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────

interface RiskScore { score: number; label: string; color: string; }

function computeRisk(findings: Finding[]): RiskScore {
  const total = findings.length;
  if (total === 0) return { score: 0, label: "NONE", color: "#68d391" };
  const crit = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;
  const med  = findings.filter(f => f.severity === "medium").length;
  const low  = findings.filter(f => f.severity === "low").length;
  const score = Math.min(100, Math.round(((crit * 10 + high * 7 + med * 4 + low * 1) / (total * 10)) * 100));
  const label = score >= 86 ? "CRITICAL" : score >= 61 ? "HIGH" : score >= 31 ? "MEDIUM" : "LOW";
  const color = score >= 86 ? "#ff4d4d"  : score >= 61 ? "#fc8181" : score >= 31 ? "#f6e05e" : "#68d391";
  return { score, label, color };
}

// ─── SVG arc gauge ────────────────────────────────────────────────────────────

function svgGauge(score: number, color: string): string {
  // Semi-circle gauge: cx=70, cy=70, r=54. Arc length for 180° = π*r ≈ 169.6
  const r = 54;
  const arc = Math.PI * r;
  const filled = arc * (score / 100);
  const empty  = arc - filled;
  // Arc path: starts at left (0°) goes clockwise to right (180°)
  // Using a stroke-dasharray on a semi-circular path
  const bg    = "#1a2e4a";
  const label = score >= 86 ? "CRITICAL" : score >= 61 ? "HIGH" : score >= 31 ? "MEDIUM" : score > 0 ? "LOW" : "NONE";
  return `<svg viewBox="0 0 140 80" width="200" height="120" style="display:block;margin:auto">
  <path d="M 16 70 A ${r} ${r} 0 0 1 124 70" fill="none" stroke="${bg}" stroke-width="10" stroke-linecap="round"/>
  <path d="M 16 70 A ${r} ${r} 0 0 1 124 70" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round"
    stroke-dasharray="${filled.toFixed(1)} ${empty.toFixed(1)}" style="transition:stroke-dasharray 0.6s ease"/>
  <text x="70" y="58" text-anchor="middle" font-family="SF Mono,Fira Code,monospace" font-size="22" font-weight="700" fill="${color}">${score}</text>
  <text x="70" y="72" text-anchor="middle" font-family="SF Mono,Fira Code,monospace" font-size="9" fill="#718096">${label} RISK</text>
</svg>`;
}

// ─── Stacked bar ──────────────────────────────────────────────────────────────

interface BarSegment { label: string; count: number; color: string; }

function stackedBar(segments: BarSegment[], total: number): string {
  if (total === 0) return `<div class="bar-empty">No data</div>`;
  const items = segments.map(seg => {
    const pct = (seg.count / total) * 100;
    if (pct === 0) return "";
    const showLabel = pct >= 8;
    return `<div class="bar-seg" style="flex:0 0 ${pct.toFixed(2)}%;background:${seg.color};color:#070d1a" title="${esc(seg.label)}: ${seg.count} (${pct.toFixed(1)}%)">
      ${showLabel ? `<span class="bar-seg-lbl">${esc(seg.label)} ${seg.count}</span>` : ""}
    </div>`;
  }).join("");
  const legend = segments.filter(s => s.count > 0).map(s =>
    `<span class="bar-leg"><span class="bar-leg-dot" style="background:${s.color}"></span>${esc(s.label)}&nbsp;${s.count}</span>`
  ).join("");
  return `<div class="bar-track">${items}</div><div class="bar-legend">${legend}</div>`;
}

// ─── Status badge ─────────────────────────────────────────────────────────────

function statusBadge(code: number): string {
  const c = code >= 500 ? "#fc8181" : code >= 400 ? "#f6ad55" : code >= 300 ? "#63b3ed" : "#68d391";
  return `<span class="status-badge" style="background:${c}22;color:${c};border:1px solid ${c}44">${code}</span>`;
}

// ─── Severity badge ───────────────────────────────────────────────────────────

function sevBadge(sev: string): string {
  const c = sev === "critical" ? "#ff4d4d" : sev === "high" ? "#fc8181" : sev === "medium" ? "#f6e05e" : "#68d391";
  return `<span class="sev-badge" style="background:${c}22;color:${c};border:1px solid ${c}44">${sev.toUpperCase()}</span>`;
}

// ─── Section heading ──────────────────────────────────────────────────────────

function h2(title: string, count?: number): string {
  const badge = count !== undefined ? ` <span class="count-badge">${count}</span>` : "";
  return `<div class="section-head"><h2>${esc(title)}${badge}</h2></div>`;
}

// ─── Executive dashboard ──────────────────────────────────────────────────────

function buildExecDashboard(session: HuntSession): string {
  const ctx    = session.context;
  const finds  = ctx.findings;
  const crit   = finds.filter(f => f.severity === "critical").length;
  const high   = finds.filter(f => f.severity === "high").length;
  const med    = finds.filter(f => f.severity === "medium").length;
  const low    = finds.filter(f => f.severity === "low").length;

  // Use actionGraph durations (populated by autonomous engine) as the
  // authoritative source; fall back to session history if present.
  const actionGraph = ctx.actionGraph ?? [];
  const totalMs = actionGraph.length > 0
    ? actionGraph.reduce((s, a) => s + (a.durationMs ?? 0), 0)
    : session.history.reduce((s, a) => s + (a.durationMs ?? 0), 0);

  // HTTP requests = captured HTTP responses (each capture = one request made)
  const totalReqs = (ctx.capturedResponses ?? []).length;

  // Phases run = number of distinct tool actions that were executed
  const phases = actionGraph.length > 0
    ? actionGraph.length
    : session.history.length;

  function card(label: string, value: string | number, accent?: string): string {
    const col = accent ?? "#4fd1c5";
    return `<div class="dash-card"><div class="dash-label">${esc(String(label))}</div><div class="dash-value" style="color:${col}">${esc(String(value))}</div></div>`;
  }

  const dur = totalMs >= 60000
    ? `${Math.floor(totalMs / 60000)}m ${Math.round((totalMs % 60000) / 1000)}s`
    : `${(totalMs / 1000).toFixed(1)}s`;

  return `<div class="dash-grid">
  ${card("Total Findings", finds.length)}
  ${card("Critical", crit, crit > 0 ? "#ff4d4d" : "#68d391")}
  ${card("High", high, high > 0 ? "#fc8181" : "#68d391")}
  ${card("Medium", med, med > 0 ? "#f6e05e" : "#4fd1c5")}
  ${card("Low", low)}
  ${card("Endpoints", ctx.visitedEndpoints.length)}
  ${card("HTTP Requests", totalReqs)}
  ${card("Hunt Duration", dur)}
  ${card("Phases Run", phases)}
</div>`;
}

// ─── Vulnerability bar ────────────────────────────────────────────────────────

function buildVulnBar(findings: Finding[]): string {
  const total = findings.length;
  const segs: BarSegment[] = [
    { label: "CRITICAL", count: findings.filter(f => f.severity === "critical").length, color: "#ff4d4d" },
    { label: "HIGH",     count: findings.filter(f => f.severity === "high").length,     color: "#fc8181" },
    { label: "MEDIUM",   count: findings.filter(f => f.severity === "medium").length,   color: "#f6e05e" },
    { label: "LOW",      count: findings.filter(f => f.severity === "low").length,      color: "#68d391" },
  ];
  return stackedBar(segs, total);
}

// ─── Misconfiguration bar ─────────────────────────────────────────────────────

function buildMisconfigBar(audit: SecurityAuditResult | undefined): string {
  if (!audit) return `<div class="bar-empty">No security audit data — passive audit phase may not have run.</div>`;
  const headers  = (audit.headers  ?? []).filter((h: { severity: string }) => h.severity !== "info" && h.severity !== "pass").length;
  const corsIssues = audit.cors
    ? [audit.cors.allowsArbitraryOrigins, audit.cors.reflectsOrigin && audit.cors.allowCredentials]
        .filter(Boolean).length
    : 0;
  const cookies  = (audit.cookies  ?? []).filter((c: { missingSecure: boolean; missingHttpOnly: boolean }) => c.missingSecure || c.missingHttpOnly).length;
  const infoDisc = (audit.infoDisclosure ?? []).length;
  const total    = headers + corsIssues + cookies + infoDisc;
  const segs: BarSegment[] = [
    { label: "Headers",       count: headers,    color: "#fc8181" },
    { label: "CORS",          count: corsIssues, color: "#f6ad55" },
    { label: "Cookies",       count: cookies,    color: "#f6e05e" },
    { label: "Info-Disc",     count: infoDisc,   color: "#4fd1c5" },
  ];
  return stackedBar(segs, total);
}

// ─── Tech stack card ──────────────────────────────────────────────────────────

function buildTechStack(fp: TechFingerprint | undefined): string {
  if (!fp) return `<p class="muted">No fingerprint data — fingerprint phase may not have run.</p>`;
  function pill(label: string, value: string | undefined): string {
    if (!value) return "";
    return `<div class="tech-pill"><span class="tech-pill-label">${esc(label)}</span><span class="tech-pill-value">${esc(value)}</span></div>`;
  }
  const conf = fp.confidence ?? 0;
  const confColor = conf >= 70 ? "#68d391" : conf >= 40 ? "#f6e05e" : "#fc8181";
  const evidenceItems = (fp.evidence ?? []).map(e => `<li>${esc(e)}</li>`).join("");
  return `<div class="tech-grid">
  ${pill("Server",    fp.server)}
  ${pill("Language",  fp.language)}
  ${pill("Framework", fp.framework)}
  ${pill("CMS",       fp.cms)}
  ${pill("Database",  fp.database)}
</div>
<div class="conf-row">
  <span class="muted" style="font-size:0.75rem">Detection confidence</span>
  <div class="conf-track"><div class="conf-fill" style="width:${conf}%;background:${confColor}"></div></div>
  <span style="font-size:0.75rem;color:${confColor}">${conf}%</span>
</div>
${evidenceItems ? `<details class="audit-detail"><summary>Detection signals (${(fp.evidence ?? []).length})</summary><ul class="evidence-list">${evidenceItems}</ul></details>` : ""}`;
}

// ─── Security audit section ───────────────────────────────────────────────────

function buildSecurityAudit(audit: SecurityAuditResult | undefined): string {
  if (!audit) return `<p class="muted">No security audit data available.</p>`;

  // Headers
  const hRows = (audit.headers ?? []).map((h: { header: string; present: boolean; value?: string; severity: string; recommendation?: string }) => {
    const sc = h.severity === "high" || h.severity === "critical" ? "#fc8181"
             : h.severity === "medium" ? "#f6e05e" : "#68d391";
    return `<tr>
      <td class="mono">${esc(h.header)}</td>
      <td>${h.present ? `<span style="color:#68d391">✓ Present</span>` : `<span style="color:#fc8181">✗ Missing</span>`}</td>
      <td class="mono" style="font-size:0.75rem">${esc(h.value ?? "—")}</td>
      <td><span class="sev-badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${esc(h.severity.toUpperCase())}</span></td>
      <td style="font-size:0.78rem;color:#a0aec0">${esc(h.recommendation ?? "")}</td>
    </tr>`;
  }).join("");

  // CORS
  let corsHtml = `<p class="muted">No CORS probe data.</p>`;
  if (audit.cors) {
    const c = audit.cors;
    const sevC = c.severity === "high" || c.severity === "critical" ? "#fc8181" : c.severity === "medium" ? "#f6e05e" : "#68d391";
    corsHtml = `<div class="cors-grid">
  <div class="cors-item ${c.allowsArbitraryOrigins ? "flag" : "ok"}">
    ${c.allowsArbitraryOrigins ? "⚠" : "✓"}&nbsp;Allows Arbitrary Origins
  </div>
  <div class="cors-item ${c.reflectsOrigin ? "flag" : "ok"}">
    ${c.reflectsOrigin ? "⚠" : "✓"}&nbsp;Reflects Origin Header
  </div>
  <div class="cors-item ${c.allowCredentials ? "flag" : "ok"}">
    ${c.allowCredentials ? "⚠" : "✓"}&nbsp;Allow-Credentials: true
  </div>
  <div class="cors-item" style="color:${sevC}">Overall CORS Risk: <strong>${esc(String(c.severity ?? "unknown").toUpperCase())}</strong></div>
</div>`;
  }

  // Cookies
  const ckRows = (audit.cookies ?? []).map((c: { name: string; missingSecure: boolean; missingHttpOnly: boolean; sameSite?: string; severity: string }) => {
    const sc = c.severity === "high" || c.severity === "critical" ? "#fc8181" : c.severity === "medium" ? "#f6e05e" : "#68d391";
    return `<tr>
      <td class="mono">${esc(c.name)}</td>
      <td>${c.missingSecure ? `<span style="color:#fc8181">✗</span>` : `<span style="color:#68d391">✓</span>`}</td>
      <td>${c.missingHttpOnly ? `<span style="color:#fc8181">✗</span>` : `<span style="color:#68d391">✓</span>`}</td>
      <td class="mono">${esc(c.sameSite ?? "—")}</td>
      <td><span class="sev-badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${esc(c.severity.toUpperCase())}</span></td>
    </tr>`;
  }).join("");

  // Info disclosure
  const idRows = (audit.infoDisclosure ?? []).map((id: { header: string; value: string; severity: string }) => {
    const sc = id.severity === "high" || id.severity === "critical" ? "#fc8181" : id.severity === "medium" ? "#f6e05e" : "#4fd1c5";
    return `<tr>
      <td class="mono">${esc(id.header)}</td>
      <td class="mono" style="font-size:0.78rem">${esc(id.value)}</td>
      <td><span class="sev-badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${esc(id.severity.toUpperCase())}</span></td>
    </tr>`;
  }).join("");

  const sensitiveRows = (audit.sensitiveFiles ?? []).map((sf: { url: string; statusCode: number; severity: string }) =>
    `<tr>
      <td class="mono" style="font-size:0.78rem">${esc(sf.url)}</td>
      <td>${statusBadge(sf.statusCode)}</td>
      <td>${sevBadge(sf.severity)}</td>
    </tr>`
  ).join("");

  return `
<details class="audit-detail" open>
  <summary>HTTP Security Headers (${(audit.headers ?? []).length})</summary>
  ${hRows ? `<table><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Risk</th><th>Recommendation</th></tr></thead><tbody>${hRows}</tbody></table>` : `<p class="muted">No header data.</p>`}
</details>

<details class="audit-detail">
  <summary>CORS Configuration</summary>
  ${corsHtml}
</details>

<details class="audit-detail">
  <summary>Cookie Security (${(audit.cookies ?? []).length})</summary>
  ${ckRows ? `<table><thead><tr><th>Cookie</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Risk</th></tr></thead><tbody>${ckRows}</tbody></table>` : `<p class="muted">No cookie data.</p>`}
</details>

<details class="audit-detail">
  <summary>Information Disclosure (${(audit.infoDisclosure ?? []).length})</summary>
  ${idRows ? `<table><thead><tr><th>Header</th><th>Value</th><th>Risk</th></tr></thead><tbody>${idRows}</tbody></table>` : `<p class="muted">None detected.</p>`}
</details>

<details class="audit-detail">
  <summary>Sensitive File Exposure (${(audit.sensitiveFiles ?? []).length})</summary>
  ${sensitiveRows ? `<table><thead><tr><th>URL</th><th>Status</th><th>Risk</th></tr></thead><tbody>${sensitiveRows}</tbody></table>` : `<p class="muted">None detected.</p>`}
</details>`;
}

// ─── Finding cards ────────────────────────────────────────────────────────────

function buildFindingCards(findings: Finding[]): string {
  if (findings.length === 0) return `<p class="muted">No confirmed findings.</p>`;
  const order: Finding["severity"][] = ["critical", "high", "medium", "low"];
  return order.map(sev => {
    const group = findings.filter(f => f.severity === sev);
    if (group.length === 0) return "";
    const c = sev === "critical" ? "#ff4d4d" : sev === "high" ? "#fc8181" : sev === "medium" ? "#f6e05e" : "#68d391";
    const cards = group.map((f, idx) => `
<div class="finding-card" style="border-left:3px solid ${c}">
  <div class="finding-header">
    ${sevBadge(f.severity)}
    <span class="finding-title">${esc(f.title)}</span>
    <span class="finding-idx">#${idx + 1}</span>
  </div>
  <div class="finding-endpoint"><span class="label">Endpoint</span><code>${esc(f.endpoint)}</code></div>
  <details class="finding-evidence">
    <summary>Evidence &amp; Details</summary>
    <pre class="evidence-pre">${esc(f.evidence)}</pre>
  </details>
  <div class="finding-meta">
    <span class="finding-tool">Tool: ${esc(f.tool)}</span>
    <span class="finding-ts">${esc(new Date(f.timestamp).toLocaleString())}</span>
  </div>
</div>`).join("");
    return `<details class="sev-group" open>
  <summary><span style="color:${c}">${sev.toUpperCase()}</span> <span class="count-badge">${group.length}</span></summary>
  ${cards}
</details>`;
  }).join("\n");
}

// ─── Endpoint map ─────────────────────────────────────────────────────────────

function buildEndpointMap(captures: HttpCapture[], endpoints: string[], findings: Finding[]): string {
  // Build a unified map URL→statusCode (prefer capture data)
  const capMap = new Map<string, HttpCapture>();
  for (const c of (captures ?? [])) capMap.set(c.url, c);

  // Merge: all endpoints + all captures + all finding endpoints
  const allUrls = new Set<string>([
    ...endpoints,
    ...capMap.keys(),
    ...findings.map(f => f.endpoint).filter(Boolean),
  ]);
  if (allUrls.size === 0) return `<p class="muted">No endpoints discovered.</p>`;

  // Sort by status class (2xx first) then alphabetically
  const sorted = [...allUrls].sort((a, b) => {
    const sa = capMap.get(a)?.statusCode ?? 0;
    const sb = capMap.get(b)?.statusCode ?? 0;
    const ca = sa >= 500 ? 3 : sa >= 400 ? 2 : sa >= 300 ? 1 : 0;
    const cb = sb >= 500 ? 3 : sb >= 400 ? 2 : sb >= 300 ? 1 : 0;
    return ca !== cb ? ca - cb : a.localeCompare(b);
  });

  const rows = sorted.map(url => {
    const cap = capMap.get(url);
    const code = cap?.statusCode;
    const timing = cap?.timingMs !== undefined ? `${cap.timingMs}ms` : "—";
    const ct = cap?.contentType?.split(";")[0] ?? "—";
    return `<tr>
      <td class="mono ep-url">${esc(url)}</td>
      <td>${code !== undefined ? statusBadge(code) : `<span class="muted">—</span>`}</td>
      <td class="muted mono" style="font-size:0.75rem">${esc(timing)}</td>
      <td class="muted mono" style="font-size:0.75rem">${esc(ct)}</td>
    </tr>`;
  }).join("");

  return `<div class="ep-table-wrap">
<table>
  <thead><tr><th>URL</th><th>Status</th><th>Time</th><th>Content-Type</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
</div>`;
}

// ─── HTTP traffic analysis ────────────────────────────────────────────────────

function buildHttpTraffic(captures: HttpCapture[]): string {
  if (!captures || captures.length === 0) return `<p class="muted">No HTTP traffic data.</p>`;

  // Status class distribution
  const classes: Record<string, number> = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Other": 0 };
  for (const c of captures) {
    if      (c.statusCode >= 500) classes["5xx"]++;
    else if (c.statusCode >= 400) classes["4xx"]++;
    else if (c.statusCode >= 300) classes["3xx"]++;
    else if (c.statusCode >= 200) classes["2xx"]++;
    else                          classes["Other"]++;
  }
  const classColors: Record<string, string> = { "2xx": "#68d391", "3xx": "#63b3ed", "4xx": "#f6ad55", "5xx": "#fc8181", "Other": "#718096" };
  const maxClass = Math.max(...Object.values(classes));
  const classChart = Object.entries(classes).filter(([, v]) => v > 0).map(([k, v]) =>
    `<div class="chart-row">
      <span class="chart-label">${esc(k)}</span>
      <div class="chart-bar-bg"><div class="chart-bar-fill" style="width:${maxClass > 0 ? ((v / maxClass) * 100).toFixed(1) : 0}%;background:${classColors[k] ?? "#718096"}"></div></div>
      <span class="chart-count">${v}</span>
    </div>`
  ).join("");

  // Response time histogram
  const buckets = [
    { label: "< 100ms",    min: 0,    max: 100   },
    { label: "100–500ms",  min: 100,  max: 500   },
    { label: "500ms–1s",   min: 500,  max: 1000  },
    { label: "1s–3s",      min: 1000, max: 3000  },
    { label: "> 3s",       min: 3000, max: Infinity },
  ];
  const bucketed = buckets.map(b => ({
    label: b.label,
    count: captures.filter(c => c.timingMs !== undefined && c.timingMs >= b.min && c.timingMs < b.max).length,
  }));
  const maxBucket = Math.max(...bucketed.map(b => b.count));
  const timeChart = bucketed.filter(b => b.count > 0).map(b =>
    `<div class="chart-row">
      <span class="chart-label">${esc(b.label)}</span>
      <div class="chart-bar-bg"><div class="chart-bar-fill" style="width:${maxBucket > 0 ? ((b.count / maxBucket) * 100).toFixed(1) : 0}%;background:#4fd1c5"></div></div>
      <span class="chart-count">${b.count}</span>
    </div>`
  ).join("");

  const hasTimings = captures.some(c => c.timingMs !== undefined);

  return `<div class="traffic-grid">
  <div class="traffic-card">
    <div class="traffic-title">Status Code Distribution</div>
    ${classChart || `<p class="muted">No data.</p>`}
  </div>
  <div class="traffic-card">
    <div class="traffic-title">Response Time Histogram</div>
    ${hasTimings ? (timeChart || `<p class="muted">No data.</p>`) : `<p class="muted">No timing data in captures.</p>`}
  </div>
</div>`;
}

// ─── Phase timeline ───────────────────────────────────────────────────────────

function buildPhaseTimeline(history: HuntAction[]): string {
  if (history.length === 0) return `<p class="muted">No phases executed.</p>`;

  const nodes = history.map((action, i) => {
    const tp      = action.toolParams as Record<string, unknown>;
    const newEps  = typeof tp.newEndpoints === "number" ? tp.newEndpoints : 0;
    const dur     = action.durationMs ? (action.durationMs / 1000).toFixed(1) + "s" : "—";
    const finds   = action.findings.length;
    const failed  = action.state === "failed";
    const nc      = failed ? "#fc8181" : "#4fd1c5";

    return `<div class="tl-node-wrap${i < history.length - 1 ? " tl-has-line" : ""}">
  <div class="tl-node" style="border-color:${nc};color:${nc}" title="${esc(action.chosenOptionTitle)}">${i + 1}</div>
  <div class="tl-label">${esc(action.chosenOptionTitle)}</div>
  <div class="tl-pills">
    <span class="tl-pill tl-dur">${esc(dur)}</span>
    ${finds > 0    ? `<span class="tl-pill tl-find">+${finds} findings</span>` : ""}
    ${newEps > 0   ? `<span class="tl-pill tl-ep">+${newEps} eps</span>` : ""}
    ${failed       ? `<span class="tl-pill tl-fail">FAILED</span>` : ""}
  </div>
</div>`;
  }).join("\n");

  return `<div class="tl-container">${nodes}</div>`;
}

// ─── Decision trail ───────────────────────────────────────────────────────────

function buildDecisionTrail(history: HuntAction[]): string {
  if (history.length === 0) return `<p class="muted">No actions taken.</p>`;
  const rows = history.map((action, i) => {
    const tp      = action.toolParams as Record<string, unknown>;
    const newEps  = typeof tp.newEndpoints   === "number" ? String(tp.newEndpoints)   : "—";
    const reqs    = typeof tp.requests       === "number" ? String(tp.requests)       : "—";
    const cumEps  = typeof tp.totalEndpoints === "number" ? String(tp.totalEndpoints) : "—";
    const cumFind = typeof tp.totalFindings  === "number" ? String(tp.totalFindings)  : String(action.findings.length);
    const dur     = action.durationMs ? (action.durationMs / 1000).toFixed(1) + "s" : "—";
    const stateCol = action.state === "completed" ? "#68d391" : action.state === "failed" ? "#fc8181" : "#f6e05e";
    return `<tr>
      <td class="muted">${i + 1}</td>
      <td>${esc(action.chosenOptionTitle)}</td>
      <td style="color:${stateCol}">${esc(action.state)}</td>
      <td title="+${action.findings.length} this phase">${cumFind}</td>
      <td title="+${newEps} this phase">${cumEps}</td>
      <td>${reqs}</td>
      <td class="mono">${esc(dur)}</td>
    </tr>`;
  }).join("");
  return `<table>
  <thead><tr><th>#</th><th>Phase</th><th>Result</th><th>Findings ∑</th><th>Endpoints ∑</th><th>Requests</th><th>Duration</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;
}

// ─── Session log ──────────────────────────────────────────────────────────────

function buildSessionLog(events: RunEvent[]): string {
  if (!events || events.length === 0) return `<p class="muted">No events recorded.</p>`;
  const rows = events.map(ev => {
    const bg  = ev.level === "error" ? "rgba(252,129,129,0.06)" : ev.level === "warning" ? "rgba(246,224,94,0.06)" : "transparent";
    const col = ev.level === "error" ? "#fc8181" : ev.level === "warning" ? "#f6e05e" : "#4fd1c5";
    return `<tr style="background:${bg}">
      <td class="mono muted" style="font-size:0.72rem;white-space:nowrap">${esc(new Date(ev.timestamp).toLocaleString())}</td>
      <td style="color:${col};font-size:0.72rem;font-weight:700">${esc(ev.level.toUpperCase())}</td>
      <td>${esc(ev.title)}</td>
      <td class="muted" style="font-size:0.78rem">${esc(ev.detail)}</td>
    </tr>`;
  }).join("");
  return `<table>
  <thead><tr><th>Time</th><th>Level</th><th>Title</th><th>Detail</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;
}

// ─── Summary ──────────────────────────────────────────────────────────────────

function extractSummary(session: HuntSession): ReportSummary {
  const ctx = session.context;
  return {
    totalEndpoints: ctx.visitedEndpoints.length,
    escalated: ctx.findings.filter(f => f.severity === "high" || f.severity === "critical").length,
    confirmed: ctx.findings.length,
    chains: 0,
    totalRequests: session.history.reduce((s, a) => {
      const tp = a.toolParams as Record<string, unknown>;
      return s + (typeof tp.requests === "number" ? tp.requests : 0);
    }, 0),
  };
}

// ─── CSS ──────────────────────────────────────────────────────────────────────

const REPORT_CSS = `
  :root {
    --bg:       #070d1a;
    --bg2:      #0d1b2e;
    --bg3:      #0a1525;
    --border:   #1e3a5f;
    --text:     #c8d6f0;
    --text2:    #a0aec0;
    --text3:    #718096;
    --accent:   #4fd1c5;
    --blue:     #63b3ed;
    --crit:     #ff4d4d;
    --high:     #fc8181;
    --med:      #f6e05e;
    --low:      #68d391;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "SF Mono","Fira Code","Cascadia Code",monospace; background: var(--bg); color: var(--text); padding: 0; line-height: 1.6; font-size: 13px; }

  /* ── Cover ── */
  .cover { background: linear-gradient(135deg,#060c18 0%,#0d1b2e 100%); border-bottom: 2px solid var(--border); padding: 2rem 2.5rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1.5rem; }
  .cover-left h1 { font-size: 1.8rem; color: var(--accent); letter-spacing: -0.02em; }
  .cover-left .cover-target { font-size: 1rem; color: var(--blue); margin-top: 0.25rem; word-break: break-all; }
  .cover-left .cover-meta { font-size: 0.72rem; color: var(--text3); margin-top: 0.5rem; line-height: 1.8; }
  .cover-right { text-align: center; }
  .risk-badge { display: inline-block; padding: 0.4rem 1.2rem; border-radius: 6px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.1em; border: 1px solid; margin-bottom: 0.5rem; }

  /* ── Layout ── */
  .content { padding: 2rem 2.5rem; max-width: 1400px; margin: 0 auto; }
  .section { margin-bottom: 2.5rem; }

  /* ── Section headings ── */
  .section-head { margin-bottom: 0.75rem; }
  .section-head h2 { font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.14em; color: var(--blue); border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; display: flex; align-items: center; gap: 0.5rem; }
  .count-badge { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 0.1em 0.55em; font-size: 0.7rem; color: var(--text2); }

  /* ── Dashboard ── */
  .dash-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 0.75rem; }
  .dash-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem 1rem; }
  .dash-label { font-size: 0.65rem; color: var(--text3); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.3rem; }
  .dash-value { font-size: 1.4rem; font-weight: 700; color: var(--accent); }

  /* ── Risk gauge wrapper ── */
  .gauge-section { display: flex; align-items: center; gap: 2rem; flex-wrap: wrap; }
  .gauge-wrap { flex: 0 0 auto; }
  .gauge-meta { flex: 1; min-width: 200px; }
  .gauge-meta .gm-row { display: flex; justify-content: space-between; font-size: 0.8rem; padding: 0.3rem 0; border-bottom: 1px solid var(--border); }
  .gauge-meta .gm-label { color: var(--text3); }
  .gauge-meta .gm-value { font-weight: 600; }

  /* ── Stacked bars ── */
  .bar-track { height: 28px; border-radius: 4px; overflow: hidden; display: flex; margin-bottom: 0.5rem; border: 1px solid var(--border); }
  .bar-seg { display: flex; align-items: center; justify-content: center; overflow: hidden; transition: flex 0.4s ease; }
  .bar-seg-lbl { font-size: 0.68rem; font-weight: 700; white-space: nowrap; padding: 0 4px; }
  .bar-legend { display: flex; flex-wrap: wrap; gap: 0.5rem; font-size: 0.72rem; }
  .bar-leg { display: flex; align-items: center; gap: 0.25rem; color: var(--text2); }
  .bar-leg-dot { width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0; }
  .bar-empty { color: var(--text3); font-size: 0.8rem; padding: 0.5rem 0; }

  /* ── Tech stack ── */
  .tech-grid { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem; }
  .tech-pill { display: flex; align-items: center; gap: 0; border: 1px solid var(--border); border-radius: 20px; overflow: hidden; font-size: 0.72rem; }
  .tech-pill-label { background: var(--border); padding: 0.2em 0.6em; color: var(--text3); }
  .tech-pill-value { padding: 0.2em 0.7em; color: var(--accent); }
  .conf-row { display: flex; align-items: center; gap: 0.75rem; font-size: 0.75rem; margin-bottom: 0.5rem; }
  .conf-track { flex: 1; height: 6px; background: var(--bg2); border-radius: 3px; border: 1px solid var(--border); overflow: hidden; }
  .conf-fill { height: 100%; border-radius: 3px; transition: width 0.4s ease; }
  .evidence-list { padding-left: 1.2rem; font-size: 0.78rem; color: var(--text2); line-height: 1.7; }

  /* ── Security audit collapsibles ── */
  .audit-detail { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.5rem; overflow: hidden; }
  .audit-detail summary { padding: 0.6rem 1rem; cursor: pointer; font-size: 0.8rem; font-weight: 600; color: var(--blue); background: var(--bg2); user-select: none; list-style: none; display: flex; align-items: center; gap: 0.5rem; }
  .audit-detail summary::before { content: "▶"; font-size: 0.65rem; transition: transform 0.2s; }
  .audit-detail[open] summary::before { transform: rotate(90deg); }
  .audit-detail > *:not(summary) { padding: 0.75rem 1rem; }
  .cors-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 0.5rem; }
  .cors-item { background: var(--bg2); border: 1px solid var(--border); border-radius: 5px; padding: 0.5rem 0.75rem; font-size: 0.78rem; }
  .cors-item.flag { border-color: #fc818166; color: #fc8181; }
  .cors-item.ok   { border-color: #68d39166; color: #68d391; }

  /* ── Finding cards ── */
  .sev-group { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 0.75rem; overflow: hidden; }
  .sev-group > summary { padding: 0.6rem 1rem; cursor: pointer; font-size: 0.8rem; font-weight: 700; background: var(--bg2); user-select: none; list-style: none; display: flex; align-items: center; gap: 0.5rem; }
  .sev-group > summary::before { content: "▶"; font-size: 0.65rem; transition: transform 0.2s; color: var(--text3); }
  .sev-group[open] > summary::before { transform: rotate(90deg); }
  .finding-card { background: var(--bg); border-bottom: 1px solid var(--border); padding: 0.85rem 1rem 0.85rem 1.1rem; }
  .finding-card:last-child { border-bottom: none; }
  .finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; flex-wrap: wrap; }
  .finding-title { font-size: 0.9rem; font-weight: 600; color: var(--text); flex: 1; }
  .finding-idx { font-size: 0.7rem; color: var(--text3); }
  .finding-endpoint { font-size: 0.78rem; margin-bottom: 0.35rem; }
  .finding-endpoint .label { color: var(--text3); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em; margin-right: 0.4rem; }
  .finding-endpoint code { color: var(--blue); word-break: break-all; }
  .finding-evidence summary { font-size: 0.72rem; color: var(--text3); cursor: pointer; list-style: none; padding: 0.2rem 0; }
  .finding-evidence summary::before { content: "▶ "; font-size: 0.6rem; }
  .finding-evidence[open] summary::before { content: "▼ "; }
  .finding-evidence[open] { margin-bottom: 0.25rem; }
  .evidence-pre { background: var(--bg2); border: 1px solid var(--border); border-radius: 4px; padding: 0.6rem; font-size: 0.74rem; white-space: pre-wrap; word-break: break-all; color: var(--text2); margin-top: 0.25rem; max-height: 200px; overflow-y: auto; }
  .finding-meta { display: flex; gap: 1rem; font-size: 0.7rem; color: var(--text3); margin-top: 0.35rem; flex-wrap: wrap; }
  .finding-tool { background: var(--bg2); border: 1px solid var(--border); border-radius: 3px; padding: 0.1em 0.45em; }
  .sev-badge { display: inline-block; padding: 0.15em 0.55em; border-radius: 4px; font-size: 0.68rem; font-weight: 700; }

  /* ── Endpoint map ── */
  .ep-table-wrap { max-height: 400px; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px; }
  .ep-url { word-break: break-all; max-width: 500px; }
  .status-badge { display: inline-block; padding: 0.1em 0.5em; border-radius: 4px; font-size: 0.72rem; font-weight: 700; font-family: inherit; }

  /* ── Traffic charts ── */
  .traffic-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
  @media (max-width: 700px) { .traffic-grid { grid-template-columns: 1fr; } }
  .traffic-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.2rem; }
  .traffic-title { font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text3); margin-bottom: 0.75rem; }
  .chart-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }
  .chart-label { font-size: 0.7rem; color: var(--text2); width: 80px; flex-shrink: 0; text-align: right; }
  .chart-bar-bg { flex: 1; height: 14px; background: var(--bg); border-radius: 3px; overflow: hidden; border: 1px solid var(--border); }
  .chart-bar-fill { height: 100%; border-radius: 3px; transition: width 0.4s ease; }
  .chart-count { font-size: 0.7rem; color: var(--text3); width: 30px; flex-shrink: 0; }

  /* ── Phase timeline ── */
  .tl-container { display: flex; flex-wrap: wrap; gap: 0; align-items: flex-start; }
  .tl-node-wrap { display: flex; flex-direction: column; align-items: center; position: relative; min-width: 90px; max-width: 120px; }
  .tl-node-wrap.tl-has-line::after { content: ""; position: absolute; top: 16px; left: calc(50% + 18px); width: calc(100% - 36px); height: 2px; background: var(--border); }
  .tl-node { width: 32px; height: 32px; border-radius: 50%; border: 2px solid var(--accent); display: flex; align-items: center; justify-content: center; font-size: 0.72rem; font-weight: 700; background: var(--bg2); z-index: 1; }
  .tl-label { font-size: 0.62rem; color: var(--text2); text-align: center; margin-top: 0.3rem; line-height: 1.3; max-width: 90px; }
  .tl-pills { display: flex; flex-direction: column; align-items: center; gap: 0.2rem; margin-top: 0.3rem; }
  .tl-pill { font-size: 0.58rem; border-radius: 3px; padding: 0.1em 0.4em; }
  .tl-dur  { background: var(--border); color: var(--text2); }
  .tl-find { background: rgba(252,129,129,0.15); color: var(--high); }
  .tl-ep   { background: rgba(99,179,237,0.15); color: var(--blue); }
  .tl-fail { background: rgba(252,129,129,0.2); color: var(--crit); font-weight:700; }

  /* ── Tables (shared) ── */
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th, td { padding: 0.45rem 0.75rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
  th { background: var(--bg2); color: var(--accent); font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; position: sticky; top: 0; }
  tr:hover td { background: rgba(13,27,46,0.5); }

  /* ── Utility ── */
  .mono  { font-family: inherit; }
  .muted { color: var(--text3); }
  .label { color: var(--text3); }
  p.muted { font-size: 0.82rem; padding: 0.5rem 0; }

  /* ── Footer ── */
  .footer { margin-top: 3rem; border-top: 1px solid var(--border); padding: 1rem 2.5rem; font-size: 0.7rem; color: var(--text3); text-align: center; }

  /* ── Print / PDF ── */
  @page { size: A4; margin: 18mm 15mm; }
  .no-print { display: inline-flex; }
  @media print {
    .no-print { display: none !important; }
    body { background: #fff !important; color: #111 !important; font-size: 11pt; }
    .cover { background: #f0f4f8 !important; border-color: #ccc !important; page-break-inside: avoid; }
    .cover-left h1 { color: #1a5276 !important; }
    .cover-left .cover-target { color: #2471a3 !important; }
    .dash-card, .traffic-card, .audit-detail { background: #f9f9f9 !important; border-color: #ddd !important; }
    .dash-value { color: #1a5276 !important; }
    .section { page-break-inside: avoid; }
    .section-head h2 { color: #1a5276 !important; border-color: #ccc !important; }
    .sev-group, .finding-card { page-break-inside: avoid; }
    th { background: #eef !important; color: #1a5276 !important; position: static; }
    /* Expand all disclosure widgets for print */
    details { display: block !important; }
    details summary { display: none !important; }
    details[open] { display: block !important; }
    /* Remove scroll caps so full content prints */
    .ep-table-wrap { max-height: none !important; overflow: visible !important; }
    .evidence-pre { max-height: none !important; overflow: visible !important; }
    /* Timeline: let it wrap naturally */
    .tl-container { flex-wrap: wrap !important; }
    /* Traffic grid: single column on paper */
    .traffic-grid { grid-template-columns: 1fr !important; }
    /* Ensure links print as plain text */
    a::after { content: none !important; }
  }
`;

// ─── Main HTML builder ────────────────────────────────────────────────────────

function buildHtml(session: HuntSession, generatedAt: string): string {
  const ctx   = session.context;
  const finds = ctx.findings;
  const risk  = computeRisk(finds);

  const crit  = finds.filter(f => f.severity === "critical").length;
  const high  = finds.filter(f => f.severity === "high").length;
  const med   = finds.filter(f => f.severity === "medium").length;
  const low   = finds.filter(f => f.severity === "low").length;
  // Derive hunt duration from actionGraph (same logic as dashboard)
  const actionGraphHtml = ctx.actionGraph ?? [];
  const totalMs = actionGraphHtml.length > 0
    ? actionGraphHtml.reduce((s, a) => s + (a.durationMs ?? 0), 0)
    : session.history.reduce((s, a) => s + (a.durationMs ?? 0), 0);
  const dur = totalMs >= 60000
    ? `${Math.floor(totalMs / 60000)}m ${Math.round((totalMs % 60000) / 1000)}s`
    : `${(totalMs / 1000).toFixed(1)}s`;

  const captures: HttpCapture[] = ctx.capturedResponses ?? [];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>HexGuard Hunt Report — ${esc(ctx.target)}</title>
<style>${REPORT_CSS}</style>
</head>
<body>

<!-- ─── COVER ─────────────────────────────────────────────────────────── -->
<div class="cover">
  <div class="cover-left">
    <h1>&#x2756; HexGuard Hunt Report</h1>
    <div class="cover-target">${esc(ctx.target)}</div>
    <div class="cover-meta">
      Profile: <strong>${esc(session.config.profile)}</strong>&emsp;
      State: <strong>${esc(session.state)}</strong>&emsp;
      Session: <code>${esc(session.id)}</code><br/>
      Generated: ${esc(generatedAt)}
    </div>
  </div>
  <div class="cover-right">
    <div class="risk-badge" style="background:${risk.color}22;color:${risk.color};border-color:${risk.color}66">
      ${esc(risk.label)} RISK
    </div>
    ${svgGauge(risk.score, risk.color)}
    <button class="no-print" onclick="window.print()" style="margin-top:1rem;padding:0.45rem 1.1rem;background:#00e5ff;color:#070d1a;border:none;border-radius:6px;font-size:0.82rem;font-weight:700;cursor:pointer;letter-spacing:0.03em">
      &#x2399;&nbsp;Save as PDF
    </button>
  </div>
</div>

<div class="content">

<!-- ─── EXECUTIVE DASHBOARD ──────────────────────────────────────────── -->
<div class="section">
  ${h2("Executive Dashboard")}
  ${buildExecDashboard(session)}
</div>

<!-- ─── GAUGE + SUMMARY ──────────────────────────────────────────────── -->
<div class="section">
  ${h2("Risk Overview")}
  <div class="gauge-section">
    <div class="gauge-wrap">${svgGauge(risk.score, risk.color)}</div>
    <div class="gauge-meta">
      <div class="gm-row"><span class="gm-label">Risk Score</span><span class="gm-value" style="color:${risk.color}">${risk.score}/100 — ${esc(risk.label)}</span></div>
      <div class="gm-row"><span class="gm-label">Critical</span><span class="gm-value" style="color:#ff4d4d">${crit}</span></div>
      <div class="gm-row"><span class="gm-label">High</span><span class="gm-value" style="color:#fc8181">${high}</span></div>
      <div class="gm-row"><span class="gm-label">Medium</span><span class="gm-value" style="color:#f6e05e">${med}</span></div>
      <div class="gm-row"><span class="gm-label">Low</span><span class="gm-value" style="color:#68d391">${low}</span></div>
      <div class="gm-row"><span class="gm-label">Hunt Duration</span><span class="gm-value">${esc(dur)}</span></div>
    </div>
  </div>
</div>

<!-- ─── VULNERABILITY BAR ─────────────────────────────────────────────── -->
<div class="section">
  ${h2("Vulnerability Distribution", finds.length)}
  ${buildVulnBar(finds)}
</div>

<!-- ─── MISCONFIGURATION BAR ─────────────────────────────────────────── -->
<div class="section">
  ${h2("Misconfiguration Distribution")}
  ${buildMisconfigBar(ctx.securityAudit)}
</div>

<!-- ─── TECH STACK ────────────────────────────────────────────────────── -->
<div class="section">
  ${h2("Technology Stack")}
  ${buildTechStack(ctx.techFingerprint)}
</div>

<!-- ─── SECURITY AUDIT ────────────────────────────────────────────────── -->
<div class="section">
  ${h2("Security Audit")}
  ${buildSecurityAudit(ctx.securityAudit)}
</div>

<!-- ─── CONFIRMED FINDINGS ───────────────────────────────────────────── -->
<div class="section">
  ${h2("Confirmed Findings", finds.length)}
  ${buildFindingCards(finds)}
</div>

<!-- ─── ENDPOINT MAP ──────────────────────────────────────────────────── -->
<div class="section">
  ${h2("Endpoint Map", new Set([...ctx.visitedEndpoints, ...(ctx.capturedResponses ?? []).map(c => c.url), ...finds.map(f => f.endpoint).filter(Boolean)]).size)}
  ${buildEndpointMap(captures, ctx.visitedEndpoints, finds)}
</div>

<!-- ─── HTTP TRAFFIC ──────────────────────────────────────────────────── -->
<div class="section">
  ${h2("HTTP Traffic Analysis", captures.length)}
  ${buildHttpTraffic(captures)}
</div>

<!-- ─── PHASE TIMELINE ────────────────────────────────────────────────── -->
<div class="section">
  ${h2("Phase Timeline", session.history.length)}
  ${buildPhaseTimeline(session.history)}
</div>

<!-- ─── DECISION TRAIL ────────────────────────────────────────────────── -->
<div class="section">
  ${h2("Decision Trail", session.history.length)}
  ${buildDecisionTrail(session.history)}
</div>

<!-- ─── SESSION LOG ───────────────────────────────────────────────────── -->
<div class="section">
  ${h2("Session Log", ctx.events.length)}
  ${buildSessionLog(ctx.events)}
</div>

</div><!-- /content -->

<div class="footer">
  Generated by HexGuard-Hunt &mdash; Authorised security testing use only &mdash; ${esc(generatedAt)}
</div>

</body>
</html>`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function buildReport(session: HuntSession): Promise<ReportBundle> {
  const ctx = session.context;

  // ── Defensive: reconstruct visitedEndpoints from captured responses if empty ──
  if (ctx.visitedEndpoints.length === 0 && ctx.capturedResponses && ctx.capturedResponses.length > 0) {
    const reconstructed = [...new Set(
      ctx.capturedResponses
        .filter(c => c.statusCode < 500)
        .map(c => c.url),
    )];
    if (reconstructed.length > 0) ctx.visitedEndpoints = reconstructed;
  }

  // ── Always re-sync metrics ──────────────────────────────────────────────────
  session.metrics = [
    { label: "Findings",      value: String(ctx.findings.length) },
    { label: "Endpoints",     value: String(ctx.visitedEndpoints.length) },
    { label: "Actions Taken", value: String(session.history.length) },
    { label: "High/Critical", value: String(ctx.findings.filter(f => f.severity === "high" || f.severity === "critical").length) },
  ];

  const generatedAt = new Date().toISOString();
  const summary = extractSummary(session);

  const dir = sessionDir(session.id);
  await fs.mkdir(dir, { recursive: true });

  const jsonPath = path.join(dir, "report.json");
  const htmlPath = path.join(dir, "report.html");

  const jsonPayload = {
    sessionId:        session.id,
    generatedAt,
    target:           ctx.target,
    profile:          session.config.profile,
    state:            session.state,
    summary,
    metrics:          session.metrics,
    findings:         ctx.findings,
    visitedEndpoints: ctx.visitedEndpoints,
    history:          session.history,
    events:           ctx.events,
  };

  await fs.writeFile(jsonPath, JSON.stringify(jsonPayload, null, 2), "utf8");
  await fs.writeFile(htmlPath, buildHtml(session, generatedAt), "utf8");

  return {
    runId:        session.id,
    generatedAt,
    target:       ctx.target,
    summary,
    jsonPath,
    htmlPath,
  };
}
