/**
 * passiveAuditor.ts — Zero-tool passive security analysis.
 *
 * Analyses HttpCapture objects for:
 *   • Missing / weak security headers
 *   • CORS misconfiguration
 *   • Cookie flag issues
 *   • Server technology disclosure
 *   • Accessible sensitive files
 *
 * This module ALWAYS produces findings on real web targets — no tool installation required.
 */

import type { Finding, HttpCapture, SecurityAuditResult, HeaderAuditItem, CookieAuditItem, InfoDisclosureItem, RiskLevel } from "@hexguard/shared";

// ─── Header requirements ──────────────────────────────────────────────────────

const REQUIRED_HEADERS: Array<{ name: string; severity: RiskLevel; recommendation: string }> = [
  {
    name: "content-security-policy",
    severity: "high",
    recommendation: "Add Content-Security-Policy to prevent XSS. Start with: default-src 'self'",
  },
  {
    name: "strict-transport-security",
    severity: "medium",
    recommendation: "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  {
    name: "x-frame-options",
    severity: "medium",
    recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
  },
  {
    name: "x-content-type-options",
    severity: "low",
    recommendation: "Add X-Content-Type-Options: nosniff to prevent MIME sniffing",
  },
  {
    name: "referrer-policy",
    severity: "low",
    recommendation: "Add Referrer-Policy: no-referrer-when-downgrade or strict-origin",
  },
  {
    name: "permissions-policy",
    severity: "low",
    recommendation: "Add Permissions-Policy to restrict browser APIs (camera, geolocation, etc.)",
  },
];

// Headers that leak server technology
const DISCLOSURE_HEADERS = [
  "server", "x-powered-by", "x-aspnet-version",
  "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
];

// ─── ID & timestamp helpers ───────────────────────────────────────────────────

function makeId(): string {
  return `finding-passive-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

// ─── Main audit function ──────────────────────────────────────────────────────

export function auditCaptures(
  captures: HttpCapture[],
  target: string,
): { findings: Finding[]; audit: SecurityAuditResult } {
  const findings: Finding[] = [];

  // Use the root-path response as the primary audit target
  const root =
    captures.find(c => {
      try { return new URL(c.url).pathname === "/"; } catch { return false; }
    }) ?? captures[0];

  // ── Security Headers ───────────────────────────────────────────────────────
  const headerAudit: HeaderAuditItem[] = [];

  if (root) {
    for (const req of REQUIRED_HEADERS) {
      const present = req.name in root.headers;
      const value   = root.headers[req.name];
      headerAudit.push({ header: req.name, present, value, severity: req.severity, recommendation: req.recommendation });

      if (!present) {
        const label = req.name
          .split("-")
          .map(w => w[0]!.toUpperCase() + w.slice(1))
          .join(" ");
        findings.push({
          id:        makeId(),
          timestamp: nowIso(),
          title:     `Missing ${label} header`,
          severity:  req.severity,
          endpoint:  root.url,
          evidence:  `The '${req.name}' header is absent from the HTTP response.\nRecommendation: ${req.recommendation}`,
          tool:      "passive-auditor",
        });
      }
    }
  }

  // ── Information Disclosure ────────────────────────────────────────────────
  const infoDisclosure: InfoDisclosureItem[] = [];

  if (root) {
    for (const hdr of DISCLOSURE_HEADERS) {
      const val = root.headers[hdr];
      if (val) {
        infoDisclosure.push({ header: hdr, value: val, severity: "low" });
        findings.push({
          id:        makeId(),
          timestamp: nowIso(),
          title:     `Server technology exposed via '${hdr}' header`,
          severity:  "low",
          endpoint:  root.url,
          evidence:  `${hdr}: ${val}\nExposing the technology stack assists attackers in targeting known vulnerabilities.`,
          tool:      "passive-auditor",
        });
      }
    }
  }

  // ── CORS Check (uses the capture sent with evil Origin header) ────────────
  const corsCapture = captures.find(c =>
    c.headers["access-control-allow-origin"] !== undefined
  );
  let corsAudit: SecurityAuditResult["cors"] = null;

  if (corsCapture) {
    const acao = corsCapture.headers["access-control-allow-origin"] ?? "";
    const acac = corsCapture.headers["access-control-allow-credentials"] === "true";
    const isWildcard = acao === "*";
    const reflectsEvil = acao.includes("evil-tester.hexguard.com");

    corsAudit = {
      allowsArbitraryOrigins: isWildcard || reflectsEvil,
      reflectsOrigin:         reflectsEvil,
      allowCredentials:       acac,
      severity:               isWildcard || (reflectsEvil && acac) ? "high" : reflectsEvil ? "medium" : "low",
    };

    if (isWildcard) {
      findings.push({
        id:        makeId(),
        timestamp: nowIso(),
        title:     "CORS wildcard — any origin allowed",
        severity:  "high",
        endpoint:  corsCapture.url,
        evidence:  `Access-Control-Allow-Origin: *\nAny website can make cross-origin requests to this endpoint.`,
        tool:      "passive-auditor",
      });
    } else if (reflectsEvil && acac) {
      findings.push({
        id:        makeId(),
        timestamp: nowIso(),
        title:     "CORS reflects arbitrary origin with credentials",
        severity:  "high",
        endpoint:  corsCapture.url,
        evidence:  `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: true\nThis allows cross-site requests including cookies/auth from attacker-controlled origins.`,
        tool:      "passive-auditor",
      });
    } else if (reflectsEvil) {
      findings.push({
        id:        makeId(),
        timestamp: nowIso(),
        title:     "CORS reflects arbitrary origin",
        severity:  "medium",
        endpoint:  corsCapture.url,
        evidence:  `Access-Control-Allow-Origin: ${acao}\nThe server reflects the request Origin header. Cross-origin reads are possible.`,
        tool:      "passive-auditor",
      });
    }
  }

  // ── Cookie Audit ──────────────────────────────────────────────────────────
  const cookieAudit: CookieAuditItem[] = [];

  for (const cap of captures) {
    const raw = cap.headers["set-cookie"];
    if (!raw) continue;

    // Multiple Set-Cookie headers are sometimes joined with ", " — split carefully
    const cookieStrings = raw.split(/,(?=[^ ])/);
    for (const cookieStr of cookieStrings) {
      const name          = cookieStr.split(";")[0]?.split("=")[0]?.trim() ?? "unknown";
      const lower         = cookieStr.toLowerCase();
      const missingSecure  = !lower.includes("; secure") && !lower.startsWith("secure");
      const missingHttpOnly = !lower.includes("httponly");
      const sameSiteMatch  = /samesite=(\w+)/i.exec(cookieStr);
      const sameSite       = sameSiteMatch?.[1];

      const sev: RiskLevel = missingSecure && missingHttpOnly ? "high"
        : missingSecure || missingHttpOnly                    ? "medium"
        : "low";

      cookieAudit.push({ name, missingSecure, missingHttpOnly, sameSite, severity: sev });

      const issues: string[] = [];
      if (missingSecure)   issues.push("Secure flag missing — cookie sent over HTTP");
      if (missingHttpOnly) issues.push("HttpOnly flag missing — accessible via JavaScript");
      if (!sameSite)       issues.push("SameSite not set — CSRF risk");

      if (issues.length > 0) {
        findings.push({
          id:        makeId(),
          timestamp: nowIso(),
          title:     `Cookie '${name}' has insecure flags`,
          severity:  sev,
          endpoint:  cap.url,
          evidence:  `Set-Cookie: ${cookieStr.slice(0, 200)}\nIssues:\n${issues.map(i => `  • ${i}`).join("\n")}`,
          tool:      "passive-auditor",
        });
      }
    }
  }

  // ── Sensitive Files ───────────────────────────────────────────────────────
  const sensitiveFiles: SecurityAuditResult["sensitiveFiles"] = [];
  const SENSITIVE_PATTERNS = [".env", ".git", "backup", "phpinfo", "swagger", "openapi", "api-docs", "config.php", "wp-config"];

  for (const cap of captures) {
    if (cap.statusCode < 200 || cap.statusCode >= 300) continue;
    const urlLower = cap.url.toLowerCase();
    if (!SENSITIVE_PATTERNS.some(p => urlLower.includes(p))) continue;

    const sev: RiskLevel = (urlLower.includes(".env") || urlLower.includes(".git") || urlLower.includes("wp-config"))
      ? "critical" : "high";

    sensitiveFiles.push({ url: cap.url, statusCode: cap.statusCode, severity: sev });
    findings.push({
      id:        makeId(),
      timestamp: nowIso(),
      title:     `Sensitive file accessible: ${cap.url.split("/").pop() ?? cap.url}`,
      severity:  sev,
      endpoint:  cap.url,
      evidence:  `HTTP ${cap.statusCode} response from ${cap.url}\nBody preview: ${cap.bodyPreview.slice(0, 300)}`,
      tool:      "passive-auditor",
    });
  }

  return {
    findings,
    audit: {
      target,
      headers:         headerAudit,
      cors:            corsAudit,
      cookies:         cookieAudit,
      infoDisclosure,
      sensitiveFiles,
    },
  };
}
