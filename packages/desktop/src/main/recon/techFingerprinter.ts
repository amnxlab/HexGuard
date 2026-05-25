/**
 * techFingerprinter.ts — Detect web technology stack from HTTP responses.
 *
 * Analyses response headers and HTML body to identify:
 *   • Server software (nginx, Apache, IIS, Caddy)
 *   • Language (PHP, Python, Ruby, Java, Node.js)
 *   • Framework (Django, Laravel, Rails, Express, Spring, ASP.NET)
 *   • CMS (WordPress, Drupal, Joomla, Ghost)
 *
 * Returns a TechFingerprint with a suggestedWordlist hint for the prober.
 */

import type { HttpCapture, TechFingerprint } from "@hexguard/shared";

// ─── Signature table ──────────────────────────────────────────────────────────

interface Sig {
  field: "server" | "language" | "framework" | "cms";
  value: string;
  patterns: RegExp[];           // match against: headers concat + body preview
  headerOnly?: boolean;         // if true, only scan headers
  suggestedWordlist?: string;   // filename inside /wordlists/
}

const SIGNATURES: Sig[] = [
  // ── CMS ──
  { field: "cms",       value: "WordPress", patterns: [/wp-content|wp-includes|wordpress/i],           suggestedWordlist: "common.txt" },
  { field: "cms",       value: "Drupal",    patterns: [/Drupal|sites\/default|drupal\.js/i] },
  { field: "cms",       value: "Joomla",    patterns: [/joomla|\/administrator\/index\.php/i] },
  { field: "cms",       value: "Ghost",     patterns: [/ghost\/core|content\/themes\/casper/i] },

  // ── Frameworks ──
  { field: "framework", value: "Django",    patterns: [/csrfmiddlewaretoken|django/i] },
  { field: "framework", value: "Laravel",   patterns: [/laravel_session|XSRF-TOKEN/i] },
  { field: "framework", value: "Rails",     patterns: [/_rails_session|csrf-token.*rails/i] },
  { field: "framework", value: "Express",   patterns: [/express/i], headerOnly: true },
  { field: "framework", value: "Spring",    patterns: [/jsessionid|X-Application-Context/i] },
  { field: "framework", value: "ASP.NET",   patterns: [/__VIEWSTATE|ASP\.NET_SessionId/i] },
  { field: "framework", value: "Next.js",   patterns: [/__NEXT_DATA__|_next\/static/i] },
  { field: "framework", value: "Nuxt",      patterns: [/__nuxt__|_nuxt\//i] },

  // ── Languages ──
  { field: "language",  value: "PHP",       patterns: [/\.php\b|X-Powered-By.*PHP/i] },
  { field: "language",  value: "Python",    patterns: [/Python\/|python/i], headerOnly: true },
  { field: "language",  value: "Ruby",      patterns: [/Phusion_Passenger|rack\./i], headerOnly: true },
  { field: "language",  value: "Java",      patterns: [/Java\/|Servlet\/|JSP/i], headerOnly: true },
  { field: "language",  value: "Node.js",   patterns: [/node\.js/i], headerOnly: true },

  // ── Servers ──
  { field: "server",    value: "nginx",     patterns: [/nginx/i],             headerOnly: true },
  { field: "server",    value: "Apache",    patterns: [/Apache/i],            headerOnly: true },
  { field: "server",    value: "IIS",       patterns: [/Microsoft-IIS/i],     headerOnly: true },
  { field: "server",    value: "Caddy",     patterns: [/Caddy/i],             headerOnly: true },
  { field: "server",    value: "LiteSpeed", patterns: [/LiteSpeed/i],         headerOnly: true },
  { field: "server",    value: "Cloudflare",patterns: [/cloudflare/i],        headerOnly: true },
];

// ─── Main export ──────────────────────────────────────────────────────────────

export function detectTech(captures: HttpCapture[]): TechFingerprint {
  const result: TechFingerprint = { evidence: [], confidence: 0 };
  let matchCount = 0;

  for (const cap of captures) {
    // Build a combined text from header values + body (for pattern matching)
    const headerText = Object.entries(cap.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
    const bodyText = cap.bodyPreview;
    const combined = `${headerText}\n${bodyText}`;

    for (const sig of SIGNATURES) {
      // Already detected this field
      if (result[sig.field]) continue;

      const text = sig.headerOnly ? headerText : combined;
      if (sig.patterns.some(p => p.test(text))) {
        result[sig.field] = sig.value;
        result.evidence.push(`${sig.field}:${sig.value} detected in ${cap.url}`);
        if (sig.suggestedWordlist) result.suggestedWordlist = sig.suggestedWordlist;
        matchCount++;
      }
    }
  }

  // Raw Server header as final fallback
  const root = captures[0];
  if (root && !result.server && root.headers["server"]) {
    result.server = root.headers["server"].split("/")[0]?.trim() ?? root.headers["server"];
    result.evidence.push(`Server header: ${root.headers["server"]}`);
    matchCount++;
  }

  result.confidence = Math.min(100, matchCount * 25);
  return result;
}
