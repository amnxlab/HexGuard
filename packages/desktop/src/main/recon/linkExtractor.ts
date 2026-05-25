/**
 * linkExtractor.ts — Passive endpoint discovery from HTML bodies,
 * robots.txt entries, and XML sitemaps.
 *
 * All functions are pure (no I/O).  The caller is responsible for fetching.
 */

// ─── HTML link extraction ─────────────────────────────────────────────────────

/**
 * Extract all unique, same-origin URLs from an HTML document.
 *
 * Scans `href`, `src`, and `action` attributes.  Returns both bare pathname
 * endpoints (for surface mapping) and full URLs that contain query strings
 * (as potential injection points).
 */
export function extractLinks(html: string, baseUrl: string): string[] {
  let base: URL;
  try { base = new URL(baseUrl); } catch { return []; }

  const urls = new Set<string>();

  // Match href / src / action attribute values (quoted only — safe parse)
  const attrRe = /(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  let m: RegExpExecArray | null;

  while ((m = attrRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? "").trim();
    if (!raw) continue;
    // Skip non-HTTP schemes
    if (/^(?:data:|javascript:|mailto:|tel:|#)/.test(raw)) continue;

    try {
      const u = new URL(raw, baseUrl);
      // Only keep same-origin URLs
      if (u.origin !== base.origin) continue;

      // Always add the bare pathname endpoint
      const endpoint = `${u.origin}${u.pathname}`;
      urls.add(endpoint);

      // Also add the full URL when it carries query params (injection surface)
      if (u.search) urls.add(`${u.origin}${u.pathname}${u.search}`);
    } catch { continue; }
  }

  return [...urls];
}

// ─── robots.txt ───────────────────────────────────────────────────────────────

/**
 * Parse `Disallow:` and `Allow:` entries from a robots.txt body and
 * return them as absolute URLs.
 *
 * Wildcard patterns are stripped to their base path (e.g. `/api/*` → `/api/`).
 */
export function parseRobotsTxt(body: string, baseUrl: string): string[] {
  const originBase = baseUrl.replace(/\/$/, "");
  const seen = new Set<string>();

  for (const line of body.split(/\r?\n/)) {
    const m = line.match(/^(?:Disallow|Allow)\s*:\s*(.+)/i);
    if (!m) continue;

    let p = m[1]!.trim();
    if (!p || p === "/") continue;

    // Strip wildcard and end-of-line anchors
    p = p.replace(/\$.*/g, "").replace(/\*.*/g, "").trim();
    if (!p || p === "/") continue;

    try {
      const abs = new URL(p, originBase + "/").toString();
      seen.add(abs);
    } catch { continue; }
  }

  return [...seen];
}

// ─── XML sitemap ──────────────────────────────────────────────────────────────

/**
 * Extract `<loc>` URLs from an XML sitemap (or sitemap index).
 * Only returns same-origin URLs.
 */
export function parseSitemap(xml: string, baseUrl: string): string[] {
  let base: URL;
  try { base = new URL(baseUrl); } catch { return []; }

  const urls: string[] = [];
  const locRe = /<loc[^>]*>\s*([^<]+)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;

  while ((m = locRe.exec(xml)) !== null) {
    const raw = m[1]!.trim();
    try {
      const u = new URL(raw);
      if (u.origin === base.origin) urls.push(u.href);
    } catch { continue; }
  }

  return [...new Set(urls)];
}
