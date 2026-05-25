/**
 * formExtractor.ts — Extract HTML forms and their input fields from captured
 * response bodies.  Uses pure string/regex parsing — no DOM dependency.
 */

import type { ExtractedForm, ExtractedFormField } from "@hexguard/shared";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function attr(tag: string, name: string): string {
  // Match name="value", name='value', or name=value (unquoted)
  const re = new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]*))`, "i");
  const m = re.exec(tag);
  if (!m) return "";
  return (m[1] ?? m[2] ?? m[3] ?? "").trim();
}

function resolveUrl(base: string, action: string): string {
  if (!action) return base;
  try {
    return new URL(action, base).toString();
  } catch {
    return base;
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Parse all HTML `<form>` elements from `html`, resolve relative `action`
 * URLs against `baseUrl`, and return an array of `ExtractedForm` objects.
 *
 * Only keeps forms that have at least one named input so purely decorative
 * forms (e.g. search-with-only-submit) don't pollute the attack surface.
 */
export function extractForms(html: string, baseUrl: string): ExtractedForm[] {
  const forms: ExtractedForm[] = [];

  // Split on <form …> open tags (non-greedy)
  const formOpenRe = /<form(\s[^>]*)?>/gi;
  const formCloseRe = /<\/form\s*>/gi;

  let match: RegExpExecArray | null;

  // Collect all <form> tag positions and attributes
  const opens: Array<{ index: number; tag: string }> = [];
  while ((match = formOpenRe.exec(html)) !== null) {
    opens.push({ index: match.index, tag: match[0] });
  }

  const closes: number[] = [];
  while ((match = formCloseRe.exec(html)) !== null) {
    closes.push(match.index);
  }

  for (let i = 0; i < opens.length; i++) {
    const start = opens[i]!.index + opens[i]!.tag.length;
    const end   = closes[i] ?? html.length;
    const formBody = html.slice(start, end);
    const formTag  = opens[i]!.tag;

    const rawAction = attr(formTag, "action");
    const rawMethod = (attr(formTag, "method") || "GET").toUpperCase();
    const method: ExtractedForm["method"] = rawMethod === "POST" ? "POST" : "GET";
    const action = resolveUrl(baseUrl, rawAction);

    // Extract <input>, <textarea>, <select> elements
    const fields: ExtractedFormField[] = [];
    const inputRe = /<(input|textarea|select)(\s[^>]*)?\/?>/gi;
    let inputMatch: RegExpExecArray | null;
    while ((inputMatch = inputRe.exec(formBody)) !== null) {
      const tag  = inputMatch[0];
      const name = attr(tag, "name");
      if (!name) continue;           // skip unnamed inputs
      const type  = (attr(tag, "type") || inputMatch[1] === "textarea" ? "text" : "text").toLowerCase();
      const value = attr(tag, "value");
      fields.push({ name, type: type || "text", value });
    }

    // Only keep forms with at least one named field
    if (fields.length > 0) {
      forms.push({ action, method, fields });
    }
  }

  return forms;
}

/**
 * Collect `ExtractedForm[]` from multiple HTML captures (keyed by URL).
 * Skips captures with non-HTML content types.
 */
export function extractFormsFromCaptures(
  captures: Array<{ url: string; bodyPreview: string; contentType: string }>,
): ExtractedForm[] {
  const all: ExtractedForm[] = [];
  for (const cap of captures) {
    if (!cap.contentType.includes("html")) continue;
    const forms = extractForms(cap.bodyPreview, cap.url);
    all.push(...forms);
  }
  // De-duplicate by (action, method)
  const seen = new Set<string>();
  return all.filter(f => {
    const key = `${f.method}:${f.action}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
