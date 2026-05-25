/**
 * httpClient.ts — Thin fetch() wrapper that returns HttpCapture objects.
 *
 * Uses Node.js native fetch() (available in Electron / Node 18+).
 * No external dependencies.
 */

import type { HttpCapture } from "@hexguard/shared";
import type { RateLimiter } from "./rateLimiter";

const DEFAULT_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const BASE_HEADERS: Record<string, string> = {
  "User-Agent":      DEFAULT_UA,
  "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
  "Connection":      "keep-alive",
};

export interface FetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  followRedirects?: boolean;
  bearerToken?: string;
  /** If provided, the request waits for a rate-limiter slot before firing. */
  rateLimiter?: RateLimiter;
}

/**
 * Fetch a URL and return an HttpCapture.
 * Returns null on network error or timeout.
 */
export async function httpFetch(
  url: string,
  options: FetchOptions = {},
): Promise<HttpCapture | null> {
  if (options.rateLimiter) await options.rateLimiter.acquire();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  const startMs = Date.now();

  try {
    const reqHeaders: Record<string, string> = { ...BASE_HEADERS, ...options.headers };
    if (options.bearerToken) {
      reqHeaders["Authorization"] = `Bearer ${options.bearerToken}`;
    }

    const res = await fetch(url, {
      method:   options.method ?? "GET",
      headers:  reqHeaders,
      signal:   controller.signal,
      redirect: options.followRedirects === false ? "manual" : "follow",
      body:     options.body,
    });

    clearTimeout(timeout);
    const timingMs = Date.now() - startMs;

    // Normalise headers to lower-case
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

    // Body preview — 8 KB cap
    let bodyPreview = "";
    try { bodyPreview = (await res.text()).slice(0, 8192); } catch { /* ignore */ }

    return {
      url,
      method:      options.method ?? "GET",
      statusCode:  res.status,
      headers,
      bodyPreview,
      contentType: headers["content-type"] ?? "",
      timingMs,
    };
  } catch {
    clearTimeout(timeout);
    return null;
  }
}

/**
 * Fetch a URL with an injected evil Origin header to test CORS.
 */
export async function httpFetchCorsProbe(
  url: string,
  options: FetchOptions = {},
): Promise<HttpCapture | null> {
  return httpFetch(url, {
    ...options,
    headers: {
      ...options.headers,
      "Origin": "https://evil-tester.hexguard.com",
    },
    followRedirects: false,
  });
}
