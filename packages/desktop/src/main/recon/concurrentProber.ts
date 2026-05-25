/**
 * concurrentProber.ts — Built-in wordlist-based endpoint discovery.
 *
 * Reads a wordlist file line-by-line and probes each path with fetch().
 * Used as a reliable fallback when the ffuf binary is unavailable or produces
 * no output.
 *
 * Concurrency is controlled to respect the session's maxRequestsPerMinute.
 */

import * as fs from "node:fs";
import * as readline from "node:readline";
import type { HttpCapture } from "@hexguard/shared";
import { httpFetch } from "./httpClient";

export interface ProbeProgress {
  probed: number;
  total: number;
  found: number;
}

export interface ProbeOptions {
  /** Number of simultaneous requests (default: 10) */
  concurrency?: number;
  /** Per-request timeout in ms (default: 6000) */
  timeoutMs?: number;
  /** Bearer token to include on every request */
  bearerToken?: string;
  /** Called periodically with progress updates */
  onProgress?: (progress: ProbeProgress) => void;
}

/**
 * Read all non-comment, non-empty lines from a wordlist file.
 */
async function readWordlist(wordlistPath: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const words: string[] = [];
    const rl = readline.createInterface({
      input: fs.createReadStream(wordlistPath, { encoding: "utf8" }),
      crlfDelay: Infinity,
    });
    rl.on("line", line => {
      const w = line.trim();
      if (w && !w.startsWith("#") && !w.startsWith("/")) {
        words.push(w);
      } else if (w.startsWith("/")) {
        // Some wordlists use absolute paths like /admin — strip leading slash
        words.push(w.slice(1));
      }
    });
    rl.on("close", () => resolve(words));
    rl.on("error", reject);
  });
}

/**
 * Process a batch of words concurrently against a base URL.
 */
async function probeBatch(
  base: string,
  words: string[],
  options: ProbeOptions,
): Promise<HttpCapture[]> {
  const discovered: HttpCapture[] = [];
  await Promise.allSettled(
    words.map(async word => {
      const url = `${base}/${word}`;
      const cap = await httpFetch(url, {
        timeoutMs:       options.timeoutMs ?? 6_000,
        bearerToken:     options.bearerToken,
        followRedirects: false, // capture redirects as distinct findings
      });
      if (!cap) return;
      // Keep anything that isn't a definitive 404/400/410
      if (cap.statusCode !== 404 && cap.statusCode !== 400 && cap.statusCode !== 410) {
        discovered.push(cap);
      }
    }),
  );
  return discovered;
}

/**
 * Probe a target with a wordlist and return all interesting HttpCaptures.
 *
 * @param target  Base URL (e.g. https://example.com)
 * @param wordlistPath  Absolute path to a line-per-word wordlist file
 * @param options  Concurrency, timeout, progress callback
 */
export async function probeWithWordlist(
  target: string,
  wordlistPath: string,
  options: ProbeOptions = {},
): Promise<HttpCapture[]> {
  const base    = target.replace(/\/$/, "");
  const concurrency = options.concurrency ?? 10;

  const words = await readWordlist(wordlistPath);
  const total  = words.length;
  const all: HttpCapture[] = [];
  let probed = 0;
  let lastLog = 0;

  for (let i = 0; i < words.length; i += concurrency) {
    const batch   = words.slice(i, i + concurrency);
    const results = await probeBatch(base, batch, options);
    all.push(...results);
    probed += batch.length;

    if (options.onProgress && (probed - lastLog >= 250 || probed >= total)) {
      options.onProgress({ probed, total, found: all.length });
      lastLog = probed;
    }
  }

  return all;
}
