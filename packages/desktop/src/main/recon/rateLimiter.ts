/**
 * rateLimiter.ts — Simple token-bucket rate limiter for outbound HTTP requests.
 *
 * Usage:
 *   const limiter = new RateLimiter(30);  // 30 req/min
 *   await limiter.acquire();              // resolves when a slot is available
 *   await httpFetch(url, options);
 *
 * Thread-safe for single-process use (Node.js event loop).
 */

export class RateLimiter {
  private readonly intervalMs: number;
  private lastTick = 0;
  private queue: Array<() => void> = [];
  private timer: ReturnType<typeof setTimeout> | null = null;

  /**
   * @param requestsPerMinute Maximum requests to allow per minute.
   *   Values < 1 disable limiting. Values > 600 are clamped to 600.
   */
  constructor(public readonly requestsPerMinute: number) {
    const rpm = Math.min(600, Math.max(1, requestsPerMinute));
    this.intervalMs = Math.floor(60_000 / rpm);
  }

  /** Resolves when the caller is allowed to fire a request. */
  acquire(): Promise<void> {
    return new Promise<void>(resolve => {
      this.queue.push(resolve);
      if (!this.timer) this.schedule();
    });
  }

  private schedule(): void {
    const now = Date.now();
    const wait = Math.max(0, this.intervalMs - (now - this.lastTick));
    this.timer = setTimeout(() => {
      this.timer = null;
      const next = this.queue.shift();
      if (next) {
        this.lastTick = Date.now();
        next();
        if (this.queue.length > 0) this.schedule();
      }
    }, wait);
  }

  /** Discard any pending requests and stop the internal timer. */
  destroy(): void {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    this.queue = [];
  }
}

/** Convenience: create a no-op limiter that never waits. */
export const UNLIMITED: RateLimiter = new RateLimiter(600);
