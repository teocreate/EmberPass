/**
 * Fixed-window rate limiter kept in process memory. Good enough for a single
 * instance; behind several instances this belongs in Redis or in PostgreSQL.
 */
export class RateLimiter {
  constructor({ limit, windowMs }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.hits = new Map();
  }

  /** Returns { allowed, remaining, retryAfter } and counts the attempt. */
  check(key, now = Date.now()) {
    const entry = this.hits.get(key);
    if (!entry || now >= entry.resetAt) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, remaining: this.limit - 1, retryAfter: 0 };
    }
    entry.count++;
    if (entry.count > this.limit) {
      return { allowed: false, remaining: 0, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    return { allowed: true, remaining: this.limit - entry.count, retryAfter: 0 };
  }

  reset(key) {
    this.hits.delete(key);
  }

  /** Drops expired windows; call periodically so the map cannot grow forever. */
  sweep(now = Date.now()) {
    for (const [key, entry] of this.hits) if (now >= entry.resetAt) this.hits.delete(key);
  }
}
