// Per-IP sliding-window rate limiter for the public-chat path.
//
// Distinct from a2a-acl's RateLimiter which keys on (caller_did, slug).
// At the public-chat layer the caller_did doesn't yet exist (the
// receiver-side ACL's caller is *us*, the portal); the actual abuse
// vector is "one IP floods the chat endpoint." So we key on IP +
// receiver-slug here, then a2a-acl's per-(portal_did, slug) limit kicks
// in upstream as a global ceiling.
//
// Bucket count is bounded — under attacker-controlled IP floods the
// oldest bucket is evicted. Trade-off: a real visitor whose bucket
// gets evicted under flood gets a fresh window. Acceptable: degraded
// rate-limiting beats service denial. Set maxBuckets based on
// legitimate traffic; see SECURITY.md for sizing guidance.

const SWEEP_INTERVAL_MS = 60_000;

export class IpRateLimiter {
  constructor({ requestsPerMinute, maxBuckets = 100_000 } = {}) {
    if (!Number.isFinite(requestsPerMinute) || requestsPerMinute <= 0) {
      throw new Error('requestsPerMinute must be a positive number');
    }
    if (!Number.isFinite(maxBuckets) || maxBuckets <= 0) {
      throw new Error('maxBuckets must be a positive number');
    }
    this.limit = requestsPerMinute;
    this.maxBuckets = maxBuckets;
    this.windowMs = 60_000;
    this.buckets = new Map();
    this.sweepInterval = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
    if (this.sweepInterval.unref) this.sweepInterval.unref();
  }

  /**
   * Atomic check-and-record. Returns true if the request is allowed
   * and records it. False if it would exceed the limit.
   *
   * key shape: typically `${ip}|${slug}` — but JSON-encoded to defend
   * against an IP that contains the chosen separator.
   */
  consume(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    let bucket = this.buckets.get(key);
    if (!bucket) {
      // Bucket cap — sweep first, then evict oldest by Map insertion order.
      if (this.buckets.size >= this.maxBuckets) {
        this.sweep();
        if (this.buckets.size >= this.maxBuckets) {
          const oldest = this.buckets.keys().next().value;
          this.buckets.delete(oldest);
        }
      }
      bucket = [];
      this.buckets.set(key, bucket);
    }
    // Splice once instead of shift() in a loop — O(n) vs O(n²) per call.
    if (bucket.length > 0 && bucket[0] < cutoff) {
      let idx = 0;
      while (idx < bucket.length && bucket[idx] < cutoff) idx += 1;
      bucket.splice(0, idx);
    }
    if (bucket.length >= this.limit) return false;
    bucket.push(now);
    return true;
  }

  sweep() {
    const cutoff = Date.now() - this.windowMs;
    for (const [k, bucket] of this.buckets) {
      if (bucket.length > 0 && bucket[0] < cutoff) {
        let idx = 0;
        while (idx < bucket.length && bucket[idx] < cutoff) idx += 1;
        bucket.splice(0, idx);
      }
      if (bucket.length === 0) this.buckets.delete(k);
    }
  }

  size() { return this.buckets.size; }
  stop() { clearInterval(this.sweepInterval); }

  /**
   * Build a rate-limit key from a request + receiver slug. Use
   * JSON.stringify so an IP containing the separator (highly unusual
   * for IPs but trivial to keep safe) can't collide with another
   * (ip, slug) tuple.
   */
  static keyOf(ip, slug) {
    return JSON.stringify([String(ip), String(slug)]);
  }
}
