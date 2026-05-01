// Caller-identity capture for the public-chat path.
//
// The visitor is unauthenticated — the portal signs envelopes on their
// behalf. But we want a stable identity to record in audit so receivers
// can:
//   1. Distinguish individual sessions / clients in their audit log.
//   2. Add per-DID ACL grants over time as a specific external caller
//      builds up a clean reputation (e.g. "this Claude session DID has
//      sent 100 polite messages over a week — grant it read_memory:public").
//
// Two complementary sources:
//   - X-Caller-DID header   — opt-in self-declaration. Validated for
//                             shape but NOT cryptographically verified.
//                             Audit-only signal. The caller's DID still
//                             can't sign envelopes the receiver will
//                             accept (that requires klaw-side key
//                             registration).
//   - Visitor hash          — server-derived from (ip, user-agent,
//                             session_id?). Stable per session but
//                             reveals nothing about the visitor.
//
// We do NOT include the raw IP in the audit record — only the hash.
// Operators who need the IP for incident response can keep it in the
// upstream proxy log; this library deliberately doesn't propagate it.

import { createHash } from 'node:crypto';

// Same shape a2a-acl validates against. Don't trust attacker-supplied
// strings as DIDs without shape validation; they end up in audit logs
// + downstream ACL queries.
const DID_PATTERN = /^did:[a-z0-9]{1,32}:[A-Za-z0-9._-]{1,256}$/;
const MAX_HEADER_LEN = 256;

/**
 * Parse + validate the X-Caller-DID header. Returns the DID string if
 * it matches DID_PATTERN, else null. Never throws — bad headers are
 * silently dropped (audit-only signal).
 */
export function parseClaimedDid(headerValue) {
  if (typeof headerValue !== 'string') return null;
  if (headerValue.length === 0 || headerValue.length > MAX_HEADER_LEN) return null;
  if (!DID_PATTERN.test(headerValue)) return null;
  return headerValue;
}

/**
 * Derive a stable visitor hash from request fingerprint. Same visitor
 * (same IP + UA + session) gets the same hash within a process; cross-
 * process / cross-deployment determinism is not required.
 *
 * Inputs are coerced to strings; missing fields contribute empty.
 * Output is a hex-encoded SHA-256 truncated to 32 hex chars
 * (16 bytes of entropy — plenty for audit deduplication, not enough
 * to be a stable cross-system identifier).
 */
export function hashVisitor({ ip, userAgent, sessionId } = {}) {
  const h = createHash('sha256');
  h.update(String(ip ?? ''));
  h.update('|');
  h.update(String(userAgent ?? ''));
  h.update('|');
  h.update(String(sessionId ?? ''));
  return h.digest('hex').slice(0, 32);
}

/**
 * Build the standard caller-id record from an Express request.
 * Centralised so audit + rate-limit + middleware all agree on what
 * "this caller" means for a given HTTP request.
 *
 * @param {object} req
 * @param {object} [opts]
 *   @param {string} [opts.didHeaderName='x-caller-did']
 *   @param {string} [opts.clientHeaderName='x-ownify-client']
 *   @param {(req: object) => string|null} [opts.getSessionId]
 */
export function captureCallerId(req, opts = {}) {
  const didHeader = opts.didHeaderName ?? 'x-caller-did';
  const clientHeader = opts.clientHeaderName ?? 'x-ownify-client';
  const getSessionId = opts.getSessionId ?? ((r) => r.session?.id ?? null);

  const claimedDid = parseClaimedDid(req.get?.(didHeader) ?? req.headers?.[didHeader]);
  const client = req.get?.(clientHeader) ?? req.headers?.[clientHeader] ?? null;
  const ip = req.ip ?? req.connection?.remoteAddress ?? null;
  const userAgent = req.get?.('user-agent') ?? req.headers?.['user-agent'] ?? null;
  let sessionId;
  try { sessionId = getSessionId(req); } catch { sessionId = null; }

  return {
    claimed_did: claimedDid,
    client: typeof client === 'string' && client.length <= MAX_HEADER_LEN ? client : null,
    visitor_hash: hashVisitor({ ip, userAgent, sessionId }),
  };
}
