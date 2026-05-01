// publicChatMiddleware — Express middleware that turns an unauthenticated
// HTTP POST into a properly-signed AAE request to a receiver gateway.
//
// Pipeline per request:
//   1. Resolve receiver (caller-supplied callback): slug → { did, url }
//      Fail with 404 if the receiver is unknown.
//   2. Per-IP rate-limit (per-(ip, slug)). 429 on overflow.
//   3. Optional sanitisation of req.body (a2a-acl exports sanitiseDeep).
//   4. Capture caller-id (X-Caller-DID + visitor hash) for audit.
//   5. Sign an AAE envelope on the portal's behalf (this library's DID).
//   6. POST to receiver.url with the envelope in X-AAE.
//   7. Stream the receiver's response back to the visitor.
//   8. Fire audit row to caller-supplied sink.
//
// Things this middleware deliberately does NOT do:
//   - Authentication of the visitor. The whole point is unauth.
//   - Bearer-token swap-over-mid-flight. If you want auth, use a
//     separate route with auth middleware in front of this one.
//   - Long-running streaming. Each request is one POST → one response.
//   - Caching. The receiver decides what's cacheable; we just forward.

import { sanitiseDeep } from 'a2a-acl';
import { signEnvelope } from './envelope.js';
import { IpRateLimiter } from './ip-rate-limit.js';
import { captureCallerId } from './caller-id.js';
import { buildAuditRow, emitAudit } from './audit.js';

const DEFAULT_AUD = 'a2a-ingress';
const DEFAULT_HEADER_NAME = 'X-AAE';
const DEFAULT_FORWARD_TIMEOUT_MS = 30_000;

function defaultSlugFromParams(req) {
  return req.params?.slug ?? null;
}

/**
 * @param {object} cfg
 *   @param {(slug: string) => Promise<{did: string, url: string} | null>} cfg.resolveReceiver
 *      Caller-supplied lookup. Return null for unknown receivers (→ 404).
 *   @param {string} cfg.callerDid
 *      The DID this library signs as. Typically your portal's own DID
 *      registered with MolTrust (or your own identity registry).
 *   @param {object} cfg.signingKey
 *      Result of loadSigningKey(seed). The private key never leaves
 *      the process — we only ever sign with it.
 *   @param {string} cfg.callerSigKeyId
 *      The key_id the receiver will resolve to your public key. Convention:
 *      whatever your receiver's KeyResolver uses to look up your pubkey.
 *
 *   @param {object} [cfg.rateLimiter]   — IpRateLimiter instance (or compatible). Constructed lazily if absent.
 *   @param {number} [cfg.requestsPerMinute=30] — used only if no rateLimiter passed
 *
 *   @param {(req: object) => string|null} [cfg.getSlug] — defaults to req.params.slug
 *   @param {string} [cfg.aud='a2a-ingress'] — must match the receiver's expectedAud
 *   @param {string} [cfg.envelopeHeader='X-AAE'] — header name to send the envelope in
 *   @param {boolean} [cfg.sanitise=true] — strip prompt-injection markers from req.body before forward
 *   @param {number} [cfg.forwardTimeoutMs=30000] — fetch timeout to receiver
 *
 *   @param {object} [cfg.callerIdOpts] — passed to captureCallerId()
 *
 *   @param {(row: object) => void|Promise<void>} [cfg.sink] — audit sink
 *   @param {object} [cfg.logger] — pino-style { info, warn, error }
 */
export function publicChatMiddleware(cfg) {
  if (!cfg || typeof cfg !== 'object') throw new Error('publicChatMiddleware requires a config object');
  if (typeof cfg.resolveReceiver !== 'function') throw new Error('cfg.resolveReceiver callback required');
  if (typeof cfg.callerDid !== 'string' || cfg.callerDid.length === 0) throw new Error('cfg.callerDid required');
  if (!cfg.signingKey || !cfg.signingKey.key) throw new Error('cfg.signingKey required (call loadSigningKey first)');
  if (typeof cfg.callerSigKeyId !== 'string' || cfg.callerSigKeyId.length === 0) throw new Error('cfg.callerSigKeyId required');

  const rateLimiter = cfg.rateLimiter ?? new IpRateLimiter({
    requestsPerMinute: cfg.requestsPerMinute ?? 30,
  });
  const getSlug = cfg.getSlug ?? defaultSlugFromParams;
  const aud = cfg.aud ?? DEFAULT_AUD;
  const envelopeHeader = cfg.envelopeHeader ?? DEFAULT_HEADER_NAME;
  const sanitiseEnabled = cfg.sanitise !== false;
  const forwardTimeoutMs = cfg.forwardTimeoutMs ?? DEFAULT_FORWARD_TIMEOUT_MS;
  const callerIdOpts = cfg.callerIdOpts ?? {};
  const logger = cfg.logger ?? null;

  return async function publicChat(req, res) {
    const slug = getSlug(req);
    if (!slug || typeof slug !== 'string') {
      return res.status(400).json({ error: 'missing_slug' });
    }

    // 1. Receiver lookup
    let receiver;
    try {
      receiver = await cfg.resolveReceiver(slug);
    } catch (err) {
      logger?.error?.({ err: err?.message, slug }, 'resolveReceiver threw');
      return res.status(503).json({ error: 'receiver_lookup_unavailable' });
    }
    if (!receiver) {
      return res.status(404).json({ error: 'receiver_not_found' });
    }
    if (typeof receiver.did !== 'string' || typeof receiver.url !== 'string') {
      logger?.error?.({ slug }, 'resolveReceiver returned malformed receiver');
      return res.status(500).json({ error: 'receiver_misconfigured' });
    }

    // 2. Per-IP rate limit
    const ip = req.ip ?? req.connection?.remoteAddress ?? 'unknown';
    const rlKey = IpRateLimiter.keyOf(ip, slug);
    if (!rateLimiter.consume(rlKey)) {
      const callerIdEarly = captureCallerId(req, callerIdOpts);
      emitAudit({
        sink: cfg.sink, logger,
        row: buildAuditRow({
          receiverSlug: slug,
          callerDid: cfg.callerDid,
          claimedDid: callerIdEarly.claimed_did,
          visitorHash: callerIdEarly.visitor_hash,
          client: callerIdEarly.client,
          rateLimited: true,
        }),
      });
      return res.status(429).json({ error: 'rate_limit_exceeded' });
    }

    // 3. Sanitise (if enabled). Body must be JSON-parsed already
    //    (mount express.json() before this middleware).
    if (sanitiseEnabled && req.body && typeof req.body === 'object') {
      const { value, hits } = sanitiseDeep(req.body);
      req.body = value;
      if (hits > 0) {
        logger?.warn?.({ slug, hits }, 'public-chat payload sanitised');
      }
    }

    // 4. Capture caller-id for audit
    const callerId = captureCallerId(req, callerIdOpts);

    // 5. Sign envelope on portal's behalf. We pass receiver.did as `sub`
    //    so the receiver-side `expectedSub` validation (cross-peer
    //    replay defence) accepts it: an envelope built for receiver A
    //    cannot be replayed against receiver B.
    let envelope;
    try {
      envelope = signEnvelope({
        iss: cfg.callerDid,
        sub: receiver.did,
        aud,
        sig_key_id: cfg.callerSigKeyId,
      }, cfg.signingKey);
    } catch (err) {
      logger?.error?.({ err: err?.message, slug }, 'envelope signing failed');
      return res.status(500).json({ error: 'envelope_signing_failed' });
    }

    // 6. Forward to receiver
    let upstream;
    let upstreamBody;
    let upstreamStatus = null;
    try {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), forwardTimeoutMs);
      try {
        upstream = await fetch(receiver.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            [envelopeHeader]: envelope,
          },
          body: JSON.stringify(req.body ?? {}),
          signal: ac.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      upstreamStatus = upstream.status;
      upstreamBody = await upstream.text();
    } catch (err) {
      logger?.error?.({ err: err?.message, slug, url: receiver.url }, 'forward to receiver failed');
      emitAudit({
        sink: cfg.sink, logger,
        row: buildAuditRow({
          receiverSlug: slug,
          callerDid: cfg.callerDid,
          claimedDid: callerId.claimed_did,
          visitorHash: callerId.visitor_hash,
          client: callerId.client,
          jti: extractJtiFromEnvelope(envelope),
          upstreamStatus: 0,
        }),
      });
      return res.status(502).json({ error: 'receiver_unreachable' });
    }

    // 7. Stream response back. Don't echo upstream-set CORS or
    //    Set-Cookie — those belong to the receiver-portal trust
    //    boundary, not the visitor's browser.
    res.status(upstream.status);
    const ct = upstream.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);
    res.send(upstreamBody);

    // 8. Audit
    emitAudit({
      sink: cfg.sink, logger,
      row: buildAuditRow({
        receiverSlug: slug,
        callerDid: cfg.callerDid,
        claimedDid: callerId.claimed_did,
        visitorHash: callerId.visitor_hash,
        client: callerId.client,
        jti: extractJtiFromEnvelope(envelope),
        upstreamStatus,
      }),
    });
  };
}

// Pull jti from a base64url-encoded envelope without re-importing the
// verifier. Best-effort — used for audit only, returns null on any
// parse error rather than throwing.
function extractJtiFromEnvelope(envelopeStr) {
  try {
    const json = Buffer.from(
      envelopeStr.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    ).toString('utf8');
    const parsed = JSON.parse(json);
    return typeof parsed?.jti === 'string' ? parsed.jti : null;
  } catch {
    return null;
  }
}
