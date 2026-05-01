// publicChatMiddleware — Express middleware that turns an unauthenticated
// HTTP POST into a properly-signed AAE request to a receiver gateway.
//
// Pipeline per request:
//   1. Resolve receiver (caller-supplied callback): slug → { did, url }
//      Fail with 404 if the receiver is unknown OR if the receiver
//      shape / DID / URL is malformed (collapsed to 404 deliberately
//      to prevent slug-existence enumeration via status code).
//   2. Validate receiver.url — block non-http(s), private/loopback IPs,
//      and (if configured) any host outside the allowlist (SSRF defence).
//   3. Per-IP rate-limit (per-(ip, slug)). 429 on overflow.
//   4. Body size guard. 413 if oversized.
//   5. Optional sanitisation of req.body (a2a-acl exports sanitiseDeep).
//   6. Capture caller-id (X-Caller-DID + visitor hash) for audit.
//   7. Sign an AAE envelope on the portal's behalf (this library's DID).
//   8. POST to receiver.url with the envelope in X-AAE.
//   9. Stream the receiver's response back to the visitor.
//  10. Fire audit row to caller-supplied sink.
//
// IP-source caveat: req.ip resolves from X-Forwarded-For when Express
// trust proxy is enabled. This middleware reads req.ip directly. You
// MUST deploy behind a reverse proxy you control AND set Express
// trust proxy to that proxy's exact CIDR — never `true` blindly. See
// README.md "Deployment requirements".

import { sanitiseDeep } from 'a2a-acl';
import { signEnvelope } from './envelope.js';
import { IpRateLimiter } from './ip-rate-limit.js';
import { captureCallerId } from './caller-id.js';
import { buildAuditRow, emitAudit } from './audit.js';
import { validateReceiverUrl } from './url-validation.js';

const DEFAULT_AUD = 'a2a-ingress';
const DEFAULT_HEADER_NAME = 'X-AAE';
const DEFAULT_FORWARD_TIMEOUT_MS = 30_000;
const DEFAULT_RESOLVE_RECEIVER_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;          // 64 KiB request body cap
const DEFAULT_MAX_RESPONSE_BODY_BYTES = 1 * 1024 * 1024;  // 1 MiB response body cap
const DEFAULT_ALLOWED_PROTOCOLS = ['https:'];

// Accepts standard HTTP-token-flavoured header names. RFC 7230 token
// chars are broader, but for envelope headers we only need
// alphanumerics + '-' + '_'. Restrictive enough to refuse smuggling
// attempts (newlines, colons, control chars) without false-positives
// on real-world envelope header names like X-AAE / X-Klaw-AAE.
const HEADER_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

// Default browser-hardening headers on the visitor-facing response.
// `default-src 'none'` on CSP is the strictest possible — blocks
// scripts, images, fetch, frames, etc. Appropriate for an API surface
// being proxied. If you proxy actual HTML through this middleware
// (rare), pass `responseSecurityHeaders: false` or a custom object.
const DEFAULT_RESPONSE_SECURITY_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
});

// Same shape the receiver-side a2a-acl validates — keep them locally
// so we don't depend on caller-id.js's regex (which is for header
// validation, conceptually distinct from receiver-DID validation
// even if the regex is the same).
const RECEIVER_DID_PATTERN = /^did:[a-z0-9]{1,32}:[A-Za-z0-9._-]{1,256}$/;

function defaultSlugFromParams(req) {
  return req.params?.slug ?? null;
}

function clampHttpStatus(n) {
  // Defends against res.status() throwing on non-standard upstream codes.
  // Express only accepts 100-999. fetch() can in principle hand back
  // anything if the upstream is broken; we treat anything outside
  // 100-599 as "upstream produced garbage" → 502.
  if (Number.isInteger(n) && n >= 100 && n <= 599) return n;
  return 502;
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
 *      The key_id the receiver will resolve to your public key.
 *
 *   @param {string[]} [cfg.allowedReceiverHosts]
 *      SSRF defence — if set, receiver.url's hostname must match at
 *      least one entry (exact or '*.example.com' wildcard). Strongly
 *      recommended for production.
 *   @param {string[]} [cfg.allowedProtocols=['https:']]
 *      Permitted URL protocols. Add 'http:' only for local dev.
 *   @param {boolean} [cfg.allowPrivateHosts=false]
 *      Skip the private-IP / loopback check. Set true only for tests.
 *
 *   @param {object} [cfg.rateLimiter]   — IpRateLimiter instance. Constructed lazily if absent.
 *   @param {number} [cfg.requestsPerMinute=30] — used only if no rateLimiter passed
 *
 *   @param {(req: object) => string|null} [cfg.getSlug] — defaults to req.params.slug
 *   @param {string} [cfg.aud='a2a-ingress'] — must match the receiver's expectedAud
 *   @param {string} [cfg.envelopeHeader='X-AAE'] — header name to send the envelope in
 *   @param {boolean} [cfg.sanitise=true] — strip prompt-injection markers before forward (mutates req.body)
 *   @param {number} [cfg.maxBodyBytes=65536] — hard ceiling on serialized request body size; 413 if exceeded
 *   @param {number} [cfg.forwardTimeoutMs=30000] — covers BOTH the request and body-read phases of the upstream call
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
  const resolveReceiverTimeoutMs = cfg.resolveReceiverTimeoutMs ?? DEFAULT_RESOLVE_RECEIVER_TIMEOUT_MS;
  const maxBodyBytes = cfg.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const maxResponseBodyBytes = cfg.maxResponseBodyBytes ?? DEFAULT_MAX_RESPONSE_BODY_BYTES;
  const callerIdOpts = cfg.callerIdOpts ?? {};
  const logger = cfg.logger ?? null;
  const urlValidationOpts = {
    allowedReceiverHosts: cfg.allowedReceiverHosts,
    allowedReceiverPorts: cfg.allowedReceiverPorts,
    deniedReceiverPorts: cfg.deniedReceiverPorts,
    allowedProtocols: cfg.allowedProtocols ?? DEFAULT_ALLOWED_PROTOCOLS,
    allowPrivateHosts: cfg.allowPrivateHosts === true,
  };
  // Compose response security headers. `false` opts out entirely
  // (operator's choice); an object merges with defaults so callers
  // can override one header without losing the others.
  let responseSecurityHeaders;
  if (cfg.responseSecurityHeaders === false) {
    responseSecurityHeaders = {};
  } else if (cfg.responseSecurityHeaders && typeof cfg.responseSecurityHeaders === 'object') {
    responseSecurityHeaders = { ...DEFAULT_RESPONSE_SECURITY_HEADERS, ...cfg.responseSecurityHeaders };
  } else {
    responseSecurityHeaders = { ...DEFAULT_RESPONSE_SECURITY_HEADERS };
  }

  // Construct-time validation
  if (!HEADER_NAME_PATTERN.test(envelopeHeader)) {
    throw new Error(`cfg.envelopeHeader must match ${HEADER_NAME_PATTERN} — newlines/colons/control chars enable header injection`);
  }
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new Error('cfg.maxBodyBytes must be a positive integer');
  }
  if (!Number.isInteger(maxResponseBodyBytes) || maxResponseBodyBytes <= 0) {
    throw new Error('cfg.maxResponseBodyBytes must be a positive integer');
  }
  if (!Number.isFinite(resolveReceiverTimeoutMs) || resolveReceiverTimeoutMs <= 0) {
    throw new Error('cfg.resolveReceiverTimeoutMs must be a positive number');
  }

  return async function publicChat(req, res) {
    const slug = getSlug(req);
    if (!slug || typeof slug !== 'string') {
      return res.status(400).json({ error: 'missing_slug' });
    }

    // 1. Receiver lookup. Wrapped in a hard timeout so a slow callback
    //    (DB stall, RPC hang) can't pin a request handler indefinitely
    //    — slowloris-style DoS via the resolveReceiver path.
    let receiver;
    try {
      let timer;
      const timeoutP = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('resolveReceiver_timeout')), resolveReceiverTimeoutMs);
      });
      try {
        receiver = await Promise.race([
          Promise.resolve(cfg.resolveReceiver(slug)),
          timeoutP,
        ]);
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      const isTimeout = err?.message === 'resolveReceiver_timeout';
      logger?.error?.({ err: err?.message, slug, timeout: isTimeout }, 'resolveReceiver failed');
      return res.status(isTimeout ? 504 : 503).json({
        error: isTimeout ? 'receiver_lookup_timeout' : 'receiver_lookup_unavailable',
      });
    }
    if (!receiver) {
      return res.status(404).json({ error: 'receiver_not_found' });
    }
    if (typeof receiver.did !== 'string' || typeof receiver.url !== 'string'
        || !RECEIVER_DID_PATTERN.test(receiver.did)) {
      // Operator-side bug — log loudly server-side, but return 404 to
      // the client so an attacker can't enumerate "exists but broken"
      // versus "doesn't exist". Same status as the unknown-slug case.
      logger?.error?.({ slug, didShape: typeof receiver.did }, 'resolveReceiver returned malformed receiver — fix your callback');
      return res.status(404).json({ error: 'receiver_not_found' });
    }

    // 2. SSRF defence — validate receiver.url before any network call
    const urlCheck = validateReceiverUrl(receiver.url, urlValidationOpts);
    if (!urlCheck.ok) {
      // Same 404 collapse as above for the same reason.
      logger?.error?.({ slug, reason: urlCheck.reason }, 'resolveReceiver returned blocked URL — fix your callback');
      return res.status(404).json({ error: 'receiver_not_found' });
    }
    const validatedUrl = urlCheck.url.toString();

    // 3. Per-IP rate limit
    // IMPORTANT: req.ip is X-Forwarded-For-derived when Express trust
    // proxy is enabled. Deploy behind a reverse proxy you control and
    // set trust proxy to that proxy's exact CIDR — never `true`
    // blindly. See README.md.
    //
    // The 'unknown' fallback fires only if Express has no IP info at
    // all (broken / very unusual deployment). All such requests
    // share one rate-limit bucket — fail-closed by design. The
    // alternative (random per-request fallback) would let attackers
    // strip IP headers to bypass rate-limit entirely.
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

    // 4. Body size guard. We rely on upstream express.json() having
    //    already parsed and rejected oversized payloads, but defend in
    //    depth — a forgotten { limit } leaves Express 4 unbounded.
    let serializedBody;
    try {
      serializedBody = JSON.stringify(req.body ?? {});
    } catch (err) {
      logger?.warn?.({ slug, err: err?.message }, 'request body not serializable');
      return res.status(400).json({ error: 'body_not_serializable' });
    }
    if (Buffer.byteLength(serializedBody, 'utf8') > maxBodyBytes) {
      return res.status(413).json({ error: 'payload_too_large', max_bytes: maxBodyBytes });
    }

    // 5. Sanitise (if enabled). Mutates req.body in place.
    if (sanitiseEnabled && req.body && typeof req.body === 'object') {
      const { value, hits } = sanitiseDeep(req.body);
      req.body = value;
      if (hits > 0) {
        logger?.warn?.({ slug, hits }, 'public-chat payload sanitised');
        // Re-serialize after mutation so the bytes we forward match
        // the (smaller) sanitised payload.
        serializedBody = JSON.stringify(req.body ?? {});
      }
    }

    // 6. Capture caller-id for audit
    const callerId = captureCallerId(req, callerIdOpts);

    // 7. Sign envelope on portal's behalf. We pass receiver.did as `sub`
    //    so the receiver-side `expectedSub` validation rejects an
    //    envelope built for receiver A replayed against receiver B.
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

    // 8. Forward to receiver. The single AbortController spans BOTH
    //    the request and body-read phases — clearing the timer too
    //    early would let a slow upstream stall the body read
    //    indefinitely.
    let upstream;
    let upstreamBody;
    let upstreamStatus = null;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), forwardTimeoutMs);
    try {
      upstream = await fetch(validatedUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          [envelopeHeader]: envelope,
        },
        body: serializedBody,
        signal: ac.signal,
        // SSRF defence #2: NEVER follow redirects. validateReceiverUrl
        // ran against the URL we were handed; a 3xx Location pointing
        // at a private IP / disallowed host would bypass that check
        // entirely if we followed it. Receivers should return their
        // final URL from resolveReceiver, never one that redirects.
        redirect: 'error',
      });
      upstreamStatus = upstream.status;
      // Stream-read the response body with a hard size cap. text()
      // would buffer the entire response; a fast malicious upstream
      // can stream multi-GB inside the forward timeout and exhaust
      // process memory. Abort the fetch as soon as the cap is hit.
      const reader = upstream.body?.getReader?.();
      if (reader) {
        const chunks = [];
        let total = 0;
        let truncated = false;
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > maxResponseBodyBytes) {
            try { ac.abort(); } catch { /* ignore */ }
            try { await reader.cancel(); } catch { /* ignore */ }
            truncated = true;
            break;
          }
          chunks.push(value);
        }
        if (truncated) {
          throw new Error('upstream_body_too_large');
        }
        upstreamBody = Buffer.concat(chunks).toString('utf8');
      } else {
        // No streaming body (e.g. HEAD-style upstream). Empty body.
        upstreamBody = '';
      }
    } catch (err) {
      const tooLarge = err?.message === 'upstream_body_too_large';
      logger?.error?.({ err: err?.message, slug, url: validatedUrl, tooLarge }, 'forward to receiver failed');
      emitAudit({
        sink: cfg.sink, logger,
        row: buildAuditRow({
          receiverSlug: slug,
          callerDid: cfg.callerDid,
          claimedDid: callerId.claimed_did,
          visitorHash: callerId.visitor_hash,
          client: callerId.client,
          jti: extractJtiFromEnvelope(envelope),
          upstreamStatus: tooLarge ? upstreamStatus : 0,
        }),
      });
      return res.status(502).json({
        error: tooLarge ? 'upstream_body_too_large' : 'receiver_unreachable',
        ...(tooLarge ? { max_bytes: maxResponseBodyBytes } : {}),
      });
    } finally {
      clearTimeout(timer);
    }

    // 9. Stream response back. Don't echo upstream-set CORS or
    //    Set-Cookie — those belong to the receiver/portal trust
    //    boundary, not the visitor's browser. Clamp the upstream
    //    status to a valid HTTP range; non-standard codes from a
    //    broken upstream become 502 rather than crashing res.status().
    //    Hardcode X-Content-Type-Options: nosniff so a compromised /
    //    misconfigured receiver returning text/html with active
    //    content can't be MIME-sniffed and executed by the visitor's
    //    browser.
    res.status(clampHttpStatus(upstreamStatus));
    for (const [name, value] of Object.entries(responseSecurityHeaders)) {
      res.setHeader(name, value);
    }
    const ct = upstream.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);
    res.send(upstreamBody);

    // 10. Audit
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
// parse error rather than throwing. replaceAll instead of regex so the
// pattern doesn't get copy-pasted into a code path that processes
// attacker input (CodeQL js/polynomial-redos hygiene — same fix as
// b64url in envelope.js).
function extractJtiFromEnvelope(envelopeStr) {
  try {
    const json = Buffer.from(
      envelopeStr.replaceAll('-', '+').replaceAll('_', '/'),
      'base64',
    ).toString('utf8');
    const parsed = JSON.parse(json);
    return typeof parsed?.jti === 'string' ? parsed.jti : null;
  } catch {
    return null;
  }
}
