// Audit row builder for the public-chat path.
//
// One row per request. Caller-supplied sink decides where it lands
// (Postgres, Loki, console, /dev/null in tests). Sink may be sync or
// async; failures are logged at error level — a missing audit trail
// is a security signal, not a quiet warning.
//
// Sensitive fields the row deliberately does NOT contain:
//   - raw IP address          (only the visitor_hash)
//   - request body            (may contain user secrets / PII)
//   - response body           (same)
//   - signing key material    (never)
//
// What it DOES contain:
//   - timestamp
//   - receiver_slug           (which agent the request was forwarded to)
//   - caller_did              (the portal's signing DID — always us)
//   - claimed_did             (the X-Caller-DID self-declaration, if any)
//   - visitor_hash            (server-derived stable session hash)
//   - client                  (X-Ownify-Client / similar — UA-style label)
//   - jti                     (envelope nonce — useful for cross-referencing
//                              against a2a-acl's audit on the receiver)
//   - upstream_status         (HTTP status from the receiver gateway)
//   - rate_limited            (true if the request was rejected before forward)

export function buildAuditRow({
  receiverSlug,
  callerDid,
  claimedDid = null,
  visitorHash = null,
  client = null,
  jti = null,
  upstreamStatus = null,
  rateLimited = false,
}) {
  return {
    ts: new Date().toISOString(),
    receiver_slug: receiverSlug ?? null,
    caller_did: callerDid ?? null,
    claimed_did: claimedDid,
    visitor_hash: visitorHash,
    client,
    jti,
    upstream_status: upstreamStatus,
    rate_limited: !!rateLimited,
  };
}

export function emitAudit({ sink, logger = null, row }) {
  if (typeof sink === 'function') {
    try {
      Promise.resolve(sink(row)).catch((err) => {
        // Wrap the .error?.() call too — a logger proxy that throws
        // on .error access would otherwise re-throw inside an async
        // chain and surface as an unhandled rejection.
        try {
          logger?.error?.(
            { err: err?.message ?? String(err), row },
            'audit sink rejected — public-chat audit trail has gaps',
          );
        } catch { /* logger threw too — give up silently */ }
      });
    } catch (err) {
      try {
        logger?.error?.(
          { err: err?.message ?? String(err), row },
          'audit sink threw — public-chat audit trail has gaps',
        );
      } catch { /* logger threw too — give up silently */ }
    }
  }
  // logger.info() can throw if the caller passed a malicious /
  // mis-implemented logger proxy. Don't let that crash the request
  // handler — the audit trail's value isn't worth taking down the
  // service over.
  try {
    logger?.info?.(row, 'public-chat request');
  } catch { /* swallow logger failures */ }
}
