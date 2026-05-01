# Changelog

## 0.1.0 — 2026-05-01

Initial public release. Sender-side counterpart to a2a-acl.

### Added

- `signEnvelope(claims, keyMaterial, opts)` — build + sign an AAE
  envelope. Cross-peer-replay defence (`sub = receiver.did`),
  5-minute lifetime cap, randomised `jti` per call, exports
  `signablePayload` + `SIGNED_FIELDS` from a2a-acl for cross-language
  signer compatibility.
- `loadSigningKey(seed)` — load a 32-byte Ed25519 seed (Buffer or
  base64url string) into a Node KeyObject. Throws loudly on
  wrong-length or wrong-type input.
- `IpRateLimiter` — sliding-window per `(ip, slug)` rate limiter with
  bucket-count cap. Same sweep/evict-oldest pattern as a2a-acl's
  per-(caller_did, slug) RateLimiter.
- `parseClaimedDid(headerValue)` — shape-validate a `X-Caller-DID`
  header without trusting it for auth. Returns the DID or null.
- `hashVisitor({ ip, userAgent, sessionId })` — derive a stable
  16-byte SHA-256 visitor identifier for audit.
- `captureCallerId(req, opts)` — Express helper that combines
  `parseClaimedDid` + `hashVisitor` + client-label capture.
- `buildAuditRow(...)` + `emitAudit({ sink, logger, row })` — audit
  row construction and fire-and-forget sink invocation. Sink
  rejections are logged at error level (audit-trail gaps are a
  security signal, not a warning).
- `publicChatMiddleware(cfg)` — Express middleware that composes
  the whole pipeline: resolve receiver → rate-limit → sanitise →
  capture caller-id → sign envelope → forward → stream response →
  emit audit.

### Strict defaults

- Audience required (default `'a2a-ingress'`).
- Cross-peer-replay defence on (envelope `sub` always set to receiver DID).
- Sanitiser on (`sanitise: true`).
- Per-IP rate limit on (default `requestsPerMinute: 30` if no rateLimiter passed).
- Bucket caps on rate limiter (100k IPs).
- Forward timeout on (default 30s).
- Body in audit OFF — only metadata.
- Raw IP in audit OFF — only the visitor hash.
- Receiver `Set-Cookie` / CORS headers stripped — they belong to the
  receiver/portal trust boundary, not the visitor's browser.

### Compatibility

Tested end-to-end against `a2a-acl@0.1.4`. Re-exports `signablePayload`
+ `SIGNED_FIELDS` from a2a-acl so cross-language signers reproduce
identical canonical bytes.
