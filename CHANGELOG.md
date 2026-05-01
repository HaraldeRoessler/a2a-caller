# Changelog

## 0.1.1 — 2026-05-01

Two external review rounds covering 12 + 7 findings respectively,
all in-scope items addressed in this release. Major themes: SSRF
defence, oversize/overrun caps, no-enumeration error responses,
documentation of deployment-layer requirements.

### Fixed

- **SSRF (HIGH)** — `receiver.url` from `resolveReceiver` is now
  parsed + validated before any `fetch()`. Default policy: https
  only, literal private/loopback/link-local/cloud-metadata IPs
  rejected. New `allowedReceiverHosts` config tightens to specific
  hostnames or `*.example.com` wildcards. New `allowedProtocols`
  + `allowPrivateHosts` config for explicit dev/test relaxation.
  New `validateReceiverUrl` + `isPrivateOrLoopbackHost` exports
  for callers who want to apply the same checks elsewhere.
- **Body-read timeout (MED)** — `forwardTimeoutMs` now spans the
  ENTIRE upstream call including body read; `clearTimeout` moved
  to `finally` so a slow upstream that stalls mid-body can no
  longer pin a request handler.
- **Status-handling crash (MED)** — non-standard upstream HTTP
  codes (`<100` / `>599` / non-integer) now clamp to 502 rather
  than throwing in `res.status()`.
- **Receiver DID validation (MED)** — `receiver.did` is shape-
  checked against the same DID regex used for headers BEFORE
  signing. Junk DIDs no longer end up in the envelope `sub` claim.
- **Body size guard (LOW-MED)** — new `maxBodyBytes` config
  (default 64 KiB). Oversized requests get 413 before signing.
  Sanitiser-induced shrinkage is re-serialised so forwarded bytes
  match the cleaned payload.
- **Slug enumeration (LOW)** — malformed-receiver-callback path
  now returns `404 receiver_not_found` (same as unknown slug)
  rather than `500 receiver_misconfigured`. Operator-side bugs
  still log via `logger.error`.
- **Hop validation (LOW)** — `claims.hop` validated as integer
  in `[0, 10]`. NaN/Infinity/negative throw at sign time rather
  than slipping past the receiver-side `depthGuard` cap.
- **Sweep no-op when empty (LOW)** — `IpRateLimiter.sweep()`
  early-exits when `buckets.size === 0` so the periodic interval
  does no Map iteration on an idle limiter.
- **Regex hygiene (LOW)** — `extractJtiFromEnvelope` switched
  from `.replace(/-/g, '+')` to `.replaceAll('-', '+')` (same
  CodeQL `js/polynomial-redos` discipline as the b64url fix in
  0.1.0+1).
- **a2a-acl version range (LOW)** — `^0.1.4` → `~0.1.4` so
  unintended minor bumps can't drift the `signablePayload` /
  `SIGNED_FIELDS` contract that the receiver depends on.
- **`publishConfig.provenance: true`** added so future GitHub
  Actions–driven publishes surface npm provenance metadata for
  consumers to verify.

### Added — documentation

- README "Deployment requirements" section spelling out (a) the
  reverse-proxy + `trust proxy` setup needed for the per-IP rate
  limit to function, (b) the multi-replica caveat, (c) how to use
  `allowedReceiverHosts` for production. Marked "trust proxy: true"
  as forbidden in production with a callout.
- README documents that `sanitise: true` mutates `req.body` so
  downstream middleware sees the cleaned payload.
- SECURITY.md expanded "NOT defended" section: DNS rebinding,
  multi-replica rate-limit, X-Forwarded-For spoofing without a
  controlled proxy, npm provenance pre-Actions-workflow.

### Example

- `examples/express-server.js` — `trust proxy: true` → `'loopback'`
  with an inline explanation of why, plus a giant warning block
  on the in-process key generation that says "DEMO ONLY, never copy
  into production." Demo also opts into `allowPrivateHosts: true` +
  `allowedProtocols: ['http:', 'https:']` explicitly so the
  production defaults stay strict.

### Tests

- 75 tests passing (was 45). New coverage:
  - `url-validation.test.js` — 19 tests covering IPv4/IPv6 private
    ranges, cloud metadata, allowlist exact + wildcard match,
    case-insensitivity, malformed URLs.
  - `envelope.test.js` — 4 new tests for hop validation
    (negative, non-integer, oversized, valid range).
  - `middleware.test.js` — 7 new tests for SSRF rejection
    (private IP, cloud metadata, non-http protocol, allowlist
    miss), receiver.did shape rejection, body size guard,
    maxBodyBytes config validation.
- `node --test --test-force-exit` so the runner exits cleanly
  even when middleware leaves orphan `setInterval` handles
  (they're already `unref`'d but Node 22's runner doesn't always
  honour that signal in CI environments).

### Compatibility

Existing 0.1.0 consumers: response shape changed for the
"malformed receiver returned by your callback" case
(`500 receiver_misconfigured` → `404 receiver_not_found`).
Source-of-truth for the issue is now the server-side `logger.error`
line. All other API surfaces are additive.

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
