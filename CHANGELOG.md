# Changelog

## 0.1.3 — 2026-05-01

Fourth review round (two reviewers, 9 unique findings — most edge-case;
two MEDIUM hardening items, the rest defence-in-depth). All in-scope
items addressed.

### Fixed

- **resolveReceiver slowloris (MED)** — the lookup callback is now
  wrapped in `Promise.race` against `resolveReceiverTimeoutMs` (default
  5000ms). Slow DB / RPC stalls no longer pin request handlers
  indefinitely. Timeout surfaces as `504 receiver_lookup_timeout`,
  generic failure as `503 receiver_lookup_unavailable`.
- **Unbounded upstream response body (MED)** — `upstream.text()`
  replaced with a streaming reader that tracks accumulated bytes
  and aborts the fetch + cancels the reader as soon as
  `maxResponseBodyBytes` (default 1 MiB) is exceeded. Surfaces as
  `502 upstream_body_too_large` with the cap value in the response.
- **IPv6 zone-ID SSRF bypass (MED)** — `isPrivateOrLoopbackHost`
  now strips `%zone` suffixes before `node:net.isIP()` so
  `fe80::1%eth0` correctly resolves to fe80::/10 link-local
  classification. Hostnames with `%` that don't otherwise resolve
  to a recognised IP class are also rejected as suspect (defence
  in depth).
- **localhost / ip6-localhost not blocked (LOW)** — explicit
  set-membership check at the top of `isPrivateOrLoopbackHost`
  for `localhost`, `localhost.localdomain`, `ip6-localhost`,
  `ip6-loopback`. Previously these passed because they're DNS
  names, not IP literals — only the port denylist was protecting
  http://localhost:NNN/ deployments.
- **Default response security headers (LOW)** — `X-Frame-Options:
  DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors
  'none'`, `Referrer-Policy: no-referrer` now hard-coded on every
  visitor response alongside the existing `nosniff`. Override via
  `cfg.responseSecurityHeaders` (object merges with defaults; pass
  `false` to disable entirely if you proxy actual HTML).
- **`envelopeHeader` header injection (LOW)** — validated at
  middleware construct time against `^[A-Za-z0-9_-]+$`. A caller
  passing `'X-AAE\nX-Injected: yes'` or `'Content-Type:Bad'` now
  throws loudly rather than silently enabling header smuggling.
- **`logger.info` outside try/catch (LOW)** — `emitAudit` now wraps
  every logger call (info AND the error fallback in sink-rejection
  handling) so a logger proxy that throws on access cannot crash
  the request handler. Audit-trail value isn't worth taking down
  the service.
- **Extreme `requestsPerMinute` memory blow-up (INFO)** —
  `IpRateLimiter` constructor caps `requestsPerMinute` at 10 000
  with a clear error pointing operators at CDN/proxy rate-limits
  for higher capacity. Previously an unbounded value × maxBuckets
  100k could allocate ~800 GB of timestamp memory.

### Documented (no code change)

- **Shared "unknown" rate-limit bucket** — when both `req.ip` and
  `req.connection.remoteAddress` are unavailable, all such requests
  share one bucket (fail-closed). Random fallback would let
  attackers strip IP headers to bypass rate-limit entirely. Comment
  added to the middleware noting the deliberate trade-off.

### Tests

- 89 → 107 tests passing. New coverage:
  - `url-validation.test.js`: localhost variants, IPv6 zone-ID
    stripping, suspect %-suffix rejection (4 new).
  - `middleware.test.js`: resolveReceiver timeout (1), upstream
    body cap with streaming-large response (1), default response
    security headers (1), `responseSecurityHeaders: false` opt-out
    (1), responseSecurityHeaders override-merge (1), envelopeHeader
    injection patterns (1 with 4 sub-cases), maxResponseBodyBytes
    + resolveReceiverTimeoutMs construct validation (2).
  - `ip-rate-limit.test.js`: requestsPerMinute upper bound (1).
  - **New file** `audit.test.js` — 6 tests covering throwing
    logger, throwing logger proxy, sync sink throws, async sink
    rejects, both sink and logger throw, well-behaved baseline.

### Compatibility

Behavioural changes:
- Hostnames `localhost`, `localhost.localdomain`, `ip6-localhost`,
  `ip6-loopback` now blocked by `validateReceiverUrl` even with
  `allowedProtocols: ['http:']`. Add `allowPrivateHosts: true`
  for tests / dev as before.
- Responses now carry CSP/X-Frame-Options/Referrer-Policy by
  default. If you proxy a surface that needs other framing or
  loading semantics, override via `cfg.responseSecurityHeaders`.
- Upstream responses larger than 1 MiB now return
  `502 upstream_body_too_large`. Raise `maxResponseBodyBytes`
  if your receivers legitimately stream more.

## 0.1.2 — 2026-05-01

Third external review round (overlapping reviewers; 10 + 4 raw findings,
one was a misread of 0.1.1). All in-scope items addressed.

### Fixed

- **SSRF via HTTP redirects (HIGH)** — `fetch()` now runs with
  `redirect: 'error'`. A receiver responding 3xx to an attacker
  -controlled Location used to bypass `validateReceiverUrl` (which
  only inspected the initial URL); now any redirect surfaces as
  `502 receiver_unreachable`. Receivers must return their final
  URL from `resolveReceiver`.
- **Embedded credentials in receiver URL (MED)** — URLs with
  `username` or `password` (e.g. `https://user:pw@host/...`) are
  rejected with `url_embedded_credentials` before any `fetch()`.
  Without this, `fetch()` synthesised an Authorization header from
  the embedded credentials and leaked them to the receiver.
- **Arbitrary internal-service ports on allowlisted hosts (MED)** —
  default port denylist for well-known internal services (SSH, SMTP,
  Redis, PostgreSQL, MongoDB, RabbitMQ, kubelet, Docker daemon,
  Memcached, Elasticsearch, etc.; full list as `DEFAULT_DENIED_PORTS`).
  Optional `allowedReceiverPorts` config for strict allowlist mode
  that overrides the denylist. Optional `deniedReceiverPorts` to
  override the default set.
- **IPv6 fully-expanded loopback (LOW)** — `isPrivateOrLoopbackHost`
  now explicitly matches `0:0:0:0:0:0:0:1` and `0:0:0:0:0:0:0:0` in
  addition to the compressed `::1` / `::` forms. Defends against
  future Node URL-parser changes that might keep the expanded form.
- **`X-Content-Type-Options: nosniff` (LOW)** — hard-coded on every
  visitor response. A compromised receiver returning misleading
  Content-Type can no longer be MIME-sniffed and executed by the
  visitor's browser.
- **`loadSigningKey` regex consistency (LOW)** — switched from
  `.replace(/-/g, '+')` to `.replaceAll('-', '+')` to match the
  rest of the library. Same code-hygiene rationale as the b64url
  encoder fix in 0.1.0+1; pre-empts a copy-paste regex from
  reaching an attacker-input path in a future refactor.

### Added — documentation

- README "Deployment requirements" section now documents:
  - The full SSRF default-deny list (protocols, private IPs,
    embedded credentials, internal-service ports, redirects).
  - `allowedReceiverPorts` for tight port allowlisting.
  - Allowlist wildcard semantics: `*.example.com` matches sub-hosts
    at ANY depth, not just one level (consistent with browser cookie
    scoping).
  - "Request body mutation" subsection explaining `sanitise: true`
    replaces `req.body` in place.
  - "Multi-replica rate-limiter" subsection with a complete
    Redis-backed `consume(key)` example so operators can drop in
    a multi-pod-safe limiter.
- SECURITY.md "Defended" section expanded with the redirect-error,
  embedded-credentials, and nosniff fixes.

### Tests

- 75 → 89 tests passing. New coverage:
  - `url-validation.test.js`: IPv6 expanded loopback (1), embedded
    credentials reject (2), port denylist (3 well-known services),
    standard port pass (2), `allowedReceiverPorts` allowlist (3).
  - `middleware.test.js`: receiver redirect → 502 (1), nosniff
    response header (1), embedded-credentials rejection (1).

### Reviewer note

A reviewer flagged "no dedicated unit tests for url-validation.js"
in this round — `test/url-validation.test.js` was added in 0.1.1
with 19 tests; this release brings it to 28. Total file count is
now 5 test files, 89 tests, all passing.

### Compatibility

Behavioural change: receivers that respond with HTTP redirects now
surface as `502 receiver_unreachable` instead of the response of
the redirect target. URLs returned by `resolveReceiver` should be
final (no 3xx). Otherwise additive — port denylist and embedded-
credentials check only fire for clearly-malicious URLs that legitimate
deployments never produce.

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
