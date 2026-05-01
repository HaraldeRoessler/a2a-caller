# Security

## Threat model

`a2a-caller` is the **sender** in an A2A pipeline. It signs AAE
envelopes with a private Ed25519 key, forwards them to receivers,
and records audit metadata. The threats it defends against fall into
three groups:

### Defended

- **SSRF via attacker-controlled receiver URLs** — `receiver.url` is
  parsed and validated before any `fetch()`. Default policy: https
  only, literal private/loopback/link-local/cloud-metadata IPs
  rejected (IPv4 and IPv6 including the fully-expanded `0:0:0:0:0:0:0:1`
  form), URLs with embedded credentials rejected, well-known internal
  service ports (Redis, PostgreSQL, MongoDB, kubelet, etc.) on the
  port denylist. Optional `allowedReceiverHosts` allowlist tightens to
  exact hostnames or `*.example.com` wildcards. Optional
  `allowedReceiverPorts` allowlist locks outbound to specific ports.
- **SSRF via HTTP redirects** — `fetch()` runs with `redirect: 'error'`
  so a receiver that 3xx-redirects to a private IP cannot bypass
  `validateReceiverUrl` (which only saw the initial URL). Receivers
  must return their final URL from `resolveReceiver`.
- **Browser MIME-sniffing / clickjacking / referrer leakage** of
  compromised receiver responses — `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Content-Security-Policy: default-src
  'none'; frame-ancestors 'none'`, and `Referrer-Policy: no-referrer`
  are all hard-coded on every visitor response. Override via
  `cfg.responseSecurityHeaders` if you proxy actual HTML.
- **Slowloris via slow `resolveReceiver` callback** — the lookup is
  wrapped in a `Promise.race` against `resolveReceiverTimeoutMs`
  (default 5s). Returns `504 receiver_lookup_timeout` rather than
  pinning the request handler.
- **Unbounded upstream response body** — response is read with a
  streaming reader and aborted at `maxResponseBodyBytes` (default
  1 MiB). Returns `502 upstream_body_too_large`. Defends against
  a fast malicious upstream streaming multi-GB inside the
  forward-timeout window.
- **IPv6 zone-ID SSRF bypass** — `fe80::1%eth0` and similar zoned
  IPv6 forms have their `%zone` stripped before `isIP()` so the
  fe80::/10 link-local prefix check still fires. Hostnames with
  `%` that don't otherwise resolve to a recognised IP class are
  also blocked.
- **localhost / ip6-localhost SSRF** — explicit set-membership
  check on `localhost`, `localhost.localdomain`, `ip6-localhost`,
  `ip6-loopback` (these are DNS names, not IP literals, so the
  IP-range check alone wouldn't catch them).
- **Header injection via `envelopeHeader` config** — validated at
  construct time against `^[A-Za-z0-9_-]+$`. Newlines / colons /
  control chars throw loudly rather than enabling HTTP smuggling.
- **Logger-failure crash propagation** — `emitAudit` wraps every
  logger call in try/catch. A misbehaving logger proxy cannot crash
  the request handler.
- **Extreme `requestsPerMinute` memory blow-up** — capped at 10 000
  at `IpRateLimiter` construct time. Higher capacity belongs in a
  CDN / proxy rate-limit, not in-process bucket arrays.
- **Replay against another receiver** — `sub = receiver.did` is set
  on every envelope, the receiver-side `expectedSub` check rejects
  envelopes captured for one peer and replayed against another.
- **Long-lived envelopes** — hard 5-minute lifetime cap; longer
  envelopes throw at signing time.
- **Outsized hop counts** — `claims.hop` validated as integer in
  `[0, 10]`; defends against `Infinity`/`NaN` slipping past the
  receiver-side `depthGuard` cap.
- **Oversized request bodies** — `maxBodyBytes` default 64 KiB.
  Overflow returns 413 before signing or forwarding.
- **Slow upstream** — `forwardTimeoutMs` (default 30s) bounds the
  ENTIRE upstream call including body read; clearTimeout fires in
  `finally` so the timer covers both phases.
- **Spoofed `X-Caller-DID` headers** — shape-validated against a
  strict DID regex with a 256-char length cap. Audit-only signal
  by design; not used for authorization.
- **Malformed receiver.did** — DID shape validated before signing
  so junk doesn't end up in the envelope `sub` claim.
- **Slug enumeration via status code** — unknown slugs and
  malformed-receiver-callback both return `404 receiver_not_found`,
  preventing attackers from probing slug existence.
- **Status-handling crash on garbage upstream** — non-standard HTTP
  status codes from a broken receiver clamp to 502 rather than
  throwing in `res.status()`.
- **Oversized client labels / DIDs in audit** — collapsed to `null`
  before insertion so audit logs stay clean.
- **IP-flood DoS on the public chat path** — per-`(ip, slug)`
  sliding window with bucket-count cap. Under flood the rate-limiter
  evicts oldest buckets rather than growing memory unboundedly.
- **Audit-trail gaps from sink failures** — sink rejections are logged
  at error level, not warn (a missing audit row is a security signal).

### NOT defended

- **DNS rebinding** — the SSRF defence checks the URL's hostname IP
  literal at validation time. A hostname that resolves to a public IP
  at check-time and a private IP at fetch-time will bypass the check.
  Mitigate at the network layer (forward proxy that re-validates per
  connection) or by resolving once and passing a literal IP to fetch.
- **Multi-replica rate-limit bypass** — `IpRateLimiter` keeps state
  per process. Across N replicas behind a load balancer, an attacker
  effectively gets `N × requestsPerMinute` capacity. Layer a
  CDN/reverse-proxy rate limit in front, or implement a Redis-backed
  limiter with the same `consume(key)` shape and pass it via
  `cfg.rateLimiter`. Documented in README "Deployment requirements".
- **`X-Forwarded-For` spoofing without a controlled reverse proxy** —
  if you set Express `trust proxy: true` (or omit a proxy entirely),
  any client can forge `X-Forwarded-For` and bypass the per-IP rate
  limit. The library reads `req.ip` directly. README "Deployment
  requirements" spells out the correct setup.
- **SQL injection in `resolveReceiver`** — your callback, your
  responsibility. Parameterise queries.
- **Prompt injection beyond the known marker set** — `sanitiseDeep`
  strips the documented patterns; novel prompt-injection vectors
  flow through. Apply receiver-side LLM-aware filtering.
- **Multi-replica nonce reuse** — the in-process state means two
  pods can each sign with the same `jti` if they happen to generate
  matching 128-bit randoms (vanishingly small probability in practice).
  For deployments that genuinely need cryptographic guarantees across
  replicas, use a shared NonceCache implementation; the library doesn't
  ship one.
- **Tarball provenance** — npm `--provenance` is enabled in
  `publishConfig` but only takes effect when published from a
  GitHub Actions workflow with `id-token: write` permissions.
  Until that workflow lands (post-0.1.x), consumers should pin to
  the exact resolved version in their lockfiles.
- **Side-channel timing on signing** — Ed25519 signing time is
  message-length-bounded but not constant-time across all
  implementations. Acceptable for receiver-side trust decisions
  in this design (the signer is trusted within the operator boundary).
- **Compromise of the signing key** — if your `PORTAL_SIGNING_SEED` is
  exposed, an attacker can sign envelopes that receivers will accept
  for the lifetime of the receiver-side cache + 5min envelope
  lifetime. Rotate keys via `callerSigKeyId` (mint a new key, register
  it on the receiver, switch the env var, retire the old key after
  the cache TTL).
- **Visitor anonymity from the receiver** — receivers see the portal's
  `caller_did` and the `claimed_did` you forward via X-Caller-DID. They
  do NOT see the IP (only the visitor hash). If your receiver
  operator is hostile to visitors, the portal-mediated path is
  the wrong design.

## Sizing guidance

- `requestsPerMinute` per IP: start at 30. Real public-chat traffic
  rarely exceeds 1 request/sec sustained per legitimate visitor.
- `maxBuckets`: 100k by default. One bucket per active IP per minute.
  Increase if you serve >100k unique-IP visitors/minute.
- Envelope lifetime: 300s default and hard cap. Don't try to extend it.
- `forwardTimeoutMs`: 30s default. Most receivers respond <2s; the
  long timeout exists for first-call cold-start tolerance.

## Reporting a vulnerability

Email `harald.roessler@dsncon.com`. Use a subject line including
`[a2a-caller security]` so it routes correctly. Encrypted reports
welcome — public key on request.

Please do not file public GitHub issues for vulnerabilities. After
the fix lands and any affected operators have had time to upgrade,
the issue and a CVE entry will be public.
