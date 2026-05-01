# Security

## Threat model

`a2a-caller` is the **sender** in an A2A pipeline. It signs AAE
envelopes with a private Ed25519 key, forwards them to receivers,
and records audit metadata. The threats it defends against fall into
three groups:

### Defended

- **Replay against another receiver** — `sub = receiver.did` is set
  on every envelope, the receiver-side `expectedSub` check rejects
  envelopes captured for one peer and replayed against another.
- **Long-lived envelopes** — hard 5-minute lifetime cap; longer
  envelopes throw at signing time.
- **Spoofed `X-Caller-DID` headers** — shape-validated against a
  strict DID regex with a 256-char length cap. Audit-only signal
  by design; not used for authorization.
- **Oversized client labels / DIDs in audit** — collapsed to `null`
  before insertion so audit logs stay clean.
- **IP-flood DoS on the public chat path** — per-`(ip, slug)`
  sliding window with bucket-count cap. Under flood the rate-limiter
  evicts oldest buckets rather than growing memory unboundedly;
  trade-off is documented in code.
- **Audit-trail gaps from sink failures** — sink rejections are logged
  at error level, not warn (a missing audit row is a security signal).
- **Slow upstream** — `forwardTimeoutMs` (default 30s) bounds receiver
  call duration so an unresponsive receiver can't pin a request handler.

### NOT defended

- **Network egress** — if your portal can reach an attacker-controlled
  URL via `resolveReceiver`, it will sign an envelope and POST there.
  Validate `receiver.url` in your callback (allowlist hosts,
  reject non-HTTPS in production).
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
