# a2a-caller

Sender-side counterpart to [a2a-acl](https://github.com/HaraldeRoessler/a2a-acl).
Express middleware that lets unauthenticated web traffic — visitors,
LLM sandboxes (Claude / ChatGPT / Cursor), third-party services —
reach AAE-protected agent-to-agent endpoints. Your service signs
envelopes on the visitor's behalf, captures their identity for audit,
rate-limits per IP.

Pair with a2a-acl on the receiver side and you have a full
sender/receiver stack for letting public web traffic talk to
agent-web peers without bypassing any of the security primitives.

MIT, no runtime dependencies beyond `a2a-acl` itself (which is
zero-dep). Express is a peer dep — works with Express 4 and 5.

## What it gives you

A single middleware factory that handles the whole pipeline per request:

1. **Receiver lookup** — your callback maps `slug → { did, url }`.
2. **Per-IP rate-limit** — sliding window per `(ip, slug)`. 429 on overflow.
3. **Payload sanitisation** — strips prompt-injection markers (uses `a2a-acl`'s `sanitiseDeep`).
4. **Caller-id capture** — `X-Caller-DID` (opt-in self-declaration) + server-derived visitor hash.
5. **AAE envelope signing** — Ed25519, 5-minute lifetime, fresh nonce, cross-peer-replay defence built in.
6. **Forward to receiver** — `POST receiver.url` with `X-AAE: <envelope>`.
7. **Response stream-back** — receiver's response goes straight to the visitor.
8. **Audit row** — fire-and-forget to your sink.

## Why this exists

The receiver-side `a2a-acl` library is "default deny on every inbound
A2A call". Great for agent-to-agent traffic with established DIDs.
But on the public web you have visitors — humans, LLMs, automation
scripts — that don't have DIDs of their own (yet). Without a sender-side
library you'd either skip authentication ("public path bypass") or
roll your own envelope signer in every project.

`a2a-caller` is the standard way to bridge the two: visitors hit a
public endpoint, your portal signs as itself (its DID is a real
MolTrust-or-equivalent identity with its own trust score), receivers
treat the portal as a known peer with `message`-only capability.
Visitors get audited via `X-Caller-DID` + visitor hash, so receivers
can grant per-DID upgrades over time.

## Install

```sh
npm install a2a-caller express
```

Requires Node 20+. Express is a peer dep.

## Usage

```js
import express from 'express';
import { publicChatMiddleware, loadSigningKey, IpRateLimiter } from 'a2a-caller';

// 1. Load your signing key once at startup. The 32-byte Ed25519 seed
//    lives in a Secret / KMS / file — never in source. Throws loudly
//    if malformed (operator-time error, fail loud).
const signingKey = { key: loadSigningKey(process.env.PORTAL_SIGNING_SEED) };

// 2. Wire the middleware. Every callback is yours to define.
const app = express();
app.use(express.json({ limit: '64kb' }));

app.post('/v1/chat/:slug', publicChatMiddleware({
  // Where to find the receiver
  resolveReceiver: async (slug) => {
    const tenant = await db.tenants.findOne({ slug });
    if (!tenant) return null;
    return { did: tenant.moltrust_did, url: `https://a2a-${slug}.example.com/api/a2a/message` };
  },

  // Your portal's identity
  callerDid: 'did:moltrust:my-portal-frontend-...',
  signingKey,
  callerSigKeyId: 'my-portal-v1',  // receiver's KeyResolver maps this → your pubkey

  // Per-IP rate-limit (passed instance, OR pass requestsPerMinute and one is built lazily)
  rateLimiter: new IpRateLimiter({ requestsPerMinute: 30 }),

  // Optional audit sink
  sink: (row) => db.public_chat_audit.insert(row),

  // Optional pino-style logger
  logger: console,
}));

app.listen(3000);
```

That's the whole shape. A complete working example is in
[`examples/express-server.js`](./examples/express-server.js)
(`npm run example` — it spins up both a portal AND a mock a2a-acl
receiver so you can see the round-trip end to end).

## What the visitor sends

```sh
curl -X POST https://your-portal.example.com/v1/chat/acme \
     -H "Content-Type: application/json" \
     -H "X-Caller-DID: did:moltrust:claude-sess-xyz" \   # optional, audit-only
     -d '{"message": "Hi, can you tell me about your roadmap?"}'
```

`X-Caller-DID` is **audit-only**. The library shape-validates it
(`did:method:id` regex, length cap) but does not cryptographically
verify ownership. That's by design — visitors can't realistically
sign envelopes the receiver would accept, and trying to fake that
contract opens spoofing vectors. The visitor's *real* identity for
authorization purposes is "the portal" (your `callerDid`); the
`claimed_did` ends up in audit so receivers can graduate well-behaved
visitor DIDs to per-DID ACL grants over time.

## Strict defaults

Same posture as a2a-acl: the strictest setting that doesn't break the
common case is on by default.

- **SSRF defence on** — `receiver.url` returned by your `resolveReceiver`
  callback is validated before any `fetch()`: protocol must be `https:`
  by default, hostname must NOT be a literal private/loopback/link-local/
  metadata IP. Optional `allowedReceiverHosts` allowlist tightens this
  to specific hostnames or `*.example.com` wildcards. See **Deployment
  requirements** below.
- **Body size cap on** — default `maxBodyBytes: 65536` (64 KiB).
  Oversized requests get a 413 before any signing or forwarding.
- **Envelope lifetime: 5 minutes**, hard-capped. A signer with a
  longer `exp` gets rejected by the verifier; a caller passing
  `lifetimeSec > 300` to `signEnvelope` throws at signing time.
- **Hop count cap** — `claims.hop` validated as integer in `[0, 10]`;
  defends in depth against a caller bypassing the receiver's
  `depthGuard` with `Infinity` or `NaN`.
- **Cross-peer replay defence** — every envelope has `sub = receiver.did`,
  so an envelope signed for receiver A can't be replayed against
  receiver B (the receiver-side `expectedSub` rejects it).
- **Per-IP rate limit fail-closed** when bucket cap exceeds — degraded
  rate-limiting beats service denial.
- **Bounded everything** — rate-limit buckets, header lengths, DID
  shapes, oversized client labels collapse to null rather than
  flow into audit.
- **Sanitiser on by default** — strips known prompt-injection markers
  before the envelope is built (so the signed payload is the
  cleaned version). Note: this **mutates `req.body`** in place; downstream
  middleware sees the sanitised payload.
- **No slug enumeration via status code** — unknown slugs and
  malformed-receiver-callback both return `404 receiver_not_found`.
  Operator-side bugs are logged via `logger.error` so they're visible
  to you without leaking the existence of valid slugs to attackers.
- **Upstream status clamped** — non-standard HTTP codes from a
  broken receiver collapse to 502 rather than throwing in `res.status()`.
- **No request/response body in audit** — only metadata. Sensitive
  payload contents stay out of the audit table by default.

## Deployment requirements

A few things the library cannot enforce on its own — you have to wire
them at the deployment layer for the per-IP rate limit and SSRF
defence to work as intended:

### Reverse proxy + correct `trust proxy`

The middleware reads `req.ip` for the rate-limit key. With Express
`trust proxy: true` (or no proxy in front), an attacker can spoof
`X-Forwarded-For` on every request and bypass per-IP limits entirely.

**Required:**
1. Deploy behind a reverse proxy you control (nginx, Cloudflare, ALB).
2. The proxy MUST strip / overwrite incoming `X-Forwarded-For` headers.
3. Set Express `trust proxy` to that proxy's exact CIDR — e.g.
   `app.set('trust proxy', 'loopback')` for a same-host nginx, or
   `app.set('trust proxy', ['10.0.0.0/8'])` for an in-cluster ingress.
4. **Never** `app.set('trust proxy', true)` in production.

### Multi-replica deployments

The default `IpRateLimiter` uses a per-process `Map`. Across N replicas
behind a load balancer, attackers get N× the allowed request volume.
For HA deployments:
- Put a CDN / reverse-proxy rate limit in front as the primary defence.
- Or supply your own `rateLimiter` config implementing the same
  `consume(key)` shape, backed by Redis or similar.
- `a2a-caller` itself is single-process; a Redis-backed limiter is
  v0.2 territory.

### SSRF allowlist

The default validation blocks:
- Non-`https:` protocols
- Literal private/loopback/link-local/cloud-metadata IPs (IPv4 + IPv6, including the fully-expanded form)
- URLs with embedded credentials (`https://user:pw@host/...`)
- Well-known internal-service ports (Redis 6379, PostgreSQL 5432, MongoDB 27017, kubelet 10250, etc. — full list in `src/url-validation.js`)
- HTTP redirect responses from the receiver (`fetch` runs with `redirect: 'error'`)

For production, also pass an `allowedReceiverHosts` allowlist
scoped to your actual receiver domains:

```js
publicChatMiddleware({
  // ...
  allowedReceiverHosts: ['*.ownify.ai', 'agent.example.com'],
  // Optional: tight port allowlist (overrides the denylist above)
  allowedReceiverPorts: [443, 8443],
});
```

**Allowlist semantics**:
- Exact entries match the host literally (`agent.example.com` matches only `agent.example.com`).
- Wildcard entries (`*.example.com`) match **any depth** of subdomain — `sub.example.com` AND `a.b.c.example.com`. They do NOT match the apex (`example.com` itself). This is consistent with browser cookie scoping. If you want to limit to a single subdomain depth, list the specific hosts explicitly.

DNS-rebinding attacks (a hostname that resolves to a public IP at
check-time, private IP at fetch-time) are NOT defended at this layer —
mitigate with a forward proxy that re-validates per connection, or by
resolving DNS once and passing a literal IP to fetch.

### Request body mutation

When `sanitise: true` (the default), `req.body` is **replaced in place**
with the sanitised version. Any downstream Express middleware mounted
on the same route will see the cleaned payload, not the raw one. Set
`sanitise: false` if you need to preserve the original body.

### Multi-replica rate-limiter

The default `IpRateLimiter` is per-process. For HA deployments swap
in a Redis-backed implementation with the same shape — only one method
is required:

```js
const redisRateLimiter = {
  consume: async (key) => {
    // Atomically increment a per-key counter with a 60s expiry.
    // Return false when the per-minute limit is exceeded.
    const count = await redis.incr(`rl:${key}`);
    if (count === 1) await redis.expire(`rl:${key}`, 60);
    return count <= REQUESTS_PER_MINUTE;
  },
};

publicChatMiddleware({
  // ...
  rateLimiter: redisRateLimiter,
});
```

`IpRateLimiter.keyOf(ip, slug)` is exported as a helper if you want
to re-use the same `(ip, slug)` JSON-encoded key shape. Until you
swap in something multi-replica-aware, layer a CDN / reverse-proxy
rate limit (Cloudflare, nginx `limit_req`) in front as the primary
defence and treat the in-process limiter as best-effort.

## What's req.firewall (and what isn't)

This middleware is the SENDER side. It does not write to `req.firewall`
(that's the receiver-side a2a-acl convention). Caller information is
captured into a separate object the audit row references; if you
need to inspect what the middleware would record, call
`captureCallerId(req)` directly:

```js
import { captureCallerId } from 'a2a-caller';
const callerId = captureCallerId(req);
// → { claimed_did, client, visitor_hash }
```

## What's NOT in this library

- **Authentication.** The whole point is unauth. If you want
  Bearer-token / OAuth / session-based auth, mount it on a *different*
  route — this library is for the deliberately-public path.
- **Storage.** Your DB schema, your tables, your queries. The four
  callbacks (`resolveReceiver`, `signingKey`, `sink`, optional
  `getSlug` / `callerIdOpts.getSessionId`) are the contract.
- **Multi-replica state.** Same constraint as a2a-acl — the per-IP
  rate-limiter is in-process. For HA deployments running multiple
  replicas, swap to a Redis-backed implementation with the same
  interface (v0.2 if there's demand).
- **Long-running streaming.** Each request is one POST → one response.
  Server-Sent Events / WebSocket bridges to receivers are out of scope.
- **The signing key.** You provide it. We never ship a default;
  starting without `loadSigningKey(seed)` throws.

## Cross-language signers

This library imports `signablePayload` and `SIGNED_FIELDS` from
`a2a-acl` and re-exports them. A signer in Python / Rust / Go can
produce bit-identical envelopes by replicating the same allowlist
and canonicalisation — see `a2a-acl`'s SECURITY.md for the spec.

## Security

See [SECURITY.md](./SECURITY.md) for the full threat model, the things
this library does NOT defend against (network egress filtering,
SQL injection in your `resolveReceiver` callback, prompt injection
beyond known markers, multi-replica nonce reuse), and how to report
a vulnerability.

## License

[MIT](./LICENSE).
