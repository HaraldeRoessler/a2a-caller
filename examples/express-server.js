// Working end-to-end example: a portal + a mock receiver, both running
// in this process. The portal exposes /v1/chat/:slug; visitors POST a
// message; the portal signs an AAE envelope; the receiver verifies it
// and echoes back. Run with `npm run example` then:
//
//   curl -X POST http://localhost:4400/v1/chat/acme \
//        -H "Content-Type: application/json" \
//        -H "X-Caller-DID: did:moltrust:demo-claude-1" \
//        -d '{"message":"hi"}'

import express from 'express';
import { generateKeyPairSync } from 'node:crypto';
import { verifyAae, NonceCache, KeyResolver, RevocationChecker } from 'a2a-acl';
import { publicChatMiddleware, loadSigningKey, IpRateLimiter } from '../src/index.js';

// ============================================================================
//   ⚠ DEMO ONLY — NEVER RUN THIS BLOCK IN PRODUCTION ⚠
//
//   We generate an Ed25519 keypair on every startup so the example is
//   self-contained. In production:
//     - the seed lives in a Secret / KMS / encrypted env var
//     - it is loaded ONCE at startup via loadSigningKey(seed)
//     - it is rotated by minting a new key and switching the
//       callerSigKeyId, NOT by regenerating in process
//     - if you copy this snippet into a real deployment you have
//       given every restart a fresh identity, broken every receiver's
//       cached pubkey lookup, and lost the ability to revoke past keys
// ============================================================================
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const seed = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
const pubB64url = publicKey.export({ format: 'der', type: 'spki' })
  .subarray(-32).toString('base64')
  .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

// 2. Stand up a mock RECEIVER on port 4500. In production this is
//    your tenant's a2a-acl-protected agent gateway.
const receiver = express();
receiver.use(express.json());
const recvKeyResolver = new KeyResolver({
  resolve: async (id) => id === 'demo-portal-v1' ? { public_key_b64url: pubB64url, sig_alg: 'Ed25519' } : null,
});
const recvNonceCache = new NonceCache();
const recvRevoke = new RevocationChecker({ check: async () => false });

receiver.post('/api/a2a/message', async (req, res) => {
  const env = req.get('x-aae');
  const v = await verifyAae(env, {
    keyResolver: recvKeyResolver,
    revocationChecker: recvRevoke,
    nonceCache: recvNonceCache,
    expectedAud: 'a2a-ingress',
    expectedSub: 'did:moltrust:tenant-acme',
  });
  if (!v.verified) {
    return res.status(401).json({ error: 'aae_rejected', reason: v.reason });
  }
  res.json({
    received_from: v.issuer,
    received_message: req.body?.message ?? null,
    note: 'In production this would be the agent\'s LLM reply.',
  });
});
receiver.listen(4500, () => console.log('mock receiver listening on http://127.0.0.1:4500'));

// 3. Stand up the PORTAL on port 4400.
const portal = express();
portal.use(express.json({ limit: '64kb' }));
// IMPORTANT: trust proxy MUST be a specific list of CIDRs you control,
// never `true` (which trusts every hop blindly). With `true`, an
// attacker can spoof X-Forwarded-For on every request and bypass the
// per-IP rate limiter completely. This demo binds to loopback only.
portal.set('trust proxy', 'loopback');

portal.post('/v1/chat/:slug', publicChatMiddleware({
  resolveReceiver: async (slug) => {
    if (slug !== 'acme') return null;
    return {
      did: 'did:moltrust:tenant-acme',
      url: 'http://127.0.0.1:4500/api/a2a/message',
    };
  },
  callerDid: 'did:moltrust:demo-portal-1',
  signingKey: { key: loadSigningKey(seed) },
  callerSigKeyId: 'demo-portal-v1',
  rateLimiter: new IpRateLimiter({ requestsPerMinute: 30 }),
  // SSRF defence: explicitly allow http (demo only) AND localhost.
  // Production deployments should drop these flags entirely so the
  // library defaults (https-only, private hosts blocked) apply, and
  // optionally pass `allowedReceiverHosts: ['agent.example.com']`.
  allowedProtocols: ['http:', 'https:'],
  allowPrivateHosts: true,
  sink: (row) => console.log('AUDIT', JSON.stringify(row)),
  logger: console,
}));

portal.listen(4400, () => {
  console.log('portal listening on http://127.0.0.1:4400');
  console.log('try:');
  console.log('  curl -X POST http://127.0.0.1:4400/v1/chat/acme \\');
  console.log('       -H "Content-Type: application/json" \\');
  console.log('       -H "X-Caller-DID: did:moltrust:demo-claude-1" \\');
  console.log('       -d \'{"message":"hi"}\'');
});
