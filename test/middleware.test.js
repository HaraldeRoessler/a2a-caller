// Middleware integration tests. Uses Express + a minimal HTTP mock as
// the "receiver gateway" — verifies the inbound envelope shape and
// streams a canned response back.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import express from 'express';
import { verifyAae, NonceCache, KeyResolver, RevocationChecker } from 'a2a-acl';
import { publicChatMiddleware, loadSigningKey, IpRateLimiter } from '../src/index.js';

function freshKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const seed = pkcs8.subarray(pkcs8.length - 32);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const rawPub = spki.subarray(spki.length - 32);
  const pubB64url = Buffer.from(rawPub).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { seed, pubB64url };
}

// Spin up a minimal "receiver" that captures + verifies the envelope,
// echoing back what it received. Lets the middleware test assert on
// the actual signed bytes the receiver would see in production.
function startMockReceiver(pubB64url, expectedSubGetter = (env) => 'tenant-acme') {
  const captures = [];
  const keyResolver = new KeyResolver({
    resolve: async (id) => id === 'caller-v1' ? { public_key_b64url: pubB64url, sig_alg: 'Ed25519' } : null,
  });
  const revocationChecker = new RevocationChecker({ check: async () => false });
  const nonceCache = new NonceCache();

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    const envHeader = req.headers['x-aae'] || req.headers['x-klaw-aae'];
    const verify = await verifyAae(envHeader, {
      keyResolver, revocationChecker, nonceCache,
      expectedAud: 'a2a-ingress',
      expectedSub: expectedSubGetter({ headers: req.headers, body }),
    });
    captures.push({ headers: req.headers, body, verify });
    res.statusCode = verify.verified ? 200 : 401;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: verify.verified, reason: verify.reason ?? null, echoed: body }));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}/`,
        captures,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

function startApp(middleware) {
  const app = express();
  app.use(express.json());
  app.post('/v1/chat/:slug', middleware);
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

test('end-to-end: visitor POST → portal signs → receiver verifies', async () => {
  const { seed, pubB64url } = freshKeypair();
  const recv = await startMockReceiver(pubB64url, () => 'did:moltrust:tenant-acme');
  const app = await startApp(publicChatMiddleware({
    resolveReceiver: async (slug) => slug === 'acme' ? { did: 'did:moltrust:tenant-acme', url: recv.url } : null,
    callerDid: 'did:moltrust:portal-1',
    signingKey: { key: loadSigningKey(seed) },
    callerSigKeyId: 'caller-v1',
    requestsPerMinute: 100,
  }));

  const r = await fetch(`${app.baseUrl}/v1/chat/acme`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-caller-did': 'did:moltrust:claude-sess-1' },
    body: JSON.stringify({ message: 'hi' }),
  });
  assert.equal(r.status, 200);
  const json = await r.json();
  assert.equal(json.ok, true, `verifier rejected: ${json.reason}`);
  assert.equal(recv.captures.length, 1);
  assert.equal(recv.captures[0].verify.verified, true);

  await app.close();
  await recv.close();
});

test('unknown slug → 404 receiver_not_found', async () => {
  const { seed } = freshKeypair();
  const app = await startApp(publicChatMiddleware({
    resolveReceiver: async () => null,
    callerDid: 'did:moltrust:p',
    signingKey: { key: loadSigningKey(seed) },
    callerSigKeyId: 'k',
    requestsPerMinute: 100,
  }));
  const r = await fetch(`${app.baseUrl}/v1/chat/unknown`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: 'x' }),
  });
  assert.equal(r.status, 404);
  await app.close();
});

test('rate-limit overflow → 429', async () => {
  const { seed, pubB64url } = freshKeypair();
  const recv = await startMockReceiver(pubB64url, () => 'did:moltrust:t');
  const app = await startApp(publicChatMiddleware({
    resolveReceiver: async () => ({ did: 'did:moltrust:t', url: recv.url }),
    callerDid: 'did:moltrust:p',
    signingKey: { key: loadSigningKey(seed) },
    callerSigKeyId: 'caller-v1',
    rateLimiter: new IpRateLimiter({ requestsPerMinute: 1 }),
  }));

  const a = await fetch(`${app.baseUrl}/v1/chat/x`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  });
  const b = await fetch(`${app.baseUrl}/v1/chat/x`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(a.status, 200);
  assert.equal(b.status, 429);
  await app.close();
  await recv.close();
});

test('audit sink fires once per request and includes claimed_did', async () => {
  const { seed, pubB64url } = freshKeypair();
  const recv = await startMockReceiver(pubB64url, () => 'did:moltrust:t');
  const rows = [];
  const app = await startApp(publicChatMiddleware({
    resolveReceiver: async () => ({ did: 'did:moltrust:t', url: recv.url }),
    callerDid: 'did:moltrust:portal',
    signingKey: { key: loadSigningKey(seed) },
    callerSigKeyId: 'caller-v1',
    requestsPerMinute: 100,
    sink: (row) => rows.push(row),
  }));
  await fetch(`${app.baseUrl}/v1/chat/x`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-caller-did': 'did:moltrust:visitor-1' },
    body: '{}',
  });
  // Sink fires after res.send completes; give the event loop a tick.
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].caller_did, 'did:moltrust:portal');
  assert.equal(rows[0].claimed_did, 'did:moltrust:visitor-1');
  assert.match(rows[0].visitor_hash, /^[0-9a-f]{32}$/);
  assert.equal(rows[0].rate_limited, false);
  assert.ok(rows[0].jti, 'jti should be extracted from envelope');
  await app.close();
  await recv.close();
});

test('config validation: missing resolveReceiver → throw at construct', () => {
  const { seed } = freshKeypair();
  assert.throws(
    () => publicChatMiddleware({
      callerDid: 'did:x:1', signingKey: { key: loadSigningKey(seed) }, callerSigKeyId: 'k',
    }),
    /resolveReceiver/,
  );
});

test('config validation: missing signingKey → throw at construct', () => {
  assert.throws(
    () => publicChatMiddleware({
      resolveReceiver: async () => null,
      callerDid: 'did:x:1', callerSigKeyId: 'k',
    }),
    /signingKey/,
  );
});

test('config validation: missing callerDid → throw at construct', () => {
  const { seed } = freshKeypair();
  assert.throws(
    () => publicChatMiddleware({
      resolveReceiver: async () => null,
      signingKey: { key: loadSigningKey(seed) }, callerSigKeyId: 'k',
    }),
    /callerDid/,
  );
});

test('receiver returning malformed shape → 500 receiver_misconfigured', async () => {
  const { seed } = freshKeypair();
  const app = await startApp(publicChatMiddleware({
    resolveReceiver: async () => ({ did: 123, url: 456 }),
    callerDid: 'did:moltrust:p',
    signingKey: { key: loadSigningKey(seed) },
    callerSigKeyId: 'k',
    requestsPerMinute: 100,
  }));
  const r = await fetch(`${app.baseUrl}/v1/chat/x`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(r.status, 500);
  await app.close();
});
