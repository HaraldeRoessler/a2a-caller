// Crown-jewel test: sign with a2a-caller, verify with a2a-acl.
// If this passes, sender and receiver agree on the wire format.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  verifyAae, NonceCache, KeyResolver, RevocationChecker,
} from 'a2a-acl';
import { signEnvelope, loadSigningKey, signablePayload, SIGNED_FIELDS } from '../src/envelope.js';

// Helper: generate an Ed25519 keypair, return both halves in the
// shapes the two libraries want.
function freshKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  // a2a-caller wants the raw 32-byte seed (or a base64url string of it).
  // Node exposes it via the privateKey export's last 32 bytes of PKCS8.
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const seed = pkcs8.subarray(pkcs8.length - 32);
  // a2a-acl wants the raw 32-byte public key as base64url.
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const rawPub = spki.subarray(spki.length - 32);
  const pubB64url = Buffer.from(rawPub).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { seed, pubB64url };
}

test('roundtrip: signEnvelope → verifyAae verifies', async () => {
  const { seed, pubB64url } = freshKeypair();
  const key = { key: loadSigningKey(seed) };

  const envelope = signEnvelope({
    iss: 'did:moltrust:portal-1',
    sub: 'tenant-acme',
    aud: 'a2a-ingress',
    sig_key_id: 'portal-1-v1',
  }, key);

  const result = await verifyAae(envelope, {
    keyResolver: new KeyResolver({
      resolve: async (id) => id === 'portal-1-v1' ? { public_key_b64url: pubB64url, sig_alg: 'Ed25519' } : null,
    }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    expectedAud: 'a2a-ingress',
    expectedSub: 'tenant-acme',
  });

  assert.equal(result.verified, true, `verify failed: ${result.reason}`);
  assert.equal(result.issuer, 'did:moltrust:portal-1');
});

test('roundtrip: cross-peer replay defence — sub mismatch rejected', async () => {
  const { seed, pubB64url } = freshKeypair();
  const key = { key: loadSigningKey(seed) };

  const envelope = signEnvelope({
    iss: 'did:moltrust:portal-1',
    sub: 'tenant-acme',
    aud: 'a2a-ingress',
    sig_key_id: 'portal-1-v1',
  }, key);

  // Verifier expects a DIFFERENT sub — should reject.
  const result = await verifyAae(envelope, {
    keyResolver: new KeyResolver({ resolve: async () => ({ public_key_b64url: pubB64url, sig_alg: 'Ed25519' }) }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    expectedAud: 'a2a-ingress',
    expectedSub: 'tenant-different',
  });
  assert.equal(result.verified, false);
  assert.equal(result.reason, 'wrong_subject');
});

test('roundtrip: replay detected on second use of same envelope', async () => {
  const { seed, pubB64url } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  const envelope = signEnvelope({
    iss: 'did:moltrust:p',
    sub: 't',
    aud: 'a2a-ingress',
    sig_key_id: 'p-v1',
  }, key);

  const ctx = {
    keyResolver: new KeyResolver({ resolve: async () => ({ public_key_b64url: pubB64url, sig_alg: 'Ed25519' }) }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    expectedAud: 'a2a-ingress',
    expectedSub: 't',
  };
  assert.equal((await verifyAae(envelope, ctx)).verified, true);
  assert.equal((await verifyAae(envelope, ctx)).reason, 'replay');
});

test('signEnvelope rejects missing iss', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  assert.throws(() => signEnvelope({ aud: 'a', sig_key_id: 'k' }, key), /iss required/);
});

test('signEnvelope rejects missing aud', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  assert.throws(() => signEnvelope({ iss: 'did:x:1', sig_key_id: 'k' }, key), /aud required/);
});

test('signEnvelope rejects missing sig_key_id', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  assert.throws(() => signEnvelope({ iss: 'did:x:1', aud: 'a' }, key), /sig_key_id required/);
});

test('signEnvelope rejects missing keyMaterial', () => {
  assert.throws(() => signEnvelope({ iss: 'did:x:1', aud: 'a', sig_key_id: 'k' }, {}), /keyMaterial.key required/);
});

test('signEnvelope rejects oversized lifetime', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  assert.throws(
    () => signEnvelope({ iss: 'did:x:1', aud: 'a', sig_key_id: 'k' }, key, { lifetimeSec: 600 }),
    /lifetimeSec/,
  );
});

test('signEnvelope rejects sub-MIN lifetime', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  assert.throws(
    () => signEnvelope({ iss: 'did:x:1', aud: 'a', sig_key_id: 'k' }, key, { lifetimeSec: 1 }),
    /lifetimeSec/,
  );
});

test('signEnvelope rejects exp-iat > MAX even when supplied directly', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  const now = Math.floor(Date.now() / 1000);
  assert.throws(
    () => signEnvelope({
      iss: 'did:x:1', aud: 'a', sig_key_id: 'k',
      iat: now, exp: now + 600,
    }, key),
    /lifetime/,
  );
});

test('signEnvelope generates a unique jti per call', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  const e1 = signEnvelope({ iss: 'did:x:1', aud: 'a', sig_key_id: 'k' }, key);
  const e2 = signEnvelope({ iss: 'did:x:1', aud: 'a', sig_key_id: 'k' }, key);
  assert.notEqual(e1, e2, 'consecutive envelopes must differ (random jti)');
});

test('signEnvelope honours a caller-supplied jti', () => {
  const { seed } = freshKeypair();
  const key = { key: loadSigningKey(seed) };
  const env = signEnvelope({ iss: 'did:x:1', aud: 'a', sig_key_id: 'k', jti: 'fixed-jti-1' }, key);
  const parsed = JSON.parse(Buffer.from(env.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  assert.equal(parsed.jti, 'fixed-jti-1');
});

test('loadSigningKey rejects wrong-length seed', () => {
  assert.throws(() => loadSigningKey(Buffer.alloc(31)), /32 bytes/);
  assert.throws(() => loadSigningKey(Buffer.alloc(33)), /32 bytes/);
});

test('loadSigningKey rejects non-buffer non-string input', () => {
  assert.throws(() => loadSigningKey(12345), /must be a base64url string/);
  assert.throws(() => loadSigningKey(null), /must be a base64url string/);
});

test('loadSigningKey accepts base64url string', () => {
  const { seed } = freshKeypair();
  const seedB64url = Buffer.from(seed).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const key = loadSigningKey(seedB64url);
  assert.ok(key, 'should produce a KeyObject');
});

test('SIGNED_FIELDS re-export matches a2a-acl', async () => {
  const a2aAcl = await import('a2a-acl');
  assert.deepEqual(SIGNED_FIELDS, a2aAcl.SIGNED_FIELDS,
    'SIGNED_FIELDS must be the exact same constant — drift breaks signing compatibility');
});

test('signablePayload re-export produces identical bytes to a2a-acl', async () => {
  const a2aAcl = await import('a2a-acl');
  const env = { v: 1, iss: 'did:x:1', aud: 'a', iat: 1, exp: 2, jti: 'j', sig_key_id: 'k', sig_alg: 'Ed25519', hop: 0 };
  assert.deepEqual(signablePayload(env), a2aAcl.signablePayload(env));
});
