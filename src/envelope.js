// AAE envelope construction + Ed25519 signing.
//
// This is the inverse of a2a-acl's verifyAae(). The verifier and signer
// MUST agree on:
//   1. Which fields are signed (SIGNED_FIELDS, imported from a2a-acl)
//   2. The exact bytes signed over (signablePayload, imported from a2a-acl)
//   3. The signature algorithm (Ed25519)
//   4. The wire format (base64url(JSON({...claims, sig})))
//
// By depending on a2a-acl directly we get all four for free —
// signers in this library produce envelopes the receiver-side
// verifyAae() will accept by construction.
//
// The signing key MUST be a 32-byte Ed25519 private seed. We accept
// it either as a Buffer/Uint8Array or as a base64url-encoded string.
// Production deployments should keep the key in a Secret / KMS / file
// the application reads at startup — never in source.

import { createPrivateKey, sign as cryptoSign, randomBytes } from 'node:crypto';
import { signablePayload, SIGNED_FIELDS } from 'a2a-acl';

const DEFAULT_LIFETIME_SEC = 300; // 5 minutes — matches a2a-acl's maxLifetimeSec
const MAX_LIFETIME_SEC = 300;     // hard cap; longer envelopes get rejected by verifier
const MIN_LIFETIME_SEC = 5;       // sub-5s envelopes are likely a clock-skew bug

// Wrap a raw 32-byte Ed25519 seed in PKCS8 DER so Node's crypto.createPrivateKey can consume it.
const PKCS8_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * Convert a base64url-encoded 32-byte Ed25519 seed (or a 32-byte
 * Buffer/Uint8Array) into a Node KeyObject suitable for cryptoSign.
 *
 * Throws on malformed input. Don't catch this at the boundary — a
 * misconfigured signing key is an operator-time error that should
 * surface loudly at startup.
 */
export function loadSigningKey(seed) {
  let raw;
  if (typeof seed === 'string') {
    raw = Buffer.from(seed.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } else if (Buffer.isBuffer(seed)) {
    raw = seed;
  } else if (seed instanceof Uint8Array) {
    raw = Buffer.from(seed);
  } else {
    throw new Error('signing key must be a base64url string, Buffer, or Uint8Array');
  }
  if (raw.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${raw.length}`);
  }
  const pkcs8 = Buffer.concat([PKCS8_HEADER, raw]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Build + sign an AAE envelope.
 *
 * @param {object} claims
 *   @param {string} claims.iss      — caller DID (e.g. 'did:moltrust:...')
 *   @param {string} claims.sub      — receiver subject (typically the receiver's slug)
 *   @param {string} claims.aud      — audience (must match the receiver's expectedAud, default 'a2a-ingress')
 *   @param {string} claims.sig_key_id — key id the receiver will resolve to your public key
 *   @param {number} [claims.iat]    — issued-at unix seconds; defaults to now
 *   @param {number} [claims.exp]    — expiry unix seconds; defaults to iat + lifetimeSec
 *   @param {number} [claims.hop]    — hop count for chained delegations; defaults to 0
 *   @param {Array<object>} [claims.perm] — capability assertions, structure-defined by your application
 *   @param {string} [claims.jti]    — nonce; defaults to a fresh 128-bit random value
 *
 * @param {object} keyMaterial
 *   @param {KeyObject} keyMaterial.key — result of loadSigningKey()
 *
 * @param {object} [opts]
 *   @param {number} [opts.lifetimeSec=300] — used only when claims.exp is absent
 *
 * @returns {string} base64url-encoded JSON envelope ready for the X-AAE / X-Klaw-AAE header
 */
export function signEnvelope(claims, keyMaterial, opts = {}) {
  if (!claims || typeof claims !== 'object') throw new Error('claims required');
  if (!keyMaterial || !keyMaterial.key) throw new Error('keyMaterial.key required (call loadSigningKey first)');
  if (typeof claims.iss !== 'string' || claims.iss.length === 0) throw new Error('claims.iss required');
  if (typeof claims.aud !== 'string' || claims.aud.length === 0) throw new Error('claims.aud required');
  if (typeof claims.sig_key_id !== 'string' || claims.sig_key_id.length === 0) throw new Error('claims.sig_key_id required');

  const lifetimeSec = opts.lifetimeSec ?? DEFAULT_LIFETIME_SEC;
  if (!Number.isFinite(lifetimeSec) || lifetimeSec < MIN_LIFETIME_SEC || lifetimeSec > MAX_LIFETIME_SEC) {
    throw new Error(`lifetimeSec must be a finite number between ${MIN_LIFETIME_SEC} and ${MAX_LIFETIME_SEC}`);
  }

  const now = Math.floor(Date.now() / 1000);
  const iat = claims.iat ?? now;
  const exp = claims.exp ?? (iat + lifetimeSec);
  if (exp - iat > MAX_LIFETIME_SEC) {
    throw new Error(`envelope lifetime (exp - iat) must not exceed ${MAX_LIFETIME_SEC}s`);
  }

  // Build the signed view by enumerating SIGNED_FIELDS in order. We
  // intentionally call signablePayload from a2a-acl so the bytes we
  // sign equal the bytes the verifier hashes. Adding/removing fields
  // requires a coordinated bump in both libraries.
  const env = {
    v: 1,
    iss: claims.iss,
    aud: claims.aud,
    iat,
    exp,
    jti: claims.jti ?? b64url(randomBytes(16)),
    sig_key_id: claims.sig_key_id,
    sig_alg: 'Ed25519',
    hop: claims.hop ?? 0,
  };
  if (claims.sub != null) env.sub = claims.sub;
  if (claims.perm != null) env.perm = claims.perm;

  const payload = signablePayload(env);
  const sigBuf = cryptoSign(null, payload, keyMaterial.key);
  env.sig = b64url(sigBuf);

  // Wire format: base64url-encoded JSON of the full envelope including sig.
  // The verifier base64url-decodes, JSON.parses, then re-derives the signed
  // bytes from SIGNED_FIELDS — so any extra keys we put on env (or any
  // ordering choice) doesn't affect verification.
  return b64url(Buffer.from(JSON.stringify(env), 'utf8'));
}

// Re-export for callers who need the signed-fields contract directly
// (e.g. a Python signer producing bit-identical bytes).
export { signablePayload, SIGNED_FIELDS };
