import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseClaimedDid, hashVisitor, captureCallerId } from '../src/caller-id.js';

test('parseClaimedDid accepts well-formed DIDs', () => {
  assert.equal(parseClaimedDid('did:moltrust:abc123'), 'did:moltrust:abc123');
  assert.equal(parseClaimedDid('did:web:example.com'), 'did:web:example.com');
  assert.equal(parseClaimedDid('did:key:z6Mk_abc-123.456'), 'did:key:z6Mk_abc-123.456');
});

test('parseClaimedDid rejects malformed input', () => {
  assert.equal(parseClaimedDid(''), null);
  assert.equal(parseClaimedDid('not-a-did'), null);
  assert.equal(parseClaimedDid('did:'), null);
  assert.equal(parseClaimedDid('did:method:'), null);
  assert.equal(parseClaimedDid(null), null);
  assert.equal(parseClaimedDid(undefined), null);
  assert.equal(parseClaimedDid(12345), null);
});

test('parseClaimedDid rejects oversized input', () => {
  const huge = 'did:x:' + 'a'.repeat(500);
  assert.equal(parseClaimedDid(huge), null);
});

test('parseClaimedDid rejects DIDs with invalid characters in id', () => {
  assert.equal(parseClaimedDid('did:moltrust:has spaces'), null);
  assert.equal(parseClaimedDid('did:moltrust:has\nnewline'), null);
});

test('hashVisitor produces deterministic 32-char hex', () => {
  const h = hashVisitor({ ip: '1.1.1.1', userAgent: 'curl/8', sessionId: 'sess-1' });
  assert.match(h, /^[0-9a-f]{32}$/);
  assert.equal(h, hashVisitor({ ip: '1.1.1.1', userAgent: 'curl/8', sessionId: 'sess-1' }));
});

test('hashVisitor differs on different inputs', () => {
  const a = hashVisitor({ ip: '1.1.1.1', userAgent: 'A' });
  const b = hashVisitor({ ip: '1.1.1.1', userAgent: 'B' });
  assert.notEqual(a, b);
});

test('hashVisitor handles all-empty input', () => {
  const h = hashVisitor({});
  assert.match(h, /^[0-9a-f]{32}$/);
});

test('captureCallerId reads X-Caller-DID via req.get', () => {
  const req = {
    get: (name) => (name.toLowerCase() === 'x-caller-did' ? 'did:moltrust:abc' : null),
    ip: '5.5.5.5',
    headers: {},
  };
  const id = captureCallerId(req);
  assert.equal(id.claimed_did, 'did:moltrust:abc');
  assert.match(id.visitor_hash, /^[0-9a-f]{32}$/);
});

test('captureCallerId falls back to req.headers when req.get absent', () => {
  const req = {
    headers: { 'x-caller-did': 'did:moltrust:xyz', 'user-agent': 'curl/8.7' },
    ip: '5.5.5.5',
  };
  const id = captureCallerId(req);
  assert.equal(id.claimed_did, 'did:moltrust:xyz');
});

test('captureCallerId returns null claimed_did when header missing', () => {
  const req = { headers: {}, ip: '1.1.1.1' };
  const id = captureCallerId(req);
  assert.equal(id.claimed_did, null);
});

test('captureCallerId truncates oversized X-Ownify-Client', () => {
  const huge = 'x'.repeat(500);
  const req = {
    get: (name) => (name.toLowerCase() === 'x-ownify-client' ? huge : null),
    headers: {},
    ip: '1.1.1.1',
  };
  const id = captureCallerId(req);
  assert.equal(id.client, null, 'oversized client header must collapse to null');
});

test('captureCallerId visitor_hash stable across same request shape', () => {
  const make = () => ({
    get: (n) => n.toLowerCase() === 'user-agent' ? 'Mozilla/X' : null,
    headers: {},
    ip: '9.9.9.9',
    session: { id: 'sess-z' },
  });
  const a = captureCallerId(make());
  const b = captureCallerId(make());
  assert.equal(a.visitor_hash, b.visitor_hash);
});
