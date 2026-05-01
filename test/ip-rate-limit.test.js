import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IpRateLimiter } from '../src/ip-rate-limit.js';

test('allows up to limit, denies the next', () => {
  const rl = new IpRateLimiter({ requestsPerMinute: 3 });
  const k = IpRateLimiter.keyOf('1.2.3.4', 'tenant-x');
  assert.equal(rl.consume(k), true);
  assert.equal(rl.consume(k), true);
  assert.equal(rl.consume(k), true);
  assert.equal(rl.consume(k), false);
  rl.stop();
});

test('separate IPs have separate buckets', () => {
  const rl = new IpRateLimiter({ requestsPerMinute: 1 });
  assert.equal(rl.consume(IpRateLimiter.keyOf('1.1.1.1', 's')), true);
  assert.equal(rl.consume(IpRateLimiter.keyOf('1.1.1.2', 's')), true);
  rl.stop();
});

test('separate slugs (same IP) have separate buckets', () => {
  const rl = new IpRateLimiter({ requestsPerMinute: 1 });
  assert.equal(rl.consume(IpRateLimiter.keyOf('1.1.1.1', 's1')), true);
  assert.equal(rl.consume(IpRateLimiter.keyOf('1.1.1.1', 's2')), true);
  rl.stop();
});

test('keyOf is JSON-encoded — defends against IP-with-separator collisions', () => {
  const k1 = IpRateLimiter.keyOf('1.1.1.1|x', 'y');
  const k2 = IpRateLimiter.keyOf('1.1.1.1', 'x|y');
  assert.notEqual(k1, k2, 'JSON encoding must avoid pipe-separator collision');
});

test('rejects invalid requestsPerMinute', () => {
  assert.throws(() => new IpRateLimiter({ requestsPerMinute: 0 }), /positive number/);
  assert.throws(() => new IpRateLimiter({ requestsPerMinute: -5 }), /positive number/);
  assert.throws(() => new IpRateLimiter({ requestsPerMinute: NaN }), /positive number/);
  assert.throws(() => new IpRateLimiter({ requestsPerMinute: Infinity }), /positive number/);
});

test('rejects invalid maxBuckets', () => {
  assert.throws(() => new IpRateLimiter({ requestsPerMinute: 1, maxBuckets: 0 }), /positive number/);
  assert.throws(() => new IpRateLimiter({ requestsPerMinute: 1, maxBuckets: NaN }), /positive number/);
});

test('bucket cap evicts oldest when full', () => {
  const rl = new IpRateLimiter({ requestsPerMinute: 10, maxBuckets: 3 });
  rl.consume(IpRateLimiter.keyOf('1', 's'));
  rl.consume(IpRateLimiter.keyOf('2', 's'));
  rl.consume(IpRateLimiter.keyOf('3', 's'));
  assert.equal(rl.size(), 3);
  rl.consume(IpRateLimiter.keyOf('4', 's'));
  assert.equal(rl.size(), 3, 'should still be 3 after eviction');
  rl.stop();
});

test('size() reflects active buckets', () => {
  const rl = new IpRateLimiter({ requestsPerMinute: 5 });
  assert.equal(rl.size(), 0);
  rl.consume(IpRateLimiter.keyOf('a', 'b'));
  assert.equal(rl.size(), 1);
  rl.stop();
});
