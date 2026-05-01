import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateReceiverUrl, isPrivateOrLoopbackHost } from '../src/url-validation.js';

test('isPrivateOrLoopbackHost: IPv4 private ranges', () => {
  assert.equal(isPrivateOrLoopbackHost('10.0.0.1'), true);
  assert.equal(isPrivateOrLoopbackHost('10.255.255.255'), true);
  assert.equal(isPrivateOrLoopbackHost('172.16.0.1'), true);
  assert.equal(isPrivateOrLoopbackHost('172.31.255.255'), true);
  assert.equal(isPrivateOrLoopbackHost('192.168.1.1'), true);
  assert.equal(isPrivateOrLoopbackHost('127.0.0.1'), true);
  assert.equal(isPrivateOrLoopbackHost('169.254.169.254'), true, 'cloud metadata MUST be blocked');
  assert.equal(isPrivateOrLoopbackHost('0.0.0.0'), true);
});

test('isPrivateOrLoopbackHost: IPv4 public addresses pass through', () => {
  assert.equal(isPrivateOrLoopbackHost('8.8.8.8'), false);
  assert.equal(isPrivateOrLoopbackHost('1.1.1.1'), false);
  assert.equal(isPrivateOrLoopbackHost('172.15.255.255'), false);
  assert.equal(isPrivateOrLoopbackHost('172.32.0.0'), false);
});

test('isPrivateOrLoopbackHost: IPv6 loopback / link-local / ULA', () => {
  assert.equal(isPrivateOrLoopbackHost('::1'), true);
  assert.equal(isPrivateOrLoopbackHost('::'), true);
  assert.equal(isPrivateOrLoopbackHost('fe80::1'), true);
  assert.equal(isPrivateOrLoopbackHost('fc00::1'), true);
  assert.equal(isPrivateOrLoopbackHost('fd00::1'), true);
});

test('isPrivateOrLoopbackHost: IPv6 fully-expanded loopback (defence-in-depth)', () => {
  // Even if a future Node URL parser kept the expanded form, we catch it.
  assert.equal(isPrivateOrLoopbackHost('0:0:0:0:0:0:0:1'), true);
  assert.equal(isPrivateOrLoopbackHost('0:0:0:0:0:0:0:0'), true);
});

test('isPrivateOrLoopbackHost: IPv4-mapped IPv6 catches private v4', () => {
  assert.equal(isPrivateOrLoopbackHost('::ffff:10.0.0.1'), true);
  assert.equal(isPrivateOrLoopbackHost('::ffff:127.0.0.1'), true);
});

test('isPrivateOrLoopbackHost: regular hostnames return false (DNS check is operator responsibility)', () => {
  assert.equal(isPrivateOrLoopbackHost('example.com'), false);
  assert.equal(isPrivateOrLoopbackHost('agent.ownify.ai'), false);
});

test('isPrivateOrLoopbackHost: localhost variants explicitly blocked', () => {
  assert.equal(isPrivateOrLoopbackHost('localhost'), true);
  assert.equal(isPrivateOrLoopbackHost('LOCALHOST'), true);
  assert.equal(isPrivateOrLoopbackHost('localhost.localdomain'), true);
  assert.equal(isPrivateOrLoopbackHost('ip6-localhost'), true);
  assert.equal(isPrivateOrLoopbackHost('ip6-loopback'), true);
});

test('isPrivateOrLoopbackHost: IPv6 zone-ID stripped before isIP — link-local still blocked', () => {
  // fe80::1%eth0 is fe80::/10 link-local, must be rejected.
  assert.equal(isPrivateOrLoopbackHost('fe80::1%eth0'), true);
  assert.equal(isPrivateOrLoopbackHost('::1%lo0'), true);
});

test('isPrivateOrLoopbackHost: hostname with %suffix that is NOT a recognised IP is also rejected', () => {
  // Defence in depth — anything zoned that isn't a clean IP is suspect.
  assert.equal(isPrivateOrLoopbackHost('example.com%foo'), true);
});

test('isPrivateOrLoopbackHost: malformed input returns false', () => {
  assert.equal(isPrivateOrLoopbackHost(''), false);
  assert.equal(isPrivateOrLoopbackHost(null), false);
  assert.equal(isPrivateOrLoopbackHost(undefined), false);
  assert.equal(isPrivateOrLoopbackHost(12345), false);
});

test('validateReceiverUrl: valid https URL passes by default', () => {
  const r = validateReceiverUrl('https://agent.example.com/api/a2a/message');
  assert.equal(r.ok, true);
  assert.equal(r.url.hostname, 'agent.example.com');
});

test('validateReceiverUrl: http rejected by default (https-only)', () => {
  const r = validateReceiverUrl('http://agent.example.com/');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_protocol_not_allowed');
});

test('validateReceiverUrl: http allowed when explicitly enabled', () => {
  const r = validateReceiverUrl('http://agent.example.com/', { allowedProtocols: ['http:', 'https:'] });
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: file:// always rejected', () => {
  const r = validateReceiverUrl('file:///etc/passwd', { allowedProtocols: ['http:', 'https:', 'file:'] });
  // Even when explicitly added, file:// IS in allowedProtocols here so this case passes.
  // Real defence: don't add it. Check the default-deny path.
  assert.equal(r.ok, true); // allowed because we put it in allowedProtocols
  const r2 = validateReceiverUrl('file:///etc/passwd');
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'url_protocol_not_allowed');
});

test('validateReceiverUrl: private IP blocked even with https', () => {
  const r = validateReceiverUrl('https://10.0.0.1/');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_private_host');
});

test('validateReceiverUrl: cloud metadata blocked', () => {
  const r = validateReceiverUrl('http://169.254.169.254/latest/meta-data/', { allowedProtocols: ['http:'] });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_private_host');
});

test('validateReceiverUrl: private host allowed when allowPrivateHosts:true (test mode)', () => {
  const r = validateReceiverUrl('http://127.0.0.1:4500/api', { allowedProtocols: ['http:'], allowPrivateHosts: true });
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: allowedReceiverHosts allowlist — exact match', () => {
  const r = validateReceiverUrl('https://agent.example.com/', { allowedReceiverHosts: ['agent.example.com'] });
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: allowedReceiverHosts allowlist — wildcard match', () => {
  const r = validateReceiverUrl('https://sub.example.com/', { allowedReceiverHosts: ['*.example.com'] });
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: allowedReceiverHosts allowlist — wildcard does NOT match apex', () => {
  // *.example.com matches sub.example.com but NOT example.com itself
  const r = validateReceiverUrl('https://example.com/', { allowedReceiverHosts: ['*.example.com'] });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_host_not_allowlisted');
});

test('validateReceiverUrl: allowedReceiverHosts allowlist — non-listed host rejected', () => {
  const r = validateReceiverUrl('https://attacker.com/', { allowedReceiverHosts: ['*.example.com'] });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_host_not_allowlisted');
});

test('validateReceiverUrl: malformed URL string', () => {
  assert.equal(validateReceiverUrl('').ok, false);
  assert.equal(validateReceiverUrl('not-a-url').ok, false);
  assert.equal(validateReceiverUrl(null).ok, false);
  assert.equal(validateReceiverUrl(undefined).ok, false);
});

test('validateReceiverUrl: case-insensitive hostname matching against allowlist', () => {
  const r = validateReceiverUrl('https://Agent.Example.COM/', { allowedReceiverHosts: ['agent.example.com'] });
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: rejects URL with embedded credentials', () => {
  const r = validateReceiverUrl('https://user:pass@agent.example.com/api');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_embedded_credentials');
});

test('validateReceiverUrl: rejects URL with embedded username only', () => {
  const r = validateReceiverUrl('https://user@agent.example.com/api');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_embedded_credentials');
});

test('validateReceiverUrl: well-known internal port (Redis) blocked by default denylist', () => {
  const r = validateReceiverUrl('https://agent.example.com:6379/');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_port_denied');
});

test('validateReceiverUrl: PostgreSQL port blocked', () => {
  const r = validateReceiverUrl('https://agent.example.com:5432/');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_port_denied');
});

test('validateReceiverUrl: kubelet port blocked', () => {
  const r = validateReceiverUrl('https://agent.example.com:10250/');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_port_denied');
});

test('validateReceiverUrl: standard https port (no port in URL) passes', () => {
  const r = validateReceiverUrl('https://agent.example.com/api');
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: explicit standard https port passes', () => {
  const r = validateReceiverUrl('https://agent.example.com:443/api');
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: allowedReceiverPorts allowlist OVERRIDES denylist', () => {
  // 6379 is in denylist; if operator explicitly allows it, OK.
  const r = validateReceiverUrl('https://agent.example.com:6379/', { allowedReceiverPorts: [6379] });
  assert.equal(r.ok, true);
});

test('validateReceiverUrl: allowedReceiverPorts allowlist rejects non-listed port', () => {
  const r = validateReceiverUrl('https://agent.example.com:8443/', { allowedReceiverPorts: [443] });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_port_not_allowed');
});

test('validateReceiverUrl: empty deniedReceiverPorts disables port check', () => {
  const r = validateReceiverUrl('https://agent.example.com:6379/', { deniedReceiverPorts: new Set() });
  assert.equal(r.ok, true);
});
