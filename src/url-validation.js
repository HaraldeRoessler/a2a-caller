// Receiver-URL validation — SSRF defence layer.
//
// The middleware will POST a signed AAE envelope to whatever URL the
// caller's resolveReceiver() returns. A buggy/compromised callback
// could direct that POST at internal infrastructure (cloud metadata
// services, internal admin panels, Redis/Postgres, etc.). This module
// blocks the most obvious classes of that attack at the URL layer
// before any network call fires.
//
// What it catches:
//   - Non-http(s) protocols (file://, data://, gopher://, ...)
//   - Literal private/loopback/link-local/metadata IP addresses in the
//     hostname (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7, fe80::/10)
//   - Hostname mismatch against a caller-supplied allowlist
//
// What it does NOT catch (operator must layer on):
//   - DNS rebinding — a hostname that resolves to a public IP at
//     check-time and a private IP at fetch-time. Mitigation: pin DNS
//     resolution to a single result and pass a literal IP to fetch,
//     or use a forward proxy that re-validates per-connection.
//   - IPv6 mapped IPv4 (::ffff:10.0.0.1) — caught only if the hostname
//     parses cleanly via net.isIP(). For belt-and-braces, normalise
//     before resolveReceiver() returns.
//   - Open redirects on the receiver. We POST and forward the response;
//     the response body is not followed.

import { isIP } from 'node:net';

const PRIVATE_V4_RANGES = [
  // [networkInt, prefixLen]
  [0x0a000000, 8],   // 10.0.0.0/8
  [0xac100000, 12],  // 172.16.0.0/12
  [0xc0a80000, 16],  // 192.168.0.0/16
  [0x7f000000, 8],   // 127.0.0.0/8 — loopback
  [0xa9fe0000, 16],  // 169.254.0.0/16 — link-local + cloud metadata
  [0x00000000, 8],   // 0.0.0.0/8 — "this network"
];

function v4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const x = Number(p);
    if (!Number.isInteger(x) || x < 0 || x > 255) return null;
    n = (n * 256) + x;
  }
  return n >>> 0;
}

function inRangeV4(ip, [network, prefix]) {
  const ipInt = v4ToInt(ip);
  if (ipInt === null) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (network & mask);
}

function isPrivateV6(ip) {
  // Normalise — Node's URL hostname strips brackets but lowercases.
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;       // loopback / unspecified
  if (lower.startsWith('fe8') || lower.startsWith('fe9') ||
      lower.startsWith('fea') || lower.startsWith('feb')) return true;  // fe80::/10 link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;    // fc00::/7 unique local
  // IPv4-mapped IPv6: ::ffff:10.0.0.1 → check the v4 portion
  const v4mapped = lower.match(/^::ffff:([0-9.]+)$/);
  if (v4mapped) {
    return PRIVATE_V4_RANGES.some((r) => inRangeV4(v4mapped[1], r));
  }
  return false;
}

/**
 * Returns true if the hostname is a literal IP address in a private,
 * loopback, link-local, or "this-network" range. Hostnames that aren't
 * IP literals (regular DNS names) return false — we leave DNS-based
 * filtering to the operator's network layer.
 */
export function isPrivateOrLoopbackHost(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0) return false;
  const family = isIP(hostname);
  if (family === 4) {
    return PRIVATE_V4_RANGES.some((r) => inRangeV4(hostname, r));
  }
  if (family === 6) {
    return isPrivateV6(hostname);
  }
  return false;
}

function hostMatchesPattern(host, pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) return false;
  if (pattern === host) return true;
  // Wildcard at the leading position only: *.example.com matches
  // sub.example.com but not example.com itself (consistent with
  // browser cookie scoping). No internal wildcards permitted.
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // ".example.com"
    return host.length > suffix.length && host.endsWith(suffix);
  }
  return false;
}

/**
 * Validate a receiver URL string before fetch().
 *
 * @param {string} urlStr
 * @param {object} [opts]
 *   @param {string[]} [opts.allowedReceiverHosts]
 *      If present, hostname MUST match at least one entry. Entries are
 *      either exact hostnames ('agent.example.com') or wildcard
 *      patterns ('*.example.com' — matches sub-hosts only, not apex).
 *   @param {string[]} [opts.allowedProtocols=['https:']]
 *      Permitted URL protocols. Default https-only. Add 'http:' for
 *      local development.
 *   @param {boolean} [opts.allowPrivateHosts=false]
 *      If true, skip the private-IP / loopback check. Used by tests
 *      that point at 127.0.0.1.
 *
 * @returns {{ ok: true, url: URL } | { ok: false, reason: string }}
 */
export function validateReceiverUrl(urlStr, opts = {}) {
  if (typeof urlStr !== 'string' || urlStr.length === 0) {
    return { ok: false, reason: 'url_missing' };
  }
  let url;
  try {
    url = new URL(urlStr);
  } catch {
    return { ok: false, reason: 'url_invalid' };
  }
  const allowedProtocols = opts.allowedProtocols ?? ['https:'];
  if (!allowedProtocols.includes(url.protocol)) {
    return { ok: false, reason: 'url_protocol_not_allowed' };
  }
  if (!opts.allowPrivateHosts && isPrivateOrLoopbackHost(url.hostname)) {
    return { ok: false, reason: 'url_private_host' };
  }
  if (Array.isArray(opts.allowedReceiverHosts) && opts.allowedReceiverHosts.length > 0) {
    const host = url.hostname.toLowerCase();
    const matched = opts.allowedReceiverHosts.some((p) => hostMatchesPattern(host, String(p).toLowerCase()));
    if (!matched) return { ok: false, reason: 'url_host_not_allowlisted' };
  }
  return { ok: true, url };
}
