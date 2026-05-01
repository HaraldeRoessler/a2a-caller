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
  // WHATWG URL parsers normalise compressed IPv6 (`::1`) but don't
  // always normalise the fully-expanded form. Defend against both
  // representations explicitly so a future Node version that decides
  // to keep the expanded form can't silently bypass the check.
  if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') return true;
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

// Default denylist of well-known internal-service ports. A receiver URL
// pointing at one of these is almost certainly an attack — even if the
// hostname is allowlisted, an attacker who controls resolveReceiver
// can pivot to the internal service via the same DNS name. The
// denylist is non-breaking (default ports 80/443/etc. still work);
// operators wanting a strict allowlist pass `allowedReceiverPorts`.
const DEFAULT_DENIED_PORTS = new Set([
  22,    // SSH
  23,    // Telnet
  25,    // SMTP
  53,    // DNS
  111,   // RPC
  135,   // RPC endpoint mapper (Windows)
  139,   // NetBIOS
  445,   // SMB
  1433,  // SQL Server
  1521,  // Oracle
  2049,  // NFS
  2375,  // Docker daemon (unsecured)
  2376,  // Docker daemon (TLS)
  3306,  // MySQL
  3389,  // RDP
  5432,  // PostgreSQL
  5984,  // CouchDB
  6379,  // Redis
  6443,  // Kubernetes API
  7000,  // Cassandra
  7001,  // Cassandra
  8086,  // InfluxDB
  9042,  // Cassandra
  9092,  // Kafka
  9200,  // Elasticsearch
  9300,  // Elasticsearch
  10250, // Kubernetes kubelet
  11211, // Memcached
  15672, // RabbitMQ
  25565, // Minecraft (any DB-flavoured app port)
  27017, // MongoDB
  27018, // MongoDB
  27019, // MongoDB
  50000, // SAP / HANA
]);

// Loopback hostnames operators / curl / browsers commonly resolve to
// 127.0.0.1 or ::1. node:net.isIP() doesn't catch these (they're DNS
// names, not IP literals). Reject them explicitly so a misconfigured
// `allowedProtocols: ['http:']` + a buggy `resolveReceiver` returning
// `http://localhost:9999/` can't reach a service bound to 127.0.0.1.
const LOOPBACK_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback']);

/**
 * Returns true if the hostname is a literal IP address in a private,
 * loopback, link-local, or "this-network" range — OR a well-known
 * loopback DNS name. Regular DNS names not in the loopback set
 * return false; DNS-based filtering for those is left to the
 * operator's network layer.
 */
export function isPrivateOrLoopbackHost(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0) return false;
  const lower = hostname.toLowerCase();
  if (LOOPBACK_HOSTNAMES.has(lower)) return true;
  // IPv6 zone-ID defence: an URL like http://[fe80::1%25eth0]/ produces
  // hostname "fe80::1%eth0" — Node's isIP() returns 0 for the zoned
  // form and the link-local fe80::/10 prefix-check would never run.
  // Strip the zone before isIP(); ALSO reject zoned hostnames that
  // don't otherwise resolve to a known IP class (defence in depth).
  const stripped = lower.includes('%') ? lower.split('%')[0] : lower;
  const family = isIP(stripped);
  if (family === 4) {
    return PRIVATE_V4_RANGES.some((r) => inRangeV4(stripped, r));
  }
  if (family === 6) {
    return isPrivateV6(stripped);
  }
  // Hostname has a `%` suffix but doesn't resolve to a recognised IP
  // family even after stripping — treat as suspect, block.
  if (lower !== stripped) return true;
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
 *      patterns ('*.example.com' — matches sub-hosts at ANY depth, not
 *      apex). See README "Allowlist semantics" for examples.
 *   @param {string[]} [opts.allowedProtocols=['https:']]
 *      Permitted URL protocols. Default https-only. Add 'http:' for
 *      local development.
 *   @param {boolean} [opts.allowPrivateHosts=false]
 *      If true, skip the private-IP / loopback check. Used by tests
 *      that point at 127.0.0.1.
 *   @param {number[]} [opts.allowedReceiverPorts]
 *      If present, the URL's port (or scheme-default) MUST match one
 *      of these. Strict allowlist mode — when set it OVERRIDES the
 *      built-in port denylist. Pass `[443, 8443]` to lock outbound
 *      to specific HTTPS ports.
 *   @param {Iterable<number>} [opts.deniedReceiverPorts=DEFAULT_DENIED_PORTS]
 *      Port-denylist for the common internal-service ports (Redis,
 *      PostgreSQL, MongoDB, kubelet, etc.). Used only when
 *      `allowedReceiverPorts` is not set. Pass `new Set()` to disable.
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
  // Reject URLs with embedded credentials (https://user:pw@host/...).
  // fetch() will turn these into an Authorization: Basic header,
  // leaking creds to whatever receiver answered the DNS lookup. There
  // is never a legitimate reason for resolveReceiver to return such
  // a URL — the portal's own credentials should travel via secret
  // configuration, not URL strings.
  if (url.username || url.password) {
    return { ok: false, reason: 'url_embedded_credentials' };
  }
  if (!opts.allowPrivateHosts && isPrivateOrLoopbackHost(url.hostname)) {
    return { ok: false, reason: 'url_private_host' };
  }
  // Port check. Effective port is what new URL() resolved (empty
  // string for scheme-default → use the protocol's default).
  const effectivePort = url.port === ''
    ? (url.protocol === 'https:' ? 443 : url.protocol === 'http:' ? 80 : null)
    : Number(url.port);
  if (Array.isArray(opts.allowedReceiverPorts) && opts.allowedReceiverPorts.length > 0) {
    if (!opts.allowedReceiverPorts.includes(effectivePort)) {
      return { ok: false, reason: 'url_port_not_allowed' };
    }
  } else {
    const denylist = opts.deniedReceiverPorts ?? DEFAULT_DENIED_PORTS;
    if (effectivePort != null && (denylist instanceof Set ? denylist.has(effectivePort) : Array.from(denylist).includes(effectivePort))) {
      return { ok: false, reason: 'url_port_denied' };
    }
  }
  if (Array.isArray(opts.allowedReceiverHosts) && opts.allowedReceiverHosts.length > 0) {
    const host = url.hostname.toLowerCase();
    const matched = opts.allowedReceiverHosts.some((p) => hostMatchesPattern(host, String(p).toLowerCase()));
    if (!matched) return { ok: false, reason: 'url_host_not_allowlisted' };
  }
  return { ok: true, url };
}

// Exported so callers can override / extend the denylist.
export { DEFAULT_DENIED_PORTS };
