// safe-fetch.mjs: SSRF-safe outbound HTTP for Node 20+. Zero dependencies.
//
// Why this exists: the usual SSRF fix ("resolve the hostname, check the IP, then fetch")
// has a time-of-check/time-of-use gap. fetch() resolves DNS again, and a short-TTL record
// can answer with a public IP for the check and 127.0.0.1 for the connection (DNS
// rebinding). Redirects are a second gap: the check runs on the first URL only.
//
// This helper validates the IP *at connect time* through the socket's `lookup` hook, so
// the address that's checked is the address that's dialed. TLS still verifies the
// certificate against the original hostname. Every redirect hop is re-validated, IP
// literals (which skip DNS) are checked directly, and the module uses its own connection
// pool so it can never reuse a socket that other code opened to an internal host.
//
// Usage:
//   import { safeFetch } from './safe-fetch.mjs';
//   const res = await safeFetch(userSuppliedUrl, { timeoutMs: 5000 });
//   const data = await res.json();          // a standard fetch Response
//
// Defense in depth: also block egress at the network layer (egress proxy, security
// group, or IMDSv2 with hop limit 1). Application checks are one layer, not the only one.

import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';

export class SsrfBlockedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SsrfBlockedError';
    this.code = 'ERR_SSRF_BLOCKED';
  }
}

export class SafeFetchError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SafeFetchError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// IP policy
// ---------------------------------------------------------------------------

// Non-global IPv4 ranges (IANA special-purpose registry) plus CGNAT, which cloud providers
// use for metadata services (Alibaba: 100.100.100.200).
const V4_BLOCKED = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) V4_BLOCKED.addSubnet(addr, prefix, 'ipv4');

/** Expand an IPv6 string (no brackets, no zone) into eight 16-bit groups. */
function ipv6Groups(ip) {
  let s = ip;
  const dotted = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/); // trailing dotted quad, e.g. ::ffff:127.0.0.1
  if (dotted) {
    const p = dotted[2].split('.').map(Number);
    s = `${dotted[1]}${((p[0] << 8) | p[1]).toString(16)}:${((p[2] << 8) | p[3]).toString(16)}`;
  }
  let parts = s.split(':');
  if (s.includes('::')) {
    const [l, r] = s.split('::');
    const left = l ? l.split(':') : [];
    const right = r ? r.split(':') : [];
    parts = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  }
  return parts.map((h) => parseInt(h, 16));
}

function v4FromGroups(hi, lo) {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

/**
 * True only for globally routable unicast addresses. Everything else (loopback, private,
 * link-local, metadata, CGNAT, multicast, documentation, ULA) is rejected. IPv6 forms that
 * embed an IPv4 address (IPv4-mapped, NAT64, 6to4) are judged by the embedded address.
 * @param {string} ip
 * @returns {boolean}
 */
export function isPublicAddress(ip) {
  if (typeof ip !== 'string') return false;
  const addr = ip.replace(/^\[|\]$/g, '').split('%')[0]; // strip brackets and zone id
  const family = net.isIP(addr);
  if (family === 4) return !V4_BLOCKED.check(addr, 'ipv4');
  if (family !== 6) return false;

  const g = ipv6Groups(addr.toLowerCase());
  // ::ffff:0:0/96, IPv4-mapped
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return isPublicAddress(v4FromGroups(g[6], g[7]));
  // 64:ff9b::/96, NAT64 well-known prefix (DNS64 networks use it for public IPv4 hosts)
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return isPublicAddress(v4FromGroups(g[6], g[7]));
  // 2002::/16, 6to4: the IPv4 address sits in groups 1-2
  if (g[0] === 0x2002) return isPublicAddress(v4FromGroups(g[1], g[2]));
  // Only 2000::/3 is global unicast; within it, carve out the special-purpose blocks.
  if ((g[0] & 0xe000) !== 0x2000) return false;
  if (g[0] === 0x2001 && g[1] < 0x0200) return false; // 2001::/23 IETF protocol assignments (Teredo, benchmarking, ORCHID)
  if (g[0] === 0x2001 && g[1] === 0x0db8) return false; // 2001:db8::/32 documentation
  if (g[0] === 0x3fff && g[1] < 0x1000) return false; // 3fff::/20 documentation
  return true;
}

const BLOCKED_HOSTNAMES = /^(localhost|metadata|metadata\.google\.internal|instance-data)\.?$|\.(localhost|local|internal|home\.arpa)\.?$/i;

/**
 * Build a dns-style lookup function that refuses to return any non-allowed address.
 * Pass it as `lookup` to http.request, net.connect, axios (`lookup`), or got (`dnsLookup`).
 * If a hostname resolves to several addresses and ANY of them is blocked, the lookup fails:
 * a name that points at both public and private space is not one you want to talk to.
 * @param {(ip: string) => boolean} [isAllowedAddress]
 */
export function createGuardedLookup(isAllowedAddress = isPublicAddress) {
  return function guardedLookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (typeof options === 'number') options = { family: options };
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err);
      const bad = addresses.find((a) => !isAllowedAddress(a.address));
      if (bad || addresses.length === 0) {
        return callback(new SsrfBlockedError(`${hostname} resolves to a blocked address (${bad ? bad.address : 'none'})`));
      }
      if (options.all) return callback(null, addresses);
      return callback(null, addresses[0].address, addresses[0].family);
    });
  };
}

/**
 * Synchronous checks on the URL itself: protocol, port, credentials, hostname, and IP
 * literals (which never go through DNS, so the lookup hook can't see them).
 * Returns the parsed URL. Throws SsrfBlockedError.
 * @param {string | URL} input
 * @param {{ allowedProtocols?: string[], allowedPorts?: number[] | null, isAllowedAddress?: (ip: string) => boolean, allowHostname?: (host: string) => boolean }} [opts]
 */
export function assertSafeUrl(input, opts = {}) {
  const {
    allowedProtocols = ['http:', 'https:'],
    allowedPorts = [80, 443],
    isAllowedAddress = isPublicAddress,
    allowHostname,
  } = opts;
  let url;
  try {
    url = input instanceof URL ? new URL(input.href) : new URL(String(input));
  } catch {
    throw new SsrfBlockedError('not an absolute URL');
  }
  if (!allowedProtocols.includes(url.protocol)) throw new SsrfBlockedError(`protocol ${url.protocol} is not allowed`);
  if (url.username || url.password) throw new SsrfBlockedError('credentials in URL are not allowed');
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (allowedPorts && !allowedPorts.includes(port)) throw new SsrfBlockedError(`port ${port} is not allowed`);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host) throw new SsrfBlockedError('missing host');
  if (net.isIP(host)) {
    if (!isAllowedAddress(host)) throw new SsrfBlockedError(`address ${host} is blocked`);
  } else if (BLOCKED_HOSTNAMES.test(host) && !(allowHostname && allowHostname(host))) {
    throw new SsrfBlockedError(`hostname ${host} is blocked`);
  }
  if (allowHostname && !net.isIP(host) && !allowHostname(host)) throw new SsrfBlockedError(`hostname ${host} is not on the allowlist`);
  return url;
}

/**
 * Validate-only check, including DNS: use it to reject bad URLs early, e.g. when a user
 * saves a webhook URL. It is NOT a substitute for safeFetch at send time: DNS can change
 * between this check and the request, so the request itself must be pinned.
 * Resolves to the parsed URL; rejects with SsrfBlockedError.
 * @param {string | URL} input
 * @param {Parameters<typeof assertSafeUrl>[1]} [opts]
 */
export async function validateUrl(input, opts = {}) {
  const url = assertSafeUrl(input, opts);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!net.isIP(host)) {
    const lookup = createGuardedLookup(opts.isAllowedAddress || isPublicAddress);
    await new Promise((resolve, reject) => lookup(host, { all: true }, (err) => (err ? reject(err) : resolve())));
  }
  return url;
}

// Dedicated pools: never share sockets with the rest of the app (a pooled socket to an
// internal host, opened by trusted code, would otherwise be reused without a lookup).
const agents = new Map();
function agentFor(protocol, isAllowedAddress) {
  const key = `${protocol}|${isAllowedAddress === isPublicAddress ? 'default' : 'custom'}`;
  if (isAllowedAddress !== isPublicAddress) {
    // A custom policy gets its own short-lived agent so policies never share sockets.
    const Agent = protocol === 'https:' ? https.Agent : http.Agent;
    return new Agent({ keepAlive: false, lookup: createGuardedLookup(isAllowedAddress) });
  }
  if (!agents.has(key)) {
    const Agent = protocol === 'https:' ? https.Agent : http.Agent;
    agents.set(key, new Agent({ keepAlive: true, maxSockets: 64, lookup: createGuardedLookup(isPublicAddress) }));
  }
  return agents.get(key);
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);
const CROSS_ORIGIN_STRIP = ['authorization', 'cookie', 'proxy-authorization'];

function requestOnce(url, { method, headers, body, signal, maxResponseBytes, truncate, isAllowedAddress }) {
  return new Promise((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(url, {
      method,
      headers,
      signal,
      agent: agentFor(url.protocol, isAllowedAddress),
      lookup: createGuardedLookup(isAllowedAddress),
    }, (res) => {
      const chunks = [];
      let size = 0;
      let failed = false;
      res.on('data', (chunk) => {
        if (failed) return;
        size += chunk.length;
        if (size > maxResponseBytes && truncate) {
          chunks.push(chunk.subarray(0, chunk.length - (size - maxResponseBytes)));
          failed = true; // stop reading; resolve with what we have
          resolve({ status: res.statusCode, rawHeaders: res.rawHeaders, location: res.headers.location, body: Buffer.concat(chunks), truncated: true });
          req.destroy();
          return;
        }
        if (size > maxResponseBytes) {
          failed = true;
          const err = new SafeFetchError(`response exceeded ${maxResponseBytes} bytes`, 'ERR_RESPONSE_TOO_LARGE');
          reject(err);
          req.destroy(err);
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (!failed) resolve({ status: res.statusCode, rawHeaders: res.rawHeaders, location: res.headers.location, body: Buffer.concat(chunks) });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    if (body != null) req.write(body);
    req.end();
  });
}

/**
 * fetch-like GET/POST to an untrusted URL. Resolves to a standard `Response` whose `url`
 * is the final URL after redirects. Rejects with SsrfBlockedError (code ERR_SSRF_BLOCKED)
 * if any hop targets a blocked address, protocol, or port.
 *
 * @param {string | URL} input
 * @param {{
 *   method?: string, headers?: Record<string, string>, body?: string | Uint8Array,
 *   maxRedirects?: number, timeoutMs?: number, maxResponseBytes?: number, signal?: AbortSignal,
 *   truncate?: boolean,   // true: return the first maxResponseBytes instead of failing (link previews); response.truncated tells you
 *   allowedProtocols?: string[], allowedPorts?: number[] | null,
 *   isAllowedAddress?: (ip: string) => boolean, allowHostname?: (host: string) => boolean,
 * }} [init]
 * @returns {Promise<Response>}
 */
export async function safeFetch(input, init = {}) {
  const {
    maxRedirects = 5,
    timeoutMs = 10_000,
    maxResponseBytes = 5 * 1024 * 1024,
    isAllowedAddress = isPublicAddress,
  } = init;
  let method = (init.method || 'GET').toUpperCase();
  let body = init.body;
  let headers = Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;

  let current = assertSafeUrl(input, init);
  for (let hop = 0; ; hop++) {
    let res;
    try {
      res = await requestOnce(current, { method, headers, body, signal, maxResponseBytes, truncate: init.truncate === true, isAllowedAddress });
    } catch (err) {
      if (err && err.name === 'AbortError' && timeout.aborted) throw new SafeFetchError(`timed out after ${timeoutMs} ms`, 'ERR_TIMEOUT');
      throw err;
    }

    if (REDIRECT_STATUSES.has(res.status) && res.location) {
      if (hop >= maxRedirects) throw new SafeFetchError(`more than ${maxRedirects} redirects`, 'ERR_TOO_MANY_REDIRECTS');
      const next = assertSafeUrl(new URL(res.location, current), init); // re-validate every hop
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
        method = 'GET';
        body = undefined;
        delete headers['content-type'];
        delete headers['content-length'];
      }
      if (next.origin !== current.origin) {
        headers = { ...headers };
        for (const h of CROSS_ORIGIN_STRIP) delete headers[h];
      }
      current = next;
      continue;
    }

    const responseHeaders = new Headers();
    for (let i = 0; i < res.rawHeaders.length; i += 2) {
      try { responseHeaders.append(res.rawHeaders[i], res.rawHeaders[i + 1]); } catch { /* skip invalid header */ }
    }
    const response = new Response(NULL_BODY_STATUSES.has(res.status) || method === 'HEAD' ? null : res.body, {
      status: res.status,
      headers: responseHeaders,
    });
    Object.defineProperty(response, 'url', { value: current.href });
    Object.defineProperty(response, 'truncated', { value: res.truncated === true });
    return response;
  }
}
