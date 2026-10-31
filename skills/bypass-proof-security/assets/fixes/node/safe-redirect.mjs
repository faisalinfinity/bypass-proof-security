// safe-redirect.mjs: open-redirect-proof handling of ?next= / ?returnTo= values. Node 18+ / browsers.
//
// String checks like startsWith('/'), !startsWith('//'), includes(host) or a regex all
// lose to inputs the browser normalizes differently from your check: '/\evil.com',
// '/\t/evil.com', ' //evil.com', 'https://trusted.com@evil.com', 'java\tscript:'.
// The robust fix is to let the browser's own algorithm (WHATWG URL) parse the value,
// then decide on the parsed origin, and emit a value we re-serialized ourselves.
//
// Usage (Express):
//   import { safeRedirectTarget } from './safe-redirect.mjs';
//   res.redirect(303, safeRedirectTarget(req.query.next, { allowedOrigins: ['https://app.example.com'] }));

const BASE = 'https://redirect-base.invalid';

/**
 * Returns a value that is safe to put in a Location header (or window.location):
 * either a same-origin path ("/x?y#z") or an absolute URL on an allowed origin.
 * Anything else returns `fallback`.
 *
 * @param {unknown} input           untrusted value, e.g. req.query.next
 * @param {{ allowedOrigins?: string[], fallback?: string, maxLength?: number }} [opts]
 *   allowedOrigins: exact origins such as 'https://app.example.com' (scheme + host + port).
 *                   Exact match only. Don't use suffix or regex matching here.
 * @returns {string}
 */
export function safeRedirectTarget(input, opts = {}) {
  const { allowedOrigins = [], fallback = '/', maxLength = 2048 } = opts;
  if (typeof input !== 'string' || input.length === 0 || input.length > maxLength) return fallback;

  let url;
  try {
    url = new URL(input, BASE); // same parser browsers use: strips tabs/newlines, maps \ to /, etc.
  } catch {
    return fallback;
  }

  if (url.origin === BASE) {
    // Relative input. Re-serialize the path ourselves, collapsing leading slashes:
    // '/.//evil.com' and '/x/..//evil.com' normalize to the pathname '//evil.com',
    // which would become protocol-relative if emitted as-is.
    return '/' + url.pathname.replace(/^\/+/, '') + url.search + url.hash;
  }

  if ((url.protocol === 'https:' || url.protocol === 'http:') && allowedOrigins.includes(url.origin)) {
    return url.href;
  }
  return fallback;
}

/**
 * Boolean form, for validation at write time (e.g. when saving an OAuth client's
 * redirect_uri). Prefer safeRedirectTarget at use time.
 * @param {unknown} input
 * @param {{ allowedOrigins?: string[] }} [opts]
 */
export function isSafeRedirect(input, opts = {}) {
  const marker = '\u0000fallback';
  return safeRedirectTarget(input, { ...opts, fallback: marker }) !== marker;
}

/**
 * OAuth/OIDC redirect_uri check: exact string match against pre-registered URIs.
 * The OAuth 2.0 Security BCP (RFC 9700) requires exact matching. Prefix, wildcard, and
 * "same host" matching have each caused real account-takeover bugs.
 * @param {string} redirectUri
 * @param {string[]} registered
 */
export function isRegisteredRedirectUri(redirectUri, registered) {
  return typeof redirectUri === 'string' && registered.includes(redirectUri);
}
