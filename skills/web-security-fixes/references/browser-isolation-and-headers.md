# Browser isolation and security headers

The browser enforces these controls for you, but only if you send them correctly. They're defense in depth: they make an XSS, CSRF, clickjacking, or cross-site leak bug unexploitable even when the code bug is still there. Run `scripts/check-headers.mjs <url>` to grade a live response.

## Contents
- [Baseline header set](#baseline-header-set)
- [Strict CSP](#strict-csp)
- [Trusted Types](#trusted-types)
- [Fetch Metadata: resource isolation policy](#fetch-metadata-resource-isolation-policy)
- [COOP, COEP, CORP and XS-Leaks](#coop-coep-corp-and-xs-leaks)
- [postMessage](#postmessage)
- [Obsolete headers](#obsolete-headers)

## Baseline header set

| Header | Value | Note |
|---|---|---|
| `Content-Security-Policy` | strict policy (below) | The biggest XSS mitigation |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Add `preload` only after every subdomain serves HTTPS. Removing a preload takes months |
| `X-Content-Type-Options` | `nosniff` | Stops user uploads being sniffed as HTML or JS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (or `no-referrer` on pages with tokens in URLs) | Reset and magic-link tokens in URLs leak via Referer |
| `Cross-Origin-Opener-Policy` | `same-origin` (`same-origin-allow-popups` if you open OAuth/payment popups that need `window.opener`) | Cuts `window.opener` references; blocks a class of XS-Leaks |
| `Cross-Origin-Resource-Policy` | `same-origin` on API responses and private files | Stops other sites embedding your responses as `<img>`/`<script>` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` and so on, for features you don't use | Limits what injected or third-party code can request |
| CSP `frame-ancestors` | `'none'` (or `'self'`) | Clickjacking. `X-Frame-Options: DENY` for very old browsers. `frame-ancestors` is ignored in a `<meta>` CSP |
| `Cache-Control` | `no-store` on authenticated, personalized responses | See `http-layer-cache-smuggling.md` |

## Strict CSP

An allowlist CSP (`script-src 'self' https://cdn.example.com https://www.google.com`) is mostly bypassable. Allowed CDNs and Google domains host JSONP endpoints and old Angular builds that run attacker-supplied script ("script gadgets"). Use a **nonce- or hash-based** policy instead:

```
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic' https: 'unsafe-inline';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  form-action 'self';
  report-to csp
Reporting-Endpoints: csp="https://example.com/csp-reports"
```

How it works:
- `'strict-dynamic'` lets nonce-approved scripts load their own dependencies. Browsers that support nonces ignore `https:` and `'unsafe-inline'`, which exist only as fallbacks for very old browsers.
- `object-src 'none'` and `base-uri 'none'` close the two classic bypasses (plugin content, and an injected `<base href>` that re-points your nonce'd relative scripts).

### Fixes that don't hold

| Mistake | Effect |
|---|---|
| `script-src 'self' 'unsafe-inline'` with no nonce or hash | No XSS protection at all |
| Nonce generated once at startup, or cached HTML with a nonce in it | An attacker reads the nonce from any page and reuses it. Generate 128+ random bits **per response** and don't cache nonce'd HTML at a shared cache (or use hashes for static pages) |
| `'unsafe-eval'` "because a library needs it" | Re-opens `eval`-style gadgets. Find a CSP-compatible build, or use `'wasm-unsafe-eval'` if it's only WebAssembly |
| Missing `base-uri` | `<base href=//evil.example/>` makes `<script nonce=... src="/app.js">` load from the attacker |
| Allowlisting `https://*.googleapis.com`, `cdnjs`, `unpkg`, or `jsdelivr` | Anyone can publish packages and JSONP there. Use SRI-pinned self-hosted copies |
| `default-src` set but `script-src` relies on it | Works, but then `'strict-dynamic'` must be in `default-src`. Keep an explicit `script-src` |
| Enforcing straight away | Breaks inline handlers (`onclick=`), `javascript:` links, and third-party tags. Ship `Content-Security-Policy-Report-Only` first, fix the reports, then enforce |

### Rollout

1. Send the policy as `Content-Security-Policy-Report-Only` with a reporting endpoint. Collect reports for 1–2 weeks of real traffic.
2. Remove inline event handlers (`onclick=` becomes `addEventListener`) and `javascript:` URLs. Add the nonce to every `<script>` you render, and to `<style>` if you lock down `style-src`.
3. Switch to enforcing, and keep a report-only copy of the *next* stricter policy (e.g. with Trusted Types) running alongside.

### Per stack

**Express (helmet 8):**

```js
import crypto from 'node:crypto';
import helmet from 'helmet';
app.use((req, res, next) => { res.locals.cspNonce = crypto.randomBytes(16).toString('base64'); next(); });
app.use(helmet({
  contentSecurityPolicy: { directives: {
    scriptSrc: [(req, res) => `'nonce-${res.locals.cspNonce}'`, "'strict-dynamic'", 'https:', "'unsafe-inline'"],
    objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"],
  } },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true },
}));
// templates: <script nonce="<%= cspNonce %>" src="/app.js"></script>
```

**Next.js:** nonce CSP is set in `proxy.ts` (formerly middleware) and forces dynamic rendering. Hash-based CSP or `'strict-dynamic'` with SRI keeps static pages static. For the full trade-off and a template, see the security reference in the separate `nextjs-ship-ready` skill (`npx skills add faisalinfinity/nextjs-production-skill --skill nextjs-ship-ready`), if it's installed.

**Django 6.0+ (built in):**

```python
MIDDLEWARE += ["django.middleware.csp.ContentSecurityPolicyMiddleware"]
TEMPLATES[0]["OPTIONS"]["context_processors"] += ["django.template.context_processors.csp"]
from django.utils.csp import CSP
SECURE_CSP_REPORT_ONLY = {   # rename to SECURE_CSP when reports are clean
    "script-src": [CSP.NONCE, CSP.STRICT_DYNAMIC],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "frame-ancestors": [CSP.NONE],
}
# templates: <script nonce="{{ csp_nonce }}" src="..."></script>
```

On Django < 6, use `django-csp` 4.x (`CONTENT_SECURITY_POLICY = {"DIRECTIVES": {...}}`).

**Flask / FastAPI:** generate the nonce per request (`secrets.token_urlsafe(16)`), store it on `g` or `request.state`, and set the header in an `after_request` hook or middleware. Pass the nonce to templates. Don't build CSP strings from user input.

## Trusted Types

Baseline since February 2026 (Chrome/Edge 83, Safari 26, Firefox 148). With Trusted Types enforced, DOM XSS sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `script.src`, `setAttribute('on…')`) throw a TypeError for plain strings. Only values produced by a named policy are accepted.

```
Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; trusted-types app-html dompurify; report-to csp
```

```js
const appHtml = window.trustedTypes?.createPolicy('app-html', {
  createHTML: (input) => DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: false }),
});
el.innerHTML = appHtml ? appHtml.createHTML(userHtml) : DOMPurify.sanitize(userHtml);
// DOMPurify can return a TrustedHTML itself: DOMPurify.sanitize(x, { RETURN_TRUSTED_TYPE: true }) (policy name 'dompurify')
```

Rollout:
1. Report-only.
2. Fix each reported sink. Usually that means `textContent`, or one sanitizing policy.
3. List every policy name in `trusted-types`.
4. Enforce.

**Don't** create a `default` policy that passes strings through unchanged. That turns enforcement off while looking compliant. React, Angular, and Lit are compatible. Check third-party widgets in report-only first.

## Fetch Metadata: resource isolation policy

Browsers send `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and `Sec-Fetch-Dest` with every request (all major browsers since 2023). A short server middleware rejects cross-site requests that aren't top-level navigations. That blocks CSRF, XSSI, and most XS-Leaks on endpoints that never needed to be cross-site.

```js
// Express. Put it before routes; exempt endpoints that are meant to be cross-site.
const CROSS_SITE_OK = new Set(['/webhooks/stripe', '/oauth/callback', '/api/public']);
app.use((req, res, next) => {
  const site = req.get('sec-fetch-site');
  if (!site || CROSS_SITE_OK.has(req.path)) return next();               // old browser or non-browser client
  if (site === 'same-origin' || site === 'same-site' || site === 'none') return next();
  if (req.get('sec-fetch-mode') === 'navigate' && req.method === 'GET'
      && !['object', 'embed'].includes(req.get('sec-fetch-dest'))) return next(); // plain link clicks
  res.status(403).send('cross-site request blocked');
});
```

```python
# Django / Flask / FastAPI: same logic in middleware
def allowed(request):
    site = request.headers.get("Sec-Fetch-Site")
    if not site or site in ("same-origin", "same-site", "none"):
        return True
    return request.headers.get("Sec-Fetch-Mode") == "navigate" and request.method == "GET" \
        and request.headers.get("Sec-Fetch-Dest") not in ("object", "embed")
```

`same-site` includes sibling subdomains. If subdomains are run by different teams or host user content, allow only `same-origin`.

## COOP, COEP, CORP and XS-Leaks

XS-Leaks infer cross-origin state ("is this user logged in", "does this search have results") from side channels: frame counts, `window.opener`, response timing, status codes via `<script>`/`<img>` error events, and cache probing. Defenses, cheapest first:
- `SameSite=Lax` or `Strict` session cookies: cross-site subresource requests arrive logged-out.
- Fetch Metadata isolation (above): cross-site subresource requests are refused.
- `Cross-Origin-Opener-Policy: same-origin`: an attacker's `window.open` handle can't count frames or read `history.length`.
- `Cross-Origin-Resource-Policy: same-origin` on JSON and private files.
- Make sensitive endpoints respond the same way (same status, similar size) for "found" and "not found" when probed cross-site.
- `COEP: require-corp` or `credentialless` is only needed for cross-origin isolation (`SharedArrayBuffer`, high-resolution timers). Turning it on requires CORP or CORS on every subresource. Don't enable it as a generic hardening step.

## postMessage

```js
// receiver
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://app.example.com') return;          // exact match, never includes()/endsWith()
  const msg = MessageSchema.safeParse(e.data);                  // validate shape: it's untrusted input
  if (!msg.success) return;
  handle(msg.data);
});
// sender: always name the target origin when sending anything sensitive
iframe.contentWindow.postMessage({ token }, 'https://widget.example.com');   // never '*'
```

Fixes that don't hold: `if (e.origin.includes('example.com'))` (passes `example.com.evil.example`), `if (e.origin.endsWith('.example.com'))` (passes any subdomain, including user-content ones), and checking `e.source` instead of `e.origin`.

## Obsolete headers

- `X-XSS-Protection`: the browser filter is gone. `1; mode=block` created XS-Leaks in old browsers. Send `0` or omit it.
- `Expect-CT`, `Public-Key-Pins`: removed from browsers. Delete them.
- `Feature-Policy`: replaced by `Permissions-Policy`.
- CSP `require-sri-for`: never shipped. Use `Integrity-Policy: blocked-destinations=(script)` (plus `Integrity-Policy-Report-Only` for rollout) to require SRI on scripts in browsers that support it. Check current support on MDN before relying on it alone.
