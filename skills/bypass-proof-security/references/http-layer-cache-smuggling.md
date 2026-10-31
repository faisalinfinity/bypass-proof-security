# HTTP layer: Host trust, proxies, cache poisoning and deception, request smuggling

Bugs that live between the client, your proxies and CDN, and your app: places where two components disagree about what a request means. App code can't fix all of these, but it causes or prevents most of them.

## Contents
- [Host header and forwarded headers](#host-header-and-forwarded-headers)
- [Web cache poisoning](#web-cache-poisoning)
- [Web cache deception](#web-cache-deception)
- [Request smuggling and desync](#request-smuggling-and-desync)
- [Proxy access rules vs path normalization](#proxy-access-rules-vs-path-normalization)
- [Regression tests](#regression-tests)

## Host header and forwarded headers

### Verified with Express 5.3

Request headers sent by the client: `X-Forwarded-For: 6.6.6.6, 10.0.0.5`, `X-Forwarded-Host: evil.example`.

| `app.set('trust proxy', ...)` | `req.ip` | `req.hostname` |
|---|---|---|
| unset | socket address | real `Host` |
| `true` | **`6.6.6.6`** (leftmost, attacker-written) | **`evil.example`** |
| `1` (one proxy hop) | `10.0.0.5` (added by your proxy) | **`evil.example`** |

Consequences:
- **`trust proxy: true` lets clients choose their IP.** That breaks rate limits, IP allowlists, audit logs, and geo rules. Set the exact hop count (`1` for one load balancer) or the proxy CIDRs.
- **`req.hostname` / `req.host` / `X-Forwarded-Host` / Django `request.get_host()` with `USE_X_FORWARDED_HOST=True` are attacker-influenced** unless your edge overwrites or strips the header. Build absolute URLs in emails (password reset, invites, verification), redirects, canonical tags, and OAuth `redirect_uri` from a **configured** base URL (`APP_URL`), never from the request. Otherwise you get password-reset poisoning: the victim gets a real token in a link to the attacker's host.

Per stack:
- Django: set `ALLOWED_HOSTS` exactly (never `["*"]` in production). Leave `USE_X_FORWARDED_HOST = False` unless the proxy sets it. Behind TLS termination, use `SECURE_PROXY_SSL_HEADER` only if the proxy strips the client's copy.
- Flask/FastAPI: `werkzeug.middleware.proxy_fix.ProxyFix(app, x_for=1, x_proto=1)` with exact counts. Uvicorn: `--forwarded-allow-ips` set to your proxy IPs, not `*`.
- Rails: `config.hosts` (host authorization). `request.remote_ip` handles trusted proxies.
- Edge: have the load balancer or CDN overwrite `X-Forwarded-For`, `-Host`, and `-Proto`, not append client-supplied values.

## Web cache poisoning

A shared cache (CDN, Varnish, nginx `proxy_cache`) keys responses on a few things (method, host, path, maybe the query). If the response also depends on an **unkeyed** input, one attacker request poisons the cached page for every user.

Common unkeyed inputs: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL` / `X-Rewrite-URL`, `X-HTTP-Method-Override`, `Accept-Language`, cookies, and query parameters the CDN strips from the key (`utm_*`, or "ignore query string" settings).

Typical bug: a framework builds asset or canonical URLs from `X-Forwarded-Host`. A request with `X-Forwarded-Host: evil.example` gets `<script src="https://evil.example/app.js">` cached for everyone.

Fixes that hold:
- Don't reflect request headers into responses. Use configured values for hosts, schemes, and asset URLs.
- If a response legitimately varies on a header, put that header in the cache key (`Vary` and CDN key config), or mark the response uncacheable.
- Strip unexpected forwarding headers at the edge before they reach the origin.
- Cache only what's meant to be shared: `Cache-Control: public, max-age=...` explicitly on static and anonymous pages, and `private` or `no-store` on everything else (next section).

## Web cache deception

The opposite direction: the attacker gets a **victim's** personalized page cached, then reads it.

1. The victim follows `https://app.example.com/account/settings/x.css` (or `/account/settings;x.css`, `/account/settings%2Fx.css`, `/account/settings%23x.css`).
2. The app ignores the suffix (lenient routing) and returns the victim's settings page.
3. The CDN sees `.css`, caches the response, and the attacker fetches the same URL.

Fixes that hold:
- **Every authenticated or personalized response:** `Cache-Control: no-store` (or `private, no-cache`). Configure the CDN to respect origin `Cache-Control` and not override it by file extension. Cloudflare "Cache Deception Armor" also checks that the `Content-Type` matches the extension.
- **Strict routing:** unknown suffixes, trailing segments, and `;` path parameters return 404, not the parent page. Express: `app.set('strict routing', true)` / `caseSensitive`, and avoid wildcard catch-alls that render authenticated pages. Spring: matrix variables and suffix pattern matching are off in recent versions; keep them off.
- **CDN rules by path prefix** (`/static/*`, `/_next/static/*`, `/assets/*`), not by extension.

```js
// Express: default to private for anything that touched the session
app.use((req, res, next) => { if (req.session?.userId) res.set('Cache-Control', 'no-store'); next(); });
```

## Request smuggling and desync

The front end and the back end disagree about where one request ends (`Content-Length` vs `Transfer-Encoding`, HTTP/2 → HTTP/1 downgrade, obsolete line folding). The attacker prefixes someone else's request: they steal it, poison the cache, or bypass front-end access rules.

What the app and platform team control:
- **Keep HTTP parsers patched.** Node's llhttp rejects ambiguous messages by default; never run with `--insecure-http-parser` or `insecureHTTPParser: true`. Python: keep gunicorn ≥ 23 (request smuggling CVE-2024-1135, CVE-2024-6827), h11/uvicorn, and hypercorn current. Same for Puma, Tomcat, and Jetty.
- **Reject ambiguity at the edge:** requests with both `Content-Length` and `Transfer-Encoding`, duplicate `Content-Length`, or `Transfer-Encoding` values other than exactly `chunked`. Most managed load balancers do this. Check custom nginx and HAProxy configs.
- **Prefer HTTP/2 or HTTP/1.1 end-to-end with one parser family**, or HTTP/2 to the origin. Mixed parsers with connection reuse are where desync lives. If you can't avoid that, disabling backend connection reuse closes the hole at a performance cost.
- Don't let the app accept requests that arrive with a body on `GET` and pass them upstream unchanged.

## Proxy access rules vs path normalization

"Block `/admin` at the proxy" fails when the proxy and app normalize paths differently:
- `/admin/` and `//admin`
- `/%61dmin` (percent-encoded letter)
- `/admin;x` (Tomcat and Spring path parameters)
- `/static/..%2fadmin` (encoded traversal)
- `/ADMIN` (case-insensitive app routes)
- `/admin.` (trailing dot)
- `X-Original-URL: /admin` (IIS/Symfony rewrite headers)

Enforce authorization **in the application**, on the resolved route and the resource, and treat proxy rules as defense in depth only. Disable `X-Original-URL` / `X-Rewrite-URL` support unless your edge sets them.

## Regression tests

- Host poisoning: request a password reset with `Host: evil.example` and `X-Forwarded-Host: evil.example`, then assert the emailed link starts with your configured `APP_URL`.
- IP spoofing: with your production `trust proxy` value, send `X-Forwarded-For: 1.2.3.4` and assert the rate limiter keys on the proxy-supplied address.
- Cache headers: every authenticated route returns `Cache-Control` containing `no-store` or `private`. Assert this in a test that walks the route table.
- Deception: `GET /account/settings/x.css` and `/account/settings;x.css` return 404, not the settings page.
- On a server the user owns, `check-headers.mjs` flags missing `Cache-Control` on responses that set cookies:

  ```bash
  node <skill-dir>/scripts/check-headers.mjs https://app.example.com/account
  ```
