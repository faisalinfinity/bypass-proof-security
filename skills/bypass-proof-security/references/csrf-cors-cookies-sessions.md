# CSRF, CORS, cookies and sessions

These are all one question: what can another site make the user's browser do, or read, with the user's cookies?

## Contents
- [CSRF](#csrf)
- [CORS](#cors)
- [WebSockets (CSWSH)](#websockets-cswsh)
- [Cookies](#cookies)
- [Sessions](#sessions)
- [Regression tests](#regression-tests)

## CSRF

### Fixes that don't hold

| Belief or fix | Why it fails |
|---|---|
| "Browsers default to `SameSite=Lax`, so we're safe" | Chrome defaults unmarked cookies to Lax; not every browser does. Chrome also exempts unmarked cookies from Lax for top-level POSTs during their first 2 minutes. Set `SameSite` explicitly. |
| `SameSite=Lax` and done | Lax still sends cookies on top-level **GET** navigations. Any state change on GET (`/logout`, `/delete?id=`, `/approve?token=`) is still forgeable. |
| `SameSite` stops sibling subdomains | SameSite is about the *site* (registrable domain), not the origin. `evil.user-content.example.com` or a taken-over `old.example.com` counts as same-site with `app.example.com`. |
| "It's a JSON API, so forms can't post to it" | A form with `enctype="text/plain"` can send a body that parses as JSON. If the server parses JSON regardless of `Content-Type`, it's forgeable. |
| Referer check: `referer.includes('example.com')` | `https://evil.example/?example.com`. Referer is also often stripped, and failing open on a missing Referer is a bypass. |
| Unsigned double-submit cookie (`cookie == header`) | A sibling subdomain can set (toss) the cookie for your domain, then send the matching header. |
| `@csrf_exempt` / `skip_forgery_protection` on an endpoint "because the SPA calls it" | That endpoint is now forgeable. Fix the client to send the token instead. |
| `_method=DELETE` override accepted from query strings | Turns a GET navigation into a DELETE. |

### The fix that holds

Layer these; each is cheap:
1. **No state changes on GET/HEAD**, ever.
2. **Framework CSRF protection on** for every cookie-authenticated state-changing route:
   - Django `CsrfViewMiddleware` (default on). Set `CSRF_TRUSTED_ORIGINS` exactly, never with wildcards over user-content domains.
   - Rails `protect_from_forgery with: :exception`.
   - Laravel `VerifyCsrfToken` / `ValidateCsrfToken`.
   - Spring Security CSRF (don't `.csrf().disable()` for cookie sessions).
   - Next.js Server Actions compare `Origin` to `Host` automatically. Set `serverActions.allowedOrigins` only for real proxies.
   - Express: `csurf` is deprecated. Use `csrf-csrf` (signed double-submit, session-bound) or `csrf-sync` (synchronizer token).
   - FastAPI/Starlette has no built-in CSRF. Use the Origin + Fetch Metadata check below, or `starlette-csrf`.
3. **Origin check** on unsafe methods: reject when `Origin` is present and not in your exact allowlist. Browsers send `Origin` on all cross-origin POSTs.
4. **Fetch Metadata** isolation middleware: `browser-isolation-and-headers.md#fetch-metadata-resource-isolation-policy`.
5. **Cookies:** `SameSite=Lax` (or `Strict` for admin and banking), set explicitly, with the `__Host-` prefix (below).
6. **JSON APIs:** require `Content-Type: application/json` and reject everything else with 415. That forces a CORS preflight for cross-origin callers.

```js
// Express: Origin check for unsafe methods (complements the CSRF token / Fetch Metadata)
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (origin && !ALLOWED_ORIGINS.has(origin)) return res.status(403).send('bad origin');
  if (!origin && req.get('sec-fetch-site') === 'cross-site') return res.status(403).send('cross-site');
  next();
});
```

## CORS

CORS **relaxes** the same-origin policy. Every CORS bug is a policy that relaxes too much, usually by letting an arbitrary origin read credentialed responses.

### Fixes that don't hold (verified with Express 5 + cors 2.8 and Starlette 1.10)

| Config | Result |
|---|---|
| Express `cors({ origin: true, credentials: true })` | **Reflects any origin** with `Allow-Credentials: true`. Every site can read your users' data. |
| Express `cors({ origin: /example\.com$/ })` | Allows `https://evilexample.com` (no dot boundary) and `https://example.com.evil.example`. Unescaped dots match any character too. |
| FastAPI/Starlette `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` | **Reflects the request's origin** (it can't send `*` with credentials), so any site can read authenticated responses. |
| Django `CORS_ALLOW_ALL_ORIGINS = True` + `CORS_ALLOW_CREDENTIALS = True` | Same: reflect-all with credentials. |
| Hand-rolled `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` | Reflect-all. |
| Allowing `null` | Sandboxed iframes and `data:` documents send `Origin: null`. Any attacker can produce it. |
| `*.example.com` | Any XSS, user-content host, or subdomain takeover can read your API. |
| No `Vary: Origin` while ACAO varies | A shared cache serves one origin's ACAO to another, breaking legit clients or caching a permissive header. |
| CORS checks treated as auth | CORS only controls what *browsers* let other sites read. curl ignores it. Authorization still has to happen server-side. |

### The fix that holds

An exact-match `Set` of origins, credentials only when cookies are actually needed, and `Vary: Origin`.

```js
// Express (cors package)
const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use('/api', cors({
  origin: (origin, cb) => cb(null, origin !== undefined && ALLOWED.has(origin) ? origin : false),
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
}));
app.use((req, res, next) => { res.vary('Origin'); next(); });   // cors only adds Vary for allowed origins; caches need it on every response
```

```python
# FastAPI / Starlette
app.add_middleware(CORSMiddleware,
    allow_origins=["https://app.example.com", "https://admin.example.com"],  # exact list, never "*" with credentials
    allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["content-type", "authorization"])
# Django (django-cors-headers)
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]   # avoid CORS_ALLOWED_ORIGIN_REGEXES; never ALLOW_ALL with CREDENTIALS
```

If origins really are dynamic (customer custom domains), look each one up in the database by exact value. Don't pattern-match.

The policy function can be exercised locally, and a server the user owns can be checked for reflection. `check-headers.mjs` sends `Origin: https://websec-probe.invalid` and `Origin: null`:

```bash
node <skill-dir>/scripts/probe-validator.mjs cors-origin src/cors.ts isAllowedOrigin
node <skill-dir>/scripts/check-headers.mjs https://api.example.com/me
```

## WebSockets (CSWSH)

The WebSocket handshake carries cookies and isn't subject to CORS. An attacker's page can open a socket to your server *as the user* unless you check `Origin` during the handshake.

```js
// ws
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
  if (!ALLOWED.has(req.headers.origin)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); return socket.destroy(); }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});
// Socket.IO: new Server(httpServer, { cors: { origin: [...ALLOWED], credentials: true } })
```

- Django Channels: wrap the app in `AllowedHostsOriginValidator` (or `OriginValidator(app, ["https://app.example.com"])`).
- FastAPI: check `websocket.headers.get("origin")` before `await websocket.accept()`.
- Also authenticate the socket: a token in the first message, or the session cookie with the origin check above.

## Cookies

```
Set-Cookie: __Host-session=<opaque random>; Path=/; Secure; HttpOnly; SameSite=Lax
```

- `__Host-` prefix: the browser only accepts it with `Secure`, `Path=/`, and **no** `Domain`. Subdomains can't set or overwrite it, which kills cookie tossing and session fixation via siblings.
- `HttpOnly`: XSS can't read it. It can still *use* it, so this doesn't replace fixing XSS.
- Don't set `Domain=example.com` unless subdomains truly need the cookie. It sends the session to every subdomain, including ones you don't control well.
- Keep cookies small and opaque. No JWTs with PII in cookies you can't revoke (see `authn-tokens-oauth.md`).
- Express: `cookie: { secure: true, httpOnly: true, sameSite: 'lax' }` plus `app.set('trust proxy', 1)` behind TLS-terminating proxies, or `secure` cookies won't be set.
- Django: `SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_SAMESITE = "Lax"`, and `SESSION_COOKIE_NAME = "__Host-sessionid"` (no `SESSION_COOKIE_DOMAIN`).

## Sessions

| Mistake | Fix |
|---|---|
| Same session ID before and after login (fixation) | Rotate on login and privilege change. Express: `req.session.regenerate()`. Django: `login()` does `cycle_key()`. Rails: `reset_session` before setting the user. Laravel: `$request->session()->regenerate()`. |
| Logout only deletes the cookie client-side | Destroy the server-side session (`req.session.destroy()`, `logout(request)`). With signed client-side sessions (Flask default, Rails cookie store), the old cookie still works until it expires, so use server-side sessions where revocation matters. |
| No idle or absolute timeout | Idle timeout (e.g. 30 min for sensitive apps) plus an absolute lifetime. Require re-authentication for sensitive actions (change email or password, add an MFA device, payouts). |
| Password change or reset doesn't kill other sessions | Invalidate all of the user's sessions and refresh tokens. Django: `update_session_auth_hash` for the current one only; others die because the hash changes. |
| Weak signing secret (`SECRET_KEY = "dev"`, committed `.env`) | Anyone can forge sessions. Generate 32+ random bytes, keep it out of git, and rotate it if exposed. |

## Regression tests

- Probe the CORS function with the `cors-origin` corpus (all 11 attack origins).
- Add integration tests that hit a state-changing route:
  - with no CSRF token → expect 403
  - with `Origin: https://evil.example` → expect 403
  - with `Sec-Fetch-Site: cross-site` and `Sec-Fetch-Mode: no-cors` → expect 403
  - as a GET where only POST should work → expect 405
  - with the correct token and origin → expect 2xx (so the protection doesn't break the app).
- Session fixation: capture the session ID before login, log in, and assert it changed.
