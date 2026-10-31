# Open redirects and URL parsing

Covers `?next=`, `?returnTo=`, `?redirect_uri=`, `?continue=` after login, logout, and OAuth; `window.location = param`; `<a href={userUrl}>`; and any "is this URL ours?" check. Open redirects matter more than they look:
- They turn OAuth flows into token theft (the code or token lands on the attacker's site).
- They bypass SSRF allowlists ("only fetch from our domain", via a redirect on our domain).
- They lend your domain to phishing.

## Contents
- [Spot it](#spot-it)
- [Why string checks fail: parser differentials](#why-string-checks-fail-parser-differentials)
- [Fixes that don't hold](#fixes-that-dont-hold)
- [The fix that holds](#the-fix-that-holds)
- [OAuth / OIDC redirect_uri](#oauth--oidc-redirect_uri)
- [Client-side navigation and links](#client-side-navigation-and-links)
- [Regression tests](#regression-tests)

## Spot it

```bash
grep -rnE "redirect\(|res\.redirect|Location['\"]?\s*[:,]|RedirectResponse|HttpResponseRedirect|redirect_to|header\(['\"]Location|sendRedirect|window\.location|location\.(href|assign|replace)|router\.push|navigate\(" . \
  | grep -iE "next|return|redirect|continue|url|callback|target|dest|back|goto"
```

## Why string checks fail: parser differentials

Browsers parse URLs with the WHATWG URL algorithm. Your check probably doesn't. Each row was verified with Node's `URL` (which implements WHATWG) and CPython's `urllib.parse`:

| Input | Browser goes to | What naive checks see |
|---|---|---|
| `//evil.example` | `https://evil.example/` | starts with `/` |
| `/\evil.example` | `https://evil.example/` (`\` is `/` in http(s) URLs) | starts with `/`, not `//`; Python: no netloc |
| `/<TAB>/evil.example` | `https://evil.example/` (tab and newline are removed) | starts with `/`, not `//` |
| ` //evil.example` (leading space) | `https://evil.example/` (leading C0 and space are stripped) | Python: no netloc, path `' //evil.example'` |
| `https://evil.example\@trusted.example` | `https://evil.example/@trusted.example` | Python `urlparse().hostname == 'trusted.example'` |
| `https://trusted.example@evil.example/` | `https://evil.example/` (userinfo) | `startsWith('https://trusted.example')` |
| `/.//evil.example`, `/x/..//evil.example` | same origin, path `//evil.example` | fine as-is, **but** `new URL(x).pathname` re-emitted as `Location` becomes `//evil.example` |
| `http:evil.example` (current page is https) | `http://evil.example/` | no `//`, looks relative |
| `java<TAB>script:alert(1)`, `\x01javascript:alert(1)` | `javascript:` URL | `!startsWith('javascript:')` |

So: never validate the raw string. Parse with the **same algorithm the browser will use**, decide on the parsed origin, and emit a value you re-serialized yourself.

## Fixes that don't hold

| Fix | Breaks on |
|---|---|
| `next.startsWith('/')` | `//evil.example` |
| `startsWith('/') && !startsWith('//')` | `/\evil.example`, `/<TAB>/evil.example` |
| `url.includes('trusted.example')` / `endsWith('trusted.example')` | `https://evil.example/?trusted.example`, `https://eviltrusted.example` |
| Regex `^https://trusted.example` | `https://trusted.example.evil.example`, `https://trustedXexample` (unescaped `.`) |
| Python `if not urlparse(next).netloc` | `/\evil.example`, ` //evil.example` |
| Python `urlparse(next).hostname == 'trusted.example'` | `https://evil.example\@trusted.example` |
| `const u = new URL(next, base); res.redirect(u.pathname)` | `/.//evil.example` → `Location: //evil.example` |
| Blocklist `javascript:` | `JaVaScRiPt:`, `java\tscript:`, `\x01javascript:`, `data:`, `vbscript:` |
| Allow any subdomain `*.trusted.example` | An XSS or subdomain takeover anywhere becomes an open redirect (and a token-theft sink in OAuth) |

## The fix that holds

1. **Best:** don't take URLs at all. Take a route name or an opaque key (`?next=billing`) and map it server-side.
2. **Same-origin paths:** parse with WHATWG URL against a dummy base. Accept only if the origin didn't change. Emit `'/' + pathname-without-leading-slashes + search + hash`.
3. **Cross-origin:** compare the parsed `origin` (scheme + host + port) to an exact allowlist. No suffix and no regex matching.
4. **Fallback:** send everything else to a fixed default (`/`). Don't echo the input in an error page either.

**Node:** `assets/fixes/node/safe-redirect.mjs`:

```js
import { safeRedirectTarget } from './lib/safe-redirect.mjs';
// Express
app.post('/login', async (req, res) => {
  // ...authenticate...
  res.redirect(303, safeRedirectTarget(req.body.next, { allowedOrigins: ['https://app.example.com'] }));
});
// Next.js route handler / server action
import { redirect } from 'next/navigation';
redirect(safeRedirectTarget(formData.get('next')));
```

**Python:** `assets/fixes/python/safe_redirect.py`. It applies the browser's normalization (strip C0 and space, remove tab/CR/LF, turn `\` into `/`) before `urlsplit`, then emits the normalized value so both sides agree:

```python
from safe_redirect import safe_redirect_target
# Flask
return redirect(safe_redirect_target(request.args.get("next"), {"https://app.example.com"}), code=303)
# FastAPI
return RedirectResponse(safe_redirect_target(request.query_params.get("next")), status_code=303)
```

**Django:** use the framework's check, which handles these cases:

```python
from django.utils.http import url_has_allowed_host_and_scheme
nxt = request.POST.get("next", "")
if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
    nxt = "/"
return redirect(nxt)
```

`LoginView` and `LogoutView` already do this. Custom views often don't.

**Other stacks:**
- Rails 7+: `redirect_to params[:next]` raises `UnsafeRedirectError` for other hosts when `raise_on_open_redirects` is on (the default for new apps). Don't pass `allow_other_host: true` with user input.
- Laravel: `redirect()->intended()` uses the session, not user input. For a `?next=`, validate with `Str::startsWith($next, '/') && ! Str::startsWith($next, ['//', '/\\'])` **after** `str_replace(["\t", "\n", "\r"], '', trim($next))`, or better, map keys to routes.
- Spring: `UriComponentsBuilder.fromUriString(next).build()`. Require `getHost() == null`, a path starting with exactly one `/`, and no `\` in the input.

## OAuth / OIDC redirect_uri

- **Exact string match** against URIs registered per client (RFC 9700, the OAuth 2.0 Security BCP). Not prefix, not "same host", not wildcard, not "path starts with".
- Loopback redirect URIs for native apps (`http://127.0.0.1:{port}/`): only the port varies, per RFC 8252. Implement that exception narrowly.
- Store `state` (CSRF) and the PKCE `code_verifier` server-side or in an encrypted, HttpOnly cookie. Bind them to the browser session and use them once.
- The post-login `next` inside your `state` is still user input. Run it through `safeRedirectTarget` after the callback.
- If your authorization server has any open redirect on an allowed redirect host, attackers can chain it. Fix every redirect on that host, not only the OAuth one.

## Client-side navigation and links

```js
// window.location / router.push / <a href> with user-influenced URLs
function safeHref(input) {
  try {
    const u = new URL(input, location.href);
    return u.protocol === 'https:' || u.protocol === 'http:' || u.protocol === 'mailto:' ? u.href : '#';
  } catch { return '#'; }
}
```

React escapes text but not URLs. Before React 19, `<a href={user.website}>` with `javascript:alert(1)` ran on click. React 19 replaces `javascript:` URLs in `href`, `src`, `action`, `formAction` and `<object data>` with a URL that throws. Don't rely on that alone: `window.open`, `location.assign`, `router.push`, Vue `:href`, Angular `[href]` with `bypassSecurityTrust*`, and server-rendered templates aren't covered. `data:` and `vbscript:` aren't covered either. Lint with `react/jsx-no-script-url`.

## Regression tests

```bash
node <skill-dir>/scripts/probe-validator.mjs redirect src/lib/redirect.ts safeNext --allowed https://app.example.com
```

The redirect oracle resolves whatever your function returns exactly as a browser would (WHATWG URL, relative to the login page), so string-level "looks fine" doesn't count. A legit input passes only if it still lands on the expected page. Python projects: `assets/tests/pytest_template.py` (redirect section). Its oracle is conservative. For an exact browser check, pipe your outputs through Node's `URL` (`new URL(output, currentPage)`) in CI.
