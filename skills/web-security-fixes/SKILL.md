---
name: web-security-fixes
description: Remediation-first web security for Node/TypeScript and Python apps (notes for Go, Java, PHP, Ruby). Makes security fixes hold against bypasses, not just code review: per bug class it gives the structural fix, the naive fixes that fail and the inputs that break them, drop-in hardened helpers, and regression tests from a bypass corpus. Ships a scanner for dangerous sinks and fixes that don't hold, a probe that bypass-tests your own validator, and a live header/CORS checker. Use when fixing or reviewing a vulnerability; triaging Semgrep, CodeQL, Snyk, ZAP, Burp, pentest or bug-bounty findings; hardening an app; or writing code that fetches user URLs, redirects, handles paths or uploads, renders user HTML, verifies JWT/OAuth/webhooks, sets CORS/CSP/cookies, or changes balances or limits. Covers SSRF, XSS, CSRF, CORS, IDOR, open redirect, path traversal, injection, prototype pollution, races, deserialization, XXE, ReDoS, cache poisoning, request smuggling.
---

# Web security fixes that hold

Security fixes usually fail in one way: the code blocks the reported payload, passes review and the happy-path test, then falls to the next variant. `startsWith('/')` lets `//evil.com` through. `replace('../','')` turns `....//` into `../`. Resolve-then-fetch loses to DNS rebinding. Bugs also cluster: the code next to a reported sink often handles the same untrusted input just as badly.

This skill makes the fix hold. For each class it gives the structural fix, the fixes that don't hold together with the inputs that break them, drop-in helpers, and tools that prove the result.

**Scope:** defensive work on code the user owns or is authorized to change. Live checks (`check-headers.mjs`) send plain GETs only, and only to the URL the user gives. Don't point them at third-party sites.

## Ground rules

1. **Trust order:** the installed library's own docs and code, then this skill, then your memory. Security APIs and defaults change between versions. The [version traps](#version-traps) were verified against the versions listed.
2. **Find the root cause, not the payload.** A fix that blocks the reported string but not its variants is still a vulnerability. Fix the class and sweep for its siblings.
3. **Prefer structure over validation, and validation over blocklists.** See [the fix ladder](#the-fix-ladder).
4. **Prove it.** Every fix gets a regression test that fails on the old code and passes on the new.
5. **Don't break legitimate use.** Every corpus has `legit` inputs too. A fix that rejects real users gets reverted.

## The remediation loop

Use it for every finding, whether it came from a scanner, a pentest report, a bug-bounty submission, or code review.

1. **Locate the sink and every path into it.** Read the code, don't trust the report's line number alone. Note the framework and library versions (`package.json`, lockfile, `pip show`).
2. **Reproduce with a failing test.** Start from `assets/corpus/<class>.json` or `assets/tests/` and run it. **It must fail on the current code.** If it passes, you haven't reproduced the bug yet.
3. **Apply the structural fix** from the matching reference. Reuse `assets/fixes/` helpers when they fit; they're tested against the full corpus.
4. **Prove the fix.** Run the test again, run `scripts/probe-validator.mjs` on the function you changed, and run the project's own test suite.
5. **Sweep for variants and neighbors.** Fix the class, not just the line: also check code next to the sink that handles the same untrusted input (e.g. a regex parsing fetched HTML right after the SSRF fix). `node <skill-dir>/scripts/scan.mjs . --rule <rule-id>`, plus a grep for the helper or sink you just fixed. The same mistake is usually copy-pasted.
6. **Report** (format below), including what you could not verify.

```bash
node <skill-dir>/scripts/scan.mjs [dir]                                    # sinks + fixes that don't hold (--json, --strict, --rule, --list-rules)
node <skill-dir>/scripts/probe-validator.mjs <class> <module> [export]     # run the corpus against YOUR function
node <skill-dir>/scripts/check-headers.mjs <url> [--cookie "sid=..."]       # CSP, HSTS, cookies, CORS reflection, cache headers
```

`<skill-dir>` is this skill's directory. `scan.mjs` findings are candidates: open each one and confirm it before changing code, and say so when one is a false positive.

## The fix ladder

Pick the highest rung that fits:

1. **Remove the sink.** Map a key to a route instead of taking a URL. Store files under generated IDs instead of user names. Use a library instead of shelling out.
2. **Make it safe by construction:**
   - parameterized queries
   - parse with the same parser the consumer uses, then compare the canonical form (WHATWG URL origin, resolved path components)
   - pin the IP you checked
   - atomic conditional writes and unique constraints
   - output encoding by the framework
3. **Allowlist** exact values (origins, hosts, sort keys, MIME types) after parsing.
4. **Validate** shape and type with a schema at the boundary.
5. **Never blocklist.** Encodings, parsers, and normalization always offer another spelling.

Defense in depth (CSP, Trusted Types, Fetch Metadata, egress proxies, RLS) goes *on top of* the fix, never instead of it.

## Fixes that don't hold

Every row was verified, by the bundled corpus and tests or against the named library version.

| Class | Fix that doesn't hold | Input or condition that breaks it | Fix that holds |
|---|---|---|---|
| SSRF | Blocklist `localhost`, `127.`, `10.` strings | `http://0x7f.1/`, `http://2130706433/`, `http://[::ffff:127.0.0.1]/`, `http://127。0。0。1/` | Classify the **resolved** IP, all ranges ([ssrf](references/ssrf-and-outbound-requests.md)) |
| SSRF | Resolve, check the IP, then `fetch(url)` | DNS rebinding: the second resolution returns 127.0.0.1 (`probe-validator.mjs ssrf-fetch` reproduces it) | Check inside the connect call: `safeFetch` / `createSsrfSafeAgent` / `guarded_httpx_client` |
| SSRF | Validate the first URL only | A public URL that 302s to `169.254.169.254` | Re-validate every hop |
| SSRF | Python `ip.is_global` | `64:ff9b::7f00:1` (NAT64 → loopback) counts as global | `is_public_address()` |
| Redirect | `next.startsWith('/')` | `//evil.com`, `/\evil.com`, `/<TAB>/evil.com` | Parse with WHATWG URL, compare the origin, re-emit ([redirects](references/redirects-and-url-parsing.md)) |
| Redirect | Python `not urlparse(x).netloc` / `.hostname == ours` | `' //evil.com'`, `'https://evil.com\@ours.com'` | Normalize like a browser first (`safe_redirect_target`), or Django `url_has_allowed_host_and_scheme` |
| Redirect | `res.redirect(new URL(x, base).pathname)` | `/.//evil.com` becomes `Location: //evil.com` | Collapse leading slashes |
| Path | `p.replace('../', '')` | `....//....//etc/passwd` | Resolve, then compare path components ([files](references/files-paths-uploads.md)) |
| Path | `resolved.startsWith(base)` | `../uploads_evil/x` (sibling prefix) | `path.relative` / `Path.is_relative_to` |
| Path | Python `os.path.join(base, p)` | `p = "/etc/passwd"` discards base | `resolve_inside()` |
| Archives | `tarfile.extractall(dest)` | Writes `../` entries outside on Python ≤ 3.13 | `extractall(dest, filter="data")` |
| XSS | Regex-strip `<script>` | `<img src=x onerror=…>`, `<scr<script>ipt>` | Framework escaping; DOMPurify/nh3 allowlist ([xss](references/xss-and-html-injection.md)) |
| XSS | Sanitize, then `.replace()`/decode/concatenate | Entity-encoded markup comes back to life | Sanitize **last**; ship the output unchanged |
| XSS | `JSON.stringify(data)` inside `<script>` | `"</script><script>…"` in any string | Escape `<` `>` `&` as `\u003c` `\u003e` `\u0026` |
| XSS | HTML-escape a value placed in `href` | `javascript:alert(1)` | Check the parsed scheme |
| CORS | Express `cors({ origin: true, credentials: true })` | Reflects every origin with credentials | An exact `Set` of origins ([cors](references/csrf-cors-cookies-sessions.md#cors)) |
| CORS | FastAPI `allow_origins=["*"], allow_credentials=True` | Starlette reflects any origin with credentials (1.10) | An exact origin list |
| CORS | `origin: /example\.com$/` | `https://evilexample.com` | Exact match |
| CSRF | "SameSite=Lax is the default" | GET state changes; sibling subdomains are same-site; browser defaults differ | Token or Origin check + Fetch Metadata + explicit SameSite |
| JWT | `jwt.decode()` to read the user | Unsigned or forged tokens | `jwt.verify` / `jwtVerify` ([auth](references/authn-tokens-oauth.md)) |
| JWT | `jwt.verify(t, key)` (jsonwebtoken 9) | Another service's token (no iss/aud check); tokens without `exp` live forever | Pass `algorithms`, `issuer`, `audience`; require `exp` |
| IDOR | Check the parent, fetch the child by ID | `/orgs/mine/projects/<theirs>` | Scope the query: `where: { id, orgId: session.orgId }` ([authz](references/authorization-idor-mass-assignment.md)) |
| Mass assignment | `delete body.role` | `isAdmin`, `orgId`, nested fields, next year's columns | Allowlist schema (`zod .strict()`, Pydantic `extra="forbid"`) |
| Race | Read, check in code, write | 20 parallel requests all pass the check | Conditional `UPDATE … WHERE balance >= x` + row count, unique constraints, `FOR UPDATE` ([races](references/race-conditions-and-business-logic.md)) |
| Proto pollution | Skip `__proto__` only | `{"constructor":{"prototype":{…}}}` | Skip `__proto__`/`constructor`/`prototype` at every level, or Map + schema ([parsing](references/deserialization-prototype-pollution-redos.md)) |
| Webhooks | HMAC over `JSON.stringify(body)` | Re-serialized bytes never match, so the check gets disabled | Verify the raw body, timing-safe, with a timestamp window and dedupe ([webhooks](references/webhooks-and-third-party-callbacks.md)) |
| Proxies | `app.set('trust proxy', true)` | Client-chosen `X-Forwarded-For` becomes `req.ip` | An exact hop count ([http](references/http-layer-cache-smuggling.md)) |
| Host | Reset links from `req.hostname` / `get_host()` | `X-Forwarded-Host: evil.example` gets a real token mailed to the attacker | A configured `APP_URL` |
| ReDoS | "Well-known" regex such as `^(\w+\s?)*$` | 32 characters pin the CPU | Cap the length, remove ambiguity, use RE2 (`probe-validator.mjs redos`) |

## Writing new code: proactive defaults

When the task is building, not fixing, write it right the first time:

- **Outbound requests to user URLs:** `safeFetch` / `guarded_httpx_client`. Never a bare `fetch(userUrl)`.
- **Redirect after login:** `safeRedirectTarget(next, { allowedOrigins })`. Use `303` after POST.
- **Files:** generated storage keys; `resolveInside` when names map to paths; uploads sniffed by content, size-capped, served from a separate origin with `nosniff` and `Content-Disposition`.
- **HTML from users:** DOMPurify (Node) or nh3 (Python) with an allowlist, as the last step before rendering. No `|safe` or `mark_safe` on unsanitized values.
- **Data access:** every query scoped by owner or tenant from the session. Request bodies parsed through allowlist schemas.
- **Auth:** a maintained library; `jwtVerify` with algorithms, issuer, audience and required `exp`; argon2id for passwords; one-time tokens hashed at rest.
- **Money, credits, coupons, limits:** atomic conditional writes plus unique constraints, with a concurrency test.
- **Webhooks:** raw body, the provider's verifier or `verify-webhook`, timestamp window, dedupe on the event ID.
- **Headers:** strict nonce CSP (report-only first), HSTS, `nosniff`, `frame-ancestors`, `__Host-` cookies with `Secure; HttpOnly; SameSite=Lax`, and an exact CORS allowlist.

## Tools

| Tool | What it does |
|---|---|
| `scripts/scan.mjs` | 61 rules across JS/TS, Python, Go, Java/Kotlin, PHP, Ruby, and templates. Two kinds: **sinks** (user input reaching a dangerous API) and **naive fixes** (a fix that exists but doesn't hold). Skips tests, build output, vendored and minified code. Suppress a reviewed line with `websec-ignore` or `websec-ignore:<rule-id>`. `--strict` for CI. |
| `scripts/probe-validator.mjs` | Imports your function and runs the corpus against it. Classes: `redirect`, `ssrf`, `ssrf-fetch` (DNS rebinding + IP literals against a loopback server), `path`, `cors-origin`, `proto-pollution` (`--mode merge\|set`), `xss` (adds a jsdom/linkedom re-parse for mXSS when available), `redos` (worker + hard timeout), and `jwt` (none-alg, key confusion, expiry, iss/aud). Oracles judge the *effect*, e.g. where a browser actually navigates. `--allowed https://app.yours.com` retargets the redirect and CORS attacks at your real host. Exit code 1 on any bypass. |
| `scripts/check-headers.mjs` | Grades a live URL: CSP quality (unsafe-inline, gadget hosts, missing `object-src`/`base-uri`, **reused nonces**), HSTS, cookies, CORS reflection with credentials, and `Cache-Control` on personalized responses. |
| `assets/fixes/node/` | `safe-fetch.mjs` (`truncate: true` for previews), `safe-fetch-undici.mjs`, `safe-redirect.mjs`, `safe-path.mjs`, `safe-merge.mjs`, `verify-webhook.mjs`, `tokens.mjs`. Zero dependencies (except the undici variant). |
| `assets/fixes/python/` | `safe_fetch.py` (httpx + stdlib), `safe_redirect.py`, `safe_path.py`, `verify_webhook.py`. Python 3.9+. |
| `assets/corpus/` | Attack and legit inputs per class, each with a one-line reason. Inert test strings that target only loopback, private, metadata and `.example` addresses. |
| `assets/tests/` | `vitest.template.ts` and `pytest_template.py`: redirect, SSRF (validator **and** an in-suite DNS-rebinding test against the code that fetches), path, CORS, proto pollution, XSS, webhook, race, and the two-user authorization test. Copy, adapt the imports, and watch them fail on the vulnerable code first. |

Copy helpers into the project (e.g. `src/lib/security/`) instead of importing from the skill directory, and keep their header comments. They explain why each check exists.

TypeScript modules: `probe-validator.mjs` imports `.ts` directly on Node 22.18+; otherwise use `npx tsx <skill-dir>/scripts/probe-validator.mjs ...`. If a function needs config or lives in a module with side effects, write a 3-line adapter that exports a plain function.

## Report format

```markdown
# Security fix: <short title>
**Class:** <SSRF | XSS | ...> · **Severity:** <critical/high/medium/low> · **Location:** `path/file.ts:42` (+ N variants)

**Exploit:** <the concrete input and what it achieves, e.g. `?next=/\evil.com` redirects to evil.com after login>
**Root cause:** <one sentence: why the old check didn't hold>
**Fix:** <what changed and which rung of the ladder; helper used>
**Proof:** <test name(s); "failed before, passes after"; probe-validator summary e.g. "redirect: 24/24 attacks blocked, 6/6 legit OK">
**Variants swept:** <scan rule(s) run, other locations fixed or confirmed safe>
**Residual risk / not verified:** <e.g. "renderer egress not covered; needs network policy", "no staging URL for check-headers">
```

When there are several findings, rank them by exploitability and impact. Merge findings that share a root cause into one entry, and list every location under it.

## Version traps

Verified in October 2026 against the versions shown. If the project uses something older or newer, check the installed docs.

| Assumption | Reality |
|---|---|
| `jwt.verify(token, key)` checks issuer and audience | jsonwebtoken 9.0: only if you pass `issuer`/`audience`. Tokens without `exp` are accepted |
| PyJWT `decode` without `algorithms` picks a safe default | PyJWT 2.x refuses to run. With `algorithms`, `iss` is still unchecked unless passed, and `exp` is optional unless `options={"require": [...]}` |
| `jinja2.Environment()` autoescapes | Jinja2 3.1: `autoescape=False` by default. Flask and Starlette enable it for `.html`/`.htm`/`.xml`/`.xhtml`/`.svg` only |
| `yaml.load(s)` is the normal call | PyYAML 6 requires a Loader. `UnsafeLoader`/`Loader` execute code; use `safe_load` |
| `tarfile.extractall` is safe | Python 3.13 writes `../` entries outside the destination (with a warning); 3.14 blocks them by default. Pass `filter="data"` |
| lxml resolves external entities | lxml ≥ 5 doesn't by default; `resolve_entities=True` re-enables file reads |
| CSP `require-sri-for` enforces SRI | Never shipped. Use `Integrity-Policy` |
| Trusted Types is Chrome-only | Baseline since February 2026 (Chrome/Edge 83, Safari 26, Firefox 148) |
| React escapes everything | React 19 neutralizes `javascript:` in `href`/`src`/`action`; `data:` URLs, `window.open`, and `location.assign` are still yours to check |
| `csurf` for Express CSRF | Deprecated. Use `csrf-csrf` or `csrf-sync`, plus Origin and Fetch Metadata checks |
| `bleach` for Python HTML sanitizing | Deprecated since January 2023. Use `nh3` |
| `express` `trust proxy: true` is the usual setting | It makes `req.ip` the client-supplied left-most `X-Forwarded-For` (Express 5.3). Use the hop count |

## References

Read only the file(s) the task needs. Each one goes: spot it, fixes that don't hold, the fix that holds (Node + Python code, notes for other stacks), regression tests.

- [references/ssrf-and-outbound-requests.md](references/ssrf-and-outbound-requests.md): IP policy, DNS rebinding, redirects, metadata, Node/Python/Go/Java/PHP/Ruby, renderers, egress.
- [references/redirects-and-url-parsing.md](references/redirects-and-url-parsing.md): parser differentials, open redirect, OAuth `redirect_uri`, client-side navigation.
- [references/xss-and-html-injection.md](references/xss-and-html-injection.md): output contexts, escape hatches, DOMPurify/nh3, Markdown, JSON in script.
- [references/browser-isolation-and-headers.md](references/browser-isolation-and-headers.md): strict CSP rollout, Trusted Types, Fetch Metadata, COOP/CORP, XS-Leaks, postMessage.
- [references/csrf-cors-cookies-sessions.md](references/csrf-cors-cookies-sessions.md): SameSite reality, CORS misconfigurations, WebSocket origin, cookie prefixes, session lifecycle.
- [references/authn-tokens-oauth.md](references/authn-tokens-oauth.md): JWT verification, sessions vs tokens, passwords, reset links, MFA, OIDC clients.
- [references/authorization-idor-mass-assignment.md](references/authorization-idor-mass-assignment.md): query scoping, Postgres RLS, mass assignment, GraphQL, the two-user test.
- [references/injection.md](references/injection.md): SQL (identifiers, ORDER BY, LIKE), NoSQL operators, commands and argument injection, SSTI, headers/logs, CSV.
- [references/files-paths-uploads.md](references/files-paths-uploads.md): traversal, zip slip and bombs, uploads, serving user content.
- [references/race-conditions-and-business-logic.md](references/race-conditions-and-business-logic.md): atomic writes, locks, idempotency keys, concurrency tests.
- [references/deserialization-prototype-pollution-redos.md](references/deserialization-prototype-pollution-redos.md): prototype and class pollution, unsafe deserializers, XXE, ReDoS.
- [references/http-layer-cache-smuggling.md](references/http-layer-cache-smuggling.md): Host/forwarded headers, cache poisoning and deception, request smuggling, proxy path rules.
- [references/webhooks-and-third-party-callbacks.md](references/webhooks-and-third-party-callbacks.md): provider formats, raw body, replay, ordering.

## Related skills

- **Finding bugs:** review-oriented skills (for example, getsentry's `security-review`) are good at surfacing candidates. Use this skill to fix them so the fix holds.
- **Next.js apps:** `nextjs-ship-ready` (same author: `npx skills add faisalinfinity/nextjs-production-skill --skill nextjs-ship-ready`) covers Server Actions, the nonce-vs-static CSP trade-off, and Next-specific headers.
- **Platform rules:** first-party skills such as Supabase's and Firebase's security-rules skills cover their own platforms. Prefer them for those rules.
