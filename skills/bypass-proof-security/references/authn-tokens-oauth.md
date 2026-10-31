# Authentication, tokens and OAuth/OIDC

Covers JWT verification, sessions vs tokens, password storage, reset and magic-link flows, login hardening, MFA, and acting as an OAuth/OIDC client.

## Contents
- [JWT verification](#jwt-verification)
- [JWT as a session](#jwt-as-a-session)
- [Passwords](#passwords)
- [Reset links, magic links, email verification](#reset-links-magic-links-email-verification)
- [Login and MFA](#login-and-mfa)
- [OAuth / OIDC clients](#oauth--oidc-clients)
- [Regression tests](#regression-tests)

## JWT verification

### What libraries do by default (verified)

| Library | Rejects `alg: none` / wrong key / expired | Checks `iss` / `aud` without being told | Requires `exp` |
|---|---|---|---|
| `jsonwebtoken` 9.0 `jwt.verify(t, key)` | yes | **no** (only if you pass `issuer`, `audience`) | **no**: tokens without `exp` never expire |
| `jose` 6 `jwtVerify(t, key, opts)` | yes | only if passed | only with `requiredClaims: ['exp']` |
| PyJWT 2.15 `jwt.decode(t, key, algorithms=[...])` | yes; refuses to run without `algorithms` | `aud`: rejects a token carrying `aud` if you don't pass `audience`. `iss`: **no** | **no**; use `options={"require": ["exp"]}` |

### Fixes that don't hold

| Code | Problem |
|---|---|
| `jwt.decode(token)` (jsonwebtoken) used to read the user | `decode` never verifies. Anyone can mint claims. The probe catches this with 5+ forged tokens. |
| PyJWT `jwt.decode(t, options={"verify_signature": False})` "for now" | Same: unauthenticated claims. |
| `jwt.verify(t, secret)` with no `issuer`/`audience` | A valid token for *another service* that shares the key or IdP is accepted (confused deputy). |
| Algorithm taken from the token header in a hand-rolled verifier | Key confusion: an attacker signs HS256 with your RSA **public** key as the HMAC secret. Pin the algorithm in code. |
| Fetching keys from the token's `jku` / `x5u` header | The attacker hosts the keys. Use only the JWKS URL from your config or OIDC discovery. |
| Using `kid` in a file path or SQL query | Path traversal (`../../dev/null` gives an empty key) or SQL injection. Look `kid` up in a fixed map. |
| HS256 with a short or guessable secret | Offline brute force from any captured token. Use 256+ random bits, or asymmetric keys when several services verify. |
| Large `clockTolerance` / `leeway` (hours) | Extends every token's life. Keep it ≤ 60 s. |

### The fix that holds

```js
// jose (Node, edge, browsers)
import { jwtVerify, createRemoteJWKSet } from 'jose';
const JWKS = createRemoteJWKSet(new URL('https://idp.example.com/.well-known/jwks.json'));   // module scope: cached
export async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    algorithms: ['RS256'], issuer: 'https://idp.example.com/', audience: 'https://api.example.com',
    requiredClaims: ['exp', 'sub'], clockTolerance: 30,
  });
  return payload;
}
// jsonwebtoken
jwt.verify(token, publicKeyPem, { algorithms: ['RS256'], issuer: ISS, audience: AUD, clockTolerance: 30 });
// ...and reject tokens without exp: if (typeof claims.exp !== 'number') throw ...
```

```python
import jwt  # PyJWT
jwks = jwt.PyJWKClient("https://idp.example.com/.well-known/jwks.json")  # module scope: caches keys
def verify_access_token(token: str) -> dict:
    key = jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256"], issuer="https://idp.example.com/",
                      audience="https://api.example.com", leeway=30, options={"require": ["exp", "iss", "aud", "sub"]})
```

## JWT as a session

Stateless JWTs can't be revoked before `exp`. If they're your session:
- Keep access tokens short (5–15 min). Use rotating refresh tokens stored server-side, with **reuse detection**: if a used refresh token is presented again, revoke the whole family.
- Store them in `HttpOnly; Secure; SameSite` cookies, not `localStorage`, where any XSS reads them. Then you need CSRF protection (`csrf-cors-cookies-sessions.md`).
- If you need instant logout, revocation on password change, or "sign out all devices", an opaque server-side session ID is simpler and stronger.

## Passwords

- Hash with **argon2id** (OWASP minimum: m=19 MiB, t=2, p=1), or scrypt (N=2^17, r=8, p=1), or bcrypt cost ≥ 10.
  - Node: `argon2` package, or `crypto.scrypt`.
  - Python: `argon2-cffi` (`PasswordHasher()`). Django's default PBKDF2 hasher is acceptable; adding `Argon2PasswordHasher` first is better.
- **bcrypt truncates at 72 bytes.** Long passphrases collide past that point. Some versions also stop at a NUL byte in pre-hashed input, so don't pre-hash with a raw digest. Prefer argon2id for new systems.
- Compare with the library's verify function (constant-time). Never `==` hashes.
- Rehash on login when parameters change (`needsRehash` / `check_needs_rehash`).
- Check new passwords against breached lists (k-anonymity HIBP API). Require at least 8 characters, allow at least 64, and don't impose composition rules (NIST SP 800-63B).

## Reset links, magic links, email verification

Use `assets/fixes/node/tokens.mjs` (`issueOneTimeToken`, `hashToken`, `safeEqual`), or in Python `secrets.token_urlsafe(32)` plus `hashlib.sha256`.

| Mistake | Fix |
|---|---|
| Token from `Math.random`, `uuid` v1, a timestamp, or the user ID | 256-bit random: `crypto.randomBytes(32)` / `secrets.token_urlsafe(32)` |
| Token stored in plaintext | Store SHA-256(token). A DB leak shouldn't give account takeover. |
| Reusable, or valid for days | Single use (delete in the same transaction that changes the password), 15–60 min expiry |
| Reset URL built from the request's `Host` / `X-Forwarded-Host` | Host-header poisoning sends the victim a link to the attacker's domain, carrying a valid token. Build links from a configured `APP_URL`. |
| Different responses for "no such email" | Account enumeration. Same message, same timing ("If an account exists, we sent a link"). |
| Other sessions survive the reset | Revoke all sessions and refresh tokens on password change. |
| Token in the URL leaks via `Referer` | `Referrer-Policy: no-referrer` on the reset page. Exchange the URL token for a short form token on first load. |

## Login and MFA

- Rate limit by account **and** by IP and device. Use a progressive delay or temporary lock that doesn't let attackers lock out arbitrary users forever (e.g. require CAPTCHA after N failures rather than a hard lock).
- Same error and same timing for an unknown user and a wrong password: when the user isn't found, verify against a dummy hash.
- MFA must cover **every** path into the account: password login, OAuth/SSO login linking, password reset (reset shouldn't skip MFA), "remember this device" tokens, API key creation, and recovery-code login. Check MFA on the server for the session, not with a client flag.
- TOTP: accept ±1 step, and reject reuse of the same code (store the last used counter). Hash recovery codes and make them single-use.
- Step-up re-authentication before changing email, password, or MFA settings, and before payouts or exports.

## OAuth / OIDC clients

Use a maintained, certified library (Node `openid-client` v6, Python `Authlib`, Spring Security OAuth2 Client) instead of hand-rolling. Then make sure that:
- **Authorization code + PKCE (S256)** is used, even for confidential clients. No implicit flow.
- **`state`** is random, bound to the user's session (or an encrypted cookie), and checked once.
- **`nonce`** (OIDC) is sent and checked in the ID token.
- **The ID token is validated**: signature via the issuer's JWKS, `iss` equals the discovered issuer, `aud` contains your `client_id`, `exp`, `nonce`. If you use several IdPs, check that the issuer matches the one you started with (mix-up attacks).
- **Accounts are linked on (`iss`, `sub`), never on email.** Email claims can be unverified or mutable at some IdPs. Linking a new SSO login to an existing account by email has caused real account takeovers. If you must link by email, require `email_verified: true` **and** an IdP you trust to verify it, and confirm with the existing account's password or MFA.
- **`redirect_uri`** is registered and matched exactly (see `redirects-and-url-parsing.md#oauth--oidc-redirect_uri`).
- **Tokens** stay server-side when possible (BFF pattern). Don't put provider access tokens in the browser if the browser doesn't need them.

## Regression tests

```bash
# HS256
node <skill-dir>/scripts/probe-validator.mjs jwt src/auth/verify.ts verifyAccessToken --alg HS256 --secret "$TEST_SECRET" --iss https://issuer.example --aud api
# RS256 / ES256: give the probe a test keypair your verifier trusts in test mode
node <skill-dir>/scripts/probe-validator.mjs jwt src/auth/verify.ts verifyAccessToken --alg RS256 --private-key test/priv.pem --public-key test/pub.pem --iss ... --aud ...
```

The probe tries:
- `alg: none` (three casings), a stripped signature, and a tampered payload
- a token signed with a different key
- expired and not-yet-valid tokens, and wrong issuer or audience
- HS256 key confusion signed with your public key
- a token with no `exp`
- a valid token, which must be accepted

Point it at a 3-line adapter if your verifier needs a JWKS. Export a function that verifies against the test public key with the same options production uses.
