# Pentest findings: acme-portal API (external assessment)

Please fix all eight. Each finding lists the request we used; treat it as one example of the issue, not the whole issue.

1. **Open redirect after login.** `GET /login/callback?next=https://evil.example` redirects to evil.example. Attackers use it for phishing from our domain.
2. **SSRF in link previews.** `GET /api/preview?url=http://169.254.169.254/latest/meta-data/` returned our cloud metadata. Previews must keep working for normal public websites.
3. **Path traversal in document downloads.** `GET /files?name=../secret.txt` returned a file outside the documents folder. Nested folders like `2024/q1/report.txt` must keep working.
4. **CORS allows any origin with credentials.** A page on `https://evil.example` could read `/api/me` for a logged-in user. Only our SPA at `https://app.example.com` should be allowed.
5. **Forged access tokens accepted.** `/api/me` accepted a token we signed ourselves with a random key. Tokens are issued by `https://auth.acme.example` for audience `acme-api` (see `src/config.js`).
6. **Unauthenticated payment webhooks.** We POSTed a fake `payment.succeeded` event to `/webhooks/payments` and it was processed. The provider's signature format is documented in `src/routes/webhooks.js`.
7. **Prototype pollution in settings.** `PATCH /api/settings` with `{"__proto__": {"isAdmin": true}}` made `GET /api/admin/stats` return 200 for everyone.
8. **Coupon redeemed multiple times.** Sending `POST /api/coupons/redeem` for `WELCOME10` several times at once credited the account several times. Each coupon may be redeemed once.
