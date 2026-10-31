// verify-webhook.mjs: signature verification for inbound webhooks. Node 18+, zero dependencies.
//
// Fixes that don't hold:
//   - computing the HMAC over JSON.stringify(req.body)   re-serialization changes bytes (key
//     order, whitespace, unicode escapes), so valid events fail and people turn checks off.
//     Always sign-check the RAW body bytes.
//   - sig === expected / sig == expected                  leaks the match length through timing
//   - verifying the signature but not the timestamp       old captured events can be replayed forever
//   - one secret only                                     rotation means downtime, so nobody rotates
//
// Get the raw body:
//   Express:  app.post('/hook', express.raw({ type: 'application/json' }), (req) => req.body /* Buffer */)
//   Next.js:  export async function POST(req) { const raw = await req.text(); ... }
//   Fastify:  fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => done(null, body))
//   Hono:     const raw = await c.req.text()
//
// After verifying, also dedupe by event id (store processed ids with a TTL); the timestamp
// window narrows replay but doesn't stop a replay inside the window.

import { createHmac, timingSafeEqual } from 'node:crypto';

function toBuffer(body) {
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  throw new TypeError('rawBody must be the raw request bytes (Buffer, Uint8Array, or string), not a parsed object');
}

function equalBytes(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

function withinTolerance(timestampSec, toleranceSec, nowMs) {
  if (!/^\d{1,12}$/.test(String(timestampSec))) return false;
  return Math.abs(nowMs / 1000 - Number(timestampSec)) <= toleranceSec;
}

/**
 * Generic HMAC check. `signature` is the value from the header with any "sha256=" prefix removed.
 * Pass several secrets during rotation: any match is accepted.
 * @param {{ payload: Buffer|Uint8Array|string, signature: string, secrets: string|Buffer|Array<string|Buffer>, algorithm?: string, encoding?: 'hex'|'base64' }} o
 */
export function verifyHmac({ payload, signature, secrets, algorithm = 'sha256', encoding = 'hex' }) {
  if (typeof signature !== 'string' || signature.length === 0) return false;
  const given = Buffer.from(signature, encoding);
  const body = toBuffer(payload);
  return [].concat(secrets).some((secret) => equalBytes(given, createHmac(algorithm, secret).update(body).digest()));
}

/** GitHub: X-Hub-Signature-256: sha256=<hex>. No timestamp, so dedupe on X-GitHub-Delivery. */
export function verifyGitHub({ rawBody, signatureHeader, secrets }) {
  if (typeof signatureHeader !== 'string' || !signatureHeader.startsWith('sha256=')) return false;
  return verifyHmac({ payload: rawBody, signature: signatureHeader.slice(7), secrets });
}

/**
 * Stripe: Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]; signed payload is `${t}.${rawBody}`.
 * The endpoint secret (whsec_...) is used as the HMAC key as-is.
 */
export function verifyStripe({ rawBody, signatureHeader, secrets, toleranceSec = 300, now = Date.now() }) {
  if (typeof signatureHeader !== 'string') return false;
  let t;
  const v1 = [];
  for (const part of signatureHeader.split(',')) {
    const i = part.indexOf('=');
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === 't') t = v;
    else if (k === 'v1') v1.push(v);
  }
  if (!t || v1.length === 0 || !withinTolerance(t, toleranceSec, now)) return false;
  const payload = Buffer.concat([Buffer.from(`${t}.`), toBuffer(rawBody)]);
  return v1.some((sig) => verifyHmac({ payload, signature: sig, secrets }));
}

/** Slack: X-Slack-Signature: v0=<hex>, X-Slack-Request-Timestamp; basestring `v0:${ts}:${rawBody}`. */
export function verifySlack({ rawBody, signatureHeader, timestampHeader, secrets, toleranceSec = 300, now = Date.now() }) {
  if (typeof signatureHeader !== 'string' || !signatureHeader.startsWith('v0=')) return false;
  if (!withinTolerance(timestampHeader, toleranceSec, now)) return false;
  const payload = Buffer.concat([Buffer.from(`v0:${timestampHeader}:`), toBuffer(rawBody)]);
  return verifyHmac({ payload, signature: signatureHeader.slice(3), secrets });
}

/**
 * Standard Webhooks (standardwebhooks.com), used by Svix, Clerk, Resend, Supabase and others.
 * Headers: webhook-id, webhook-timestamp, webhook-signature ("v1,<base64> v1,<base64>").
 * Signed content: `${id}.${timestamp}.${rawBody}`; key = base64-decoded secret without "whsec_".
 */
export function verifyStandardWebhook({ rawBody, id, timestamp, signatureHeader, secrets, toleranceSec = 300, now = Date.now() }) {
  if (!id || typeof signatureHeader !== 'string' || !withinTolerance(timestamp, toleranceSec, now)) return false;
  const keys = [].concat(secrets).map((s) => Buffer.from(String(s).replace(/^whsec_/, ''), 'base64'));
  const payload = Buffer.concat([Buffer.from(`${id}.${timestamp}.`), toBuffer(rawBody)]);
  const sigs = signatureHeader.split(' ').filter((s) => s.startsWith('v1,')).map((s) => s.slice(3));
  return sigs.some((sig) => verifyHmac({ payload, signature: sig, secrets: keys, encoding: 'base64' }));
}
