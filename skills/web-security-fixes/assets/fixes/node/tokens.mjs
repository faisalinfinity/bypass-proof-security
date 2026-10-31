// tokens.mjs: secrets, tokens, and constant-time comparison. Node 18+, zero dependencies.
//
// Fixes that don't hold:
//   - Math.random() / Date.now() / uuid v1 for tokens   predictable; use crypto.randomBytes
//   - token === stored                                  timing leak; use constant-time compare
//   - storing reset tokens / API keys in plaintext       a DB read becomes account takeover; store a hash
//   - bcrypt for 256-bit random tokens                  unnecessary and slow; SHA-256 is right for
//                                                       high-entropy tokens (bcrypt/argon2 are for passwords)

import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** URL-safe random token. 32 bytes = 256 bits. */
export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

/** Hash a high-entropy token for storage (password reset, email verify, API keys, sessions). */
export function hashToken(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

const compareKey = randomBytes(32);

/**
 * Constant-time string equality that's also safe for unequal lengths: both sides are
 * HMAC'd first, so the comparison always runs over 32 bytes and leaks nothing about length.
 */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = createHmac('sha256', compareKey).update(a).digest();
  const hb = createHmac('sha256', compareKey).update(b).digest();
  return timingSafeEqual(ha, hb);
}

/**
 * One-time token record for password reset / magic links / email verification.
 * Email the `token`; store only `tokenHash` + `expiresAt`. To redeem, hash the presented token,
 * look it up, check expiry, and delete the row in the same transaction (single use).
 */
export function issueOneTimeToken(ttlMs = 30 * 60 * 1000) {
  const token = randomToken(32);
  return { token, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + ttlMs) };
}
