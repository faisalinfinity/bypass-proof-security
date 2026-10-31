// Tests that pin down real library behavior the references rely on (dev deps: jsonwebtoken, jose, dompurify, jsdom).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import jwt from 'jsonwebtoken';
import * as jose from 'jose';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { runProbe, summarize } from '../../../skills/bypass-proof-security/scripts/probe-validator.mjs';
import { verifyStandardWebhook, verifyStripe, verifyGitHub } from '../../../skills/bypass-proof-security/assets/fixes/node/verify-webhook.mjs';

test('Standard Webhooks published vector (Node helper)', () => {
  const args = { rawBody: '{"test": 2432232314}', id: 'msg_p5jXN8AQM9LWM0D4loKWxJek', timestamp: '1614265330', signatureHeader: 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=', secrets: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw' };
  assert.equal(verifyStandardWebhook({ ...args, now: 1614265330_000 }), true);
  assert.equal(verifyStandardWebhook({ ...args, rawBody: '{"test":2432232314}', now: 1614265330_000 }), false, 're-serialized JSON must fail');
  assert.equal(verifyStandardWebhook(args), false, 'outside the replay window');
});

test('Stripe-style and GitHub verification', () => {
  const body = Buffer.from('{"id":"evt_1"}');
  const t = Math.floor(Date.now() / 1000);
  const sig = (secret, ts) => crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
  assert.ok(verifyStripe({ rawBody: body, signatureHeader: `t=${t},v1=${sig('whsec_b', t)}`, secrets: ['whsec_a', 'whsec_b'] }));
  assert.ok(!verifyStripe({ rawBody: body, signatureHeader: `t=${t - 3600},v1=${sig('whsec_b', t - 3600)}`, secrets: 'whsec_b' }));
  assert.ok(!verifyStripe({ rawBody: body, signatureHeader: `t=${t},v1=${sig('whsec_b', t).slice(0, 10)}`, secrets: 'whsec_b' }), 'truncated signature');
  assert.throws(() => verifyStripe({ rawBody: JSON.parse(body), signatureHeader: `t=${t},v1=x`, secrets: 'whsec_b' }), /raw request bytes/);
  const gh = 'sha256=' + crypto.createHmac('sha256', 's').update(body).digest('hex');
  assert.ok(verifyGitHub({ rawBody: body, signatureHeader: gh, secrets: 's' }));
});

// ---- JWT: what the libraries do by default, and what the probe catches ----
const SECRET = 'a-32-byte-or-longer-test-secret-value!!';
test('jsonwebtoken v9: verify without options already rejects alg none and wrong keys; does NOT require exp/iss/aud', async () => {
  const lenient = (t) => jwt.verify(t, SECRET);
  const r = await runProbe('jwt', lenient, { alg: 'HS256', secret: SECRET, iss: 'https://issuer.example', aud: 'api' });
  const by = Object.fromEntries(r.map((x) => [x.input, x.status]));
  assert.equal(by['alg "none", no signature'], 'pass');
  assert.equal(by['payload changed, original signature kept'], 'pass');
  assert.equal(by['expired (exp 1 hour ago)'], 'pass');
  assert.equal(by['wrong issuer'], 'fail', 'issuer is not checked unless passed');
  assert.equal(by['wrong audience'], 'fail', 'audience is not checked unless passed');
  assert.equal(by['no exp claim'], 'warn', 'tokens without exp are accepted');
  const strict = (t) => jwt.verify(t, SECRET, { algorithms: ['HS256'], issuer: 'https://issuer.example', audience: 'api' });
  const s = await runProbe('jwt', strict, { alg: 'HS256', secret: SECRET, iss: 'https://issuer.example', aud: 'api' });
  assert.equal(summarize(s).attacksThrough, 0);
});

test('jwt.decode used as verification is caught by the probe', async () => {
  const r = await runProbe('jwt', (t) => { const c = jwt.decode(t); if (!c) throw new Error('bad'); return c; }, { alg: 'HS256', secret: SECRET });
  assert.ok(summarize(r).attacksThrough >= 5);
});

test('RS256: probe key-confusion case; jose strict config passes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jwtprobe-'));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  fs.writeFileSync(path.join(dir, 'priv.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  fs.writeFileSync(path.join(dir, 'pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  const opts = { alg: 'RS256', privateKey: path.join(dir, 'priv.pem'), publicKey: path.join(dir, 'pub.pem'), iss: 'https://issuer.example', aud: 'api' };
  const pubPem = fs.readFileSync(opts.publicKey, 'utf8');
  // A hand-rolled verifier that trusts the header's alg: the classic key-confusion bug.
  const trustsHeaderAlg = (token) => {
    const [h, p, s] = token.split('.');
    const { alg } = JSON.parse(Buffer.from(h, 'base64url'));
    const data = `${h}.${p}`;
    const ok = alg === 'HS256' ? crypto.createHmac('sha256', pubPem).update(data).digest('base64url') === s
      : alg === 'RS256' ? crypto.verify('sha256', Buffer.from(data), pubPem, Buffer.from(s, 'base64url')) : false;
    if (!ok) throw new Error('bad signature');
    return JSON.parse(Buffer.from(p, 'base64url'));
  };
  const bad = await runProbe('jwt', trustsHeaderAlg, opts);
  assert.equal(bad.find((x) => x.input.startsWith('key confusion')).status, 'fail');
  const key = await jose.importSPKI(pubPem, 'RS256');
  const strict = async (t) => (await jose.jwtVerify(t, key, { algorithms: ['RS256'], issuer: opts.iss, audience: opts.aud, requiredClaims: ['exp'] })).payload;
  const good = await runProbe('jwt', strict, opts);
  assert.deepEqual(good.filter((x) => x.status !== 'pass').map((x) => x.input), []);
});

// ---- DOMPurify: correct use passes; the classic misuse fails ----
const DOMPurify = createDOMPurify(new JSDOM('').window);
test('DOMPurify default config passes the xss corpus (with jsdom re-parse oracle)', async () => {
  const r = await runProbe('xss', (h) => DOMPurify.sanitize(h));
  assert.equal(r.oracle.includes('jsdom'), true);
  assert.deepEqual(r.filter((x) => x.status === 'fail').map((x) => `${x.input} -> ${x.detail}`), []);
});
test('sanitize-then-mutate (decode entities after sanitizing) reintroduces XSS', async () => {
  const mutate = (h) => DOMPurify.sanitize(h).replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  const r = await runProbe('xss', (h) => mutate(h.replace(/</g, '&lt;').replace(/>/g, '&gt;')));
  assert.ok(summarize(r).attacksThrough > 0);
});
