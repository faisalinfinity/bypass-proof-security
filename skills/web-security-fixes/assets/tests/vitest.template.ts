// Security regression tests built from the web-security-fixes corpus (vitest; works with jest by swapping the import).
//
// How to use:
//   1. Copy this file into your test folder. Copy ../corpus/*.json next to it (tests/security/corpus/),
//      or set WEBSEC_CORPUS to the skill's assets/corpus directory.
//   2. Point each `ADAPT` import at your real function, and delete the sections you don't need.
//   3. Run it against the VULNERABLE code first and watch it fail. A test that passes before the
//      fix proves nothing. Then fix, run again, and keep it in CI.
// Conventions match scripts/probe-validator.mjs: a function "rejects" by throwing or returning
// false/null/undefined; returning true means "use the input as-is"; returning a string means "use this".

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const CORPUS = process.env.WEBSEC_CORPUS ?? path.join(__dirname, 'corpus');
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(CORPUS, `${name}.json`), 'utf8'));
async function outcome(fn: (...a: any[]) => any, ...args: any[]) {
  try { const v = await fn(...args); return v === false || v == null ? { rejected: true as const } : { rejected: false as const, value: v }; }
  catch { return { rejected: true as const }; }
}

// ---------------------------------------------------------------- open redirect
import { safeNext } from '../../src/lib/redirect'; // ADAPT: (value) => safe Location | false
describe('open redirect: ?next= handling', () => {
  const c = load('redirect');
  const { current_url, allowed_origins } = c.assumptions; // ADAPT: or replace with your own origins
  const destination = (o: Awaited<ReturnType<typeof outcome>>, input: string) => (o.rejected ? null : new URL(o.value === true ? input : String(o.value), current_url));
  it.each(c.attacks.map((a: any) => [a.input, a.why]))('does not leave the site for %j (%s)', async (input) => {
    const dest = destination(await outcome(safeNext, input), input);
    if (dest) {
      expect(['http:', 'https:']).toContain(dest.protocol);
      expect(allowed_origins).toContain(dest.origin);
    }
  });
  it.each(c.legit.map((l: any) => [l.input, l.expect]))('keeps %j working', async (input, expected) => {
    expect(destination(await outcome(safeNext, input), input)?.href).toBe(expected);
  });
});

// ---------------------------------------------------------------- SSRF (save-time URL validator)
import { validateWebhookUrl } from '../../src/lib/url-policy'; // ADAPT: async (url) => ok | throws
describe('SSRF: user-supplied URLs', () => {
  const c = load('ssrf');
  const offline = process.env.CI_OFFLINE === '1';
  it.each(c.attacks.filter((a: any) => !(offline && a.needs_dns)).map((a: any) => [a.input, a.why]))('blocks %j (%s)', async (input) => {
    expect((await outcome(validateWebhookUrl, input)).rejected).toBe(true);
  });
  it.each(c.legit.filter((l: any) => !(offline && l.needs_dns)).map((l: any) => [l.input]))('allows %j', async (input) => {
    expect((await outcome(validateWebhookUrl, input)).rejected).toBe(false);
  });
});

// ---------------------------------------------------------------- SSRF: DNS rebinding against the code that actually fetches
// Catches the most common regression: "validate the URL, then fetch(url)" (the second DNS lookup can return 127.0.0.1).
import dns from 'node:dns';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { fetchUntrusted } from '../../src/lib/http'; // ADAPT: (url) => performs the request; in tests allow non-standard ports
describe('SSRF: DNS rebinding', () => {
  it('never reaches an internal address after a public answer was validated', async () => {
    let hits = 0;
    const internal = http.createServer((_q, s) => { hits++; s.end('internal-only'); });
    await new Promise<void>((r) => internal.listen(0, '127.0.0.1', () => r()));
    const port = (internal.address() as { port: number }).port;
    const HOST = 'rebind.websec-probe.test';
    let n = 0;
    const answer = () => (++n === 1 ? '1.1.1.1' : '127.0.0.1'); // public for the check, loopback for the connection
    const real = { lookup: dns.lookup, plookup: dns.promises.lookup };
    (dns as any).lookup = (host: string, opts: any, cb: any) => {
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      if (host !== HOST) return (real.lookup as any).call(dns, host, opts, cb);
      const ip = answer();
      process.nextTick(() => (opts?.all ? cb(null, [{ address: ip, family: 4 }]) : cb(null, ip, 4)));
    };
    (dns.promises as any).lookup = async (host: string, opts: any = {}) => {
      if (host !== HOST) return (real.plookup as any).call(dns.promises, host, opts);
      const ip = answer();
      return opts.all ? [{ address: ip, family: 4 }] : { address: ip, family: 4 };
    };
    syncBuiltinESMExports();
    try {
      await Promise.race([Promise.resolve(fetchUntrusted(`http://${HOST}:${port}/`)).catch(() => {}), new Promise((r) => setTimeout(r, 3000))]);
    } finally {
      Object.assign(dns, { lookup: real.lookup });
      Object.assign(dns.promises, { lookup: real.plookup });
      syncBuiltinESMExports();
      internal.close();
    }
    expect(hits).toBe(0);
  });
});

// ---------------------------------------------------------------- path traversal
import { resolveUserFile } from '../../src/lib/files'; // ADAPT: (base, name) => absolute path | throws
describe('path traversal: user file names', () => {
  const c = load('path');
  const base = path.resolve(c.assumptions.base); // ADAPT: your real base dir if your function needs it to exist
  const inside = (p: string) => { const rel = path.relative(base, path.resolve(base, p)); return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel); };
  it.each(c.attacks.filter((a: any) => a.severity !== 'warn').map((a: any) => [a.input, a.why, a.severity]))('contains %j (%s)', async (input, _why, severity) => {
    const o = await outcome(resolveUserFile, base, input);
    if (severity === 'strict') expect(o.rejected).toBe(true);
    else if (!o.rejected) expect(inside(o.value === true ? input : String(o.value))).toBe(true);
  });
  it.each(c.legit.map((l: any) => [l.input]))('keeps %j working', async (input) => {
    const o = await outcome(resolveUserFile, base, input);
    expect(o.rejected).toBe(false);
  });
});

// ---------------------------------------------------------------- CORS origin policy
import { isAllowedOrigin } from '../../src/cors'; // ADAPT: (origin) => boolean | allowed-origin string
describe('CORS: origin allowlist', () => {
  const c = load('cors-origin');
  const allowed = c.assumptions.allowed_origins; // ADAPT: your production origins (and edit legit entries to match)
  it.each(c.attacks.filter((a: any) => a.severity !== 'warn').map((a: any) => [a.input, a.why]))('refuses %j (%s)', async (origin) => {
    const o = await outcome(isAllowedOrigin, origin);
    if (!o.rejected) expect(allowed).toContain(o.value === true ? origin : o.value);
  });
});

// ---------------------------------------------------------------- prototype pollution
import { deepMerge } from '../../src/utils/merge'; // ADAPT: (target, source) => merged
describe('prototype pollution: merge of request JSON', () => {
  const c = load('proto-pollution');
  it.each(c.merge_payloads.map((p: any) => [p.input, p.why]))('does not pollute with %s (%s)', async (payload) => {
    const target: any = {};
    await outcome(deepMerge, target, JSON.parse(payload));
    const leaked = (Object.prototype as any).pp_probe;
    delete (Object.prototype as any).pp_probe;
    expect(leaked).toBeUndefined();
    expect(({} as any).pp_probe).toBeUndefined();
  });
});

// ---------------------------------------------------------------- XSS sanitizer
import { sanitizeComment } from '../../src/lib/sanitize'; // ADAPT: (html) => safe html
describe('XSS: comment sanitizer', () => {
  const c = load('xss');
  const dangerous = /<\s*\/?\s*(script|iframe|object|embed|base)\b|<[a-z][^>]*\son[a-z]+\s*=|(?:href|src|action|formaction)\s*=\s*["']?\s*(?:javascript|vbscript|data:text\/html)|srcdoc\s*=/i;
  it.each(c.attacks.filter((a: any) => a.severity !== 'warn').map((a: any) => [a.input, a.why]))('neutralizes %j (%s)', async (input) => {
    const o = await outcome(sanitizeComment, input);
    if (!o.rejected) expect(String(o.value)).not.toMatch(dangerous);
  });
  // Deeper check (mutation XSS with a real parser): node <skill>/scripts/probe-validator.mjs xss src/lib/sanitize.ts sanitizeComment
});

// ---------------------------------------------------------------- webhook signature (route-level)
import request from 'supertest';
import { app } from '../../src/app'; // ADAPT
describe('webhook: signature verification', () => {
  const secret = process.env.TEST_WEBHOOK_SECRET ?? 'whsec_test'; // ADAPT: the secret your test env configures
  const body = JSON.stringify({ id: 'evt_test_1', type: 'payment.succeeded' });
  const sign = (b: string, t: number) => `t=${t},v1=${crypto.createHmac('sha256', secret).update(`${t}.${b}`).digest('hex')}`; // ADAPT: provider format
  const post = (b: string, sig?: string) => request(app).post('/webhooks/stripe').set('content-type', 'application/json').set('stripe-signature', sig ?? '').send(b);
  const now = () => Math.floor(Date.now() / 1000);
  it('accepts a valid signature', async () => { await post(body, sign(body, now())).expect((r) => expect(r.status).toBeLessThan(300)); });
  it('rejects a changed byte', async () => { await post(body.replace('succeeded', 'succeedeD'), sign(body, now())).expect(400); });
  it('rejects re-serialized JSON (proves raw-body verification)', async () => { await post(JSON.stringify(JSON.parse(body), null, 1), sign(body, now())).expect(400); });
  it('rejects a replayed old event', async () => { const t = now() - 600; await post(body, sign(body, t)).expect(400); });
  it('rejects a missing signature', async () => { await post(body).expect(400); });
});

// ---------------------------------------------------------------- race condition (run against a real test DB)
describe('race: single-use actions under concurrency', () => {
  it('redeems a coupon exactly once with 20 parallel requests', async () => {
    const auth = { authorization: 'Bearer test-user-token' }; // ADAPT: log in a test user
    const results = await Promise.all(Array.from({ length: 20 }, () => request(app).post('/api/coupons/redeem').set(auth).send({ code: 'TEST-ONCE' })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------- authorization: the two-user test
describe('authorization: another user cannot touch my records', () => {
  it('returns 404 for every verb on another user’s resource', async () => {
    const alice = { authorization: 'Bearer alice' }; const bob = { authorization: 'Bearer bob' }; // ADAPT
    const created = await request(app).post('/api/projects').set(alice).send({ name: 'secret' });
    const id = created.body.id;
    for (const [method, url] of [['get', `/api/projects/${id}`], ['patch', `/api/projects/${id}`], ['delete', `/api/projects/${id}`]] as const) {
      const res = await (request(app) as any)[method](url).set(bob).send({ name: 'pwned' });
      expect([403, 404]).toContain(res.status);
    }
  });
});
