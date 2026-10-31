// Integration tests for safe-fetch.mjs and safe-fetch-undici.mjs (needs network for the TLS test).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns';
import { runProbe, summarize } from '../../../skills/bypass-proof-security/scripts/probe-validator.mjs';
import { safeFetch, isPublicAddress } from '../../../skills/bypass-proof-security/assets/fixes/node/safe-fetch.mjs';

// Two loopback servers = two origins. Tests opt into loopback with a custom address policy,
// exactly how an app would allowlist one internal service, and then check the policy still
// blocks everything else.
const seen = [];
function makeServer(handler) {
  const s = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => { seen.push({ port: s.address().port, method: req.method, url: req.url, headers: req.headers, body }); handler(req, res); });
  });
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(s)));
}
const a = await makeServer((req, res) => {
  const [p, q] = req.url.split('?');
  const target = new URLSearchParams(q || '').get('to');
  if (p === '/redirect') { res.writeHead(Number(new URLSearchParams(q).get('status') || 302), { location: target }); return res.end(); }
  if (p === '/big') return res.end('x'.repeat(2048));
  res.end('ok-a');
});
const b = await makeServer((req, res) => res.end('ok-b'));
after(() => { a.close(); b.close(); });
const A = `http://127.0.0.1:${a.address().port}`;
const B = `http://127.0.0.1:${b.address().port}`;
const loopbackOnly = { isAllowedAddress: (ip) => ip === '127.0.0.1', allowedPorts: null };

test('follows redirects inside policy and reports the final URL', async () => {
  const res = await safeFetch(`${A}/redirect?to=${encodeURIComponent(B + '/x')}`, loopbackOnly);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok-b');
  assert.equal(res.url, `${B}/x`);
});

for (const target of ['http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://2130706434/', 'http://[::ffff:a9fe:a9fe]/', 'file:///etc/passwd', 'http://localhost/', 'http://metadata.google.internal/']) {
  test(`re-validates redirect hop to ${target}`, async () => {
    await assert.rejects(safeFetch(`${A}/redirect?to=${encodeURIComponent(target)}`, loopbackOnly), (e) => e.code === 'ERR_SSRF_BLOCKED');
  });
}

test('blocks a hostname that resolves to a blocked address (lookup runs at connect time)', async () => {
  await assert.rejects(safeFetch('http://localtest.me/', {}), (e) => e.code === 'ERR_SSRF_BLOCKED');
  await assert.rejects(safeFetch('http://169.254.169.254.nip.io/', {}), (e) => e.code === 'ERR_SSRF_BLOCKED');
});

test('303 turns POST into GET without body; cross-origin hop drops credentials', async () => {
  seen.length = 0;
  await safeFetch(`${A}/redirect?status=303&to=${encodeURIComponent(B + '/after')}`, {
    ...loopbackOnly, method: 'POST', body: 'secret-body', headers: { authorization: 'Bearer t0k3n', cookie: 'sid=1', 'x-keep': 'yes', 'content-type': 'text/plain' },
  });
  const hop2 = seen.find((s) => s.url === '/after');
  assert.equal(hop2.method, 'GET');
  assert.equal(hop2.body, '');
  assert.equal(hop2.headers.authorization, undefined);
  assert.equal(hop2.headers.cookie, undefined);
  assert.equal(hop2.headers['x-keep'], 'yes');
});

test('307 keeps method and body on the same origin', async () => {
  seen.length = 0;
  await safeFetch(`${A}/redirect?status=307&to=${encodeURIComponent(A + '/kept')}`, { ...loopbackOnly, method: 'POST', body: 'payload' });
  const hop2 = seen.find((s) => s.url === '/kept');
  assert.equal(hop2.method, 'POST');
  assert.equal(hop2.body, 'payload');
});

test('truncate: returns the first maxResponseBytes instead of failing', async () => {
  const res = await safeFetch(`${A}/big`, { ...loopbackOnly, maxResponseBytes: 1000, truncate: true });
  assert.equal(res.status, 200);
  assert.equal(res.truncated, true);
  assert.equal((await res.text()).length, 1000);
});

test('caps response size and redirect count', async () => {
  await assert.rejects(safeFetch(`${A}/big`, { ...loopbackOnly, maxResponseBytes: 1024 }), (e) => e.code === 'ERR_RESPONSE_TOO_LARGE');
  await assert.rejects(safeFetch(`${A}/redirect?to=${encodeURIComponent(A + '/redirect?to=' + encodeURIComponent(A + '/x'))}`, { ...loopbackOnly, maxRedirects: 1 }), (e) => e.code === 'ERR_TOO_MANY_REDIRECTS');
});

test('default policy blocks loopback, default ports block 6379', async () => {
  await assert.rejects(safeFetch(`${A}/`), (e) => e.code === 'ERR_SSRF_BLOCKED');
  await assert.rejects(safeFetch('http://example.com:6379/'), (e) => e.code === 'ERR_SSRF_BLOCKED');
});

test('real HTTPS fetch still verifies the certificate against the hostname', async () => {
  const res = await safeFetch('https://example.com/');
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Example Domain/i);
});

// ---- the TOCTOU gap: what the static corpus can't see ----
async function validateThenFetch(url) {
  const u = new URL(url);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('bad protocol');
  const { address } = await dns.promises.lookup(u.hostname);
  if (!isPublicAddress(address)) throw new Error('blocked');
  return fetch(url); // resolves DNS again: rebinding window
}

test('ssrf-fetch probe: validate-then-fetch is bypassed by rebinding; safeFetch is not', async () => {
  const naive = await runProbe('ssrf-fetch', validateThenFetch, { timeout: 3000 });
  assert.equal(naive.find((r) => r.input.includes('rebind')).status, 'fail', 'rebinding must reach the internal server');
  const safe = await runProbe('ssrf-fetch', (u) => safeFetch(u, { allowedPorts: null, timeoutMs: 2500 }), { timeout: 3000 });
  assert.deepEqual(safe.filter((r) => r.status !== 'pass').map((r) => `${r.input}: ${r.detail}`), []);
});

test('undici dispatcher variant passes the ssrf-fetch probe (if undici is installed)', async (t) => {
  let mod;
  try { mod = await import('../../../skills/bypass-proof-security/assets/fixes/node/safe-fetch-undici.mjs'); } catch (e) { t.skip(`undici not installed: ${e.message}`); return; }
  const { fetch: ufetch } = await import('undici');
  const agent = mod.createSsrfSafeAgent({ allowedPorts: null, connect: { timeout: 2500 } });
  for (const [name, f] of [['undici fetch', (u) => ufetch(u, { dispatcher: agent })], ['global fetch', (u) => fetch(u, { dispatcher: agent })]]) {
    const r = await runProbe('ssrf-fetch', f, { timeout: 3000 });
    assert.deepEqual(r.filter((x) => x.status !== 'pass').map((x) => `${name} ${x.input}: ${x.detail}`), []);
  }
  // redirect hop to an IP literal is caught inside the connector
  const loop = mod.createSsrfSafeAgent({ isAllowedAddress: (ip) => ip === '127.0.0.1', allowedPorts: null });
  await assert.rejects(ufetch(`${A}/redirect?to=${encodeURIComponent('http://169.254.169.254/')}`, { dispatcher: loop }), (e) => (e.cause || e).code === 'ERR_SSRF_BLOCKED');
  const ok = await ufetch('https://example.com/', { dispatcher: mod.createSsrfSafeAgent() });
  assert.equal(ok.status, 200);
  await ok.text();
});
