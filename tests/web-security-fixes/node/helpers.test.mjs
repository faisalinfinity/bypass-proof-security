// Tests for the shipped Node helpers AND the probe's oracles.
// Every helper must pass its corpus; every "naive fix" (what agents typically write) must FAIL it.
// Run: node --test tests/web-security-fixes/node/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import dns from 'node:dns';
import { runProbe, summarize, loadCorpus } from '../../../skills/web-security-fixes/scripts/probe-validator.mjs';
import { safeRedirectTarget } from '../../../skills/web-security-fixes/assets/fixes/node/safe-redirect.mjs';
import { resolveInside, safeFilename } from '../../../skills/web-security-fixes/assets/fixes/node/safe-path.mjs';
import { isPublicAddress, validateUrl } from '../../../skills/web-security-fixes/assets/fixes/node/safe-fetch.mjs';
import { safeMerge, safeSet, safeJsonParse } from '../../../skills/web-security-fixes/assets/fixes/node/safe-merge.mjs';

const allowed = loadCorpus('redirect').assumptions.allowed_origins;
const failures = (results) => results.filter((r) => r.status === 'fail').map((r) => `${r.kind} ${JSON.stringify(r.input)}: ${r.detail}`);

// ---------- redirect ----------
test('safeRedirectTarget passes the redirect corpus', async () => {
  const r = await runProbe('redirect', (n) => safeRedirectTarget(n, { allowedOrigins: allowed, fallback: null }));
  assert.deepEqual(failures(r), []);
});
test('naive redirect fixes fail the corpus', async () => {
  const naive = {
    startsWithSlash: (n) => (n.startsWith('/') ? n : null),
    noDoubleSlash: (n) => (n.startsWith('/') && !n.startsWith('//') ? n : null),
    urlPathname: (n) => { const u = new URL(n, 'https://x.invalid'); return u.pathname + u.search + u.hash; },
    hostIncludes: (n) => (n.startsWith('/') || n.includes('trusted.example') ? n : null),
  };
  for (const [name, fn] of Object.entries(naive)) {
    const s = summarize(await runProbe('redirect', fn));
    assert.ok(s.attacksThrough > 0, `${name} should let at least one attack through`);
  }
});

// ---------- path ----------
test('resolveInside passes the path corpus', async () => {
  const r = await runProbe('path', resolveInside);
  assert.deepEqual(failures(r), []);
  assert.equal(r.filter((x) => x.status === 'warn').length, 0, 'backslash entries are rejected by default');
});
test('naive path fixes fail the corpus', async () => {
  const naive = {
    replaceDotDot: (base, p) => path.join(base, p.replace(/\.\.\//g, '')),
    startsWithBase: (base, p) => { const r = path.resolve(base, p); return r.startsWith(base) ? r : null; },
    joinOnly: (base, p) => path.join(base, p),
  };
  for (const [name, fn] of Object.entries(naive)) {
    const s = summarize(await runProbe('path', fn));
    assert.ok(s.attacksThrough > 0, `${name} should let at least one attack through`);
  }
});
test('safeFilename strips directories and control characters', () => {
  assert.equal(safeFilename('../../etc/passwd'), 'passwd');
  assert.equal(safeFilename('..\\..\\boot.ini'), 'boot.ini');
  assert.equal(safeFilename('CON.txt'), '_CON.txt');
  assert.equal(safeFilename('a\u0000b.png'), 'a_b.png');
  assert.equal(safeFilename('...'), 'file');
});

// ---------- cors ----------
test('exact-match CORS allowlist passes; common regex/suffix checks fail', async () => {
  const corsAllowed = loadCorpus('cors-origin').assumptions.allowed_origins;
  const good = await runProbe('cors-origin', (o) => corsAllowed.includes(o));
  assert.deepEqual(failures(good), []);
  for (const fn of [(o) => o.endsWith('trusted.example'), (o) => /^https:\/\/(.*\.)?trusted.example/.test(o), (o) => o]) {
    assert.ok(summarize(await runProbe('cors-origin', fn)).attacksThrough > 0);
  }
});

// ---------- proto pollution ----------
function naiveMerge(t, s) {
  for (const k in s) {
    if (s[k] && typeof s[k] === 'object') { if (!t[k]) t[k] = {}; naiveMerge(t[k], s[k]); } else t[k] = s[k];
  }
  return t;
}
function protoOnlyFilterMerge(t, s) {
  for (const k of Object.keys(s)) {
    if (k === '__proto__') continue;
    if (s[k] && typeof s[k] === 'object') { if (!t[k]) t[k] = {}; protoOnlyFilterMerge(t[k], s[k]); } else t[k] = s[k];
  }
  return t;
}
test('safeMerge / safeSet pass; naive merges pollute', async () => {
  assert.deepEqual(failures(await runProbe('proto-pollution', safeMerge)), []);
  assert.deepEqual(failures(await runProbe('proto-pollution', safeSet, { mode: 'set' })), []);
  assert.ok(summarize(await runProbe('proto-pollution', naiveMerge)).attacksThrough > 0);
  assert.ok(summarize(await runProbe('proto-pollution', protoOnlyFilterMerge)).attacksThrough > 0, '__proto__-only filter must fail via constructor.prototype');
  assert.equal(({}).pp_probe, undefined, 'probe cleaned up after itself');
});
test('safeJsonParse drops dangerous keys at every level', () => {
  const v = safeJsonParse('{"a":{"__proto__":{"x":1},"b":2},"constructor":{"prototype":{}}}');
  assert.deepEqual(Object.keys(v), ['a']);
  assert.equal(v.a.b, 2);
  assert.equal(Object.getPrototypeOf(v.a), Object.prototype);
});

// ---------- xss (oracle sanity, no DOM lib in this folder) ----------
test('xss oracle flags a naive script-stripper and passes full escaping', async () => {
  const escape = (h) => h.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const esc = await runProbe('xss', escape);
  assert.equal(esc.filter((r) => r.kind === 'attack' && r.status === 'fail').length, 0);
  const strip = await runProbe('xss', (h) => h.replace(/<script.*?>.*?<\/script>/gi, ''));
  assert.ok(summarize(strip).attacksThrough >= 10);
});

// ---------- redos ----------
test('redos probe catches catastrophic regexes and passes linear ones', async () => {
  const mod = new URL('./fixtures/regexes.mjs', import.meta.url).href;
  const bad = await runProbe('redos', null, { moduleUrl: mod, exportName: 'vulnerable' });
  assert.ok(bad.some((r) => r.status === 'fail'), 'nested quantifier must be flagged');
  const ok = await runProbe('redos', null, { moduleUrl: mod, exportName: 'linear' });
  assert.deepEqual(failures(ok), []);
});

// ---------- ssrf ----------
test('isPublicAddress classification', () => {
  for (const ip of ['127.0.0.1', '0.0.0.0', '10.1.2.3', '100.100.100.200', '169.254.169.254', '172.31.255.255', '192.168.0.1', '198.18.0.1', '224.0.0.1', '255.255.255.255',
    '::1', '::', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', '64:ff9b::7f00:1', '2002:7f00:1::', '2002:a9fe:a9fe::1', 'fd00:ec2::254', 'fe80::1%en0', 'fc00::1', 'ff02::1', '2001:db8::1', '2001::1', '3fff::1', '[::1]']) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.215.14', '2606:4700:4700::1111', '2a00:1450:4001:80b::200e', '::ffff:8.8.8.8', '64:ff9b::808:808', '2002:808:808::1']) {
    assert.equal(isPublicAddress(ip), true, ip);
  }
});
test('validateUrl passes the ssrf corpus (with DNS)', async () => {
  const r = await runProbe('ssrf', (u) => validateUrl(u));
  assert.deepEqual(failures(r), []);
});
test('naive SSRF fixes vs the static corpus', async () => {
  const blocklist = (u) => { const h = new URL(u).hostname; return !['localhost', '127.0.0.1', '169.254.169.254'].includes(h) && !h.startsWith('10.') && !h.startsWith('192.168.'); };
  assert.ok(summarize(await runProbe('ssrf', blocklist)).attacksThrough > 5);
  // resolve-then-check passes the static corpus; its flaw is the TOCTOU gap, which the
  // ssrf-fetch probe exposes (see safe-fetch.test.mjs)
  const resolveThenCheck = async (u) => { const x = new URL(u); if (!['http:', 'https:'].includes(x.protocol)) return false; const { address } = await dns.promises.lookup(x.hostname); return isPublicAddress(address); };
  assert.equal(summarize(await runProbe('ssrf', resolveThenCheck)).attacksThrough, 0);
});
