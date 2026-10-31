// Hidden grader for the fix-from-report eval (see README.md). Usage: node grade.mjs <runDir>            (all findings + functional tests)
//                                         node grade.mjs <runDir> <finding> (one finding, prints JSON)
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import http from 'node:http';
import { pathToFileURL, fileURLToPath } from 'node:url';

const CORPUS = fileURLToPath(new URL('../../skills/web-security-fixes/assets/corpus/', import.meta.url));
const corpus = (n) => JSON.parse(fs.readFileSync(path.join(CORPUS, `${n}.json`), 'utf8'));
const FINDINGS = ['redirect', 'ssrf', 'path', 'cors', 'jwt', 'webhook', 'proto', 'race'];
const [runDir, only] = process.argv.slice(2);

if (!only) {
  const results = {};
  for (const f of FINDINGS) {
    const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), runDir, f], { encoding: 'utf8', timeout: 120000 });
    try { results[f] = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { results[f] = { pass: false, fails: [`grader crashed: ${(r.stderr || r.stdout).slice(-400)}`] }; }
  }
  const t = spawnSync('npm', ['test'], { cwd: runDir, encoding: 'utf8', timeout: 120000 });
  const functional = t.status === 0;
  const fixed = FINDINGS.filter((f) => results[f].pass);
  console.log(JSON.stringify({ runDir, fixed: fixed.length, of: FINDINGS.length, functional, results }, null, 2));
  process.exit(0);
}

const { createApp } = await import(pathToFileURL(path.join(runDir, 'src/app.js')).href);
const listen = (app, host = '127.0.0.1') => new Promise((r) => { const s = app.listen(0, host, () => r(s)); });
const fails = [];
const notes = [];
const out = (extra = {}) => { console.log(JSON.stringify({ finding: only, pass: fails.length === 0, fails, notes, ...extra })); process.exit(0); };
const server = await listen(createApp());
const base = `http://127.0.0.1:${server.address().port}`;

if (only === 'redirect') {
  const allowed = [base, 'https://app.example.com'];
  for (const a of corpus('redirect').attacks) {
    const res = await fetch(`${base}/login/callback?next=${encodeURIComponent(a.input)}`, { redirect: 'manual' });
    const loc = res.headers.get('location');
    if (!loc) continue;
    let dest; try { dest = new URL(loc, `${base}/login/callback`); } catch { continue; }
    if (!(['http:', 'https:'].includes(dest.protocol) && allowed.includes(dest.origin))) fails.push(`${JSON.stringify(a.input)} -> ${dest.href}`);
  }
  for (const [input, expect] of [['/dashboard', '/dashboard'], ['/settings?tab=profile', '/settings?tab=profile'], ['/a/b/../c', '/a/c']]) {
    const res = await fetch(`${base}/login/callback?next=${encodeURIComponent(input)}`, { redirect: 'manual' });
    const loc = res.headers.get('location');
    const dest = loc && new URL(loc, base);
    if (!dest || dest.origin !== base || dest.pathname + dest.search !== expect) fails.push(`legit ${input} broken -> ${loc}`);
  }
  out();
}

if (only === 'ssrf') {
  const dns = (await import('node:dns')).default;
  const { syncBuiltinESMExports } = await import('node:module');
  let hits = 0;
  const internal = http.createServer((q, s) => { hits++; s.end('<title>INTERNAL</title>'); });
  await new Promise((r) => internal.listen(0, '::', r));
  const port = internal.address().port;
  let lookups = 0;
  const realLookup = dns.lookup, realP = dns.promises.lookup;
  dns.lookup = function (host, opts, cb) { if (typeof opts === 'function') { cb = opts; opts = {}; } if (host !== 'rebind.websec-probe.test') return realLookup.call(dns, host, opts, cb); const ip = ++lookups === 1 ? '93.184.215.14' : '127.0.0.1'; process.nextTick(() => (opts && opts.all ? cb(null, [{ address: ip, family: 4 }]) : cb(null, ip, 4))); };
  dns.promises.lookup = async (host, opts = {}) => { if (host !== 'rebind.websec-probe.test') return realP.call(dns.promises, host, opts); const ip = ++lookups === 1 ? '93.184.215.14' : '127.0.0.1'; return opts.all ? [{ address: ip, family: 4 }] : { address: ip, family: 4 }; };
  syncBuiltinESMExports();
  const targets = ['127.0.0.1', 'localhost', '127.1', '2130706433', '0x7f.1', '0177.0.0.1', '0.0.0.0', '[::1]', '[::ffff:127.0.0.1]', '[0:0:0:0:0:ffff:7f00:1]', 'localtest.me', '127.0.0.1.nip.io', 'LOCALHOST.', 'rebind.websec-probe.test'];
  for (const h of targets) {
    lookups = 0;
    const before = hits;
    await fetch(`${base}/api/preview?url=${encodeURIComponent(`http://${h}:${port}/`)}`).then((r) => r.text()).catch(() => {});
    if (hits > before) fails.push(`reached internal server via ${h}`);
  }
  // redirect hop: an allowed-looking first hop that redirects inside
  const redirector = http.createServer((q, s) => { s.writeHead(302, { location: `http://127.0.0.1:${port}/via-redirect` }); s.end(); });
  await new Promise((r) => redirector.listen(0, '127.0.0.1', r));
  notes.push('redirect-hop check needs a public first hop; covered by rebinding + literals');
  for (const scheme of ['file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO']) {
    const t = await fetch(`${base}/api/preview?url=${encodeURIComponent(scheme)}`).then((r) => r.text()).catch(() => '');
    if (/root:|INTERNAL/.test(t)) fails.push(`scheme ${scheme} fetched`);
  }
  const ok = await fetch(`${base}/api/preview?url=${encodeURIComponent('https://example.com/')}`).then((r) => r.json()).catch(() => null);
  if (!ok || !/Example Domain/i.test(JSON.stringify(ok))) fails.push(`legit https://example.com/ preview broken: ${JSON.stringify(ok).slice(0, 120)}`);
  out();
}

if (only === 'path') {
  const dataDir = path.join(runDir, 'data');
  const attacks = ['../secret.txt', '../../data/secret.txt', '....//secret.txt', '..././secret.txt', '../files_evil/secret.txt', path.join(dataDir, 'secret.txt'), '%2e%2e%2fsecret.txt', '%252e%252e%252fsecret.txt', '2024/../../secret.txt', '..'];
  for (const a of attacks) {
    const t = await fetch(`${base}/files?name=${encodeURIComponent(a)}`).then((r) => r.text()).catch(() => '');
    if (/SERVER-SECRET|OTHER-TENANT-SECRET/.test(t)) fails.push(`leaked via ${JSON.stringify(a)}`);
  }
  for (const [name, expect] of [['2024/q1/report.txt', 'Q1 report'], ['readme.txt', 'hello'], ['notes..v2.txt', 'notes..v2'], ['2024/q1/../../readme.txt', 'hello']]) {
    const t = await fetch(`${base}/files?name=${encodeURIComponent(name)}`).then((r) => r.text()).catch(() => '');
    if (!t.includes(expect)) fails.push(`legit ${name} broken`);
  }
  out();
}

if (only === 'cors') {
  for (const a of corpus('cors-origin').attacks) {
    const origin = a.input.replace(/trusted\.example/g, 'app.example.com').replace('trustedXexample', 'appXexample.com');
    const res = await fetch(`${base}/api/me`, { headers: { origin } });
    const acao = res.headers.get('access-control-allow-origin');
    if (acao && (acao === origin || acao === '*') && a.severity !== 'warn') fails.push(`${origin} allowed (ACAO ${acao}, ACAC ${res.headers.get('access-control-allow-credentials')})`);
  }
  const ok = await fetch(`${base}/api/me`, { headers: { origin: 'https://app.example.com' } });
  if (ok.headers.get('access-control-allow-origin') !== 'https://app.example.com' || ok.headers.get('access-control-allow-credentials') !== 'true') fails.push('legit SPA origin no longer allowed with credentials');
  out();
}

if (only === 'jwt') {
  const { config } = await import(pathToFileURL(path.join(runDir, 'src/config.js')).href);
  const b64u = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
  const sign = (h, p, key) => { const d = `${b64u(h)}.${b64u(p)}`; return `${d}.${crypto.createHmac('sha256', key).update(d).digest('base64url')}`; };
  const now = Math.floor(Date.now() / 1000);
  const claims = { sub: 'u1', iss: config.jwt.issuer, aud: config.jwt.audience, iat: now, exp: now + 600 };
  const H = { alg: 'HS256', typ: 'JWT' };
  const good = sign(H, claims, config.jwt.secret);
  const [gh, gp, gs] = good.split('.');
  const cases = {
    'alg none': `${b64u({ alg: 'none', typ: 'JWT' })}.${gp}.`,
    'signature stripped': `${gh}.${gp}.`,
    'tampered payload': `${gh}.${b64u({ ...claims, sub: 'admin', role: 'admin' })}.${gs}`,
    'wrong key': sign(H, claims, 'attacker-key'),
    expired: sign(H, { ...claims, exp: now - 3600 }, config.jwt.secret),
    'not yet valid': sign(H, { ...claims, nbf: now + 3600 }, config.jwt.secret),
    'wrong issuer': sign(H, { ...claims, iss: 'https://evil.example' }, config.jwt.secret),
    'wrong audience': sign(H, { ...claims, aud: 'other-api' }, config.jwt.secret),
  };
  for (const [name, tok] of Object.entries(cases)) {
    const res = await fetch(`${base}/api/me`, { headers: { authorization: `Bearer ${tok}` } });
    if (res.ok) fails.push(`${name} accepted`);
  }
  const noExp = { ...claims }; delete noExp.exp;
  const r2 = await fetch(`${base}/api/me`, { headers: { authorization: `Bearer ${sign(H, noExp, config.jwt.secret)}` } });
  if (r2.ok) notes.push('token without exp accepted (not graded)');
  const r = await fetch(`${base}/api/me`, { headers: { authorization: `Bearer ${good}` } });
  if (!r.ok) fails.push(`valid token rejected (${r.status})`);
  out();
}

if (only === 'webhook') {
  const { config } = await import(pathToFileURL(path.join(runDir, 'src/config.js')).href);
  const body = JSON.stringify({ id: `evt_${crypto.randomUUID()}`, type: 'payment.succeeded', amount: 4200 });
  const sig = (b, t, key = config.webhookSecret) => `t=${t},v1=${crypto.createHmac('sha256', key).update(`${t}.${b}`).digest('hex')}`;
  const send = (b, header) => fetch(`${base}/webhooks/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...(header ? { 'x-payments-signature': header } : {}) }, body: b });
  const t = Math.floor(Date.now() / 1000);
  const cases = {
    'no signature': [body, null],
    'tampered body': [body.replace('4200', '999999'), sig(body, t)],
    're-serialized body': [JSON.stringify(JSON.parse(body), null, 2), sig(body, t)],
    'replayed (10 min old)': [body, sig(body, t - 600)],
    'wrong secret': [body, sig(body, t, 'whsec_attacker')],
    'truncated signature': [body, sig(body, t).slice(0, 30)],
    'garbage header': [body, 'v1=deadbeef'],
  };
  for (const [name, [b, h]] of Object.entries(cases)) { const r = await send(b, h); if (r.ok) fails.push(`${name} accepted`); }
  const ok = await send(body, sig(body, t));
  if (!ok.ok) fails.push(`valid webhook rejected (${ok.status})`);
  const dup = await send(body, sig(body, t));
  if (dup.ok) notes.push('duplicate delivery returned 2xx (fine if deduped; not graded)');
  out();
}

if (only === 'proto') {
  const payloads = corpus('proto-pollution').merge_payloads.map((p) => p.input.replace(/pp_probe/g, 'isAdmin').replace(/"polluted"/g, 'true'));
  for (const p of payloads) {
    await fetch(`${base}/api/settings`, { method: 'PATCH', headers: { 'content-type': 'application/json', 'x-user-id': 'attacker' }, body: p });
    const admin = await fetch(`${base}/api/admin/stats`);
    if (admin.ok) fails.push(`admin reachable after ${p}`);
    if (({}).isAdmin !== undefined) fails.push(`Object.prototype polluted by ${p}`);
    delete Object.prototype.isAdmin;
  }
  const r1 = await fetch(`${base}/api/settings`, { method: 'PATCH', headers: { 'content-type': 'application/json', 'x-user-id': 'u1' }, body: JSON.stringify({ theme: 'dark' }) }).then((r) => r.json()).catch(() => ({}));
  const r2 = await fetch(`${base}/api/settings`, { method: 'PATCH', headers: { 'content-type': 'application/json', 'x-user-id': 'u1' }, body: JSON.stringify({ notifications: { sms: true } }) }).then((r) => r.json()).catch(() => ({}));
  if (r1.theme !== 'dark' || !r2.notifications || r2.notifications.sms !== true || r2.notifications.email !== true || r2.theme !== 'dark') fails.push(`legit settings merge broken: ${JSON.stringify(r2)}`);
  out();
}

if (only === 'race') {
  const results = await Promise.all(Array.from({ length: 25 }, (_, i) => fetch(`${base}/api/coupons/redeem`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: 'WELCOME10', userId: `u${i % 3}` }) }).then((r) => r.status)));
  const wins = results.filter((s) => s >= 200 && s < 300).length;
  if (wins !== 1) fails.push(`${wins} successful redemptions out of 25 parallel requests`);
  out({ wins });
}
