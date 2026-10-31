#!/usr/bin/env node
// probe-validator.mjs: bypass-test YOUR validator or sanitizer against the corpus in ../assets/corpus.
// Zero dependencies, Node 20+. It runs your function locally and makes no network calls of its own
// (SSRF validators that resolve DNS will do lookups; pass --no-dns to skip those entries).
//
//   node probe-validator.mjs <class> <module> [export] [options]
//
// Classes:
//   redirect          fn(input) -> false | true | safeLocationString     (open redirect / returnTo)
//   ssrf              fn(url)   -> false/throw = blocked, else allowed  (may be async)
//   ssrf-fetch        fn(url)   -> performs the request (your fetch wrapper); tests DNS rebinding + IP literals
//                     against a loopback server. Local only; a correct wrapper may try 1.1.1.1 on a random port.
//   path              fn(base, input) -> false/throw | true | resolvedPath
//   cors-origin       fn(origin) -> false | true | allowOriginValue
//   proto-pollution   fn(target, source) [--mode merge]  |  fn(obj, path, value) [--mode set]
//   xss               fn(html) -> sanitizedHtml
//   redos             fn(input), timed in a worker with a hard timeout
//   jwt               fn(token) -> claims | throw      (needs --alg and --secret or --private-key/--public-key)
//
// Options:
//   --args a,b        argument order, from: input, base, origin (default per class; path = base,input)
//   --base DIR        base directory for `path` (default /srv/app/uploads; use a real dir for realpath checks)
//   --allowed A,B     allowed origins for redirect / cors-origin (default: the corpus assumptions)
//   --current URL     page the redirect happens from (default: corpus assumption)
//   --mode merge|set  proto-pollution call style (default merge)
//   --no-dns          skip corpus entries that need DNS
//   --budget MS       redos per-call budget (default from corpus, 100)
//   --alg ALG --secret S | --private-key FILE --public-key FILE  [--iss ISS] [--aud AUD]   (jwt)
//   --json            machine-readable output
// Exit code 1 if any attack gets through or any legit input is rejected (use it in CI).
//
// TypeScript modules: Node 22.18+ strips types natively; otherwise run with `npx tsx probe-validator.mjs ...`.
// Point at a module whose import has no side effects (no DB connection, no server start). If your
// function lives in a heavy module or needs configuration, write a 3-line adapter file that imports it,
// binds the config, and exports a plain function. Probe what production calls: for redirect and
// cors-origin that means the function WITH your allowed origins bound, plus --allowed <same origins>, e.g.
//   // probe-adapter.mjs
//   import { safeRedirectTarget } from './src/lib/security/safe-redirect.mjs';
//   export default (v) => safeRedirectTarget(v, { allowedOrigins: ['https://app.example.com'], fallback: null });
//   node probe-validator.mjs redirect probe-adapter.mjs --allowed https://app.example.com

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

const CORPUS_DIR = fileURLToPath(new URL('../assets/corpus/', import.meta.url));
export const loadCorpus = (cls) => JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, `${cls}.json`), 'utf8'));

const DEFAULT_ARGS = { path: ['base', 'input'] };

// The corpus uses trusted.example as "your" host. With --allowed, retarget attacks onto your real host
// (so https://trusted.example.evil.example becomes https://app.yours.com.evil.example) and use your
// origins as the legit set.
function retarget(corpus, allowed) {
  if (!allowed) return corpus;
  const host = new URL(allowed[0]).host;
  const swap = (v) => v.replaceAll('trusted.example', host);
  const attacks = corpus.attacks.map((a) => ({ ...a, input: swap(a.input) })).filter((a) => !allowed.includes(a.input));
  const relative = corpus.legit.filter((l) => l.input.startsWith('/'));
  return { ...corpus, attacks, legit: relative, allowedLegit: allowed };
}

async function call(fn, argv) {
  try {
    const value = await fn(...argv);
    return { value, threw: false };
  } catch (error) {
    return { value: undefined, threw: true, error: error && error.message ? error.message : String(error) };
  }
}
const isRejected = (r) => r.threw || r.value === false || r.value === null || r.value === undefined;
const show = (s) => (typeof s === 'string' ? JSON.stringify(s) : JSON.stringify(s));

function buildArgs(order, input, ctx) {
  return order.map((name) => (name === 'input' || name === 'origin' ? input : name === 'base' ? ctx.base : undefined));
}

// ---------------------------------------------------------------------------
// Class runners. Each returns [{ kind: 'attack'|'legit', input, why, status: 'pass'|'fail'|'warn'|'skip', detail }]
// ---------------------------------------------------------------------------

async function probeRedirect(fn, o) {
  const c = retarget(loadCorpus('redirect'), o.allowed);
  const allowed = o.allowed || c.assumptions.allowed_origins;
  const current = o.current || (o.allowed ? `${o.allowed[0]}/account/login` : c.assumptions.current_url);
  const relBase = new URL(current).origin;
  const legitList = [
    ...c.legit.map((l) => (o.allowed ? { input: l.input, expect: new URL(l.input, relBase).href } : l)),
    ...(c.allowedLegit || []).map((origin) => ({ input: `${origin}/billing`, expect: `${origin}/billing` })),
  ];
  const order = o.args || ['input'];
  const dest = (r, input) => {
    if (isRejected(r)) return null;
    const loc = r.value === true ? input : r.value;
    if (typeof loc !== 'string') return null;
    try { return new URL(loc, current); } catch { return null; }
  };
  const out = [];
  for (const e of c.attacks) {
    const r = await call(fn, buildArgs(order, e.input, o));
    const u = dest(r, e.input);
    const safe = !u || ((u.protocol === 'https:' || u.protocol === 'http:') && allowed.includes(u.origin));
    out.push({ kind: 'attack', input: e.input, why: e.why, status: safe ? 'pass' : 'fail', detail: u ? `browser goes to ${u.href}` : 'rejected' });
  }
  for (const e of legitList) {
    const r = await call(fn, buildArgs(order, e.input, o));
    const u = dest(r, e.input);
    const ok = u && u.href === e.expect;
    out.push({ kind: 'legit', input: e.input, status: ok ? 'pass' : 'fail', detail: u ? `goes to ${u.href} (expected ${e.expect})` : `rejected${r.error ? `: ${r.error}` : ''}` });
  }
  return out;
}

async function probeSsrf(fn, o) {
  const c = loadCorpus('ssrf');
  const order = o.args || ['input'];
  const out = [];
  for (const [kind, list] of [['attack', c.attacks], ['legit', c.legit]]) {
    for (const e of list) {
      if (o.noDns && e.needs_dns) { out.push({ kind, input: e.input, why: e.why, status: 'skip', detail: 'needs DNS (--no-dns)' }); continue; }
      const r = await call(fn, buildArgs(order, e.input, o));
      const rejected = isRejected(r);
      const ok = kind === 'attack' ? rejected : !rejected;
      out.push({ kind, input: e.input, why: e.why, status: ok ? 'pass' : 'fail', detail: rejected ? `blocked${r.error ? `: ${r.error}` : ''}` : 'allowed' });
    }
  }
  return out;
}

// ssrf-fetch: run the user's actual fetch wrapper against DNS rebinding and IP literals.
// A loopback HTTP server stands in for an internal service; any request that reaches it is a bypass.
// DNS is simulated in-process: the probe hostname answers 1.1.1.1 on the first lookup (what a
// validator sees) and 127.0.0.1 afterwards (what a second, unpinned lookup at connect time sees).
const REBIND_HOST = 'rebind.websec-probe.test';
async function probeSsrfFetch(fn, o) {
  const http = await import('node:http');
  const dns = (await import('node:dns')).default;
  const { syncBuiltinESMExports } = await import('node:module');
  let hits = 0;
  let lookups = 0;
  const server = http.createServer((req, res) => { hits++; res.end('internal-only response'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const answer = () => (++lookups === 1 ? '1.1.1.1' : '127.0.0.1');
  const saved = { lookup: dns.lookup, plookup: dns.promises.lookup, resolve4: dns.resolve4, presolve4: dns.promises.resolve4 };
  dns.lookup = function (host, opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    if (String(host).replace(/\.$/, '') !== REBIND_HOST) return saved.lookup.call(dns, host, opts, cb);
    const ip = answer();
    return process.nextTick(() => (opts && opts.all ? cb(null, [{ address: ip, family: 4 }]) : cb(null, ip, 4)));
  };
  dns.promises.lookup = async (host, opts = {}) => {
    if (String(host).replace(/\.$/, '') !== REBIND_HOST) return saved.plookup.call(dns.promises, host, opts);
    const ip = answer();
    return opts.all ? [{ address: ip, family: 4 }] : { address: ip, family: 4 };
  };
  dns.resolve4 = function (host, ...rest) {
    const cb = rest.pop();
    if (host !== REBIND_HOST) return saved.resolve4.call(dns, host, ...rest, cb);
    process.nextTick(() => cb(null, [answer()]));
  };
  dns.promises.resolve4 = async (host, ...rest) => (host === REBIND_HOST ? [answer()] : saved.presolve4.call(dns.promises, host, ...rest));
  syncBuiltinESMExports();

  const timeoutMs = Number(o.timeout) || 4000;
  const attempt = async (url) => {
    const before = hits;
    lookups = 0;
    const r = await Promise.race([call(fn, [url]), new Promise((res) => setTimeout(() => res({ timedOut: true }), timeoutMs))]);
    return { reached: hits > before, r, lookups };
  };
  const cases = [
    ['dns-rebinding', `http://${REBIND_HOST}:${port}/`, 'validator sees 1.1.1.1, the connection gets 127.0.0.1 (check-then-fetch TOCTOU)'],
    ['ip-literal', `http://127.0.0.1:${port}/`, 'IP literals never go through DNS hooks'],
    ['decimal-literal', `http://2130706433:${port}/`, 'decimal form of 127.0.0.1'],
    ['mapped-literal', `http://[::ffff:127.0.0.1]:${port}/`, 'IPv4-mapped IPv6 loopback'],
    ['unspecified', `http://0.0.0.0:${port}/`, '0.0.0.0 connects to the local machine'],
    ['localhost', `http://localhost:${port}/`, 'loopback by name'],
  ];
  const out = [];
  try {
    for (const [name, url, why] of cases) {
      const a = await attempt(url);
      let status = a.reached ? 'fail' : 'pass';
      let detail = a.reached ? 'REACHED the internal server' : a.r.timedOut ? `no internal hit (timed out after ${timeoutMs} ms)` : isRejected(a.r) ? `blocked${a.r.error ? `: ${a.r.error}` : ''}` : 'no internal hit';
      if (name === 'dns-rebinding' && !a.reached && a.lookups === 0 && isRejected(a.r)) {
        status = 'warn';
        detail = `inconclusive: rejected before any DNS lookup (port ${port} or hostname rule?). Allow non-standard ports in an adapter to test rebinding. ${a.r.error || ''}`;
      }
      out.push({ kind: 'attack', input: url, why, status, detail });
    }
  } finally {
    Object.assign(dns, { lookup: saved.lookup, resolve4: saved.resolve4 });
    Object.assign(dns.promises, { lookup: saved.plookup, resolve4: saved.presolve4 });
    syncBuiltinESMExports();
    server.closeAllConnections?.();
    server.close();
  }
  out.oracle = `loopback server on 127.0.0.1:${port}; requests use that port, so port allowlists must permit it (use an adapter)`;
  return out;
}

function strictlyInside(base, target) {
  const rel = path.relative(base, target);
  return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}

async function probePath(fn, o) {
  const c = loadCorpus('path');
  const base = path.resolve(o.base || c.assumptions.base);
  const order = o.args || DEFAULT_ARGS.path;
  const ctx = { ...o, base };
  const effective = (r, input) => {
    if (isRejected(r)) return null;
    const p = r.value === true ? input : r.value;
    return typeof p === 'string' ? path.resolve(base, p) : null;
  };
  const out = [];
  for (const e of c.attacks) {
    const r = await call(fn, buildArgs(order, e.input, ctx));
    const target = effective(r, e.input);
    let status;
    if (e.severity === 'warn') status = target ? 'warn' : 'pass';
    else if (e.severity === 'strict') status = target ? 'fail' : 'pass';
    else status = !target || strictlyInside(base, target) ? 'pass' : 'fail';
    out.push({ kind: 'attack', input: e.input, why: e.why, status, detail: target ? `resolves to ${target}` : 'rejected' });
  }
  for (const e of c.legit) {
    const r = await call(fn, buildArgs(order, e.input, ctx));
    const target = effective(r, e.input);
    const expect = path.resolve(base, e.input);
    out.push({ kind: 'legit', input: e.input, why: e.why, status: target === expect ? 'pass' : 'fail', detail: target ? `resolves to ${target}` : `rejected${r.error ? `: ${r.error}` : ''}` });
  }
  return out;
}

async function probeCors(fn, o) {
  const c = retarget(loadCorpus('cors-origin'), o.allowed);
  const allowed = o.allowed || c.assumptions.allowed_origins;
  if (c.allowedLegit) c.legit = c.allowedLegit.map((input) => ({ input }));
  const order = o.args || ['input'];
  const sent = (r, input) => (isRejected(r) ? null : r.value === true ? input : typeof r.value === 'string' ? r.value : null);
  const out = [];
  for (const e of c.attacks) {
    const s = sent(await call(fn, buildArgs(order, e.input, o)), e.input);
    let status = !s || allowed.includes(s) ? 'pass' : 'fail';
    if (e.severity === 'warn' && status === 'fail') status = 'warn';
    out.push({ kind: 'attack', input: e.input, why: e.why, status, detail: s ? `Access-Control-Allow-Origin: ${s}` : 'not allowed' });
  }
  for (const e of c.legit) {
    const s = sent(await call(fn, buildArgs(order, e.input, o)), e.input);
    out.push({ kind: 'legit', input: e.input, status: s === e.input ? 'pass' : 'fail', detail: s ? `Access-Control-Allow-Origin: ${s}` : 'not allowed' });
  }
  return out;
}

const PROBE_KEY = 'pp_probe';
function polluted() {
  return Object.prototype[PROBE_KEY] !== undefined || Array.prototype[PROBE_KEY] !== undefined;
}
function cleanPrototypes() {
  delete Object.prototype[PROBE_KEY];
  delete Array.prototype[PROBE_KEY];
}
function findInjectedPrototype(value, seen = new Set(), depth = 0) {
  if (value === null || typeof value !== 'object' || seen.has(value) || depth > 20) return null;
  seen.add(value);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== Array.prototype && proto !== null) {
    if (proto && Object.getPrototypeOf(proto) === Object.prototype && PROBE_KEY in proto) return 'an object in the result has an attacker-controlled prototype';
  }
  for (const k of Object.keys(value)) {
    const hit = findInjectedPrototype(value[k], seen, depth + 1);
    if (hit) return hit;
  }
  return null;
}

async function probeProto(fn, o) {
  const c = loadCorpus('proto-pollution');
  const mode = o.mode || 'merge';
  const out = [];
  if (mode === 'set') {
    for (const e of c.set_paths) {
      const target = {};
      const r = await call(fn, [target, e.input, 'polluted']);
      const bad = polluted();
      cleanPrototypes();
      out.push({ kind: 'attack', input: e.input, why: e.why, status: bad ? 'fail' : 'pass', detail: bad ? 'Object.prototype was modified' : r.threw ? `threw: ${r.error}` : 'no global effect' });
    }
    return out;
  }
  for (const e of c.merge_payloads) {
    const target = {};
    const r = await call(fn, [target, JSON.parse(e.input)]);
    const bad = polluted();
    cleanPrototypes();
    const result = r.value && typeof r.value === 'object' ? r.value : target;
    const injected = bad ? null : findInjectedPrototype(result);
    out.push({ kind: 'attack', input: e.input, why: e.why, status: bad || injected ? 'fail' : 'pass', detail: bad ? 'Object.prototype was modified (global pollution)' : injected || (r.threw ? `threw: ${r.error}` : 'no pollution') });
  }
  for (const e of c.legit_merge) {
    const target = {};
    const r = await call(fn, [target, JSON.parse(e.input)]);
    const result = r.value && typeof r.value === 'object' ? r.value : target;
    const got = e.expect_path.reduce((acc, k) => (acc == null ? acc : acc[k]), result);
    out.push({ kind: 'legit', input: e.input, why: e.why, status: got === e.expect ? 'pass' : 'fail', detail: `got ${show(got)}` });
  }
  return out;
}

// --- XSS -------------------------------------------------------------------
const URL_ATTRS = ['href', 'src', 'action', 'formaction', 'xlink:href', 'data', 'poster', 'background', 'srcset', 'codebase', 'cite', 'ping', 'lowsrc', 'dynsrc'];
const DANGEROUS_TAGS = new Set(['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base']);
function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&(tab|newline);/gi, (_, n) => (n.toLowerCase() === 'tab' ? '\t' : '\n'))
    .replace(/&colon;/gi, ':').replace(/&lpar;/gi, '(').replace(/&rpar;/gi, ')')
    .replace(/&quot;/gi, '"').replace(/&apos;/gi, "'").replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&amp;/gi, '&');
}
const dangerousUrl = (v) => /^(javascript|vbscript|data:text\/html|data:image\/svg)/.test(decodeEntities(v).replace(/[\u0000- ]/g, '').toLowerCase());

function heuristicXss(html) {
  if (/<\s*\/?\s*(script|iframe|frame|frameset|object|embed|applet|base)\b/i.test(html)) return 'dangerous element in output';
  const tags = html.match(/<[a-z][^>]*>/gi) || [];
  for (const tag of tags) {
    if (/[\s"'/]on[a-z]+\s*=/i.test(tag)) return `event handler attribute: ${tag.slice(0, 80)}`;
    if (/\ssrcdoc\s*=/i.test(tag)) return 'srcdoc attribute';
    if (/^<\s*meta\b/i.test(tag) && /refresh/i.test(tag)) return 'meta refresh';
    const attrRe = /([a-z:-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;
    let m;
    while ((m = attrRe.exec(tag))) {
      const name = m[1].toLowerCase();
      const value = m[2].replace(/^["']|["']$/g, '');
      if (URL_ATTRS.includes(name) && dangerousUrl(value)) return `${name} with a script URL`;
      if (name === 'style' && /(javascript:|expression\s*\()/i.test(decodeEntities(value))) return 'style with script URL (legacy browsers)';
    }
  }
  return null;
}

function loadDomParser() {
  const req = createRequire(path.join(process.cwd(), 'package.json'));
  try {
    const { JSDOM } = req('jsdom');
    return { name: 'jsdom', parse: (html) => { const d = new JSDOM('<!doctype html><body></body>').window.document; d.body.innerHTML = html; return d.body; } };
  } catch { /* not installed */ }
  try {
    const { parseHTML } = req('linkedom');
    return { name: 'linkedom', parse: (html) => { const { document } = parseHTML('<!doctype html><html><body></body></html>'); document.body.innerHTML = html; return document.body; } };
  } catch { /* not installed */ }
  return null;
}

function domXss(dom, html) {
  // parse -> serialize -> parse: what the browser ends up with after a round trip (mXSS)
  const reparsed = dom.parse(dom.parse(html).innerHTML);
  for (const el of reparsed.querySelectorAll('*')) {
    const tag = el.localName.toLowerCase();
    if (DANGEROUS_TAGS.has(tag)) return `<${tag}> after re-parse (mutation XSS)`;
    if (tag === 'meta' && /refresh/i.test(el.getAttribute('http-equiv') || '')) return 'meta refresh after re-parse';
    for (const attr of Array.from(el.attributes)) {
      const n = attr.name.toLowerCase();
      if (n.startsWith('on')) return `${n} handler after re-parse (mutation XSS)`;
      if (n === 'srcdoc') return 'srcdoc after re-parse';
      if (URL_ATTRS.includes(n) && dangerousUrl(attr.value)) return `${n}=${attr.value.slice(0, 40)} after re-parse`;
    }
  }
  return null;
}

async function probeXss(fn) {
  const c = loadCorpus('xss');
  const dom = loadDomParser();
  const out = [];
  for (const e of c.attacks) {
    const r = await call(fn, [e.input]);
    if (r.threw) { out.push({ kind: 'attack', input: e.input, why: e.why, status: 'pass', detail: `threw: ${r.error}` }); continue; }
    const html = String(r.value ?? '');
    const problem = heuristicXss(html) || (dom ? domXss(dom, html) : null);
    let status = problem ? 'fail' : 'pass';
    if (problem && e.severity === 'warn') status = 'warn';
    out.push({ kind: 'attack', input: e.input, why: e.why, status, detail: problem ? `${problem} | output: ${html.slice(0, 120)}` : `output: ${html.slice(0, 80)}` });
  }
  for (const e of c.legit) {
    const r = await call(fn, [e.input]);
    const html = String(r.value ?? '');
    out.push({ kind: 'legit', input: e.input, status: html.includes(e.expect_contains) ? 'pass' : 'fail', detail: `output: ${html.slice(0, 100)}` });
  }
  out.oracle = dom ? `heuristic + ${dom.name} re-parse` : 'heuristic only (install jsdom or linkedom in the project for a mutation-XSS check)';
  return out;
}

// --- ReDoS -----------------------------------------------------------------
const REDOS_WORKER = `
const { parentPort, workerData } = require('node:worker_threads');
const { performance } = require('node:perf_hooks');
(async () => {
  const mod = await import(workerData.url);
  const fn = workerData.exportName === 'default' ? (mod.default ?? mod) : mod[workerData.exportName];
  parentPort.on('message', async (input) => {
    const t0 = performance.now();
    try { await fn(input); } catch {}
    parentPort.postMessage(performance.now() - t0);
  });
  parentPort.postMessage('ready');
})().catch((e) => parentPort.postMessage({ error: String(e && e.message || e) }));
`;

function timedWorker(url, exportName) {
  const worker = new Worker(REDOS_WORKER, { eval: true, workerData: { url, exportName } });
  let pending = null;
  const settle = (how, value) => {
    if (!pending) return;
    const p = pending;
    pending = null;
    clearTimeout(p.timer);
    p[how](value);
  };
  worker.on('message', (m) => settle('resolve', m));
  worker.on('error', (e) => settle('reject', e));
  const next = (timeoutMs) => new Promise((resolve, reject) => {
    const entry = { resolve, reject };
    entry.timer = setTimeout(() => { if (pending === entry) settle('resolve', 'timeout'); }, timeoutMs);
    pending = entry;
  });
  return {
    ready: () => next(10_000),
    run: (input, timeoutMs) => { const p = next(timeoutMs); worker.postMessage(input); return p; },
    stop: () => worker.terminate(),
  };
}

async function probeRedos(fn, o) {
  const c = loadCorpus('redos');
  const budget = o.budget || c.budget_ms;
  const hardLimit = Math.max(2000, budget * 20);
  const out = [];
  for (const p of c.pumps) {
    const w = timedWorker(o.moduleUrl, o.exportName);
    const ready = await w.ready();
    if (ready !== 'ready') { await w.stop(); throw new Error(`could not load module in worker: ${JSON.stringify(ready)}`); }
    let status = 'pass';
    let detail = '';
    let worst = 0;
    for (const n of c.sizes) {
      const input = p.prefix + p.pump.repeat(n) + p.suffix;
      const ms = await w.run(input, hardLimit);
      if (ms === 'timeout') { status = 'fail'; detail = `no result after ${hardLimit} ms at ${n} repetitions (catastrophic backtracking)`; break; }
      worst = Math.max(worst, ms);
      if (ms > budget) { status = 'fail'; detail = `${ms.toFixed(0)} ms at ${n} repetitions (budget ${budget} ms)`; break; }
    }
    await w.stop();
    out.push({ kind: 'attack', input: `${p.prefix}${p.pump}×N${p.suffix}`, why: p.why, status, detail: detail || `worst ${worst.toFixed(1)} ms` });
  }
  return out;
}

// --- JWT -------------------------------------------------------------------
const b64u = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
function signJwt(header, payload, alg, key) {
  const data = `${b64u(header)}.${b64u(payload)}`;
  const bits = (alg.match(/\d+/) || ['256'])[0];
  const hash = `sha${bits === '512' ? '512' : bits === '384' ? '384' : '256'}`;
  let sig = '';
  if (/^HS/.test(alg)) sig = crypto.createHmac(hash, key).update(data).digest('base64url');
  else if (/^RS/.test(alg)) sig = crypto.sign(hash, Buffer.from(data), key).toString('base64url');
  else if (/^PS/.test(alg)) sig = crypto.sign(hash, Buffer.from(data), { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }).toString('base64url');
  else if (/^ES/.test(alg)) sig = crypto.sign(hash, Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  else if (alg === 'EdDSA') sig = crypto.sign(null, Buffer.from(data), key).toString('base64url');
  return `${data}.${sig}`;
}

async function probeJwt(fn, o) {
  const alg = o.alg;
  if (!alg) throw new Error('jwt needs --alg (and --secret, or --private-key and --public-key)');
  const symmetric = /^HS/.test(alg);
  const key = symmetric ? o.secret : o.privateKey && crypto.createPrivateKey(fs.readFileSync(o.privateKey));
  if (!key) throw new Error(symmetric ? 'jwt with HS* needs --secret' : 'jwt with an asymmetric alg needs --private-key');
  const publicPem = o.publicKey ? fs.readFileSync(o.publicKey, 'utf8') : null;
  const now = Math.floor(Date.now() / 1000);
  const claims = { sub: 'user-123', iat: now, nbf: now - 5, exp: now + 600, ...(o.iss ? { iss: o.iss } : {}), ...(o.aud ? { aud: o.aud } : {}) };
  const header = { alg, typ: 'JWT' };
  const good = signJwt(header, claims, alg, key);
  const [gh, gp, gs] = good.split('.');
  let otherKey;
  if (symmetric) otherKey = `${o.secret}-not-the-real-secret`;
  else {
    const kt = key.asymmetricKeyType;
    otherKey = kt === 'rsa' || kt === 'rsa-pss' ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      : kt === 'ec' ? crypto.generateKeyPairSync('ec', { namedCurve: key.asymmetricKeyDetails.namedCurve }).privateKey
        : crypto.generateKeyPairSync(kt).privateKey;
  }
  const cases = [
    ['alg "none", no signature', `${b64u({ alg: 'none', typ: 'JWT' })}.${gp}.`],
    ['alg "None" (case variant)', `${b64u({ alg: 'None', typ: 'JWT' })}.${gp}.`],
    ['alg "NONE" (case variant)', `${b64u({ alg: 'NONE', typ: 'JWT' })}.${gp}.`],
    ['signature removed', `${gh}.${gp}.`],
    ['payload changed, original signature kept', `${gh}.${b64u({ ...claims, sub: 'admin', role: 'admin' })}.${gs}`],
    ['signed with a different key', signJwt(header, claims, alg, otherKey)],
    ['expired (exp 1 hour ago)', signJwt(header, { ...claims, exp: now - 3600 }, alg, key)],
    ['not yet valid (nbf in 1 hour)', signJwt(header, { ...claims, nbf: now + 3600 }, alg, key)],
  ];
  if (o.iss) cases.push(['wrong issuer', signJwt(header, { ...claims, iss: 'https://evil.example' }, alg, key)]);
  if (o.aud) cases.push(['wrong audience', signJwt(header, { ...claims, aud: 'some-other-service' }, alg, key)]);
  if (publicPem && !symmetric) cases.push(['key confusion: HS256 signed with the public key as the secret', signJwt({ alg: 'HS256', typ: 'JWT' }, claims, 'HS256', publicPem)]);
  const noExp = { ...claims };
  delete noExp.exp;
  const out = [];
  for (const [why, token] of cases) {
    const r = await call(fn, [token]);
    out.push({ kind: 'attack', input: why, why, status: isRejected(r) ? 'pass' : 'fail', detail: isRejected(r) ? `rejected${r.error ? `: ${r.error}` : ''}` : `ACCEPTED -> ${show(r.value).slice(0, 80)}` });
  }
  const rNoExp = await call(fn, [signJwt(header, noExp, alg, key)]);
  out.push({ kind: 'attack', input: 'no exp claim', why: 'tokens without expiry live forever once leaked', status: isRejected(rNoExp) ? 'pass' : 'warn', detail: isRejected(rNoExp) ? 'rejected' : 'accepted (require exp: jose `requiredClaims`, PyJWT options={"require": ["exp"]})' });
  const rGood = await call(fn, [good]);
  out.push({ kind: 'legit', input: 'valid token', status: isRejected(rGood) ? 'fail' : 'pass', detail: isRejected(rGood) ? `rejected: ${rGood.error}` : 'accepted' });
  return out;
}

// ---------------------------------------------------------------------------

export const PROBES = { redirect: probeRedirect, ssrf: probeSsrf, 'ssrf-fetch': probeSsrfFetch, path: probePath, 'cors-origin': probeCors, 'proto-pollution': probeProto, xss: probeXss, redos: probeRedos, jwt: probeJwt };

/** Programmatic use: await runProbe('redirect', myFn, { allowed: [...] }) */
export async function runProbe(cls, fn, opts = {}) {
  const probe = PROBES[cls];
  if (!probe) throw new Error(`unknown class "${cls}". Use one of: ${Object.keys(PROBES).join(', ')}`);
  return probe(fn, opts);
}

export function summarize(results) {
  const count = (kind, status) => results.filter((r) => r.kind === kind && r.status === status).length;
  return {
    attacksBlocked: count('attack', 'pass'),
    attacksThrough: count('attack', 'fail'),
    warnings: results.filter((r) => r.status === 'warn').length,
    legitOk: count('legit', 'pass'),
    legitBroken: count('legit', 'fail'),
    skipped: results.filter((r) => r.status === 'skip').length,
  };
}

function parseCli(argv) {
  const pos = [];
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const key = a.slice(2).replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
    if (key === 'json' || key === 'noDns') { o[key] = true; continue; }
    o[key] = argv[++i];
  }
  if (o.args) o.args = o.args.split(',').map((s) => s.trim());
  if (o.allowed) o.allowed = o.allowed.split(',').map((s) => s.trim());
  if (o.budget) o.budget = Number(o.budget);
  return { pos, o };
}

async function main() {
  const { pos, o } = parseCli(process.argv.slice(2));
  const [cls, modulePath, exportName = 'default'] = pos;
  if (!cls || !modulePath) {
    const lines = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1);
    console.log(lines.slice(0, lines.findIndex((l) => !l.startsWith('//'))).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
    process.exit(2);
  }
  const moduleUrl = pathToFileURL(path.resolve(modulePath)).href;
  const mod = await import(moduleUrl);
  const fn = exportName === 'default' ? (mod.default ?? null) : mod[exportName];
  if (typeof fn !== 'function') {
    const names = Object.keys(mod).filter((k) => typeof mod[k] === 'function');
    console.error(`No function export "${exportName}" in ${modulePath}. Function exports: ${names.join(', ') || '(none)'}`);
    process.exit(2);
  }
  const results = await runProbe(cls, fn, { ...o, moduleUrl, exportName });
  const s = summarize(results);
  if (o.json) {
    console.log(JSON.stringify({ class: cls, module: modulePath, export: exportName, summary: s, oracle: results.oracle, results }, null, 2));
  } else {
    const icon = { pass: '✅', fail: '❌', warn: '⚠️ ', skip: '⏭️ ' };
    console.log(`\nprobe-validator · ${cls} · ${modulePath}#${exportName}${results.oracle ? ` · oracle: ${results.oracle}` : ''}\n`);
    for (const kind of ['attack', 'legit']) {
      const rows = results.filter((r) => r.kind === kind);
      if (!rows.length) continue;
      console.log(kind === 'attack' ? 'Bypass attempts (must be blocked):' : 'Legitimate inputs (must still work):');
      for (const r of rows) console.log(`  ${icon[r.status]} ${show(r.input).slice(0, 70).padEnd(72)} ${r.detail}${r.status === 'fail' && r.why ? `\n       why it matters: ${r.why}` : ''}`);
      console.log('');
    }
    console.log(`Attacks blocked: ${s.attacksBlocked}/${s.attacksBlocked + s.attacksThrough}` +
      `${s.warnings ? ` · warnings: ${s.warnings}` : ''} · legit inputs working: ${s.legitOk}/${s.legitOk + s.legitBroken}${s.skipped ? ` · skipped: ${s.skipped}` : ''}`);
    if (s.attacksThrough || s.legitBroken) console.log('Result: FAIL. Fix with the matching reference in ../references/, then re-run.');
    else console.log('Result: PASS against this corpus. A pass is evidence, not proof: also review the code path the validator protects.');
  }
  process.exit(s.attacksThrough || s.legitBroken ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => { console.error(err && err.stack ? err.stack : err); process.exit(2); });
}
