import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import { exec } from 'node:child_process';
const app = express();
app.set('trust proxy', true);                                                       // EXPECT trust-proxy-true
app.use(cors({ origin: true, credentials: true }));                                // EXPECT cors-reflect-any-origin
app.use('/v2', cors({ origin: /trusted\.example$/, credentials: true }));          // EXPECT cors-regex-origin
app.get('/preview', async (req, res) => { const r = await fetch(req.query.url as string); res.send(await r.text()); }); // EXPECT ssrf-user-url
app.get('/img', async (req, res) => { const { address } = await dns.promises.lookup(new URL(String(req.query.u)).hostname);
  if (isPrivate(address)) return res.sendStatus(400); const r = await fetch(String(req.query.u)); res.send(await r.text()); }); // EXPECT ssrf-validate-then-fetch
app.get('/check', (req, res) => { const h = new URL(String(req.query.u)).hostname; if (h === 'localhost' || h.startsWith('10.')) return res.end(); }); // EXPECT ssrf-string-blocklist
app.get('/login/done', (req, res) => res.redirect(req.query.next as string));      // EXPECT open-redirect
app.get('/login/done2', (req, res) => { const next = String(req.query.next); if (next.startsWith('/')) return res.redirect(next); }); // EXPECT redirect-startswith-slash
app.get('/file', (req, res) => res.sendFile(path.join(__dirname, 'files', req.query.name as string))); // EXPECT path-user-input
app.get('/file2', (req, res) => { const n = String(req.query.n).replace('../', ''); res.send(fs.readFileSync(n)); }); // EXPECT path-replace-dotdot
function inside(baseDir: string, p: string) { const r = path.resolve(baseDir, p); return r.startsWith(baseDir); } // EXPECT path-startswith-base
app.get('/users', async (req, res) => { const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`); res.json(rows); }); // EXPECT sqli-interpolated
app.get('/u2', async (req, res) => res.json(await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE id = ${req.query.id}`))); // EXPECT sqli-raw-unsafe
app.post('/login', async (req, res) => { const u = await Users.findOne(req.body); res.json(u); }); // EXPECT nosql-operator-injection
app.post('/convert', (req, res) => exec(`convert ${req.body.file} out.png`, () => res.end())); // EXPECT cmd-injection
app.post('/settings', (req, res) => { merge(config, req.body); res.end(); });      // EXPECT proto-merge-user-input
app.patch('/me', async (req, res) => { await prisma.user.update({ where: { id: 1 }, data: req.body }); res.end(); }); // EXPECT mass-assignment
app.get('/me', (req, res) => { const claims = jwt.decode(String(req.headers.authorization)); res.json(claims); }); // EXPECT jwt-decode-not-verify
app.get('/me2', (req, res) => { const c = jwt.verify(String(req.headers.authorization), process.env.SECRET!); res.json(c); }); // EXPECT jwt-verify-no-algorithms
const resetToken = Math.random().toString(36).slice(2);                            // EXPECT weak-random-token
app.post('/hook', (req, res) => { const expected = crypto.createHmac('sha256', 's').update(JSON.stringify(req.body)).digest('hex'); // EXPECT webhook-reserialized-body
  if (req.headers['x-signature'] === expected) res.end(); });
const sig = String(req.headers['x-sig']); if (signature === expected) {}          // EXPECT timing-unsafe-compare
app.post('/reset', (req, res) => sendMail(`https://${req.hostname}/reset?t=${resetToken}`)); // EXPECT host-header-url
const re = /^(\w+\s?)*$/;                                                           // EXPECT redos-nested-quantifier
app.get('/search', (req, res) => res.json(new RegExp(req.query.q as string).test('x'))); // EXPECT redos-user-regex
function deepMerge(target: any, source: any) { for (const key in source) { if (typeof source[key] === 'object') { target[key] = target[key] || {}; deepMerge(target[key], source[key]); } else target[key] = source[key]; } } // EXPECT proto-hand-rolled-merge
app.get('/clean', (req, res) => res.send(DOMPurify.sanitize(String(req.query.h)).replace(/&lt;/g, '<'))); // EXPECT xss-sanitize-then-mutate
const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;                             // EXPECT secret-in-public-env
https.get('https://x', { rejectUnauthorized: false });                              // EXPECT tls-verify-off
// websec-ignore: reviewed, the URL is a constant
app.get('/ok', async (req, res) => { await fetch(req.query.url as string); });     // suppressed
