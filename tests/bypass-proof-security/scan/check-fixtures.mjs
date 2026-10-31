// Compares scan.mjs findings with `EXPECT <rule-id>` markers in fixture files.
// Usage: node check-fixtures.mjs <fixtures-dir>
import fs from 'node:fs';
import path from 'node:path';
import { scan } from '../../../skills/bypass-proof-security/scripts/scan.mjs';
const dir = path.resolve(process.argv[2]);
const { findings } = scan(dir, {});
const expected = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f);
    else fs.readFileSync(f, 'utf8').split('\n').forEach((l, i) => { for (const m of l.matchAll(/EXPECT ([a-z-]+)/g)) expected.push({ file: f, line: i + 1, rule: m[1] }); });
  }
})(dir);
const abs = (f) => f;
const hit = (e) => findings.some((f) => f.path === e.file && f.line === e.line && f.rule === e.rule);
const missed = expected.filter((e) => !hit(e));
const unexpected = findings.filter((f) => !expected.some((e) => e.file === f.path && e.line === f.line && e.rule === f.rule));
console.log(`expected ${expected.length} · found ${expected.length - missed.length} · missed ${missed.length} · unexpected ${unexpected.length}`);
for (const m of missed) console.log(`MISSED  ${m.rule}  ${path.relative(dir, m.file)}:${m.line}`);
for (const u of unexpected) console.log(`EXTRA   ${u.rule}  ${path.relative(dir, u.path)}:${u.line}  ${u.code.slice(0, 90)}`);
process.exitCode = missed.length || unexpected.length ? 1 : 0;
