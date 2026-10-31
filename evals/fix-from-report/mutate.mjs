// Regression-durability metric: for each finding, replace the run's fixed file(s) with the typical naive fix
// (from the validated naive control) and check whether the run's OWN test suite fails.
// Usage: node mutate.mjs <runDir> <naiveDir>
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
const runDir = path.resolve(process.argv[2]);
const NAIVE = path.resolve(process.argv[3] || process.env.NAIVE_DIR || '/tmp/naive'); // fixture + controls/naive.patch applied
const MUTATIONS = { redirect: ['src/routes/auth.js'], ssrf: ['src/routes/preview.js'], path: ['src/routes/files.js'], cors: ['src/app.js'], jwt: ['src/lib/auth.js'], webhook: ['src/routes/webhooks.js'], proto: ['src/routes/settings.js'], race: ['src/routes/coupons.js'] };
const tmpRoot = fs.mkdtempSync('/tmp/websec-mut-');
const testCmd = (dir) => spawnSync('npm', ['test'], { cwd: dir, encoding: 'utf8', timeout: 240000 });
const clean = testCmd(runDir);
const result = { runDir, cleanPass: clean.status === 0, detected: [], missed: [] };
for (const [finding, files] of Object.entries(MUTATIONS)) {
  const dir = path.join(tmpRoot, finding);
  fs.cpSync(runDir, dir, { recursive: true, filter: (src) => path.basename(src) !== 'node_modules' && !src.includes(`${path.sep}node_modules${path.sep}`) });
  fs.symlinkSync(path.join(runDir, 'node_modules'), path.join(dir, 'node_modules'));
  for (const f of files) fs.copyFileSync(path.join(NAIVE, f), path.join(dir, f));
  // the naive auth.js route still needs currentUser; naive lib/auth.js still exports currentUser: compatible with originals
  const r = testCmd(dir);
  (r.status !== 0 ? result.detected : result.missed).push(finding);
}
fs.rmSync(tmpRoot, { recursive: true, force: true });
console.log(JSON.stringify(result));
