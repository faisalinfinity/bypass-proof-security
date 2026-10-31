// Reads [{input, output, kind, expect}] on stdin; resolves each output the way a browser does
// (WHATWG URL against the corpus current_url) and prints the failures as JSON.
import fs from 'node:fs';
const corpus = JSON.parse(fs.readFileSync(new URL('../../../skills/web-security-fixes/assets/corpus/redirect.json', import.meta.url)));
const { current_url, allowed_origins } = corpus.assumptions;
const rows = JSON.parse(fs.readFileSync(0, 'utf8'));
const failures = [];
for (const r of rows) {
  let dest = null;
  if (typeof r.output === 'string') { try { dest = new URL(r.output, current_url); } catch { dest = null; } }
  if (r.kind === 'attack') {
    const safe = !dest || ((dest.protocol === 'https:' || dest.protocol === 'http:') && allowed_origins.includes(dest.origin));
    if (!safe) failures.push({ ...r, dest: dest.href });
  } else if (!dest || dest.href !== r.expect) {
    failures.push({ ...r, dest: dest && dest.href });
  }
}
console.log(JSON.stringify(failures));
