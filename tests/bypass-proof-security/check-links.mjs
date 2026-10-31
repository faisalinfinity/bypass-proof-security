// Verifies that every references/*.md#anchor link and every assets/ or scripts/ path mentioned in the skill exists.
import fs from 'node:fs';
import path from 'node:path';
const SKILL = path.resolve(new URL('../../skills/bypass-proof-security/', import.meta.url).pathname);
const slug = (t) => t.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
const anchors = {};
for (const f of fs.readdirSync(path.join(SKILL, 'references'))) {
  const src = fs.readFileSync(path.join(SKILL, 'references', f), 'utf8').replace(/```[\s\S]*?```/g, '');
  anchors[f] = new Set([...src.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) => slug(m[1])));
}
const files = ['SKILL.md', 'scripts/scan.mjs', 'scripts/check-headers.mjs', 'scripts/probe-validator.mjs', ...fs.readdirSync(path.join(SKILL, 'references')).map((f) => `references/${f}`)];
let bad = 0, checked = 0;
for (const rel of files) {
  const src = fs.readFileSync(path.join(SKILL, rel), 'utf8');
  // markdown + plain refs: references/x.md#anchor ; scan.mjs uses R('x', 'anchor')
  const refs = [...src.matchAll(/references\/([a-z0-9-]+\.md)(?:#([a-z0-9_-]+))?/g)].map((m) => [m[1], m[2]]);
  if (rel.endsWith('scan.mjs')) for (const m of src.matchAll(/R\('([a-z0-9-]+)'(?:,\s*'([a-z0-9_-]+)')?\)/g)) refs.push([`${m[1]}.md`, m[2]]);
  // bare same-dir refs inside references/: `x.md#anchor`
  if (rel.startsWith('references/')) for (const m of src.matchAll(/`([a-z0-9-]+\.md)(?:#([a-z0-9_-]+))?`/g)) refs.push([m[1], m[2]]);
  for (const [file, anchor] of refs) {
    checked++;
    if (!anchors[file]) { console.log(`MISSING FILE  ${rel} -> ${file}`); bad++; continue; }
    if (anchor && !anchors[file].has(anchor)) { console.log(`MISSING ANCHOR ${rel} -> ${file}#${anchor}`); bad++; }
  }
  for (const m of src.matchAll(/((?:assets|scripts)\/[A-Za-z0-9_./-]+\.(?:mjs|py|json|ts))/g)) {
    checked++;
    if (!fs.existsSync(path.join(SKILL, m[1]))) { console.log(`MISSING PATH  ${rel} -> ${m[1]}`); bad++; }
  }
}
console.log(`checked ${checked} links/paths, ${bad} broken`);
process.exitCode = bad ? 1 : 0;
