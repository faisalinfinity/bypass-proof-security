// The skills CLI rejects a SKILL.md whose frontmatter isn't valid YAML (e.g. an unquoted ": " in the description).
import fs from 'node:fs';
import { parse } from 'yaml';
const src = fs.readFileSync(new URL('../../skills/web-security-fixes/SKILL.md', import.meta.url), 'utf8');
const m = src.match(/^---\n([\s\S]*?)\n---\n/);
if (!m) throw new Error('SKILL.md has no frontmatter');
const fm = parse(m[1], { strict: true });
const problems = [];
if (fm.name !== 'web-security-fixes') problems.push(`name is ${JSON.stringify(fm.name)}`);
if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(fm.name || '') || (fm.name || '').length > 64) problems.push('name must be lowercase-hyphenated, ≤ 64 chars');
if (typeof fm.description !== 'string' || !fm.description.length) problems.push('description missing');
else if (fm.description.length > 1024) problems.push(`description is ${fm.description.length} chars (max 1024)`);
const yml = fs.readFileSync(new URL('../../skills/web-security-fixes/agents/openai.yaml', import.meta.url), 'utf8');
const oa = parse(yml, { strict: true });
if (!oa.interface?.display_name || !oa.interface?.short_description) problems.push('agents/openai.yaml missing interface fields');
console.log(problems.length ? `frontmatter problems:\n- ${problems.join('\n- ')}` : `frontmatter OK (name=${fm.name}, description ${fm.description.length} chars; openai.yaml OK)`);
process.exitCode = problems.length ? 1 : 0;
