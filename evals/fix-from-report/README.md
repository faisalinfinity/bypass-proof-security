# Eval: fix eight pentest findings, with and without the skill

## Setup

`fixture/` is a small Express 5 API with eight planted vulnerabilities. `FINDINGS.md` is a pentest-style report that gives **one** example payload per finding, which is how real reports read and why naive fixes happen:

1. Open redirect
2. SSRF in link previews
3. Path traversal
4. CORS that reflects any origin with credentials
5. Forged JWTs accepted
6. Unsigned webhooks
7. Prototype pollution
8. A coupon race

Each agent got its own copy and the same prompt: *"fix all eight findings properly … the way a careful senior engineer would for production"*, with no new npm packages and `npm test` still passing. The **with-skill** runs were also told where the skill lives and to read `SKILL.md` first.

## Grading

**`grade.mjs` (hidden from the agents)** attacks each fix over HTTP with the full variant set, not the single reported payload:
- The redirect corpus, judged by where a browser lands.
- SSRF against a loopback "internal" server via 14 address forms, plus **simulated DNS rebinding**.
- Path variants including `....//` and a sibling-prefix directory.
- The CORS corpus.
- Forged JWTs (none-alg, wrong key, expired, wrong iss/aud).
- Webhook tampering, re-serialization, replay, truncation.
- `__proto__` / `constructor.prototype` payloads.
- 25 parallel coupon redemptions.

A finding counts as fixed only if **every** variant is blocked **and** legitimate use still works. The project's own functional tests must pass too.

**`mutate.mjs`** measures *regression durability*. For each finding it swaps the agent's fixed file for the typical naive fix, then runs the agent's **own** test suite. A durable fix ships a test that fails when someone later "simplifies" the code back to a bypassable version. The naive fixes are in `controls/naive.patch`:
- `startsWith('/')`
- resolve-then-check SSRF
- `replace('../', '')`
- a regex CORS origin
- `jwt.verify` without iss/aud
- HMAC over `JSON.stringify(body)`
- skipping only `__proto__`
- a re-check before write

**Controls**, so the grader itself is validated:

| Control | Fixed |
|---|---|
| Vulnerable fixture | 0/8 |
| `controls/naive.patch` (the fixes above) | **0/8**: each blocks the reported payload and fails a variant |
| `controls/reference.patch` (the skill's helpers) | 8/8 |

## Results

Two rounds, two runs per condition. Round 1 used the session's default model (a frontier model). Round 2 used a small, fast model (Haiku). Between rounds the skill gained four improvements from round-1 feedback: a scanner rule for regex HTML parsing, an in-suite DNS-rebinding test in the templates, `--allowed` retargeting in the probe, and scanner false-positive fixes.

| Run | Model | Skill | Findings fixed | Own tests catch naive regressions | Tests written | Also fixed the unreported ReDoS* | Tokens | Time |
|---|---|---|---|---|---|---|---|---|
| A1 | frontier | – | 8/8 | 7/8 | 12 | no | 96k | 7.4 min |
| A2 | frontier | – | 8/8 | 8/8 | 10 | no | 104k | 8.4 min |
| B1 | frontier | ✓ | 8/8 | 7/8 | 104 | no | 172k | 10.0 min |
| B2 | frontier | ✓ | 8/8 | 8/8 | 87 | **yes** | 200k | 12.1 min |
| C1 | small | – | 8/8 | 5/8 | 11 | no | 69k | 2.1 min |
| C2 | small | – | 8/8 | 6/8 | 10 | no | 81k | 5.8 min |
| D1 | small | ✓ | 8/8 | 6/8 | 11 | **yes** | 117k | 5.6 min |
| D2 | small | ✓ | 8/8 | 6/8 | 20 | **yes** | 108k | 3.5 min |

\* `preview.js` extracted the page title with `/<title[^>]*>([^<]*)<\/title>/i`, which is quadratic on a page of repeated `<title` (3.7 s of CPU for 240 KB, measured). It wasn't in the report.

## What this shows, honestly

- **When a well-written report names the bug, both models fix all eight correctly without the skill.** Those fixes hold against every variant the grader tries. On this task, the skill doesn't change correctness.
- **With the skill, agents found a vulnerability nobody reported in 3 of 4 runs, against 0 of 4 without.** The skill's "sweep for variants and neighbors" step, its ReDoS reference, and (in round 2) its scanner rule led agents to the quadratic regex next to the SSRF sink.
- **The frontier model wrote test-first suites about 9× larger with the skill** (87–104 tests, verified failing on the old code). Durability against naive regressions was the same as without it (7–8/8). For the small model it was marginally better (6/8 and 6/8 vs 5/8 and 6/8).
- **The cost is about 1.4–1.9× tokens** and somewhat longer runs.
- **Feedback loop:** the with-skill agents reported concrete tool gaps (a scanner false positive on `typeof signature !== 'string'`, `realpathInside` failing for new folders, the probe not retargeting to real origins, the missing in-suite rebinding test). All of them are fixed in the shipped version.

**Not tested here:** proactive use (building features where nobody mentions security, which is where the skill's description is meant to trigger), other languages, and larger codebases.

## Reproduce

```bash
cp -R fixture /tmp/run && (cd /tmp/run && npm install)      # give an agent /tmp/run and FINDINGS.md
node grade.mjs /tmp/run                                     # findings fixed + functional tests
cp -R fixture /tmp/naive && patch -d /tmp/naive -p1 < controls/naive.patch
node mutate.mjs /tmp/run /tmp/naive                         # regression durability
```
