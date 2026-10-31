# Web Security Fixes

**`web-security-fixes`** is an agent skill that makes your coding agent fix web vulnerabilities **so the fix actually holds**, not just so it passes code review. It works with **Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, OpenCode, Windsurf, Cline, Amp**, and any other agent that supports the open [Agent Skills](https://agentskills.io) format.

> Offensive skills tell you how to break it. Checklists tell you what to look for. This one makes sure your fix actually holds.

## Why

Security fixes fail in a familiar way: the code blocks the reported payload, passes review, and falls to the next variant. These are common fixes, written by people and by agents alike, that each lose to one input:

| A common fix | The input that breaks it |
|---|---|
| `if (next.startsWith('/')) redirect(next)` | `//evil.com`, `/\evil.com` |
| Resolve DNS, check the IP, then `fetch(url)` | DNS rebinding: the second lookup returns `127.0.0.1` |
| `name.replace('../', '')` | `....//....//etc/passwd` |
| `cors({ origin: /example\.com$/ })` | `https://evilexample.com` |
| `jwt.verify(token, secret)` | A token for another service (no issuer or audience check) |
| HMAC over `JSON.stringify(req.body)` | Replays, and re-serialized bodies |
| Skip the `__proto__` key | `{"constructor": {"prototype": {...}}}` |
| Re-check the coupon before saving | 20 parallel requests |

This skill teaches the structural fix for each bug class, shows the naive fixes and the exact inputs that defeat them, ships drop-in hardened helpers, and gives the agent tools to **prove** a fix holds, including against variants and neighboring bugs nobody reported.

## Does it help? Measured, not assumed

Eight agent runs fixed the same Express app with eight planted vulnerabilities, from a pentest report that gave one example payload per finding: 4 with the skill, 4 without, on a frontier model and a small fast model. A hidden grader then attacked every fix with the full variant set (DNS rebinding, `//evil.com`, `....//`, forged JWTs, webhook replays, `constructor.prototype`, 25 parallel requests…). Full method, controls and per-run numbers: [`evals/fix-from-report/`](evals/fix-from-report/).

| | Without skill | With skill |
|---|---|---|
| Reported findings fixed (all variants blocked, app still works) | 32/32 | 32/32 |
| Also fixed a vulnerability **nobody reported** (a quadratic ReDoS next to the SSRF sink) | 0/4 runs | **3/4 runs** |
| Tests written per run (frontier model) | 10–12 | 87–104, written first and confirmed failing on the old code |
| Naive-fix regressions caught by the run's own tests | 7, 8 / 5, 6 of 8 | 7, 8 / 6, 6 of 8 |
| Tokens | 1× | ≈1.4–1.9× |

The honest read:
- **When a clear report names the bug, today's models fix it correctly on their own.** The skill doesn't change that.
- **Where it helps is beyond the report:** sweeping neighbors and variants found a real unreported bug in 3 of 4 runs, against 0 of 4 without.
- **It also helps with proof:** test-first suites, probes, and scans.
- **The cost is about 1.4–1.9× tokens.**

The with-skill agents also reported four rough edges in the tools, and all of them are fixed in this version.


## What's inside

**13 references**, one per vulnerability family. Each one covers: how to spot it, fixes that don't hold, the fix that holds (Node/TypeScript and Python code, with notes for Go, Java, PHP, and Ruby), and regression tests.

SSRF and outbound requests · open redirects and URL parsing · XSS and HTML injection · strict CSP, Trusted Types, Fetch Metadata and XS-Leaks · CSRF, CORS, cookies and sessions · JWT, OAuth/OIDC, passwords and reset links · IDOR/BOLA, multi-tenancy (Postgres RLS) and mass assignment · SQL, NoSQL, command and template injection · path traversal, zip slip and uploads · race conditions and business logic · prototype pollution, deserialization, XXE and ReDoS · Host-header trust, cache poisoning and deception, request smuggling · webhook signatures.

**Three zero-dependency Node scripts:**

| Script | What it does |
|---|---|
| `scripts/scan.mjs [dir]` | 61 rules across JS/TS, Python, Go, Java/Kotlin, PHP, Ruby and templates. Flags dangerous **sinks** (user input reaching a dangerous API) and **fixes that don't hold** (`startsWith('/')` redirect checks, `replace('../')`, `cors({ origin: true })`, `allow_origins=["*"]` with credentials, HMAC over re-serialized JSON, `tarfile.extractall` without a filter…). Tested on 74 planted bugs across five languages (74/74 found, no false positives) and on four real open-source apps for noise. `--json`, `--strict` for CI. |
| `scripts/probe-validator.mjs <class> <module> [export]` | Imports **your** function and runs a bypass corpus against it: `redirect`, `ssrf`, `ssrf-fetch` (simulated DNS rebinding and IP literals against a loopback server), `path`, `cors-origin`, `proto-pollution`, `xss` (with a jsdom re-parse to catch mutation XSS), `redos` (worker with a hard timeout), and `jwt` (`alg: none`, key confusion, expiry, issuer/audience). The oracles judge the *effect*, for example where a browser actually navigates. |
| `scripts/check-headers.mjs <url>` | Grades a live URL: CSP quality (`unsafe-inline`, script-gadget hosts, missing `object-src`/`base-uri`, **nonces reused across responses**), HSTS, cookie flags and prefixes, CORS reflection with credentials, and `Cache-Control` on personalized responses. At most four plain GET requests. |

**Hardened helpers** (copy into your project):
- Node, zero dependencies: `safe-fetch` (SSRF-safe, IP checked at connect time, every redirect re-checked, TLS still verified), an undici dispatcher variant for `fetch()`, `safe-redirect`, `safe-path`, `safe-merge`, `verify-webhook` (Stripe, GitHub, Slack, Standard Webhooks), and `tokens`.
- Python 3.9+: `safe_fetch` (httpx and stdlib), `safe_redirect`, `safe_path`, and `verify_webhook`.

**Regression-test templates** for vitest/jest and pytest: redirect, SSRF, path, CORS, prototype pollution, XSS, webhook, race condition, and the two-user authorization test. Verified to pass on fixed code and fail on vulnerable code.

### How it was verified

- **Helpers:** 37 Node tests and 45 Python tests (on Python 3.9 and 3.13). They cover every corpus entry, DNS rebinding simulation, redirect chains to metadata IPs, real HTTPS certificate checks, 303/307 semantics, credential stripping across origins, and the published Standard Webhooks test vector.
- **Library defaults the references rely on**, checked by running them: jsonwebtoken 9, jose 6, PyJWT 2.15, DOMPurify 3.4, PyYAML 6, Jinja2 3.1, Flask 3.1, Starlette 1.10, Django 6 (built-in CSP), Express 5.3 (`trust proxy`), lxml 6, and tarfile on 3.9/3.13/3.14.
- **Ways of fixing that failed when tested**, each with a probe or test that reproduces it:
  - Starlette's `allow_origins=["*"]` with `allow_credentials=True` reflects **any** origin.
  - On Python 3.13, `tarfile.extractall()` writes `../` entries outside the destination.
  - `ipaddress.is_global` treats NAT64 loopback as global.
  - macOS and glibc resolve `0177.0.0.1` to different addresses.

The tests live in this repo under `tests/` (`npm test`; Python: `uv run --with pytest --with httpx pytest tests/web-security-fixes/python`).

## Install

```bash
npx skills add faisalinfinity/web-security-fixes --skill web-security-fixes
```

The [`skills` CLI](https://github.com/vercel-labs/skills) detects your agents and asks where to install. To target specific agents, pass `-a`. Add `-g` to install for your user account instead of only the current project:

| Agent | Command | Project path | User path (`-g`) |
|---|---|---|---|
| Claude Code | `npx skills add faisalinfinity/web-security-fixes --skill web-security-fixes -a claude-code` | `.claude/skills/` | `~/.claude/skills/` |
| Codex | `… -a codex` | `.agents/skills/` | `~/.agents/skills/` |
| Cursor | `… -a cursor` | `.agents/skills/` | `~/.cursor/skills/` |
| GitHub Copilot | `… -a github-copilot` | `.agents/skills/` | `~/.copilot/skills/` |
| Gemini CLI | `… -a gemini-cli` | `.agents/skills/` | `~/.gemini/skills/` |
| OpenCode | `… -a opencode` | `.agents/skills/` | `~/.config/opencode/skills/` |
| Windsurf | `… -a windsurf` | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` |
| Cline | `… -a cline` | `.agents/skills/` | `~/.agents/skills/` |
| Amp | `… -a amp` | `.agents/skills/` | `~/.config/agents/skills/` |

**Manual install:**

```bash
git clone --depth 1 https://github.com/faisalinfinity/web-security-fixes.git /tmp/wsf
mkdir -p .agents/skills && cp -R /tmp/wsf/skills/web-security-fixes .agents/skills/   # Claude Code: .claude/skills/
```

**Agents without skill support:** run `npx skills use faisalinfinity/web-security-fixes@web-security-fixes` to get a ready-to-paste prompt, or add this to `AGENTS.md`: *"For any security fix, security review, or code that handles URLs, redirects, files, HTML, tokens, webhooks, CORS/CSP/cookies, or money, follow `.agents/skills/web-security-fixes/SKILL.md`."*

## Use

The skill triggers on security work, and on writing code in risky areas (outbound fetches, redirects, uploads, auth, webhooks). Example prompts:

- "Fix the findings in this pentest report"
- "Triage these Semgrep / Snyk results and fix the real ones"
- "Add a link-preview endpoint that fetches user URLs"
- "Our CORS config: is it safe? Fix it"
- "Make the coupon redemption safe under concurrency"

Or run the tools yourself (the install path is printed by `npx skills add`):

```bash
node .agents/skills/web-security-fixes/scripts/scan.mjs .
node .agents/skills/web-security-fixes/scripts/probe-validator.mjs redirect src/lib/redirect.ts safeNext
node .agents/skills/web-security-fixes/scripts/check-headers.mjs https://staging.example.com/
```

## Safety

The skill is defensive. The corpus inputs are inert test strings that target only loopback, private, metadata, and `.example` addresses. `check-headers.mjs` sends at most four plain GET requests to the one URL you give it. Only point the live tools at systems you own or are authorized to test.

## Related skills

- **Finding bugs:** review-oriented skills (for example getsentry's `security-review`) are good at surfacing candidates. This skill fixes them so they stay fixed.
- **Next.js:** [`nextjs-ship-ready`](https://github.com/faisalinfinity/nextjs-production-skill) covers Server Actions, CSP nonce vs. static rendering, and Next.js-specific headers.

## License

MIT. See [LICENSE](LICENSE).
