# Injection: SQL, NoSQL, commands, templates, headers, logs, CSV

Covers every place where user data becomes part of code or a command that another interpreter runs: a SQL engine, a Mongo query, a shell, a template engine, an HTTP or email header parser, a log parser, or a spreadsheet.

## Contents
- [SQL](#sql)
- [NoSQL operator injection](#nosql-operator-injection)
- [OS commands and argument injection](#os-commands-and-argument-injection)
- [Server-side template injection](#server-side-template-injection)
- [Header, email, and log injection](#header-email-and-log-injection)
- [CSV / formula injection](#csv--formula-injection)
- [LDAP and XPath](#ldap-and-xpath)
- [Regression tests](#regression-tests)

## SQL

### Spot it

```bash
grep -rnE "\\\$queryRawUnsafe|\\\$executeRawUnsafe|Prisma\.raw\(|\.raw\(\s*[\`'\"].*\\\$\{|whereRaw|orderByRaw|sequelize\.query\(\s*[\`'\"].*\\\$\{|literal\(|createQueryBuilder.*\\\$\{|\.query\(\s*[\`'\"].*(\\\$\{|\+)" --include=*.{js,ts,mjs} .
grep -rnE "execute\(\s*f['\"]|execute\(\s*['\"].*%\s*\(|execute\(.*\.format\(|\.raw\(\s*f['\"]|\.extra\(|RawSQL\(|text\(\s*f['\"]" --include=*.py .
```

### Fixes that don't hold

| Fix | Breaks on |
|---|---|
| Escape quotes by hand: `x.replace("'", "''")` | Backslash escapes in MySQL (`\'`), multibyte charset tricks, numeric contexts with no quotes (`id = 1 OR 1=1`) |
| Parameterize values, interpolate `ORDER BY ${sort}` | `sort=(CASE WHEN (SELECT ...) THEN name ELSE email END)`: boolean-based extraction through ordering |
| `Prisma.$queryRawUnsafe(\`... ${x}\`)` or `Prisma.raw(x)` inside a tagged query | `Unsafe` and `raw` mean exactly that: no parameterization |
| Tagged `$queryRaw` with the template built *before* the tag: `const q = \`...${x}\`; $queryRaw(q)` | It's a plain string by then. The tag has to wrap the literal. |
| `LIKE '%' + term + '%'` with a parameter | Safe from injection, but `%`/`_` wildcards let users scan or cause slow queries. Escape them. |
| Validating that IDs "look numeric" with a regex that isn't anchored | `/\d+/.test('1 OR 1=1')` is true |
| Allowlisting table and column names by `includes()` | `name; DROP`, or quoted identifiers. Use an exact `Map` from public name to SQL identifier. |
| Django `order_by(request.GET['sort'])` | Ordering by `user__password` or other related fields leaks data one comparison at a time. Allowlist the fields. |

### The fix that holds

Values: parameters. Identifiers and keywords (columns, tables, `ASC`/`DESC`): an allowlist map. Never build SQL from strings.

```ts
// Prisma
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;            // tagged: parameterized
const SORT = { name: Prisma.sql`name`, created: Prisma.sql`created_at` } as const;
const DIR = { asc: Prisma.sql`ASC`, desc: Prisma.sql`DESC` } as const;
await prisma.$queryRaw`SELECT * FROM users ORDER BY ${SORT[sort] ?? SORT.created} ${DIR[dir] ?? DIR.desc}`;
// node-postgres
await pool.query('SELECT * FROM users WHERE id = ANY($1::uuid[])', [ids]);     // IN-lists: an array param, not a join
// Knex: ?? for identifiers (still allowlist them), ? for values
knex.raw('SELECT ?? FROM users WHERE id = ?', [allowedColumn, id]);
// LIKE with escaped wildcards
const term = q.replace(/[\\%_]/g, (c) => '\\' + c);
await pool.query("SELECT * FROM posts WHERE title ILIKE $1 ESCAPE '\\'", [`%${term}%`]);
```

```python
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))           # DB-API: params tuple, not % formatting
session.execute(text("SELECT * FROM users WHERE email = :e"), {"e": email})  # SQLAlchemy
User.objects.raw("SELECT * FROM app_user WHERE email = %s", [email])         # Django raw: params list
SORTS = {"name": "name", "created": "-created_at"}
qs = Post.objects.order_by(SORTS.get(request.GET.get("sort"), "-created_at"))
```

Other stacks: Rails `where("email = ?", email)` and `order(Arel.sql(...))` only with allowlisted values. Laravel bindings `DB::select('... where id = ?', [$id])`; `orderBy($col)` takes a raw identifier, so allowlist it. Java `PreparedStatement`, JPA named parameters, `CriteriaBuilder`. Go `db.Query("... WHERE id = $1", id)`.

Defense in depth: the app's DB user has no DDL rights and can't read other schemas. Use separate read-only credentials for reporting queries.

## NoSQL operator injection

Express's `qs` parses `?user[$ne]=x` into `{ user: { $ne: 'x' } }`. JSON bodies can carry operators directly. A query built from raw input turns "equals" into "anything":

```js
// vulnerable: POST {"email": "victim@example.com", "password": {"$ne": null}}
const user = await Users.findOne({ email: req.body.email, password: req.body.password });
```

Fixes that don't hold:
- Strip keys starting with `$` only at the top level. Nested objects and arrays still carry operators.
- `String(x)` on one field while the others stay raw.

The fix that holds:
1. Validate the **types** with a schema (`z.object({ email: z.string().email(), password: z.string() })`). An object where a string belongs is a 400.
2. Mongoose 6+: `mongoose.set('sanitizeFilter', true)` wraps `$`-prefixed values in `$eq`. Or use `mongoose.trusted()` per query.
3. Never pass user input to `$where`, `$function`, `$accumulator`, or `mapReduce` (server-side JavaScript). Disable server-side JS (`security.javascriptEnabled: false`).

Python (PyMongo): same idea. Check `isinstance(value, str)` (or validate with Pydantic) before the value reaches a filter dict.

## OS commands and argument injection

### Fixes that don't hold

| Fix | Breaks on |
|---|---|
| `exec(\`convert ${file} out.png\`)` with a blocklist of `; & \| \`` | `$(...)`, newlines, `${IFS}`, and the shell's other syntax |
| Quoting by hand: `` `"${file}"` `` | `"; rm -rf ~; "` |
| `execFile` / `subprocess.run([...])` (no shell) and done | **Argument injection**: a value starting with `-` becomes an option. `git clone --upload-pack='touch /tmp/pwn' x`, `curl -o /etc/...`, `tar --checkpoint-action=exec=...`, `ffmpeg -i ...` reading local files. |
| `shell=True` with `shlex.quote` everywhere except one variable | That one variable |

### The fix that holds

1. **Don't shell out** if a library does the job (sharp or Pillow instead of ImageMagick, simple-git or dulwich with an options allowlist, `fs`/`shutil` instead of `cp`/`rm`).
2. Otherwise call the program **without a shell**, with an **argv array**, and end options with `--`:

```js
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const run = promisify(execFile);
// file arguments: absolute paths you generated (uploads saved as /tmp/work/<uuid>.png), never user names.
// ImageMagick also reads coder prefixes from names ("msl:", "ephemeral:", "url:"): absolute generated paths avoid both
await run('magick', [inputPath, '-resize', '800x800', outputPath], { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 });
// git: always '--' before user paths/URLs; validate URLs to https:// with an allowlisted host
await run('git', ['clone', '--depth=1', '--', repoUrl, dest]);
```

```python
import subprocess
subprocess.run(["git", "clone", "--depth=1", "--", repo_url, dest], check=True, timeout=120, shell=False)
```

3. Spawning `.bat`/`.cmd` on Windows always goes through `cmd.exe` parsing. Node refuses `.bat` without `shell: true` since the 2024 security releases; don't add `shell: true` back with user input.
4. Run converters in a sandbox (container with no network, read-only filesystem, resource limits). Files are attack input too: ImageMagick and Ghostscript policies, `ffmpeg` with `-protocol_whitelist file,pipe`.

## Server-side template injection

The bug: **user input becomes the template**, not data passed to the template.

```python
render_template_string(f"Hello {name}")                        # vulnerable: {{ config.__class__... }} runs code
render_template_string("Hello {{ name }}", name=name)          # safe: name is data
```

- Jinja2, Twig, Freemarker, Velocity, Handlebars, and EJS templates compiled from user-controlled strings are code execution, not "just text".
- Need user-editable templates (email templates in a SaaS)? Use a logic-less format with a fixed placeholder set (`{{first_name}}` replaced by a function you write), or Liquid, which is designed for untrusted templates. Render in an isolated worker.
- Jinja2 `SandboxedEnvironment` reduces risk but has had escapes. It isn't a security boundary for hostile tenants.

## Header, email, and log injection

- **HTTP headers:** Node's `res.setHeader` throws on CR/LF (`ERR_INVALID_CHAR`), and Django raises `BadHeaderError`. Response splitting through framework APIs is rare. The risk is in values you build into headers by hand, such as `Content-Disposition`: use `content-disposition` (npm) or RFC 6266 `filename*=UTF-8''...` encoding, never `` `attachment; filename="${name}"` ``.
- **Email:** build messages with the library API (`nodemailer` objects; Python `email.message.EmailMessage`, which refuses newlines in header values). Never concatenate `To:` or `Subject:` lines. Validate addresses with a parser, not a regex.
- **Logs:** a newline in a logged value forges log entries (`user=alice\nINFO login ok user=admin`), and ANSI escape sequences can attack terminals that view logs. Use structured JSON logging (pino, structlog), which escapes values. Never log secrets, tokens, or full request bodies.

## CSV / formula injection

Exported cells beginning with `=`, `+`, `-`, `@`, tab, or CR are formulas when opened in Excel, Sheets, or LibreOffice. That allows data exfiltration via `=HYPERLINK`/`=WEBSERVICE`, and DDE in old Excel.

```js
const neutralize = (v) => (typeof v === 'string' && /^[=+\-@\t\r]/.test(v) ? `'${v}` : v);
```

Apply it to every user-controlled cell, then CSV-quote normally (`"` doubled, field wrapped in quotes). Python: same rule before `csv.writer`.

## LDAP and XPath

LDAP filters: escape with `ldap3.utils.conv.escape_filter_chars` (Python) or `ldap-escape` (Node). DNs need DN escaping, which is different from filter escaping. XPath: use parameterized XPath (`XPathVariableResolver` in Java, lxml `xpath('//u[@n=$n]', n=name)`) instead of string building.

## Regression tests

For each fixed query, add a test that sends a payload which changes the result if interpreted, and asserts the result didn't change:
- SQL: `1 OR 1=1`, `' OR '1'='1`, `name) --`, and a sort parameter of `(CASE WHEN 1=1 THEN name ELSE id END)`. Expect 400 or the default sort.
- NoSQL: `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}` as field values. Expect 400.
- Commands: values of `--help`, `-oProxyCommand=x`, `--upload-pack=x`, `$(id)`, `a;id`. Expect a rejection, or a literal argument after `--`.
- Templates: `{{7*7}}` and `${7*7}` render as literal text, never `49`.

`scan.mjs` flags the sink patterns above. Re-run it with `--rule` for the class you fixed to find the variants.
