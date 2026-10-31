#!/usr/bin/env node
// scan.mjs: find dangerous sinks AND fixes that don't hold. Zero dependencies, Node 18+. Read-only.
//
//   node scan.mjs [dir] [--json] [--strict] [--rule id,id] [--severity high|medium|low]
//                 [--include-tests] [--list-rules]
//
// Two kinds of rules:
//   sink       user input reaching a dangerous API (fetch(req.query.url), exec(`...${x}`), pickle.loads, ...)
//   naive-fix  a fix that looks right but doesn't hold (startsWith('/'), replace('../',''), cors origin:true, ...)
// Findings are candidates, not verdicts: open each location and confirm before changing code.
// Suppress a reviewed line with a comment containing `websec-ignore` (optionally `websec-ignore:rule-id`)
// on the same line or the line above.
// Skips: node_modules, build output, dot-directories, vendored code, minified lines, and tests (unless --include-tests).
// --strict exits 1 when any high or medium finding remains (CI).

import fs from 'node:fs';
import path from 'node:path';

const R = (file, anchor) => `references/${file}.md${anchor ? `#${anchor}` : ''}`;
const SSRF = R('ssrf-and-outbound-requests', 'the-fix-that-holds');
const REDIR = R('redirects-and-url-parsing', 'the-fix-that-holds');
const PATHS = R('files-paths-uploads', 'path-traversal');
const XSS = R('xss-and-html-injection', 'the-fix-that-holds');
const SQL = R('injection', 'sql');
const CMD = R('injection', 'os-commands-and-argument-injection');
const PROTO = R('deserialization-prototype-pollution-redos', 'prototype-pollution-javascript');
const DESER = R('deserialization-prototype-pollution-redos', 'unsafe-deserialization');
const JWT = R('authn-tokens-oauth', 'jwt-verification');
const CORS = R('csrf-cors-cookies-sessions', 'cors');
const CSRF = R('csrf-cors-cookies-sessions', 'csrf');
const HOOK = R('webhooks-and-third-party-callbacks', 'the-fix-that-holds');
const HTTP = R('http-layer-cache-smuggling', 'host-header-and-forwarded-headers');
const REDOS = R('deserialization-prototype-pollution-redos', 'redos');
const AUTHZ = R('authorization-idor-mass-assignment', 'mass-assignment');
const HDRS = R('browser-isolation-and-headers', 'strict-csp');

const USER_JS = String.raw`(?:req|request|ctx\.request|ctx|event)\.(?:query|body|params|searchParams|nextUrl\.searchParams)`;
const USER_PY = String.raw`request\.(?:args|GET|POST|form|json|query_params|data|values|path_params)`;
const SECRETY = String.raw`(?:token|secret|password|passwd|otp|nonce|salt|api_?key|session_?id|reset_?code|verification_?code|invite_?code)`;

/** @type {Array<{id:string, sev:'high'|'medium'|'low', kind:'sink'|'naive-fix'|'config', langs:string[], re?:RegExp, file?:(src:string)=>number[], why:string, fix:string, ref:string}>} */
const RULES = [
  // ---------------- SSRF ----------------
  { id: 'ssrf-user-url', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got(?:\.(?:get|post))?|needle|superagent\.(?:get|post)|undici\.request|https?\.get)\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?(?:new URL\(\s*)?${USER_JS}`),
    why: 'User input decides where the server sends a request (SSRF: cloud metadata, internal services).', fix: 'Use safeFetch() (connect-time IP pinning, per-hop redirect checks) or an exact host allowlist.', ref: SSRF },
  { id: 'ssrf-user-url', sev: 'high', kind: 'sink', langs: ['py'], re: new RegExp(String.raw`\b(?:requests|httpx|urllib3|session|client)\.(?:get|post|put|patch|delete|head|request|stream)\(\s*(?:f?['"][^'"]*\{?\s*)?${USER_PY}|urlopen\(\s*${USER_PY}`),
    why: 'User input decides where the server sends a request (SSRF).', fix: 'Use guarded_httpx_client() / safe_get() from safe_fetch.py.', ref: SSRF },
  { id: 'ssrf-user-url', sev: 'high', kind: 'sink', langs: ['go'], re: /http\.(?:Get|Post|Head)\(\s*r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)\(/,
    why: 'User input decides where the server sends a request (SSRF).', fix: 'Use an http.Client whose net.Dialer.Control rejects non-public IPs.', ref: R('ssrf-and-outbound-requests', 'go') },
  { id: 'ssrf-user-url', sev: 'high', kind: 'sink', langs: ['php'], re: /(?:curl_setopt\([^,]+,\s*CURLOPT_URL,|file_get_contents\(|Http::(?:get|post)\()\s*\$_(?:GET|POST|REQUEST)/,
    why: 'User input decides where the server sends a request (SSRF).', fix: 'Restrict protocols, validate resolved IPs, pin with CURLOPT_RESOLVE, disable redirects.', ref: R('ssrf-and-outbound-requests', 'php') },
  { id: 'ssrf-validate-then-fetch', sev: 'medium', kind: 'naive-fix', langs: ['js'],
    file: (s) => (/\blookup\s*:|dispatcher\s*:|safeFetch|createSsrfSafeAgent|createGuardedLookup|dnsLookup\s*:/.test(s) ? []
      : near(s, /\bdns(?:\.promises)?\.(?:lookup|resolve4?|resolve6)\b|\bisPrivate\w*\(|ipaddr\.(?:parse|process)|\bisPublicAddress\(|\bisIP\(/g, /\b(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|undici\.request)\s*\(/g, 15)),
    why: 'IP check and request are separate steps: the client resolves DNS again (rebinding) and follows redirects unchecked.', fix: 'Validate at connect time (safeFetch / createSsrfSafeAgent) and re-check every redirect hop. Prove it: probe-validator.mjs ssrf-fetch.', ref: SSRF },
  { id: 'ssrf-validate-then-fetch', sev: 'medium', kind: 'naive-fix', langs: ['py'],
    file: (s) => (/guarded_httpx_client|safe_get\(|resolve_checked|AbstractResolver|smokescreen/.test(s) ? []
      : near(s, /getaddrinfo|gethostbyname|ipaddress\.ip_address|\.is_private|\.is_global/g, /\b(?:requests|httpx|session|client)\.(?:get|post|put|request)\(|urlopen\(/g, 15)),
    why: 'IP check and request are separate steps: the HTTP library resolves DNS again (rebinding) and follows redirects unchecked.', fix: 'Use guarded_httpx_client() (check inside connect_tcp) or an egress proxy.', ref: R('ssrf-and-outbound-requests', 'python') },
  { id: 'ssrf-string-blocklist', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py', 'go', 'php', 'rb', 'java'],
    check: (line) => /(?:===?|!==?|\bin\b|includes\(|startsWith\(|startswith\(|HasPrefix\()\s*\(?\s*\[?\s*['"](?:localhost|127\.0\.0\.1|169\.254\.169\.254|0\.0\.0\.0|10\.|192\.168\.|172\.16\.)['"]/.test(line) && /host|url|\bip\b|addr|target|endpoint/i.test(line.replace(/(['"])(?:(?!\1).)*\1/g, '')),
    why: 'String blocklists miss 0x7f.1, 2130706433, [::ffff:127.0.0.1], 127。0。0。1, DNS names that resolve inside, and redirects.', fix: 'Classify the resolved IP (isPublicAddress) at connect time instead of matching strings.', ref: SSRF },
  { id: 'ssrf-is-global-only', sev: 'low', kind: 'naive-fix', langs: ['py'], re: /\.is_global\b/,
    why: 'ipaddress.is_global reports NAT64 64:ff9b::7f00:1 (→127.0.0.1) as global; 6to4 too before 3.12.4.', fix: 'Use is_public_address() from safe_fetch.py.', ref: SSRF },

  // ---------------- open redirect ----------------
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`(?:\bres\.redirect|\bredirect|NextResponse\.redirect|Response\.redirect|reply\.redirect|ctx\.redirect)\s*\(\s*(?:\d{3}\s*,\s*)?(?:new URL\(\s*)?(?:${USER_JS}|searchParams\.get\(|params\.get\(|formData\.get\()`),
    why: 'User input becomes the Location header: //evil.com, /\\evil.com, and https://you@evil.com all leave your site.', fix: 'safeRedirectTarget(value, { allowedOrigins }) from safe-redirect.mjs.', ref: REDIR },
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['js'], re: /(?:window\.)?location(?:\.href)?\s*=(?!=)\s*(?:params|searchParams|query|new URLSearchParams|router\.query)|location\.(?:assign|replace)\(\s*(?:params|searchParams|query|new URLSearchParams)/,
    why: 'Client-side redirect to a URL from the query string (open redirect, javascript: XSS).', fix: 'Parse with new URL() and allow only same-origin paths or exact origins.', ref: R('redirects-and-url-parsing', 'client-side-navigation-and-links') },
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['py'], re: new RegExp(String.raw`(?:redirect|RedirectResponse|HttpResponseRedirect|HttpResponsePermanentRedirect)\(\s*${USER_PY}`),
    why: 'User input becomes the Location header.', fix: 'Django: url_has_allowed_host_and_scheme. Others: safe_redirect_target().', ref: REDIR },
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['go'], re: /http\.Redirect\([^,]+,[^,]+,\s*r\.(?:URL\.Query\(\)\.Get|FormValue)\(/, why: 'User input becomes the Location header.', fix: 'Allow only same-origin paths after parsing with url.Parse; reject "//" and "\\".', ref: REDIR },
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['php'], re: /header\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)|redirect\(\s*\$request->(?:input|get|query)\(/, why: 'User input becomes the Location header.', fix: 'Map keys to routes, or validate after removing tab/newline and backslashes.', ref: REDIR },
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['rb'], re: /redirect_to\s*\(?\s*params\[|allow_other_host:\s*true/, why: 'User input becomes the Location header (or Rails open-redirect protection is turned off).', fix: 'Keep raise_on_open_redirects; map keys to paths.', ref: REDIR },
  { id: 'open-redirect', sev: 'high', kind: 'sink', langs: ['java'], re: /"redirect:"\s*\+\s*\w*(?:url|Url|next|Next|redirect|Redirect|return|Return)/, why: 'User input becomes the redirect target.', fix: 'Allow only same-origin paths after parsing; reject "//" and "\\".', ref: REDIR },
  { id: 'redirect-startswith-slash', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py'], re: /(?:next|redirect\w*|return\w*|callback\w*|continue\w*|target|dest\w*|url|goto)\s*\.\s*(?:startsWith|startswith)\(\s*['"]\/['"]\s*\)/i,
    why: "startsWith('/') accepts //evil.com, /\\evil.com and /<TAB>/evil.com (browsers normalize them to evil.com).", fix: 'Parse with the browser algorithm (safeRedirectTarget / safe_redirect_target).', ref: R('redirects-and-url-parsing', 'fixes-that-dont-hold') },
  { id: 'redirect-netloc-check', sev: 'medium', kind: 'naive-fix', langs: ['py'], re: /not\s+urlparse\([^)]*\)\.netloc|urlparse\([^)]*\)\.netloc\s*(?:==|in)\s*|urlparse\([^)]*\)\.hostname\s*(?:==|in)\s*/,
    why: "urlparse disagrees with browsers: ' //evil.com' and '/\\evil.com' have no netloc; 'https://evil.com\\@you.com' has hostname you.com.", fix: 'safe_redirect_target() (normalizes like a browser first) or Django url_has_allowed_host_and_scheme.', ref: R('redirects-and-url-parsing', 'why-string-checks-fail-parser-differentials') },
  { id: 'redirect-reemit-pathname', sev: 'low', kind: 'naive-fix', langs: ['js'], re: /redirect\([^)\n]*\.pathname\b/,
    why: "new URL('/.//evil.com', base).pathname is '//evil.com': re-emitting it creates a protocol-relative redirect.", fix: "Collapse leading slashes: '/' + pathname.replace(/^\\/+/, '').", ref: REDIR },

  // ---------------- paths ----------------
  { id: 'path-user-input', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|unlinkSync|rm|rmSync|writeFile|writeFileSync|createWriteStream|readdir|readdirSync|appendFile|copyFile)\s*\(\s*(?:path\.(?:join|resolve)\([^)]*)?${USER_JS}|path\.(?:join|resolve)\([^)\n]*${USER_JS}`),
    why: 'User input becomes a filesystem path (path traversal).', fix: 'resolveInside(base, input) / realpathInside, or store files under generated IDs.', ref: PATHS },
  { id: 'path-user-input', sev: 'high', kind: 'sink', langs: ['py'], re: new RegExp(String.raw`os\.path\.join\([^)\n]*${USER_PY}|(?:open|send_file|FileResponse|os\.remove|os\.unlink|shutil\.\w+)\(\s*(?:os\.path\.join\([^)]*)?${USER_PY}`),
    why: 'User input becomes a filesystem path; os.path.join discards the base if the input is absolute.', fix: 'resolve_inside(base, input) from safe_path.py, or send_from_directory.', ref: PATHS },
  { id: 'path-user-input', sev: 'high', kind: 'sink', langs: ['php'], re: /(?:file_get_contents|fopen|readfile|unlink|file_put_contents|include|require|include_once|require_once)\s*\(?\s*[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)/, why: 'User input becomes a filesystem path or include (traversal / LFI).', fix: 'realpath() + prefix check with DIRECTORY_SEPARATOR, or an allowlist.', ref: PATHS },
  { id: 'path-user-input', sev: 'high', kind: 'sink', langs: ['rb'], re: /send_file\(\s*params\[|File\.(?:read|open)\(\s*params\[/, why: 'User input becomes a filesystem path.', fix: 'Resolve and compare with the base directory, or use generated IDs.', ref: PATHS },
  { id: 'path-user-input', sev: 'medium', kind: 'sink', langs: ['go'], re: /filepath\.Join\([^)\n]*r\.(?:URL|FormValue|PathValue)/, why: 'User input becomes a filesystem path.', fix: 'Go 1.24+ os.Root, or filepath.IsLocal before Join.', ref: PATHS },
  { id: 'path-replace-dotdot', sev: 'high', kind: 'naive-fix', langs: ['js', 'py', 'php', 'rb', 'java', 'go'], re: /\.replace(?:All)?\(\s*(?:['"]\.\.\/?['"]|\/\\\.\\\.(?:\\\/|\/)?\/g?)|str_replace\(\s*['"]\.\.\/?['"]|strings\.Replace(?:All)?\([^,]+,\s*"\.\.\/?"/,
    why: "Stripping '../' is bypassed by '....//' (the replace output is '../').", fix: 'Resolve the full path, then compare path components with the base (resolveInside / resolve_inside).', ref: R('files-paths-uploads', 'fixes-that-dont-hold') },
  { id: 'path-startswith-base', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py', 'java'], re: /\.(?:startsWith|startswith)\(\s*(?:str\()?\s*(?:base|root|dir|baseDir|base_dir|uploadDir|upload_dir|UPLOAD_DIR|BASE_DIR|ROOT_DIR|MEDIA_ROOT|rootDir|root_dir|publicDir|storageDir|STORAGE_DIR)\w*\s*\)?\s*\)/,
    why: "String prefix check: '/srv/uploads_evil' starts with '/srv/uploads' (sibling directory).", fix: 'Compare path components: path.relative() (Node), Path.is_relative_to (Python), Path.startsWith on Path objects (Java).', ref: R('files-paths-uploads', 'fixes-that-dont-hold') },
  { id: 'tar-extractall-no-filter', sev: 'high', kind: 'sink', langs: ['py'], re: /\.extractall\((?![^)\n]*filter\s*=)/,
    why: "tarfile.extractall() without filter='data' writes '../' entries outside the destination on Python ≤ 3.13 (verified on 3.13).", fix: "tar.extractall(dest, filter='data'); for zip, still cap sizes.", ref: R('files-paths-uploads', 'archives-zip-slip-and-bombs') },

  // ---------------- XSS ----------------
  { id: 'xss-dangerously-set-inner-html', sev: 'medium', kind: 'sink', langs: ['js'], re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:(?!\s*(?:DOMPurify\.sanitize|sanitize\w*\(|purify\w*\(|clean\w*\(|safeJson|xss\(|JSON\.stringify))/,
    why: 'Raw HTML rendered without a sanitizer at this call site.', fix: 'DOMPurify.sanitize(html, allowlist) right here (sanitize last), or render text.', ref: R('xss-and-html-injection', 'rendering-user-html-and-markdown') },
  { id: 'xss-json-in-script', sev: 'high', kind: 'sink', langs: ['js'], re: /__html\s*:\s*JSON\.stringify\((?:(?!\.replace).)*$/,
    why: 'JSON.stringify inside a <script> can contain "</script>" and break out (stored XSS via JSON-LD or hydration data).', fix: "Escape <, > and & as \\u003c, \\u003e, \\u0026 after stringify.", ref: R('xss-and-html-injection', 'json-inside-script-tags') },
  { id: 'xss-inner-html', sev: 'medium', kind: 'sink', langs: ['js'], re: /\.(?:innerHTML|outerHTML)\s*(?:\+)?=(?!=)(?!\s*(?:'[^'+]*'|"[^"+]*"|\x60[^\x60$]*\x60)\s*;?\s*$)(?!\s*(?:DOMPurify|sanitize|\w*[Pp]olicy\.create|trustedTypes))|\.insertAdjacentHTML\(|document\.write(?:ln)?\(/,
    why: 'String to an HTML sink (DOM XSS) without a sanitizer at the call site.', fix: 'textContent, or DOMPurify + Trusted Types.', ref: XSS },
  { id: 'xss-framework-escape-hatch', sev: 'medium', kind: 'sink', langs: ['tpl', 'js'], re: /\bv-html\s*=|\{@html\s|\[innerHTML\]\s*=|\{\{\{(?!\{)|<%-|\{!!|th:utext|\|\s*safe\b|\{%-?\s*autoescape\s+(?:false|off)/,
    why: 'Template escape hatch renders raw HTML.', fix: 'Remove it, or sanitize the value (DOMPurify / nh3) immediately before rendering.', ref: R('xss-and-html-injection', 'spot-it') },
  { id: 'xss-angular-bypass', sev: 'high', kind: 'sink', langs: ['js'], re: /bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\(/, why: 'Disables Angular sanitization for this value.', fix: "Don't bypass; sanitize with DOMPurify if HTML is needed.", ref: XSS },
  { id: 'xss-sanitize-then-mutate', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py'], re: /(?:sanitize|clean|purify)\w*\((?:[^()\n]|\([^()\n]*\))*\)\s*\.(?:replace|replaceAll)\(/,
    why: 'Modifying HTML after sanitizing can re-create markup (verified: entity decode after DOMPurify revives <img onerror>).', fix: 'Do all transformations first; sanitize last; ship the sanitizer output unchanged.', ref: R('xss-and-html-injection', 'fixes-that-dont-hold') },
  { id: 'xss-mark-safe', sev: 'medium', kind: 'sink', langs: ['py'], re: /\b(?:mark_safe|Markup|SafeString)\(\s*(?!['"])|format_html\(\s*f['"]/, why: 'Marks a non-literal value as safe HTML (or f-string bypasses format_html escaping).', fix: 'format_html("<b>{}</b>", value); mark_safe only directly on sanitizer output.', ref: XSS },
  { id: 'xss-template-string', sev: 'high', kind: 'sink', langs: ['go'], re: /template\.(?:HTML|JS|URL|HTMLAttr)\(/, why: 'Bypasses html/template contextual escaping.', fix: 'Pass plain strings; sanitize with bluemonday if HTML is required.', ref: XSS },
  { id: 'xss-template-string', sev: 'medium', kind: 'sink', langs: ['rb'], re: /\.html_safe\b|\braw\(|<%==/, why: 'Marks a value as safe HTML.', fix: 'sanitize(html, tags:, attributes:) or plain output.', ref: XSS },
  { id: 'jinja-autoescape-off', sev: 'medium', kind: 'config', langs: ['py'], check: (line, next) => /\b(?:jinja2\.)?Environment\(/.test(line) && !/autoescape/.test(line + next) && !/class\s|def\s/.test(line),
    why: 'jinja2.Environment() defaults to autoescape=False (verified, Jinja2 3.1).', fix: 'Environment(autoescape=select_autoescape()).', ref: R('xss-and-html-injection', 'the-fix-that-holds') },
  { id: 'eval-user-input', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`\b(?:eval|new Function|setTimeout|setInterval|vm\.run\w*)\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?${USER_JS}`), why: 'User input executed as code.', fix: 'Never evaluate input; parse it (JSON.parse + schema).', ref: DESER },

  // ---------------- injection ----------------
  { id: 'sqli-raw-unsafe', sev: 'high', kind: 'sink', langs: ['js'], re: /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(|Prisma\.raw\(/, why: 'Unparameterized raw SQL.', fix: "Tagged $queryRaw`...${value}` and Prisma.sql fragments from an allowlist.", ref: SQL },
  { id: 'sqli-interpolated', sev: 'high', kind: 'sink', langs: ['js'], re: /\.(?:query|execute|raw|whereRaw|orderByRaw|havingRaw|joinRaw|selectRaw|fromRaw|unsafe)\s*\(\s*(?:\x60[^\x60]*\$\{|['"][^'"]*['"]\s*\+)|\bliteral\(\s*\x60[^\x60]*\$\{/,
    why: 'SQL built with string interpolation/concatenation.', fix: 'Parameters for values; an allowlist map for identifiers (ORDER BY, columns).', ref: SQL },
  { id: 'sqli-interpolated', sev: 'high', kind: 'sink', langs: ['py'], re: /\.(?:execute|executemany|raw|extra|executescript)\(\s*(?:f['"]|['"][^'"\n]*['"]\s*%\s*[\w(]|['"][^'"\n]*['"]\.format\(|[^,)\n]*\+\s*\w)|\b(?:text|RawSQL)\(\s*f['"]/,
    why: 'SQL built with f-strings, % formatting, .format or concatenation.', fix: 'cursor.execute(sql, params) / text(":p") with bind params.', ref: SQL },
  { id: 'sqli-interpolated', sev: 'high', kind: 'sink', langs: ['go'], re: /\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\(\s*(?:ctx,\s*)?(?:fmt\.Sprintf\(|"[^"]*"\s*\+)/, why: 'SQL built with Sprintf/concatenation.', fix: 'Placeholders ($1 / ?) with arguments.', ref: SQL },
  { id: 'sqli-interpolated', sev: 'high', kind: 'sink', langs: ['java'], re: /(?:createQuery|createNativeQuery|executeQuery|executeUpdate|prepareStatement|addBatch|execute)\(\s*"[^"]*"\s*\+/, why: 'SQL/JPQL built with concatenation.', fix: 'PreparedStatement / named parameters.', ref: SQL },
  { id: 'sqli-interpolated', sev: 'high', kind: 'sink', langs: ['php'], re: /(?:mysqli_query\([^,]+,|->query\(|->exec\(|DB::(?:select|statement|unprepared|raw)\(|whereRaw\()\s*"[^"]*\$\w|\.\s*\$_(?:GET|POST|REQUEST)\s*\.\s*["']/, why: 'SQL built with interpolated variables.', fix: 'Prepared statements / query bindings.', ref: SQL },
  { id: 'sqli-interpolated', sev: 'high', kind: 'sink', langs: ['rb'], re: /\.(?:where|order|find_by_sql|joins|group|having|pluck|select|exists\?)\(\s*"[^"]*#\{/, why: 'SQL fragment with string interpolation.', fix: 'where("x = ?", v) / hash conditions; allowlist order columns.', ref: SQL },
  { id: 'sqli-order-by-user', sev: 'medium', kind: 'sink', langs: ['py', 'js'], re: new RegExp(String.raw`order_by\(\s*${USER_PY}|orderBy\(\s*${USER_JS}`), why: 'User-chosen ordering can leak data through related fields (e.g. user__password).', fix: 'Map allowed sort keys to fields.', ref: SQL },
  { id: 'nosql-operator-injection', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|exists)\(\s*${USER_JS}\b|\$where\s*:`), why: 'Request objects used as a Mongo filter: {"$ne": null} turns equality into "anything".', fix: 'Validate types with a schema; mongoose.set("sanitizeFilter", true); never $where.', ref: R('injection', 'nosql-operator-injection') },
  { id: 'cmd-injection', sev: 'high', kind: 'sink', langs: ['js'], re: /\b(?:exec|execSync)\s*\(\s*(?:\x60[^\x60]*\$\{|[^,)\n]*\+\s*\w)|\b(?:spawn|spawnSync|execFile|execFileSync)\([^)\n]*shell\s*:\s*true/, why: 'Shell command built from variables (command injection).', fix: 'execFile/spawn with an argv array, no shell, and "--" before user values.', ref: CMD },
  { id: 'cmd-injection', sev: 'high', kind: 'sink', langs: ['py'], re: /shell\s*=\s*True|\bos\.(?:system|popen)\(|subprocess\.\w+\(\s*f['"]/, why: 'Shell command execution (command injection if any part is user-influenced).', fix: 'subprocess.run([prog, "--", arg], shell=False).', ref: CMD },
  { id: 'cmd-injection', sev: 'high', kind: 'sink', langs: ['go'], re: /exec\.Command\(\s*"(?:sh|bash|zsh|cmd|cmd\.exe|powershell)"\s*,\s*"(?:-c|\/c|-Command)"/, why: 'Shell invoked with a command string.', fix: 'exec.Command(prog, args...) without a shell.', ref: CMD },
  { id: 'cmd-injection', sev: 'high', kind: 'sink', langs: ['php'], re: /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\(\s*[^;\n]*\$_(?:GET|POST|REQUEST)|`[^`\n]*\$_(?:GET|POST|REQUEST)/, why: 'Shell command with request data.', fix: 'Avoid the shell; escapeshellarg only as a last resort.', ref: CMD },
  { id: 'cmd-injection', sev: 'high', kind: 'sink', langs: ['rb'], re: /(?:system|exec|spawn|IO\.popen|Open3\.\w+)\(\s*"[^"]*#\{|%x\{[^}]*#\{|`[^`\n]*#\{/, why: 'Shell command with interpolation.', fix: 'system(prog, arg1, arg2) argv form.', ref: CMD },
  { id: 'cmd-injection', sev: 'high', kind: 'sink', langs: ['java'], re: /Runtime\.getRuntime\(\)\.exec\(\s*(?!new String\[\])[^"\n]/, why: 'Runtime.exec with a built string.', fix: 'ProcessBuilder with a list of arguments.', ref: CMD },
  { id: 'ssti', sev: 'high', kind: 'sink', langs: ['py'], re: new RegExp(String.raw`render_template_string\(\s*(?:f['"]|${USER_PY}|[^,)\n]*\+|[^,)\n]*\.format\()|(?:Template|from_string)\(\s*(?:f['"]|${USER_PY})`), why: 'User input used as template source (server-side template injection → RCE).', fix: 'Pass input as data: render_template_string("{{ x }}", x=value).', ref: R('injection', 'server-side-template-injection') },
  { id: 'ssti', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`(?:ejs\.render|[Hh]andlebars\.compile|pug\.(?:compile|render)|nunjucks\.renderString|_\.template|Mustache\.render)\(\s*${USER_JS}`), why: 'User input used as template source.', fix: 'Fixed templates; pass input as data.', ref: R('injection', 'server-side-template-injection') },
  { id: 'csv-formula', sev: 'low', kind: 'sink', langs: ['js', 'py'], file: (s) => indexesOf(s, /text\/csv|csv\.writer\(|json2csv|papaparse\.unparse|csv-stringify/gi).slice(0, 1), why: 'CSV export: cells starting with = + - @ become formulas in spreadsheets.', fix: "Prefix those cells with a quote: v => /^[=+\\-@\\t\\r]/.test(v) ? `'${v}` : v.", ref: R('injection', 'csv--formula-injection') },

  // ---------------- prototype pollution / deserialization / regex ----------------
  { id: 'proto-merge-user-input', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`(?:merge|deepMerge|mergeDeep|extend|defaultsDeep|assignDeep|setWith|zipObjectDeep|_\.set)\s*\([^)\n]*${USER_JS}|\$\.extend\(\s*true`), why: 'Deep merge/set of request data: {"__proto__": ...} or constructor.prototype pollutes every object.', fix: 'Schema-validate, then safeMerge/safeSet (safe-merge.mjs) or Map/Object.create(null).', ref: PROTO },
  { id: 'proto-hand-rolled-merge', sev: 'medium', kind: 'naive-fix', langs: ['js'],
    file: (s) => indexesOf(s, /for\s*\(\s*(?:const|let|var)\s+(\w+)\s+(?:in|of\s+Object\.keys\(\w+\))\s*\w*\)?\s*\)?\s*\{?[\s\S]{0,240}?\[\1\]\s*=(?!=)[\s\S]{0,120}?\b(?:merge|extend|assign|deep|set)\w*\(/gi),
    why: 'Hand-rolled recursive merge: classic prototype-pollution source unless __proto__/constructor/prototype are skipped at every level.', fix: 'safeMerge from safe-merge.mjs; prove it with probe-validator.mjs proto-pollution.', ref: PROTO },
  { id: 'proto-assign-request', sev: 'medium', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`Object\.assign\(\s*\w+\s*,\s*${USER_JS}|\{\s*\.\.\.${USER_JS}\b`), why: 'Copies every request key: mass assignment (role, isAdmin, orgId) and prototype injection via own __proto__.', fix: 'Parse into an allowlisted schema (zod .strict()).', ref: AUTHZ },
  { id: 'mass-assignment', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`data\s*:\s*${USER_JS}\b\s*[,}]|\.(?:update|create|insert|save|upsert)\(\s*${USER_JS}\b\s*\)`), why: 'Whole request body written to the database (mass assignment).', fix: 'Allowlist fields with a schema; never pass req.body to the ORM.', ref: AUTHZ },
  { id: 'mass-assignment', sev: 'high', kind: 'sink', langs: ['py'], re: /fields\s*=\s*['"]__all__['"]|\*\*request\.(?:json|data|POST|form)\b|\.update\(\s*\*\*\w*(?:request|payload|body)/, why: 'All fields writable from the request (mass assignment).', fix: 'Explicit fields / separate Pydantic input model with extra="forbid".', ref: AUTHZ },
  { id: 'mass-assignment', sev: 'high', kind: 'sink', langs: ['rb'], re: /\.permit!/, why: 'permit! allows every parameter.', fix: 'params.require(:x).permit(:a, :b).', ref: AUTHZ },
  { id: 'mass-assignment', sev: 'high', kind: 'sink', langs: ['php'], re: /\$guarded\s*=\s*\[\s*\]/, why: 'Model is fully mass-assignable.', fix: '$fillable allowlist; $request->validated().', ref: AUTHZ },
  { id: 'unsafe-deserialization', sev: 'high', kind: 'sink', langs: ['py'], re: /\bpickle\.loads?\(|\bcPickle\.|\bmarshal\.loads\(|\bshelve\.open\(|jsonpickle\.decode\(|\bjoblib\.load\(|yaml\.(?:unsafe_load|load_all)\(|yaml\.load\((?![^)\n]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)|weights_only\s*=\s*False|allow_pickle\s*=\s*True|dill\.loads?\(/,
    why: 'Deserializer that can execute code (pickle/yaml Loader/torch weights_only=False).', fix: 'JSON / yaml.safe_load / safetensors / torch.load(weights_only=True).', ref: DESER },
  { id: 'unsafe-deserialization', sev: 'high', kind: 'sink', langs: ['js'], re: /['"]node-serialize['"]|\bunserialize\(/, why: 'node-serialize executes functions embedded in data.', fix: 'JSON.parse + schema.', ref: DESER },
  { id: 'unsafe-deserialization', sev: 'high', kind: 'sink', langs: ['java'], re: /new ObjectInputStream\(|enableDefaultTyping\(|activateDefaultTyping\(|@JsonTypeInfo\(\s*use\s*=\s*(?:JsonTypeInfo\.)?Id\.CLASS|new XStream\(/, why: 'Java deserialization of attacker-controlled types.', fix: 'JSON to concrete DTOs; ObjectInputFilter allowlist if unavoidable.', ref: DESER },
  { id: 'unsafe-deserialization', sev: 'high', kind: 'sink', langs: ['php'], re: /\bunserialize\((?![^)\n]*allowed_classes)/, why: 'unserialize() instantiates arbitrary classes (POP chains).', fix: "json_decode, or unserialize($s, ['allowed_classes' => false]).", ref: DESER },
  { id: 'unsafe-deserialization', sev: 'high', kind: 'sink', langs: ['rb'], re: /Marshal\.load|YAML\.unsafe_load|YAML\.load\([^)]*permitted_classes:\s*\[\s*\w/, why: 'Deserializer that instantiates arbitrary objects.', fix: 'JSON / YAML.safe_load.', ref: DESER },
  { id: 'vm-not-a-sandbox', sev: 'medium', kind: 'sink', langs: ['js'], re: /\bvm\.(?:runInNewContext|runInContext|runInThisContext|compileFunction)\(|new vm\.Script\(/, why: "Node's vm module is not a security boundary.", fix: "Don't run untrusted code; use an isolated process or a real sandbox.", ref: DESER },
  { id: 'xxe', sev: 'high', kind: 'sink', langs: ['py', 'js'], re: /resolve_entities\s*=\s*True|noent\s*:\s*true|LIBXML_NOENT/, why: 'XML parser resolves external entities (file read / SSRF). Verified: lxml resolve_entities=True leaks local files.', fix: 'defusedxml; leave entity resolution off.', ref: R('deserialization-prototype-pollution-redos', 'xml-xxe-and-entity-expansion') },
  { id: 'xxe', sev: 'medium', kind: 'config', langs: ['java'], file: (s) => (/DocumentBuilderFactory\.newInstance\(|SAXParserFactory\.newInstance\(|XMLInputFactory\.newInstance\(/.test(s) && !/disallow-doctype-decl|SUPPORT_DTD|ACCESS_EXTERNAL_DTD/.test(s) ? indexesOf(s, /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(/g) : []),
    why: 'XML factory without DTDs disabled in this file.', fix: 'setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).', ref: R('deserialization-prototype-pollution-redos', 'xml-xxe-and-entity-expansion') },
  { id: 'redos-user-regex', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`new RegExp\(\s*${USER_JS}`), why: 'User-supplied regex compiled by a backtracking engine (ReDoS).', fix: 'RE2 (re2 package) or escape the input and match literally.', ref: REDOS },
  { id: 'redos-user-regex', sev: 'high', kind: 'sink', langs: ['py'], re: new RegExp(String.raw`re\.(?:compile|match|search|fullmatch|findall|sub)\(\s*${USER_PY}`), why: 'User-supplied regex (ReDoS).', fix: 'google-re2 or re.escape().', ref: REDOS },
  { id: 'redos-nested-quantifier', sev: 'medium', kind: 'sink', langs: ['js', 'py'],
    check: (line) => /\/[^\/\n]+\/[dgimsuyv]*|RegExp\(|re\.(?:compile|match|search|fullmatch|findall|sub)\(|r['"]/.test(line) && /\((?:\?:)?(?:[^()\n\\]|\\.)*(?<!\\)[+*](?:[^()\n\\]|\\.)*\)(?:[+*]|\{\d+,\d*\})/.test(line),
    why: 'Nested quantifier like (x+)+, (\\w+\\s?)* or (x*)* backtracks exponentially on near-miss input.', fix: 'Cap input length, remove ambiguity, or use RE2. Prove it: probe-validator.mjs redos.', ref: REDOS },

  { id: 'redos-regex-html', sev: 'low', kind: 'sink', langs: ['js', 'py'], re: /(?:\.match\(|\.exec\(|re\.(?:search|match|findall)\(\s*r?['"])\s*\/?<\w+\[\^>\]\*>|\/<\w+\[\^>\]\*>\([^)]*\)<\\\//,
    why: 'Regex HTML parsing like /<title[^>]*>([^<]*)<\\/title>/ is quadratic on hostile pages (measured 3.7 s on 240 KB of "<title").', fix: 'Cap the input size first; use indexOf scanning or an HTML parser.', ref: REDOS },
  // ---------------- auth, tokens, crypto ----------------
  { id: 'jwt-decode-not-verify', sev: 'medium', kind: 'naive-fix', langs: ['js'], re: /\bjwt\.decode\(|\bjwtDecode\(|\bdecodeJwt\(/, why: 'decode() does not check the signature. Fine for reading a header before verify; never for trust decisions.', fix: 'jwt.verify / jose.jwtVerify with algorithms, issuer, audience.', ref: JWT },
  { id: 'jwt-verify-no-algorithms', sev: 'medium', kind: 'naive-fix', langs: ['js'], check: (line, next) => jwtVerifyMissingAlgorithms(line, next),
    why: 'jwt.verify without explicit algorithms/issuer/audience (jsonwebtoken does not check iss/aud or require exp unless told).', fix: 'jwt.verify(t, key, { algorithms: [...], issuer, audience }) and require exp.', ref: JWT },
  { id: 'jwt-no-verify', sev: 'high', kind: 'sink', langs: ['py', 'js'], re: /verify_signature['"]\s*:\s*False|ignoreExpiration\s*:\s*true|verify\s*=\s*False\s*\)\s*$|algorithms\s*[=:]\s*\[?\s*['"]none['"]/i, why: 'Token signature/expiry checking turned off.', fix: 'Verify signature and exp always; pin algorithms.', ref: JWT },
  { id: 'weak-random-token', sev: 'high', kind: 'sink', langs: ['js'], re: new RegExp(String.raw`${SECRETY}\w*\s*[:=][^;\n]*Math\.random\(`, 'i'), why: 'Math.random is predictable; not for secrets.', fix: "crypto.randomBytes(32).toString('base64url') (tokens.mjs randomToken).", ref: R('authn-tokens-oauth', 'reset-links-magic-links-email-verification') },
  { id: 'weak-random-token', sev: 'high', kind: 'sink', langs: ['py'], re: new RegExp(String.raw`${SECRETY}\w*\s*=[^#\n]*\brandom\.(?:random|randint|choice|choices|getrandbits|sample)\(`, 'i'), why: 'random is predictable; not for secrets.', fix: 'secrets.token_urlsafe(32).', ref: R('authn-tokens-oauth', 'reset-links-magic-links-email-verification') },
  { id: 'timing-unsafe-compare', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py'], re: /(?<!typeof\s+)(?<![.\w])\w*(?:signature|Signature|hmac|Hmac|HMAC|digest|Digest)\w*\s*(?:===|!==|==|!=)\s*(?!(?:undefined|null|None|true|false|True|False|0)\b|''|""|['"](?:string|object|number|undefined|function|boolean)['"])['"\w]/,
    why: 'Signature/HMAC compared with ==/=== (timing side channel).', fix: 'crypto.timingSafeEqual / hmac.compare_digest (verify-webhook helpers).', ref: HOOK },
  { id: 'webhook-reserialized-body', sev: 'high', kind: 'naive-fix', langs: ['js', 'py'], re: /\.update\(\s*JSON\.stringify\(|hmac\.new\([^)\n]*json\.dumps\(/, why: 'HMAC over re-serialized JSON instead of the raw request bytes: valid signatures fail, so checks get disabled.', fix: 'Verify over the raw body (express.raw / req.text() / request.body()).', ref: HOOK },
  { id: 'weak-password-hash', sev: 'high', kind: 'sink', langs: ['js', 'py'], re: /(?:createHash|hashlib\.(?:md5|sha1|sha256|sha512))\(\s*['"]?(?:md5|sha1|sha256|sha512)?['"]?\s*\)?[^\n]*\bpass(?:word|wd)\b/i, why: 'Fast hash used for passwords (offline cracking at billions/second).', fix: 'argon2id (or bcrypt/scrypt) via a password-hashing library.', ref: R('authn-tokens-oauth', 'passwords') },
  { id: 'tls-verify-off', sev: 'medium', kind: 'config', langs: ['js', 'py', 'go'], re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|CERT_NONE/, why: 'TLS certificate verification disabled (MITM).', fix: 'Fix the trust store instead of disabling verification.', ref: SSRF },

  // ---------------- CORS / CSRF / cookies / proxies ----------------
  { id: 'cors-reflect-any-origin', sev: 'high', kind: 'naive-fix', langs: ['js'], re: /cors\(\s*\{[^}]*origin\s*:\s*true|Access-Control-Allow-Origin['"]?\s*[,:]\s*(?:req|request)\.headers?(?:\.origin|\[['"]origin['"]\]|\.get\(['"]origin['"]\))|\(\s*origin\s*,\s*(?:cb|callback|done)\s*\)\s*=>\s*(?:cb|callback|done)\(\s*null\s*,\s*true\s*\)/,
    why: 'Reflects any origin; with credentials every site can read your users\' data (verified: cors({origin:true})).', fix: 'Exact Set of allowed origins.', ref: CORS },
  { id: 'cors-reflect-any-origin', sev: 'high', kind: 'naive-fix', langs: ['py'],
    file: (s) => ((/allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/.test(s) && /allow_credentials\s*=\s*True/.test(s)) || (/CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True/.test(s) && /CORS_ALLOW_CREDENTIALS\s*=\s*True/.test(s))
      ? indexesOf(s, /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True/g) : []),
    why: "allow_origins=['*'] + allow_credentials=True makes Starlette/FastAPI reflect ANY origin with credentials (verified, Starlette 1.10). Same for django-cors-headers ALLOW_ALL + CREDENTIALS.", fix: 'Exact list of origins.', ref: CORS },
  { id: 'cors-regex-origin', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py'], re: /origin\s*:\s*\[?\s*\/(?:[^\/\\\n]|\\.)+\/[gimsuy]*|CORS_ALLOWED_ORIGIN_REGEXES|allow_origin_regex\s*=/,
    why: 'Regex origin matching: missing anchors or a dot boundary admits evilexample.com or example.com.evil.net (verified for /example\\.com$/).', fix: 'Exact Set; look up dynamic custom domains by exact value.', ref: CORS },
  { id: 'cors-null-origin', sev: 'medium', kind: 'naive-fix', langs: ['js', 'py', 'php', 'rb', 'java', 'go'], re: /['"]null['"]\s*[,\]]\s*[^\n]*(?:origin|Origin|ORIGIN)|(?:origins?|ORIGINS?)\w*\s*[=:]\s*\[[^\]\n]*['"]null['"]/, why: "Allowing Origin: null lets sandboxed iframes on any site in.", fix: "Remove 'null' from the allowlist.", ref: CORS },
  { id: 'csrf-disabled', sev: 'medium', kind: 'config', langs: ['java', 'py', 'rb'], re: /csrf\(\)\.disable\(\)|csrf\s*\{\s*it\.disable\(\)\s*\}|csrf\(\s*AbstractHttpConfigurer::disable\s*\)|skip_forgery_protection|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s+:null_session/, why: 'CSRF protection disabled.', fix: 'Keep it on for cookie-authenticated routes; exempt only signature-verified webhooks.', ref: CSRF },
  { id: 'csrf-exempt', sev: 'low', kind: 'config', langs: ['py'], re: /@csrf_exempt/, why: 'CSRF exemption: fine for signature-verified webhooks, a bug for cookie-authenticated endpoints.', fix: 'Confirm the view authenticates by signature/token, not cookies.', ref: CSRF },
  { id: 'csurf-deprecated', sev: 'low', kind: 'config', langs: ['js'], re: /['"]csurf['"]/, why: 'csurf is deprecated and unmaintained.', fix: 'csrf-csrf (signed double submit) or csrf-sync.', ref: CSRF },
  { id: 'cookie-flags-off', sev: 'medium', kind: 'config', langs: ['js', 'py'], re: /\b(?:httpOnly|secure|HttpOnly|Secure)\s*:\s*false|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|httponly\s*=\s*False|secure\s*=\s*False/, why: 'Session/CSRF cookie without Secure or HttpOnly.', fix: '__Host- prefix, Secure, HttpOnly, SameSite=Lax.', ref: R('csrf-cors-cookies-sessions', 'cookies') },
  { id: 'trust-proxy-true', sev: 'medium', kind: 'config', langs: ['js', 'py'], re: /set\(\s*['"]trust proxy['"]\s*,\s*true\s*\)|forwarded.allow.ips\s*[=:]?\s*['"]?\*|--forwarded-allow-ips[= ]['"]?\*/, why: "Trusting every proxy hop lets clients set their own IP via X-Forwarded-For (verified: req.ip = attacker's value).", fix: 'Exact hop count (1) or proxy CIDRs.', ref: HTTP },
  { id: 'host-header-url', sev: 'medium', kind: 'sink', langs: ['js', 'py'], re: /\$\{\s*(?:req|request)\.(?:hostname|host|headers\.host|get\(['"]host['"]\)|headers\[['"]x-forwarded-host['"]\])|request\.(?:get_host\(\)|host_url|url_root|base_url)\s*[}+]|f['"][^'"\n]*\{request\.(?:get_host\(\)|host|base_url)/,
    why: 'Absolute URL built from the Host / X-Forwarded-Host header (password-reset poisoning, cache poisoning).', fix: 'Build links from a configured APP_URL.', ref: HTTP },
  { id: 'django-hosts-forwarded', sev: 'medium', kind: 'config', langs: ['py'], re: /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]|USE_X_FORWARDED_HOST\s*=\s*True/, why: 'Any Host header accepted / forwarded host trusted.', fix: 'Exact ALLOWED_HOSTS; USE_X_FORWARDED_HOST only if the proxy overwrites it.', ref: HTTP },
  { id: 'insecure-http-parser', sev: 'high', kind: 'config', langs: ['js'], re: /insecureHTTPParser\s*:\s*true|--insecure-http-parser/, why: 'Lenient HTTP parsing enables request smuggling.', fix: 'Remove it; fix the non-compliant client instead.', ref: R('http-layer-cache-smuggling', 'request-smuggling-and-desync') },
  { id: 'secret-in-public-env', sev: 'high', kind: 'config', langs: ['js'], re: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC)_\w*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE)\w*/, why: 'Client-exposed env prefix on a secret: it ships in the JS bundle.', fix: 'Remove the public prefix and read it server-side only.', ref: R('authn-tokens-oauth') },
  { id: 'csp-unsafe-inline-no-nonce', sev: 'low', kind: 'config', langs: ['js', 'py', 'tpl'], re: /script-src(?:(?!nonce-|strict-dynamic|sha256-|sha384-|sha512-)[^;"'\x60\n]|'(?!unsafe-inline)[^']*')*'unsafe-inline'/, why: "script-src 'unsafe-inline' without a nonce or hash gives no XSS protection.", fix: "Nonce or hash + 'strict-dynamic'.", ref: HDRS },
  { id: 'x-xss-protection-on', sev: 'low', kind: 'config', langs: ['js', 'py', 'tpl'], re: /X-XSS-Protection['"]?\s*[,:=]\s*['"]1/i, why: 'Obsolete header; "1; mode=block" created XS-Leaks in old browsers.', fix: 'Send 0 or omit; rely on CSP.', ref: R('browser-isolation-and-headers', 'obsolete-headers') },
];

// ---------------------------------------------------------------------------

const LANG_BY_EXT = {
  '.js': ['js'], '.mjs': ['js'], '.cjs': ['js'], '.jsx': ['js'], '.ts': ['js'], '.tsx': ['js'], '.mts': ['js'], '.cts': ['js'],
  '.vue': ['js', 'tpl'], '.svelte': ['js', 'tpl'], '.astro': ['js', 'tpl'],
  '.py': ['py'], '.go': ['go'], '.java': ['java'], '.kt': ['java'], '.kts': ['java'],
  '.php': ['php'], '.rb': ['rb'], '.rake': ['rb'], '.erb': ['rb', 'tpl'],
  '.html': ['tpl'], '.htm': ['tpl'], '.ejs': ['tpl'], '.hbs': ['tpl'], '.handlebars': ['tpl'], '.mustache': ['tpl'],
  '.njk': ['tpl'], '.jinja': ['tpl'], '.jinja2': ['tpl'], '.j2': ['tpl'], '.twig': ['tpl'], '.liquid': ['tpl'],
};
const SKIP_DIRS = new Set(['third_party', 'thirdparty', 'external', 'node_modules', 'dist', 'build', 'out', 'coverage', 'vendor', 'venv', 'env', '__pycache__', 'site-packages', 'target', 'bin', 'obj', 'bower_components', 'jspm_packages', 'Pods', 'DerivedData', 'storybook-static']);
const TEST_DIRS = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'e2e', 'cypress', 'playwright', '__mocks__', 'fixtures', 'testdata', 'mocks']);
const TEST_FILE = /(?:\.(?:test|spec|e2e|stories)\.[a-z]+$|^test_.*\.py$|^tests?\.py$|^conftest\.py$|_test\.(?:py|go)$|_spec\.rb$|Test\.(?:java|kt)$)/;
// config rules don't fire in dev/local/test settings files
const DEV_CONFIG_FILE = /(?:^|[\/_.-])(?:dev|development|local|test|testing|ci)\.(?:py|js|ts|mjs|cjs)$/;
const COMMENT = { js: /^\s*(?:\/\/|\*|\/\*)/, java: /^\s*(?:\/\/|\*|\/\*)/, go: /^\s*\/\//, php: /^\s*(?:\/\/|#|\*|\/\*)/, py: /^\s*#/, rb: /^\s*#/, tpl: /^\s*(?:<!--|\{#|\{\{!--)/ };

// indexes of `target` matches that come after a `check` match within `maxLines` lines
function near(src, check, target, maxLines) {
  const checks = indexesOf(src, check);
  if (!checks.length) return [];
  const lineAt = (i) => src.slice(0, i).split('\n').length;
  const checkLines = checks.map(lineAt);
  return indexesOf(src, target).filter((t) => { const tl = lineAt(t); return checkLines.some((cl) => tl >= cl && tl - cl <= maxLines); });
}

// jwt.verify(token, key) or jwt.verify(token, key, { ...no algorithms... }) → flag.
// jwt.verify(token, key, OPTIONS_VAR) → can't see the options from here; don't flag.
function jwtVerifyMissingAlgorithms(line, next) {
  const start = line.search(/\bjwt\.verify\(/);
  if (start === -1) return false;
  const text = (line.slice(start) + ' ' + next).slice('jwt.verify('.length - 1);
  let depth = 0;
  const args = [''];
  for (const ch of text) {
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) depth--;
    if (depth === 0) break;
    if (ch === ',' && depth === 1) { args.push(''); continue; }
    args[args.length - 1] += ch;
  }
  args[0] = args[0].replace(/^\(/, '');
  if (args.length < 3) return true;
  const opts = args[2].trim();
  return opts.startsWith('{') && !/algorithms/.test(opts);
}

function indexesOf(src, re) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(src))) { out.push(m.index); if (m.index === re.lastIndex) re.lastIndex++; }
  return out;
}

function langsFor(file) {
  const base = path.basename(file).toLowerCase();
  if (base.endsWith('.blade.php')) return ['php', 'tpl'];
  if (base.endsWith('.min.js') || base.endsWith('.bundle.js') || base.endsWith('.d.ts')) return [];
  return LANG_BY_EXT[path.extname(base)] || [];
}

function walk(dir, opts, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
      if (!opts.includeTests && TEST_DIRS.has(e.name)) continue;
      walk(full, opts, out);
    } else if (e.isFile()) {
      if (!opts.includeTests && TEST_FILE.test(e.name)) continue;
      const langs = langsFor(full);
      if (langs.length) out.push({ file: full, langs });
    }
  }
}

const SEV_ORDER = { high: 0, medium: 1, low: 2 };

export function scan(root, opts = {}) {
  const files = [];
  const stat = fs.statSync(root);
  if (stat.isFile()) files.push({ file: root, langs: langsFor(root) });
  else walk(root, opts, files);
  const ruleFilter = opts.rules ? new Set(opts.rules) : null;
  const minSev = opts.severity ? SEV_ORDER[opts.severity] : 2;
  const rootDir = stat.isFile() ? path.dirname(root) : root;
  const displayPath = (file) => { const rel = path.relative(process.cwd(), file); return rel.startsWith('..') ? path.relative(rootDir, file) || path.basename(file) : rel; };
  const rules = RULES.filter((r) => (!ruleFilter || ruleFilter.has(r.id)) && SEV_ORDER[r.sev] <= minSev);
  const findings = [];
  const seen = new Set();
  const counts = {};
  for (const { file, langs } of files) {
    let src;
    try {
      if (fs.statSync(file).size > 1_500_000) continue;
      src = fs.readFileSync(file, 'utf8');
    } catch { continue; }
    const lines = src.split('\n');
    if (src.length / lines.length > 200) continue; // minified or generated
    for (const l of langs) counts[l] = (counts[l] || 0) + 1;
    const devConfig = DEV_CONFIG_FILE.test(file);
    const lineStarts = [0];
    for (let i = 0; i < src.length; i++) if (src[i] === '\n') lineStarts.push(i + 1);
    const lineOf = (idx) => { let lo = 0, hi = lineStarts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1; } return lo; };
    const suppressed = (i, id) => [lines[i], lines[i - 1] || ''].some((l) => {
      const m = l.match(/websec-ignore(?::([a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*))?/);
      return m && (!m[1] || m[1].split(',').includes(id));
    });
    const stripComment = (l) => (langs.some((lg) => lg === 'py' || lg === 'rb') ? l.replace(/\s+#\s.*$/, '') : l.replace(/\s+\/\/\s.*$/, '').replace(/\{\/\*.*?\*\/\}/g, '').replace(/<!--.*?-->/g, ''));
    // Python triple-quoted blocks (docstrings) are prose, not code
    const inDocstring = new Set();
    if (langs.includes('py')) {
      let open = null;
      lines.forEach((l, i) => {
        if (open) { inDocstring.add(i); if (l.includes(open)) open = null; return; }
        const m = l.match(/^\s*[rubfRUBF]{0,2}("{3}|'{3})/);
        if (m && l.split(m[1]).length === 2) { open = m[1]; inDocstring.add(i); }
        else if (m) inDocstring.add(i); // one-line docstring
      });
    }
    const isComment = (i) => inDocstring.has(i) || langs.some((lg) => COMMENT[lg] && COMMENT[lg].test(lines[i]));
    const add = (rule, i) => {
      if (i < 0 || i >= lines.length || lines[i].length > 800 || isComment(i) || suppressed(i, rule.id)) return;
      const key = `${rule.id}|${file}|${i}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({ rule: rule.id, severity: rule.sev, kind: rule.kind, file: displayPath(file), path: file, line: i + 1, code: lines[i].trim().slice(0, 160), why: rule.why, fix: rule.fix, ref: rule.ref });
    };
    for (const rule of rules) {
      if (!rule.langs.some((l) => langs.includes(l))) continue;
      if (devConfig && rule.kind === 'config') continue;
      if (rule.file) { for (const idx of rule.file(src)) add(rule, lineOf(idx)); continue; }
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 800) continue;
        const code = stripComment(line);
        if (rule.check ? rule.check(code, lines.slice(i + 1, i + 6).map(stripComment).join(' ')) : rule.re.test(code)) add(rule, i);
      }
    }
  }
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.rule.localeCompare(b.rule) || a.file.localeCompare(b.file) || a.line - b.line);
  return { root, files: files.length, byLanguage: counts, rules: rules.length, findings };
}

function report(result) {
  const { findings } = result;
  const n = (s) => findings.filter((f) => f.severity === s).length;
  const out = [];
  out.push(`# bypass-proof-security scan: ${result.root}`);
  out.push(`Scanned ${result.files} files (${Object.entries(result.byLanguage).map(([k, v]) => `${k}: ${v}`).join(', ') || 'none'}) · ${new Set(RULES.map((r) => r.id)).size} rules · findings: 🔴 ${n('high')} high, 🟠 ${n('medium')} medium, ⚪ ${n('low')} low`);
  out.push('Candidates, not verdicts: confirm each location. Naive-fix findings mean a fix exists but probably does not hold.\n');
  for (const sev of ['high', 'medium', 'low']) {
    const group = findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    out.push(`## ${sev === 'high' ? '🔴 High' : sev === 'medium' ? '🟠 Medium' : '⚪ Low'}`);
    const byRule = new Map();
    for (const f of group) { if (!byRule.has(f.rule)) byRule.set(f.rule, []); byRule.get(f.rule).push(f); }
    for (const [rule, list] of byRule) {
      const f0 = list[0];
      out.push(`\n### ${rule}${f0.kind === 'naive-fix' ? ' (fix that does not hold)' : ''} · ${list.length}`);
      out.push(`Why: ${f0.why}\nFix: ${f0.fix}\nSee: ${f0.ref}`);
      for (const f of list.slice(0, 25)) out.push(`- \`${f.file}:${f.line}\`  \`${f.code.replace(/`/g, "'")}\``);
      if (list.length > 25) out.push(`- …and ${list.length - 25} more (use --json for all)`);
    }
    out.push('');
  }
  if (!findings.length) out.push('No findings. A clean scan is not proof of security: the scanner only sees patterns. Review authorization logic and data flows by hand.');
  return out.join('\n');
}

function main() {
  const argv = process.argv.slice(2);
  const opts = { includeTests: argv.includes('--include-tests') };
  const ri = argv.indexOf('--rule');
  if (ri !== -1) opts.rules = argv[ri + 1].split(',');
  const si = argv.indexOf('--severity');
  if (si !== -1) opts.severity = argv[si + 1];
  if (argv.includes('--list-rules')) {
    const ids = new Map();
    for (const r of RULES) { const k = r.id; if (!ids.has(k)) ids.set(k, { sev: r.sev, kind: r.kind, langs: new Set(), why: r.why }); r.langs.forEach((l) => ids.get(k).langs.add(l)); }
    for (const [id, v] of ids) console.log(`${v.sev.padEnd(6)} ${v.kind.padEnd(9)} ${id.padEnd(30)} [${[...v.langs].join(',')}] ${v.why.slice(0, 90)}`);
    return;
  }
  const valueArgs = new Set([ri + 1, si + 1].filter((i) => i > 0));
  const dir = argv.find((a, i) => !a.startsWith('--') && !valueArgs.has(i)) || '.';
  const result = scan(path.resolve(dir), opts);
  result.root = dir;
  if (argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else console.log(report(result));
  if (argv.includes('--strict') && result.findings.some((f) => f.severity !== 'low')) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) main();
