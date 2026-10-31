# XSS and HTML injection

Covers user content rendered as HTML (comments, profiles, rich text, Markdown), values interpolated into templates, attributes, URLs, inline scripts and JSON, and DOM APIs that take strings.

## Contents
- [Spot it](#spot-it)
- [Context decides the encoder](#context-decides-the-encoder)
- [Fixes that don't hold](#fixes-that-dont-hold)
- [The fix that holds](#the-fix-that-holds)
- [Rendering user HTML and Markdown](#rendering-user-html-and-markdown)
- [JSON inside script tags](#json-inside-script-tags)
- [Defense in depth: CSP and Trusted Types](#defense-in-depth-csp-and-trusted-types)
- [Regression tests](#regression-tests)

## Spot it

Framework escape hatches are where XSS lives in modern apps:

```bash
grep -rnE "dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrust|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write|\.html\(|srcdoc|new Function|setTimeout\(\s*['\"\`]|eval\(" --include=*.{js,jsx,ts,tsx,vue,svelte,html} .
grep -rnE "\|\s*safe\b|mark_safe\(|format_html\(|SafeString|Markup\(|autoescape\s+(false|off)|\{\{\{|\{!!|html_safe|raw\(|<%==|template\.HTML\(|@Html\.Raw|th:utext|\{@html" .
```

`{@html}` is Svelte, `{{{ }}}` Handlebars and Mustache, `{!! !!}` Laravel Blade, `<%==`/`html_safe`/`raw` Rails, `template.HTML` Go, `@Html.Raw` Razor, `th:utext` Thymeleaf.

## Context decides the encoder

HTML-escaping is correct for exactly one context. Using it elsewhere is the most common "fixed but still vulnerable" XSS.

| Where the value lands | Correct handling | HTML-escape alone? |
|---|---|---|
| Element text: `<p>{x}</p>` | HTML-escape `& < > " '` (framework auto-escape) | ✅ |
| Quoted attribute: `<div title="{x}">` | HTML-escape including both quotes | ✅ if quotes are escaped |
| Unquoted attribute: `<div title={x}>` | Quote the attribute | ❌ space or `>` breaks out |
| URL attribute: `href`, `src`, `action`, `formaction` | Parse; allow only `https:`/`http:`/`mailto:` (or relative), then attribute-escape | ❌ `javascript:alert(1)` has nothing to escape |
| Event handler: `onclick="f('{x}')"` | Don't. Use `addEventListener` and `data-*` attributes | ❌ the HTML parser decodes `&#39;` back to `'` before JS runs |
| Inside `<script>`: `var x = '{x}'` | Don't. Put JSON in a data block (see below) | ❌ `</script>` ends the block |
| CSS: `style="color: {x}"` | Allowlist values (e.g. a hex color regex) | ❌ |
| DOM: `el.innerHTML = x` | `el.textContent = x`, or sanitize and use Trusted Types | n/a |

## Fixes that don't hold

| Fix | Breaks on | Why |
|---|---|---|
| Strip `<script>` with a regex | `<img src=x onerror=alert(1)>`, `<scr<script>ipt>` | Dozens of elements and attributes execute script. Blocklists can't enumerate them. |
| HTML-escape, then put the value in `href` | `javascript:alert(1)` | No special characters to escape. Check the scheme. |
| HTML-escape inside an inline handler | `');alert(1)//` | The HTML parser decodes entities before the JS engine runs. |
| `JSON.stringify(data)` inside `<script>` | `{"name":"</script><script>alert(1)</script>"}` | The HTML tokenizer ends the script at `</script>`, whatever JSON thinks. |
| Sanitize, then modify the HTML (decode entities, regex replace, string-concat into a template, re-parse with a different parser) | Entity-encoded payloads that the sanitizer saw as text | The output you ship isn't the output you sanitized. **Sanitize last.** Verified with DOMPurify 3.4: decoding entities after sanitizing turns `&lt;img onerror&gt;` into live markup. |
| Sanitize once on input, store, render anywhere | The same value later lands in an attribute, a JS string, an email, or a PDF | Sanitizing depends on the output context. Store the raw value and encode or sanitize at output. |
| `sanitize-html` / DOMPurify with `style`, `svg`, `math`, or `iframe` allowed "for embeds" | `<svg><animate onbegin=...>`, CSS `url()` exfiltration | Every allowed tag and attribute widens the attack surface. Allow the minimum. |
| `encodeURIComponent(x)` in `href` | `javascript:alert(1)` survives if it's the whole URL | Encoding a component doesn't validate the scheme. |
| Escape `<` and `>` only | `" onmouseover=alert(1) x="` in a quoted attribute | Escape quotes too. |
| Python `bleach` | Deprecated since January 2023 (html5lib unmaintained) | Use `nh3` (Rust ammonia bindings). |

## The fix that holds

1. **Let the framework escape.** React, Vue, Angular, Svelte, Jinja2 (when autoescape is on), Django, Rails, Blade `{{ }}`, Go `html/template`, Razor, and Thymeleaf `th:text` all escape by default. The fix is usually to **delete the escape hatch**.
2. Autoescape configuration traps (verified on Jinja2 3.1, Flask 3.1, and Starlette 1.10):
   - Bare `jinja2.Environment()` has `autoescape=False`. Use `autoescape=select_autoescape()`.
   - Flask autoescapes `.html`, `.htm`, `.xml`, `.xhtml`, and `.svg` templates, and `render_template_string`. It doesn't autoescape a `.txt` or `.j2` template rendered as HTML.
   - Starlette/FastAPI `Jinja2Templates` uses `select_autoescape()`, so it goes by extension.
3. **URL attributes:** validate the scheme on the parsed URL (see `safeHref` in `redirects-and-url-parsing.md`).
4. **Need user HTML?** Sanitize with an allowlist, at output, as the last step (next section).
5. **Add CSP and Trusted Types** so the bug you missed doesn't execute.

## Rendering user HTML and Markdown

**Node (browser or server):** DOMPurify 3.x. Server-side it needs a DOM: `jsdom`, or `isomorphic-dompurify`.

```js
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
const DOMPurify = createDOMPurify(new JSDOM('').window);   // once, module scope (server)

const clean = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'code', 'pre', 'blockquote', 'h2', 'h3'],
  ALLOWED_ATTR: ['href', 'title'],
  ALLOWED_URI_REGEXP: /^(?:https?:|mailto:|\/(?!\/)|#)/i,
});
// then hand `clean` to the DOM unchanged: no replace(), no template concatenation, no re-parse with another parser
```

```jsx
// React
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.html, CONFIG) }} />
```

DOMPurify's default config passes this skill's whole corpus, including the mutation-XSS cases (tested with 3.4 and jsdom). The allowlist above is tighter. Keep DOMPurify updated: its mXSS fixes ship as patch releases.

Links that open in new tabs: add `rel="noopener noreferrer"` with a DOMPurify `afterSanitizeAttributes` hook. Modern browsers imply `noopener` for `target=_blank`, but `noreferrer` still matters for privacy.

**Markdown:**
- `markdown-it` with `html: false` (the default) escapes raw HTML and blocks `javascript:`, `vbscript:`, `file:`, and most `data:` links via `validateLink`. Still run the output through DOMPurify if plugins are enabled.
- `marked` does **not** sanitize its output. Always `DOMPurify.sanitize(marked.parse(md))`.
- `react-markdown` doesn't render raw HTML unless you add `rehype-raw`. If you do, add `rehype-sanitize` after it.

**Python:** `nh3` (pip install nh3):

```python
import nh3
clean = nh3.clean(
    dirty,
    tags={"p", "br", "b", "i", "em", "strong", "a", "ul", "ol", "li", "code", "pre", "blockquote"},
    attributes={"a": {"href", "title"}},
    url_schemes={"http", "https", "mailto"},
    link_rel="noopener noreferrer",
)
```

Django: render `clean` with `mark_safe(clean)` only right after sanitizing, in the same function. Never `mark_safe` a value that came from the DB or a request without sanitizing it in that call. For building HTML from parts, use `format_html("<a href='{}'>{}</a>", url, text)`, which escapes the arguments. `mark_safe(f"...{x}...")` doesn't.

**Other stacks:**
- Ruby: `Rails::HTML5::SafeListSanitizer` (`sanitize(html, tags: [...], attributes: [...])`).
- Go: `bluemonday.UGCPolicy()`, or a stricter custom policy.
- Java: OWASP Java HTML Sanitizer (`HtmlPolicyBuilder`).
- PHP: `HTMLPurifier`, or `symfony/html-sanitizer`.

## JSON inside script tags

Escape `<`, `>`, and `&` (and U+2028/U+2029 for old engines) so the HTML tokenizer can't see a closing tag:

```js
// Node / Next.js JSON-LD, hydration data
const safeJson = JSON.stringify(data).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026')
  .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJson }} />
```

- Django: `{{ data|json_script:"page-data" }}`, then `JSON.parse(document.getElementById('page-data').textContent)`.
- Jinja2: `{{ data|tojson }}` (HTML-safe escaping built in).
- Rails: `json_escape(data.to_json)`.
- Go `html/template`: escapes contextually inside `<script>`.

## Defense in depth: CSP and Trusted Types

A strict CSP (nonces or hashes plus `'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`) stops injected markup from running script even when an escape fails. Trusted Types (Baseline since February 2026: Chrome/Edge 83, Safari 26, Firefox 148) makes `innerHTML = string` a TypeError unless the string went through a named policy. That turns "we forgot to sanitize" into a crash you see in development. Rollout steps are in `browser-isolation-and-headers.md`.

## Regression tests

```bash
node <skill-dir>/scripts/probe-validator.mjs xss src/lib/sanitize.ts sanitizeComment
```

- The oracle looks for script elements, `on*` handlers, script URLs in URL attributes, `srcdoc`, `<base>`, and meta refresh in your output.
- If `jsdom` or `linkedom` resolves from the project, the probe also parses, serializes, and re-parses the output to catch mutation XSS.
- Legit entries make sure bold, links, and lists survive.

For template escape-hatch fixes, add a rendering test that puts `"><img src=x onerror=alert(1)>` through the real view and asserts the response contains `&lt;img` and no `<img src=x`.
