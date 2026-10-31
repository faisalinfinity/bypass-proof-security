# Parsing untrusted data: prototype pollution, deserialization, XXE, ReDoS

The bug class where "just parsing" the input is already dangerous.

## Contents
- [Prototype pollution (JavaScript)](#prototype-pollution-javascript)
- [Class pollution (Python)](#class-pollution-python)
- [Unsafe deserialization](#unsafe-deserialization)
- [XML: XXE and entity expansion](#xml-xxe-and-entity-expansion)
- [ReDoS](#redos)
- [Regression tests](#regression-tests)

## Prototype pollution (JavaScript)

`JSON.parse('{"__proto__": {"isAdmin": true}}')` creates an **own** property named `__proto__`. A recursive merge or set-by-path then writes through it to `Object.prototype`, and every object in the process inherits `isAdmin`. Known gadgets turn pollution into RCE:
- `child_process` options (`shell`, `env.NODE_OPTIONS`)
- template engine options (EJS `outputFunctionName`, Handlebars/Pug compile options)
- `res.render` locals

### Spot it

```bash
grep -rnE "function (deepMerge|merge|extend|assignDeep|setPath|set)\b|\[key\]\s*=\s*.*\[key\]|for \(const key in|_\.(merge|defaultsDeep|set|setWith)\(|\\\$\.extend\(true|Object\.assign\(\{\},\s*req\.|qs\.parse\(.*allowPrototypes" --include=*.{js,ts,mjs} .
```

### Fixes that don't hold (all fail the `proto-pollution` corpus)

| Fix | Breaks on |
|---|---|
| Skip the key `__proto__` | `{"constructor": {"prototype": {"x": 1}}}` reaches the same object |
| Filter only top-level keys | `{"a": {"__proto__": {...}}}` |
| `if (key in target)` / `target[key] \|\| {}` | `in` and `\|\|` see inherited properties, so the merge walks into prototypes |
| `Object.freeze(Object.prototype)` | Breaks libraries that patch prototypes (polyfills), doesn't cover other prototypes, and still allows prototype *injection* on the target |
| `Object.assign({}, userJson)` "it's shallow, so safe" | Assigning an own `__proto__` key calls the setter: the result's prototype becomes attacker-controlled (no global pollution, but `result.isAdmin` is inherited) |

### The fix that holds

1. **Validate the shape** with a schema before using the data (zod, valibot, ajv with `removeAdditional`). Unknown keys get stripped or rejected, and that includes `__proto__`.
2. **Merge or set with `assets/fixes/node/safe-merge.mjs`**:
   - `safeMerge` skips `__proto__`, `constructor`, and `prototype` at every level, and recurses only into the target's own plain objects.
   - `safeSet` throws on those path segments.
   - `safeJsonParse` drops them while parsing.
3. **Dictionaries keyed by user input:** use `new Map()` or `Object.create(null)`. Check with `Object.hasOwn(obj, key)`, not `key in obj` or `obj[key]`.
4. **Libraries:** keep lodash ≥ 4.17.21 (`merge`, `set`, `zipObjectDeep` fixes). Keep `qs` with the default `allowPrototypes: false`. Audit any hand-written `deepMerge` utility, which is the most common source.
5. **Process-wide hardening:** `node --disable-proto=delete` removes the `Object.prototype.__proto__` accessor (verified on Node 22). Test your dependencies first; `Object.getPrototypeOf`/`setPrototypeOf` keep working.

## Class pollution (Python)

The Python equivalent: recursive "update object from dict" helpers that call `setattr`/`getattr` with user keys can reach `__class__`, `__init__.__globals__`, and from there module globals and config (`{"__class__": {"__init__": {"__globals__": {"SECRET_KEY": "x"}}}}`).
- Never `setattr(obj, key, value)` with keys from input. Map input to fields through a Pydantic model or dataclass with explicit fields.
- Reject keys starting with `_` in any generic merge utility. Watch `pydash.set_`, custom `update_from_dict`, and similar.

## Unsafe deserialization

These formats run code or build arbitrary objects **while parsing**. Never feed them data an attacker can influence: request bodies, cookies, uploads, cache entries an attacker can write, queue messages from less-trusted producers, or downloaded model files.

| Stack | Dangerous | Use instead |
|---|---|---|
| Python | `pickle.loads`, `marshal`, `shelve`, `jsonpickle.decode`, `numpy.load(allow_pickle=True)`, `joblib.load`, `torch.load(weights_only=False)` | JSON, msgpack, protobuf; `safetensors` for model weights; `torch.load(..., weights_only=True)` (the default since PyTorch 2.6) |
| Python YAML | `yaml.load(s, Loader=yaml.Loader / UnsafeLoader / FullLoader)` | `yaml.safe_load` (verified: `UnsafeLoader` executes `!!python/object/apply`; PyYAML 6 requires a Loader argument) |
| Node | `node-serialize.unserialize`, `eval`/`new Function`/`vm.runIn*` on data (`vm` is **not** a sandbox), `serialize-javascript` output passed to `eval` | `JSON.parse` + schema validation |
| Java | `ObjectInputStream.readObject`, XStream without allowlist, Jackson `enableDefaultTyping` / `@JsonTypeInfo(use = Id.CLASS)`, SnakeYAML `new Yaml()` before 2.0 | JSON to concrete DTOs; if `ObjectInputStream` is unavoidable, a strict `ObjectInputFilter` allowlist |
| PHP | `unserialize($userData)`; file functions on `phar://` paths (PHP < 8.0 deserializes phar metadata) | `json_decode`; if needed, `unserialize($s, ['allowed_classes' => false])` |
| Ruby | `Marshal.load`, `YAML.unsafe_load` (`YAML.load` is safe since Psych 4) | JSON, `YAML.safe_load` |
| .NET | `BinaryFormatter` (removed in .NET 9), `NetDataContractSerializer`, `TypeNameHandling` not `None` in Json.NET | `System.Text.Json` |

Signed data isn't safe data: a signed pickle cookie is RCE for anyone who learns the key. Use JSON inside signed cookies.

## XML: XXE and entity expansion

DTDs let an XML document read local files (`<!ENTITY x SYSTEM "file:///etc/passwd">`), make requests (SSRF), or expand entities exponentially (billion laughs). XML hides in DOCX, XLSX, SVG, SAML, SOAP, RSS, and sitemaps.

Verified on lxml 6.1 / expat 2.8:
- `lxml` default parser: external entities are **not** resolved (`resolve_entities='internal'` since lxml 5). Passing `XMLParser(resolve_entities=True)` **leaks local files**.
- Python stdlib `xml.etree`: refuses external entities, and expat ≥ 2.4 limits amplification.
- `defusedxml`: refuses entity declarations outright. Use it for anything untrusted, including SAML.

Other stacks:
- Java `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, plus `XMLConstants.FEATURE_SECURE_PROCESSING`.
- .NET: `DtdProcessing = DtdProcessing.Prohibit` (the default in modern `XmlReaderSettings`; check older code).
- Node: `libxmljs` with `noent: true` resolves entities, so leave it off. `fast-xml-parser` doesn't fetch external entities.
- PHP 8: external entity loading is off by default. Never pass `LIBXML_NOENT` with untrusted XML.

## ReDoS

A regex with nested or overlapping quantifiers (`(a+)+`, `(\w+\s?)*`, `(a|aa)+`, `^([a-z0-9]+\.)+[a-z]+$`) backtracks exponentially on a near-miss input. One 30-character request can pin a CPU core. Node's single event loop means one request stalls every user.

### Fixes that don't hold

- "We only use well-known regexes": many published email and URL regexes are vulnerable. Test them.
- Timeouts around `regex.test()` in Node: the call is synchronous, so a timer can't interrupt it.
- Rewriting the regex by intuition without testing it against pump strings.
- Regex "parsing" of fetched or uploaded HTML: `/<title[^>]*>([^<]*)<\/title>/i` looks harmless, but it's **quadratic** on a page made of repeated `<title` (measured: 3.7 s of CPU for 240 KB). Any server that fetches attacker-chosen pages (link previews, scrapers) is exposed. Cap the input first, then use `indexOf`-style scanning or a real HTML parser (parse5, htmlparser2, `html.parser`).

### The fix that holds

1. **Cap the input length before matching** (emails ≤ 254 chars, slugs ≤ 100). It's cheap and turns exponential into bounded.
2. **Remove ambiguity:** each character should be matchable in only one way. Prefer `^\w+(?:\s\w+)*$` over `^(\w+\s?)*$`, use explicit separators, and avoid nested quantifiers.
3. **Use a linear-time engine** for anything user-supplied or complex:
   - Node: the `re2` package.
   - Python: `google-re2` (`import re2`). Python 3.11+ `re` also supports atomic groups `(?>...)` and possessive quantifiers `a++` to cut backtracking.
   - Go and Rust `regex` are linear already.
4. **Never compile user-supplied regexes** with a backtracking engine (search filters, "advanced match" rules). Use RE2, or escape the input and match it literally.
5. **Patch** routing and validation dependencies: path-to-regexp CVE-2024-45296 (fixed in 0.1.10 / 8.x; Express 5 uses 8.x), plus `validator`, `ua-parser-js`, and `semver` advisories.

## Regression tests

```bash
node <skill-dir>/scripts/probe-validator.mjs proto-pollution src/utils/merge.ts deepMerge            # fn(target, source)
node <skill-dir>/scripts/probe-validator.mjs proto-pollution src/utils/path.ts setByPath --mode set  # fn(obj, path, value)
node <skill-dir>/scripts/probe-validator.mjs redos src/validators.ts isValidEmail                    # worker + hard timeout
```

- The proto probe reports both global pollution (`Object.prototype` changed) and prototype injection (an object in the result got an attacker-controlled prototype), then cleans up.
- The ReDoS probe runs 12 pump families at growing sizes in a worker it can kill. A vulnerable `^(\w+\s?)*$` hangs at 32 characters; the linear rewrite stays under 1 ms at 20,000.
- Deserialization and XXE: add a test that feeds the dangerous payload (`!!python/object/apply:os.getcwd []`, an external-entity DOCTYPE) and asserts a rejection.
