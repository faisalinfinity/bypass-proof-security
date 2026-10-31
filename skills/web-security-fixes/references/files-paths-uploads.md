# Files: path traversal, archives, uploads, serving user content

## Contents
- [Path traversal](#path-traversal)
- [Archives: zip slip and bombs](#archives-zip-slip-and-bombs)
- [Uploads](#uploads)
- [Serving user files](#serving-user-files)
- [Regression tests](#regression-tests)

## Path traversal

### Spot it

```bash
grep -rnE "(readFile|createReadStream|sendFile|download|unlink|rm|writeFile|open|send_file|FileResponse|os\.path\.join|Path\(|File\.read|file_get_contents|include|require)\s*\(.*(req\.|request\.|params|query|body|filename|name|path)" .
```

### Fixes that don't hold

Verified by the `path` corpus. Each of these lets at least one attack through:

| Fix | Breaks on |
|---|---|
| `p.replace('../', '')` or `replace(/\.\.\//g, '')` | `....//....//etc/passwd` becomes `../../etc/passwd` after the replace |
| `resolved.startsWith(base)` (Node) / `str(resolved).startswith(str(base))` (Python) | `../uploads_evil/secret`: the sibling directory shares the prefix |
| `path.join(base, p)` with no check | `../../etc/passwd` |
| Python `os.path.join(base, p)` | `p = "/etc/passwd"`: an absolute second argument **discards** base |
| `if '..' in p: reject` | Also rejects the legit `report..v2.pdf`. Encoded `..%2f` decoded later gets through. On Windows, `..\\` |
| Check, then `decodeURIComponent` / `unquote` | `..%2f..%2fetc%2fpasswd` passes the check and decodes into traversal |
| Lexical check only, in a directory users can write symlinks into | `uploads/link -> /` then `link/etc/passwd` |

### The fix that holds

1. **Don't use user input as a path.** Store files under generated IDs (`crypto.randomUUID()`), look the ID up in the DB (scoped to the user, see `authorization-idor-mass-assignment.md`), and use the stored path.
2. If a name must map to a file: decode fully, then resolve, then compare by **path components**, and reject the base itself.

```js
import { resolveInside, realpathInside } from './lib/safe-path.mjs';     // assets/fixes/node/safe-path.mjs
const file = resolveInside(DOCS_DIR, req.params.name);                    // throws PathTraversalError (code ERR_PATH_TRAVERSAL)
const file2 = await realpathInside(UPLOADS_DIR, req.params.name);        // also follows symlinks
// Express: sendFile with `root` refuses '..' itself (403); don't pass an absolute user-built path
res.sendFile(req.params.name, { root: DOCS_DIR, dotfiles: 'deny' });
```

```python
from safe_path import resolve_inside        # assets/fixes/python/safe_path.py: resolve() + is_relative_to
return FileResponse(resolve_inside(DOCS_DIR, filename))
# Flask: send_from_directory(DOCS_DIR, filename) uses werkzeug.safe_join and is fine for reads
```

Other stacks: Java `base.resolve(p).normalize()` then `startsWith(base)` on `Path` objects (component-wise, unlike `String.startsWith`), and `toRealPath()` for symlinks. Go 1.24+ `os.Root` (`root.Open(name)` can't escape, even through symlinks); on older Go, `filepath.IsLocal(name)` before `filepath.Join`. PHP `realpath()` then `str_starts_with($real, $base . DIRECTORY_SEPARATOR)`.

**nginx `alias` off-by-slash:** `location /static { alias /srv/static/; }` serves `/static../app/.env` as `/srv/app/.env`. Make both sides end in `/` (`location /static/ { alias /srv/static/; }`), or use `root`.

## Archives: zip slip and bombs

Extracting an archive writes attacker-chosen paths: `../../app/server.js`, absolute paths, symlink entries pointing outside, and hard links.

- **Python tarfile:** pass `filter="data"` (Python 3.12+, plus security backports to 3.8.17, 3.9.17, 3.10.12, and 3.11.4). Verified: a default `extractall()` on **3.13 writes `../` entries outside the destination**, with only a DeprecationWarning. 3.14 blocks it by default. Older interpreters: check every member yourself and refuse links.

  ```python
  with tarfile.open(upload) as tar:
      tar.extractall(dest, filter="data")   # rejects absolute paths, '..', links outside, device files; strips setuid
  ```

- **Python zipfile:** `extract`/`extractall` drop `..` and absolute components, but still check sizes (below).
- **Node:** most zip libraries return raw entry names. For each entry: `const target = resolveInside(dest, entry.fileName)`, skip symlink entries (check the external attributes), then write. `yauzl` rejects absolute and `..` entry names by default (`decodeStrings: true`, so don't turn that off). Still apply `resolveInside`.
- **Java:** `ZipEntry.getName()` is attacker-controlled. Do `dest.resolve(name).normalize().startsWith(dest)` per entry.
- **Bombs:** cap the entry count, the total uncompressed size, and the compression ratio *while* streaming. Don't trust the sizes in headers. Nested archives: don't recurse, or recurse with a budget.

## Uploads

### Fixes that don't hold

| Fix | Breaks on |
|---|---|
| Check the extension: `name.endsWith('.png')` | `shell.php.png` on misconfigured servers, `x.png.svg`, `x.PNG`, trailing dots or spaces on Windows (`x.php.`) |
| Trust the `Content-Type` sent by the client | It's whatever the attacker sends |
| Store under the original filename | Traversal (`../`), overwriting other users' files, `index.html`, `.htaccess`, NTFS streams (`x.asp::$DATA`) |
| Image uploads are "safe" | SVG is XML that runs script when opened directly. HTML/JS polyglots get sniffed. Decompression bombs (a 10 KB PNG that decodes to 100k × 100k pixels) |
| Store in the web root / static folder | It gets served (and maybe executed) on your main origin |

### The fix that holds

1. **Limit size** before buffering. Web server: `client_max_body_size`. App: multer `limits: { fileSize, files }`; Django `DATA_UPLOAD_MAX_MEMORY_SIZE` / `FILE_UPLOAD_MAX_MEMORY_SIZE`; Starlette `request.form(max_part_size=...)`.
2. **Detect type from the content**, then allowlist it. Node `file-type` (`fileTypeFromBuffer`); Python `filetype` or `puremagic`; libmagic. Reject on a mismatch with the declared type.
3. **Generate the storage key** (`${userId}/${randomUUID()}`). Keep the original name only as metadata, cleaned with `safeFilename()` (`assets/fixes/node/safe-path.mjs`, `safe_path.py`).
4. **Re-encode images** where you can (sharp, Pillow). That strips metadata (EXIF GPS!) and polyglot payloads. Set decode limits: sharp `limitInputPixels` (default 268M pixels; lower it); Pillow `Image.MAX_IMAGE_PIXELS` (default 89,478,485, and above 2× that it raises `DecompressionBombError`).
5. **SVG:** rasterize it, sanitize it (DOMPurify with the SVG profile, server-side), or only ever serve it as an attachment from a separate origin.
6. **Object storage direct uploads:** use presigned **POST** policies with a `content-length-range` and an exact `key` prefix (and a fixed `Content-Type` condition). A presigned PUT URL doesn't limit size. Make buckets private and serve through signed GETs.
7. Scan for malware if users share files with each other. Run scanning and conversion in an isolated worker.

## Serving user files

The goal: even a malicious file can't run script on your app's origin.
- **Separate origin:** `usercontent.example-cdn.com`, a different *registrable* domain, so it doesn't share cookies or same-site status with the app (that's why `googleusercontent.com` exists).
- Headers on every user-file response:
  - `Content-Disposition: attachment; filename*=UTF-8''<encoded>` for everything that isn't a known-safe inline type
  - `X-Content-Type-Options: nosniff`
  - `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'`
  - `Cross-Origin-Resource-Policy: same-site` (or `cross-origin` if other sites embed them deliberately)
- Set `Content-Type` from **your** detected type, never from the upload request.
- Authorization: serve through an endpoint that checks access, or through short-lived signed URLs. Public bucket URLs never expire.

## Regression tests

```bash
node <skill-dir>/scripts/probe-validator.mjs path src/lib/files.ts resolveUserFile             # fn(base, input)
node <skill-dir>/scripts/probe-validator.mjs path src/lib/files.ts resolveUserFile --args input --base ./var/uploads
```

Upload tests:
- a multipart `filename="../../x.txt"` is stored under a generated key
- a `.png` whose bytes are HTML gets 415
- an SVG containing `<script>` comes back with `Content-Disposition: attachment` and a `sandbox` CSP, or is rasterized
- an oversized body gets 413
- an archive with a `../evil` entry is rejected, and nothing is written outside the destination (assert on the filesystem)
