// safe-path.mjs: keep user-influenced paths inside a base directory. Node 18+.
//
// Fixes that don't hold:
//   - p.replace('../', '')            '....//' becomes '../' after the replace
//   - resolved.startsWith(base)       '/srv/uploads_evil' starts with '/srv/uploads'
//   - path.join(base, p) alone        '../../etc/passwd' walks out
//   - checking before decoding        '..%2f' turns into '../' after a later decode
// The fix that holds: decode fully, resolve, then compare with path.relative (a real
// path-segment comparison). For directories where users or other processes can create
// symlinks, also compare the realpath.
//
// Usage:
//   import { resolveInside } from './safe-path.mjs';
//   const file = resolveInside(UPLOAD_DIR, req.params.name);   // throws on escape
//   res.sendFile(file);

import path from 'node:path';
import fs from 'node:fs/promises';

export class PathTraversalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PathTraversalError';
    this.code = 'ERR_PATH_TRAVERSAL';
  }
}

function isStrictlyInside(base, target) {
  const rel = path.relative(base, target);
  return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}

/**
 * Lexically resolve `userPath` under `baseDir` and return the absolute path.
 * Throws PathTraversalError if the result would leave baseDir (or equal it).
 * Pass the *decoded* value: run it after any URL decoding your framework does.
 * @param {string} baseDir
 * @param {string} userPath
 * @param {{ allowBackslash?: boolean }} [opts]  backslashes are rejected by default
 *   because they're separators on Windows; keep it that way unless names really need them.
 * @returns {string}
 */
export function resolveInside(baseDir, userPath, opts = {}) {
  if (typeof userPath !== 'string' || userPath.length === 0) throw new PathTraversalError('empty path');
  if (userPath.includes('\0')) throw new PathTraversalError('null byte in path');
  if (!opts.allowBackslash && userPath.includes('\\')) throw new PathTraversalError('backslash in path');
  const base = path.resolve(baseDir);
  const target = path.resolve(base, userPath);
  if (!isStrictlyInside(base, target)) throw new PathTraversalError('path escapes base directory');
  return target;
}

/**
 * Like resolveInside, but also follows symlinks: the *real* location must be inside the
 * real base. Use when the directory can contain symlinks (user uploads extracted from
 * archives, shared volumes). If the target doesn't exist yet (you're about to create it),
 * the parent directory's real path is checked instead.
 * There is still a small race if an attacker can swap a directory for a symlink between
 * this check and your open(). Where that's possible, open with O_NOFOLLOW or keep
 * attacker-writable trees on a separate volume.
 * @param {string} baseDir
 * @param {string} userPath
 * @returns {Promise<string>}
 */
export async function realpathInside(baseDir, userPath, opts = {}) {
  const lexical = resolveInside(baseDir, userPath, opts);
  const realBase = await fs.realpath(baseDir);
  // Resolve the deepest part of the path that exists, then append the rest. Works for files you are
  // about to create, including inside folders that don't exist yet.
  let existing = lexical;
  const rest = [];
  let real;
  for (;;) {
    try {
      real = path.join(await fs.realpath(existing), ...rest);
      break;
    } catch (err) {
      if (err.code !== 'ENOENT' || existing === realBase || path.dirname(existing) === existing) throw err;
      rest.unshift(path.basename(existing));
      existing = path.dirname(existing);
    }
  }
  if (!isStrictlyInside(realBase, real)) throw new PathTraversalError('path escapes base directory via symlink');
  return real;
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;

/**
 * Turn an untrusted filename (e.g. an upload's original name) into a safe single path
 * segment for display or Content-Disposition. For storage, prefer a server-generated name
 * (crypto.randomUUID()) and keep the original only as metadata.
 * @param {string} name
 * @param {{ maxLength?: number, fallback?: string }} [opts]
 */
export function safeFilename(name, opts = {}) {
  const { maxLength = 200, fallback = 'file' } = opts;
  let s = String(name ?? '').normalize('NFC');
  s = s.split(/[\\/]/).pop() || ''; // drop any directory part, for either separator
  s = s.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '');
  if (WINDOWS_RESERVED.test(s)) s = '_' + s;
  if (s.length > maxLength) {
    const ext = path.extname(s).slice(0, 16);
    s = s.slice(0, maxLength - ext.length) + ext;
  }
  return s || fallback;
}
