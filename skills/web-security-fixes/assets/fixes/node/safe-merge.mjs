// safe-merge.mjs: prototype-pollution-proof deep merge, set-by-path, and JSON parsing. Zero dependencies.
//
// Why: JSON.parse('{"__proto__": {"isAdmin": true}}') creates an *own* property named
// "__proto__". A naive recursive merge then does target["__proto__"]["isAdmin"] = true,
// which writes to Object.prototype, so every object in the process now has isAdmin.
// Fixes that don't hold:
//   - filtering only "__proto__"           {"constructor": {"prototype": {...}}} reaches the same place
//   - filtering only at the top level      {"a": {"__proto__": {...}}} pollutes on the second level
//   - Object.freeze(Object.prototype)      breaks many libraries and doesn't protect other prototypes
// The fix that holds: skip the three dangerous keys at every level, recurse only into the
// target's OWN plain-object properties, and validate the shape with a schema that strips
// unknown keys (zod .strict()/.strip(), valibot, ajv removeAdditional) before merging.

const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH = 64;

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function cloneValue(value, depth) {
  if (Array.isArray(value)) return value.map((v) => cloneValue(v, depth + 1));
  if (isPlainObject(value)) return safeMerge({}, value, depth + 1);
  return value;
}

/**
 * Deep-merge `source` into `target` (mutates and returns target). Arrays are replaced, not merged.
 * @template T
 * @param {T} target
 * @param {unknown} source
 * @returns {T}
 */
export function safeMerge(target, source, depth = 0) {
  if (depth > MAX_DEPTH) throw new RangeError('safeMerge: object nested too deeply');
  if (!isPlainObject(source)) return target;
  for (const key of Object.keys(source)) {
    if (FORBIDDEN.has(key)) continue;
    const value = source[key];
    if (isPlainObject(value)) {
      const existing = Object.hasOwn(target, key) && isPlainObject(target[key]) ? target[key] : {};
      target[key] = safeMerge(existing, value, depth + 1);
    } else {
      target[key] = cloneValue(value, depth);
    }
  }
  return target;
}

function parsePath(path) {
  if (Array.isArray(path)) return path.map(String);
  return String(path).replace(/\[([^\]]*)\]/g, '.$1').split('.').filter((s) => s !== '');
}

/**
 * Set a nested value by path ('a.b.c', 'a[b][c]', or ['a','b','c']).
 * Throws on any __proto__ / constructor / prototype segment.
 */
export function safeSet(obj, path, value) {
  const parts = parsePath(path);
  if (parts.length === 0) throw new TypeError('safeSet: empty path');
  if (parts.some((p) => FORBIDDEN.has(p))) throw new TypeError('safeSet: forbidden path segment');
  let cur = obj;
  for (const part of parts.slice(0, -1)) {
    if (!Object.hasOwn(cur, part) || cur[part] === null || typeof cur[part] !== 'object') cur[part] = {};
    cur = cur[part];
  }
  cur[parts[parts.length - 1]] = value;
  return obj;
}

/** JSON.parse that drops __proto__ / constructor / prototype keys at every level. */
export function safeJsonParse(text) {
  return JSON.parse(text, (key, value) => (FORBIDDEN.has(key) ? undefined : value));
}
