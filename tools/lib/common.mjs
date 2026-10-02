// Shared helpers for the repository tools: stable JSON, hashing, file walking, platform checkout.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

/** Object keys sorted at every level; arrays keep their order. */
export function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key]);
    return out;
  }
  return value;
}

/** Deterministic JSON text: two-space indent, LF, trailing newline; keys sorted when asked. */
export function stableJson(value, { sort = true } = {}) {
  return `${JSON.stringify(sort ? sortKeys(value) : value, null, 2)}\n`;
}

export const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
export const readText = (path) => readFileSync(path, 'utf8');

export function writeText(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

/** Repository-relative path with forward slashes. */
export const rel = (path, base = REPO) => relative(base, path).split(sep).join('/');

/** Every file under a directory, sorted, as absolute paths. */
export function walk(dir, filter = () => true) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path, filter));
    else if (filter(path)) out.push(path);
  }
  return out;
}

/**
 * The ever-co/platform checkout the contract is synchronised from. `required: false` answers null
 * (with a warning) when EVER_PLATFORM_REPO is unset, so local runs without a checkout still work.
 */
export function platformRepo({ required = true } = {}) {
  const value = process.env.EVER_PLATFORM_REPO;
  if (!value) {
    if (required) throw new Error('EVER_PLATFORM_REPO is not set: point it at an ever-co/platform checkout');
    return null;
  }
  const path = resolve(value);
  if (!existsSync(join(path, 'contracts', 'openapi', 'ever-api.v1.json')))
    throw new Error(`EVER_PLATFORM_REPO=${value} is not an ever-co/platform checkout`);
  return path;
}

/** Compares two maps of path -> text and answers the paths that differ (sorted). */
export function diffOutputs(expected, actual) {
  const paths = [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort();
  return paths.filter((p) => expected[p] !== actual[p]);
}

export function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
