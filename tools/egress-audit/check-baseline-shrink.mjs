#!/usr/bin/env node
/**
 * check-baseline-shrink: a product's ui-baseline.json may only lose entries. Every entry of the
 * working copy must be in the file as it was at the base commit (same route, attribute and URL);
 * an entry added since fails. A file that did not exist at the base is its first version and passes.
 *
 *   ever-egress-audit check-baseline-shrink --base <git ref> [--file ui-baseline.json]
 *
 * Exit 0 when the baseline only shrank (or stayed), 1 naming each added entry, 2 on a usage error.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { redactUrl } from './lib/har.mjs';

const key = (e) => `${e.route}|${e.attribute}|${redactUrl(e.url)}`;

/** The entries of `current` that are not in `base` (both ui-baseline.json documents). */
export function addedEntries(current, base) {
  const before = new Set((base?.entries ?? []).map(key));
  return (current?.entries ?? []).filter((e) => !before.has(key(e)));
}

export function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const ref = arg('base');
  if (!ref) {
    process.stderr.write('check-baseline-shrink: --base <git ref> is required\n');
    return 2;
  }
  const file = resolve(arg('file') ?? 'ui-baseline.json');
  let current;
  try {
    current = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    process.stderr.write(`check-baseline-shrink: ${file} could not be read: ${error.message}\n`);
    return 2;
  }
  let base = null;
  try {
    const text = execFileSync('git', ['show', `${ref}:./${basename(file)}`], {
      cwd: dirname(file),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    base = JSON.parse(text);
  } catch (error) {
    const stderr = String(error.stderr ?? '');
    if (/does not exist|exists on disk, but not in/.test(stderr)) {
      process.stdout.write(`check-baseline-shrink: ${basename(file)} is new since ${ref} (its first version)\n`);
      return 0;
    }
    process.stderr.write(`check-baseline-shrink: the file at ${ref} could not be read: ${stderr.trim().split('\n')[0] || error.message}\n`);
    return 2;
  }
  const added = addedEntries(current, base);
  if (added.length > 0) {
    process.stderr.write(
      `check-baseline-shrink: ${basename(file)} may only shrink; added since ${ref}:\n  ${added.map((e) => `${e.route} ${e.attribute} ${redactUrl(e.url)}`).join('\n  ')}\n`,
    );
    return 1;
  }
  const removed = (base.entries ?? []).length - (current.entries ?? []).length;
  process.stdout.write(
    `check-baseline-shrink: ok (${current.entries?.length ?? 0} entries, ${Math.max(0, removed)} removed since ${ref})\n`,
  );
  return 0;
}

if (process.argv[1] && process.argv[1].endsWith('check-baseline-shrink.mjs')) process.exit(main(process.argv.slice(2)));
