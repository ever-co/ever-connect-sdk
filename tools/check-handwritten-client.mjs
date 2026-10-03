#!/usr/bin/env node
/**
 * check-handwritten-client: only the generated client makes HTTP calls.
 *
 * Fails on `fetch(`, `new Request(`, `reqwest::` or a `/v1/` path literal in the code of the
 * packages and crates, outside the generated files and the exemptions written down in
 * tools/handwritten-client.allow.json (each with its reason). Comments are not code: a doc comment
 * may name an endpoint.
 *
 *   node tools/check-handwritten-client.mjs                 scan the packages and crates
 *   node tools/check-handwritten-client.mjs <file>...       scan these files only (the known-bad
 *                                                           fixture must fail)
 *   node tools/check-handwritten-client.mjs --self-test     the known-bad fixture fails, the tree passes
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, readJson, rel, walk } from './lib/common.mjs';

const RULES = [
  { id: 'fetch', pattern: /\bfetch\s*\(/ },
  { id: 'request', pattern: /\bnew\s+Request\s*\(/ },
  { id: 'reqwest', pattern: /\breqwest::/ },
  { id: 'path', pattern: /\/v1\// },
];
const GENERATED = [
  /^packages\/ts\/[^/]+\/src\/generated\//,
  /^crates\/[^/]+\/src\/generated\//,
  /^crates\/ever-connect-sdk\/src\/client\/generated\.rs$/,
];
const ROOTS = ['packages/ts', 'crates'];
const SOURCE = /\/src\/.*\.(ts|mts|cts|rs)$/;
const ALLOW_FILE = 'tools/handwritten-client.allow.json';
const BAD_FIXTURE = 'tools/fixtures/handwritten-client.bad.ts';

/** The code of a file, line by line, with comments blanked out (strings kept). */
export function codeLines(text) {
  const out = [];
  let inBlock = false;
  for (const line of text.split(/\r?\n/)) {
    let code = '';
    let i = 0;
    let quote = null;
    while (i < line.length) {
      const two = line.slice(i, i + 2);
      if (inBlock) {
        if (two === '*/') {
          inBlock = false;
          i += 2;
        } else i += 1;
        continue;
      }
      if (quote) {
        code += line[i];
        if (line[i] === '\\') {
          code += line[i + 1] ?? '';
          i += 2;
          continue;
        }
        if (line[i] === quote) quote = null;
        i += 1;
        continue;
      }
      if (two === '//') break;
      if (two === '/*') {
        inBlock = true;
        i += 2;
        continue;
      }
      if (line[i] === '"' || line[i] === "'" || line[i] === '`') quote = line[i];
      code += line[i];
      i += 1;
    }
    out.push(code);
  }
  return out;
}

/** Every finding of `files` (repository-relative paths) under the allow list. */
export function scan(files, allow = readJson(join(REPO, ALLOW_FILE)).exemptions) {
  const findings = [];
  for (const file of files) {
    if (GENERATED.some((g) => g.test(file))) continue;
    const exempt = allow.filter((a) => a.path === file).flatMap((a) => a.rules);
    codeLines(readFileSync(join(REPO, file), 'utf8')).forEach((code, n) => {
      for (const rule of RULES) if (!exempt.includes(rule.id) && rule.pattern.test(code)) findings.push(`${file}:${n + 1}: ${rule.id}`);
    });
  }
  return findings;
}

function tree() {
  return ROOTS.flatMap((r) => walk(join(REPO, r)))
    .map((p) => rel(p))
    .filter((p) => SOURCE.test(p) && !p.includes('/node_modules/') && !p.includes('/dist/'));
}

function main() {
  const args = process.argv.slice(2);
  const allow = readJson(join(REPO, ALLOW_FILE)).exemptions;
  for (const a of allow) if (typeof a.reason !== 'string' || a.reason.length < 20) throw new Error(`${a.path}: an exemption needs its reason`);
  if (args.includes('--self-test')) {
    const bad = scan([BAD_FIXTURE], allow);
    if (bad.length === 0) {
      process.stderr.write('check-handwritten-client self-test: the known-bad fixture passed\n');
      process.exit(1);
    }
    const good = scan(tree(), allow);
    if (good.length > 0) {
      process.stderr.write(`check-handwritten-client self-test: the tree fails:\n  ${good.join('\n  ')}\n`);
      process.exit(1);
    }
    process.stdout.write(`check-handwritten-client self-test: ok (the known-bad fixture fails with ${bad.length} finding(s))\n`);
    return;
  }
  const files = args.length > 0 ? args.map((a) => rel(join(REPO, a))) : tree();
  const findings = scan(files, allow);
  if (findings.length > 0) {
    process.stderr.write(
      `check-handwritten-client: ${findings.length} call(s) outside the generated client:\n  ${findings.join('\n  ')}\nMake the call through the client's operation table, or write the exemption and its reason in ${ALLOW_FILE}.\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`check-handwritten-client: ok (${files.length} file(s))\n`);
}

if (process.argv[1]?.endsWith('check-handwritten-client.mjs')) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`check-handwritten-client: ${error.message}\n`);
    process.exit(1);
  }
}
