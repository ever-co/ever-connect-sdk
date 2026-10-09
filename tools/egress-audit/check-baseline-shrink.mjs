#!/usr/bin/env node
/**
 * check-baseline-shrink: a product's ui-baseline.json may only lose entries.
 *
 *   ever-egress-audit check-baseline-shrink --base <git ref> --config <egress-audit.config.json> [--first-version]
 *   ever-egress-audit check-baseline-shrink --base <git ref> --file <ui-baseline.json> [--first-version]
 *
 * --config (preferred): the baseline is the file the config's ui_baseline names (default
 * ui-baseline.json beside the config), and the run fails when that path differs from the one the
 * config named at the base: pointing ui_baseline at another file, or renaming the file, counts as
 * growing it. --file names the file directly (a renamed file is new at the base, so it fails too).
 *
 * The file records base_commit: the product commit its entries were recorded from (before the first
 * module change). It must name a commit of the history and never changes once the file exists.
 *
 * Every entry of the working copy must be in the file as it was at the base (same route, attribute
 * and URL); an entry added since fails. A file that did not exist at the base fails as well, unless
 * --first-version is given: the flag is for the one change that adopts the baseline, and it fails
 * once the file exists at the base, so it cannot be left in place to accept later growth.
 *
 * Exit 0 when the baseline only shrank (or stayed, or is adopted with --first-version), 1 naming what
 * grew, 2 on a usage error or a history that cannot be read.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { redactUrl } from './lib/har.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const key = (e) => `${e.route}|${e.attribute}|${redactUrl(e.url)}`;
const show = (e) => `${e.route} ${e.attribute} ${redactUrl(e.url)}`;

/** The entries of `current` that are not in `base` (both ui-baseline.json documents). */
export function addedEntries(current, base) {
  const before = new Set((base?.entries ?? []).map(key));
  return (current?.entries ?? []).filter((e) => !before.has(key(e)));
}

/** The schema problems of a ui-baseline.json document ([] when it is valid). */
export function baselineProblems(doc) {
  const schema = JSON.parse(readFileSync(join(here, 'ui-baseline.schema.json'), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  return validate(doc) ? [] : validate.errors.map((e) => `${e.instancePath || '/'} ${e.message}`);
}

class Usage extends Error {}

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/** The text of a repository path at a ref, or null when the path does not exist there. */
function showAt(ref, repoPath, cwd) {
  try {
    return git(['show', `${ref}:${repoPath}`], cwd);
  } catch (error) {
    const stderr = String(error.stderr ?? '');
    if (/does not exist|exists on disk, but not in|path .* not in/i.test(stderr)) return null;
    throw new Usage(`${repoPath} at ${ref} could not be read: ${stderr.trim().split('\n')[0] || error.message}`);
  }
}

/** The baseline path a config names (absolute), from its ui_baseline or the default beside it. */
export function baselinePathOf(config, configFile) {
  return resolve(dirname(configFile), config?.ui_baseline ?? 'ui-baseline.json');
}

export function check({ base: ref, config: configArg, file: fileArg, firstVersion = false }) {
  if (!ref) throw new Usage('--base <git ref> is required');
  if (!configArg && !fileArg) throw new Usage('--config <egress-audit.config.json> (or --file <ui-baseline.json>) is required');
  const notes = [];
  let file = fileArg ? resolve(fileArg) : null;
  let top;
  const anchor = configArg ? dirname(resolve(configArg)) : dirname(file);
  try {
    top = git(['rev-parse', '--show-toplevel'], anchor).trim();
  } catch {
    throw new Usage(`${anchor} is not inside a git repository`);
  }
  const repoPath = (abs) => relative(top, abs).split(sep).join('/');
  try {
    git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], top);
  } catch {
    throw new Usage(`the base ${ref} is not a commit of this repository (fetch it first)`);
  }

  if (configArg) {
    const configFile = resolve(configArg);
    let config;
    try {
      config = JSON.parse(readFileSync(configFile, 'utf8'));
    } catch (error) {
      throw new Usage(`${configArg} could not be read: ${error.message}`);
    }
    const fromConfig = baselinePathOf(config, configFile);
    if (file && file !== fromConfig)
      throw new Usage(`--file ${fileArg} is not the baseline the config names (${repoPath(fromConfig)})`);
    file = fromConfig;
    // The path the config named at the base: a baseline that moved is a new baseline.
    const configAtBase = showAt(ref, repoPath(configFile), top);
    if (configAtBase !== null) {
      let before;
      try {
        before = JSON.parse(configAtBase);
      } catch (error) {
        throw new Usage(`${repoPath(configFile)} at ${ref} is not JSON: ${error.message}`);
      }
      const pathBefore = repoPath(baselinePathOf(before, configFile));
      if (pathBefore !== repoPath(file))
        return {
          exit: 1,
          problems: [
            `the baseline moved since ${ref} (${pathBefore} -> ${repoPath(file)}): a renamed or re-pointed baseline counts as growing it; keep the path`,
          ],
          notes,
        };
    } else notes.push(`${repoPath(configFile)} is new since ${ref}`);
  }

  const path = repoPath(file);
  const beforeText = showAt(ref, path, top);
  if (!existsSync(file)) {
    if (firstVersion) return { exit: 1, problems: [`--first-version was given but ${path} does not exist`], notes };
    return {
      exit: 0,
      problems: [],
      notes: [...notes, beforeText === null ? `no baseline (${path}): nothing to check` : `${path} was removed since ${ref}`],
    };
  }
  let current;
  try {
    current = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Usage(`${path} could not be read: ${error.message}`);
  }
  const problems = baselineProblems(current).map((p) => `${path} ${p}`);
  if (problems.length > 0) return { exit: 1, problems, notes };
  // base_commit: a commit of the history (an ancestor of what is checked).
  try {
    git(['merge-base', '--is-ancestor', `${current.base_commit}^{commit}`, 'HEAD'], top);
  } catch (error) {
    let shallow = true;
    try {
      shallow = git(['rev-parse', '--is-shallow-repository'], top).trim() === 'true';
    } catch {
      // unknown: treated as shallow, so the answer is a fault, not a verdict
    }
    if (error.status === 1 || !shallow)
      return { exit: 1, problems: [`base_commit ${current.base_commit} is not a commit of this branch's history`], notes };
    throw new Usage(
      `base_commit ${current.base_commit} could not be resolved (a shallow clone? fetch the full history, for example fetch-depth: 0)`,
    );
  }

  if (beforeText === null) {
    if (!firstVersion)
      return {
        exit: 1,
        problems: [
          `${path} is new since ${ref}: a baseline is adopted once, with --first-version in the change that adds it (a renamed baseline is new too)`,
        ],
        notes,
      };
    return {
      exit: 0,
      problems: [],
      notes: [
        ...notes,
        `${path} is adopted (its first version, recorded from ${current.base_commit}): ${current.entries.length} entries to review; remove --first-version after this change`,
      ],
    };
  }
  if (firstVersion)
    return {
      exit: 1,
      problems: [`--first-version is for the change that adopts the baseline, and ${path} exists at ${ref}: remove the flag`],
      notes,
    };
  let base;
  try {
    base = JSON.parse(beforeText);
  } catch (error) {
    throw new Usage(`${path} at ${ref} is not JSON: ${error.message}`);
  }
  const out = [];
  if (base.base_commit !== undefined && base.base_commit !== current.base_commit)
    out.push(`base_commit changed since ${ref} (${base.base_commit} -> ${current.base_commit}); it is fixed once the baseline exists`);
  const added = addedEntries(current, base);
  if (added.length > 0) out.push(`${path} may only shrink; added since ${ref}:\n  ${added.map(show).join('\n  ')}`);
  if (out.length > 0) return { exit: 1, problems: out, notes };
  const removed = (base.entries ?? []).length - current.entries.length;
  return { exit: 0, problems: [], notes: [...notes, `ok (${current.entries.length} entries, ${Math.max(0, removed)} removed since ${ref})`] };
}

export function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  let result;
  try {
    result = check({ base: arg('base'), config: arg('config'), file: arg('file'), firstVersion: argv.includes('--first-version') });
  } catch (error) {
    process.stderr.write(`check-baseline-shrink: ${error.message}\n`);
    return 2;
  }
  for (const n of result.notes) process.stdout.write(`check-baseline-shrink: ${n}\n`);
  for (const p of result.problems) process.stderr.write(`check-baseline-shrink: ${p}\n`);
  return result.exit;
}

if (process.argv[1] && process.argv[1].endsWith('check-baseline-shrink.mjs')) process.exit(main(process.argv.slice(2)));
