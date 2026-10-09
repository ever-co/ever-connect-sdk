#!/usr/bin/env node
/**
 * static-hostnames: no Ever-owned host (the ever_owned names of ever-hosts.json and every name under
 * them) and no Ever Platform base URL variable appears outside the directories that may name them
 * (the module packages, docs, the audit and tests), so no other code can call Ever Platform behind
 * the modules' back.
 *
 *   ever-egress-audit static-hostnames [--root <dir>] --allow-dirs <dir>,<dir>,**\/*.test.*
 *       [--optin-hosts <optin-hosts.json> | --config <egress-audit.config.json>]
 *       [--baseline <ui-baseline.json>] [--all-files]
 *
 * --optin-hosts (or the config's optin_hosts, default optin-hosts.json beside the config): the
 * product's documented operator opt-ins, hosts of older features that stay off until an operator
 * turns them on; the scan accepts exactly those hosts. Only this scan reads the file.
 * --baseline: the product's ui-baseline.json references are accepted, each only as its exact URL
 * (as the baseline writes it, or without its trailing slash) where a line names it; the rest of the
 * line, and every other use of the same host, is still scanned.
 * --all-files: scan every file under the root, built output included (for example .next/static),
 * instead of the files git tracks.
 *
 * Exit 0 when clean, 1 with file:line findings, 2 on a usage error.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { hostOfUrl, hostsInText, isEverOwned, loadEverHosts, loadOptinHosts, normaliseHost } from './hosts.mjs';

export const VARIABLE_PATTERNS = [/\bEVER_PLATFORM_API_URL\b/];
/** The patterns of the first version (ever.co hosts only), kept for importers; the scan reads ever-hosts.json. */
export const HOST_PATTERNS = [/\bever\.co\b/, /\bapi\.ever\.co\b/, /\bapp\.ever\.co\b/, ...VARIABLE_PATTERNS];
const TEXT = /\.(m?[jt]sx?|cjs|json|ya?ml|html|css|vue|svelte|rs|go|py|php|env|example|sample|conf|toml)$|(^|\/)(Dockerfile|\.env[^/]*)$/;
const SKIP = new Set(['node_modules', '.git', 'dist', 'build', 'target', 'coverage', '.next', '.turbo', 'vendor']);
const SKIP_ALL_FILES = new Set(['node_modules', '.git']);

/** A minimal glob: `dir/` or `dir` prefixes, and `**\/*.test.*` style suffix patterns. */
export function allowed(file, patterns) {
  return patterns.some((p) => {
    if (p.includes('*')) {
      const quote = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
      const source = p
        .split('**/')
        .map((part) => part.split('*').map(quote).join('[^/]*'))
        .join('(?:.*/)?');
      return new RegExp(`^${source}$`).test(file);
    }
    const dir = p.replace(/\/$/, '');
    return file === dir || file.startsWith(`${dir}/`);
  });
}

function walkFiles(root, skip) {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (skip.has(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(relative(root, p).split(sep).join('/'));
    }
  };
  walk(root);
  return out;
}

function files(root, allFiles) {
  if (allFiles) return walkFiles(root, SKIP_ALL_FILES);
  try {
    return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split('\0')
      .filter(Boolean);
  } catch {
    return walkFiles(root, SKIP);
  }
}

const quoteRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * A matcher that blanks each accepted baseline URL out of a line: the URL exactly (or without its
 * trailing slash), not followed by more of a URL, so `https://gauzy.co/` never excuses
 * `https://gauzy.co/api/x`.
 */
export function baselineMatcher(urls = []) {
  const forms = [...new Set(urls.flatMap((u) => [u, u.replace(/\/$/, '')]).filter((u) => u && hostOfUrl(u)))];
  if (forms.length === 0) return null;
  forms.sort((a, b) => b.length - a.length);
  return new RegExp(`(${forms.map(quoteRe).join('|')})(?![\\w./~%?#:@-])`, 'gi');
}

/** The Ever-owned hosts a line names, minus the accepted ones; and whether it names the base URL variable. */
export function lineFindings(line, accepted = new Set(), lists = loadEverHosts(), baseline = null) {
  const text = baseline ? line.replace(baseline, ' ') : line;
  const hosts = hostsInText(text).filter((h) => isEverOwned(h, lists) && !accepted.has(normaliseHost(h)));
  const variable = VARIABLE_PATTERNS.some((p) => p.test(line));
  return { hosts, variable };
}

/**
 * file:line of every Ever-owned host or base URL variable outside allowDirs.
 * opts: {optinHosts: Set, baselineUrls: string[], allFiles: boolean}. (baselineHosts, a Set of hosts,
 * is no longer honoured: a baseline excuses its exact URLs only.)
 */
export function scanHostnames(root, allowDirs, opts = {}) {
  const lists = loadEverHosts();
  const accepted = new Set([...(opts.optinHosts ?? [])].map(normaliseHost));
  const baseline = baselineMatcher(opts.baselineUrls ?? []);
  const findings = [];
  for (const file of files(root, opts.allFiles)) {
    if (!TEXT.test(file) || allowed(file, allowDirs)) continue;
    let text;
    try {
      text = readFileSync(join(root, file), 'utf8');
    } catch {
      continue;
    }
    text.split('\n').forEach((line, i) => {
      const f = lineFindings(line, accepted, lists, baseline);
      if (f.hosts.length > 0 || f.variable) findings.push(`${file}:${i + 1}`);
    });
  }
  return findings;
}

/** The hosts of a ui-baseline.json's links (kept for importers; the scan accepts baselineUrls only). */
export function baselineHosts(file) {
  const data = JSON.parse(readFileSync(file, 'utf8'));
  return new Set((data.entries ?? []).map((e) => hostOfUrl(e.url)).filter(Boolean));
}

/** The URLs of a ui-baseline.json's entries. */
export function baselineUrls(file) {
  const data = JSON.parse(readFileSync(file, 'utf8'));
  return [...new Set((data.entries ?? []).map((e) => String(e.url ?? '')).filter(Boolean))];
}

export function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const root = resolve(arg('root') ?? '.');
  const allow = (arg('allow-dirs') ?? '').split(',').filter(Boolean);
  let optinFile = arg('optin-hosts');
  if (!optinFile && arg('config')) {
    const configPath = resolve(arg('config'));
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    const candidate = resolve(dirname(configPath), config.optin_hosts ?? 'optin-hosts.json');
    if (config.optin_hosts || existsSync(candidate)) optinFile = candidate;
  }
  let optinHosts = new Set();
  let baseline = [];
  try {
    if (optinFile) optinHosts = loadOptinHosts(resolve(optinFile));
    if (arg('baseline')) baseline = baselineUrls(resolve(arg('baseline')));
  } catch (error) {
    process.stderr.write(`static-hostnames: ${error.message}\n`);
    return 2;
  }
  const findings = scanHostnames(root, allow, { optinHosts, baselineUrls: baseline, allFiles: argv.includes('--all-files') });
  if (findings.length > 0) {
    process.stderr.write(
      `static-hostnames: an Ever host or the Ever Platform base URL outside the allowed directories:\n  ${findings.join('\n  ')}\n`,
    );
    return 1;
  }
  process.stdout.write(`static-hostnames: ok${optinHosts.size ? ` (${optinHosts.size} operator opt-in host(s) accepted)` : ''}\n`);
  return 0;
}

if (process.argv[1] && process.argv[1].endsWith('static-hostnames.mjs')) process.exit(main(process.argv.slice(2)));
