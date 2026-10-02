#!/usr/bin/env node
/**
 * check-public-safe: every file, commit message and branch name of this repository stays fit for
 * a public repository.
 *
 * Two sets of rules:
 *   - the generic rules in tools/public-safe.words.json (a product noun outside the technical
 *     allow-list of the egress harness and of commit messages, banned words, hosts, internal
 *     paths, design-document references, draft markers, numbered section signs and work-item and
 *     task identifiers);
 *   - a phrase list kept outside the repository, read from the environment variable
 *     EVER_BANNED_PHRASES_JSON (a CI secret) or from the git-ignored local file
 *     tools/banned-phrases.private.json. Without one, those rules are skipped with a note, so
 *     forks and fresh clones still run the generic rules.
 *
 * A finding prints the file, the line and the rule id, never the matched text, so the private
 * list stays out of public CI logs.
 *
 *   node tools/check-public-safe.mjs                       files, branch name, commits of the range
 *   node tools/check-public-safe.mjs --commits <range>     scan the commit messages of <range>
 *   node tools/check-public-safe.mjs --files <f> [<f> …]   scan only these files
 *   node tools/check-public-safe.mjs --self-test           prove each rule can fail
 *
 * The default commit range is origin/<base>..HEAD on a pull request (GITHUB_BASE_REF), the pushed
 * range on a push (EVER_PUSH_BEFORE..HEAD) and origin/develop..HEAD locally when it exists.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(fileURLToPath(new URL('..', import.meta.url)));
const WORDS = JSON.parse(readFileSync(join(REPO, 'tools', 'public-safe.words.json'), 'utf8'));
const LOCAL_LIST = join(REPO, 'tools', 'banned-phrases.private.json');
const FIXTURES = join(REPO, 'tools', 'fixtures', 'public-safe');

const re = (rule) => new RegExp(rule.pattern, rule.flags ?? '');
const NOUN = re(WORDS.noun);
const NOUN_OK = WORDS.noun.technical.map((t) =>
  /[\\^$()[\]|?*+]/.test(t) ? new RegExp(t, 'i') : new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
);
const HOST = re(WORDS.hosts);
const HOST_OK = new Set(WORDS.hosts.allowed.map((h) => h.toLowerCase()));
const PLAN_ID = re(WORDS.plan_id);
// Long base64url runs (signatures, keys, hashes) are not prose: the identifier rule ignores them.
const BLOB = /[A-Za-z0-9_-]{40,}/g;

/** Compiles a private phrase list (an array, or {phrases, patterns}) into numbered rules. */
export function compilePhraseList(doc) {
  const items = Array.isArray(doc) ? doc : [...(doc?.phrases ?? []), ...(doc?.patterns ?? [])];
  if (!Array.isArray(items) || items.length === 0) throw new Error('the phrase list is empty or malformed');
  return items.map((item, i) => {
    const id = `P${i + 1}`;
    if (typeof item === 'string') {
      const left = /^\w/.test(item) ? '\\b' : '';
      const right = /\w$/.test(item) ? '\\b' : '';
      const body = item.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
      return { id, re: new RegExp(`${left}${body}${right}`, 'i') };
    }
    if (typeof item?.pattern !== 'string') throw new Error(`phrase list item ${i + 1} is malformed`);
    return { id, re: new RegExp(item.pattern, (item.flags ?? 'i').replace(/[gy]/g, '')) };
  });
}

/** The heading path of every line of a Markdown text: the nearest heading above it. */
function headingsByLine(lines) {
  let current = '';
  let fence = false;
  return lines.map((line) => {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    else if (!fence) {
      const m = /^#{1,6}\s+(.*)$/.exec(line);
      if (m) current = m[1].trim();
    }
    return current;
  });
}

/** The `file` of a commit message: it may describe harness work, with the technical terms only. */
const COMMIT_MESSAGE = ':commit-message';

function nounAllowed(file, line, heading) {
  const inPath = file === COMMIT_MESSAGE || WORDS.noun.allowed_paths.some((p) => file.startsWith(p));
  const inSection = WORDS.noun.allowed_sections.some((s) => s.file === file && heading.replace(/^[0-9.]+\s+/, '').startsWith(s.heading));
  if (!inPath && !inSection) return false;
  // Every occurrence on the line must be part of a technical term.
  let rest = line;
  for (const ok of NOUN_OK) rest = rest.replace(new RegExp(ok.source, `${ok.flags}g`), ' ');
  return !NOUN.test(rest);
}

/** Findings in one text, as `<where>:<line>: <rule id>` strings (the text itself is never printed). */
export function findings(text, where, phraseRules = [], { file = where } = {}) {
  const out = [];
  const lines = text.split(/\r?\n/);
  const headings = file.endsWith('.md') ? headingsByLine(lines) : lines.map(() => '');
  const base = file.split('/').pop();
  lines.forEach((line, i) => {
    const at = `${where}:${i + 1}`;
    if (NOUN.test(line) && !nounAllowed(file, line, headings[i])) out.push(`${at}: ${WORDS.noun.id}`);
    for (const rule of WORDS.banned) {
      if (!re(rule).test(line)) continue;
      if (rule.allow_files?.includes(base)) continue;
      if (rule.allow_lines?.some((p) => new RegExp(p).test(line))) continue;
      out.push(`${at}: ${rule.id}`);
    }
    for (const m of line.matchAll(new RegExp(HOST.source, `${HOST.flags}g`))) {
      if (!HOST_OK.has(m[0].toLowerCase())) {
        out.push(`${at}: ${WORDS.hosts.id}`);
        break;
      }
    }
    for (const rule of [...WORDS.paths, ...WORDS.markers]) if (re(rule).test(line)) out.push(`${at}: ${rule.id}`);
    if (PLAN_ID.test(line.replace(BLOB, ' '))) out.push(`${at}: ${WORDS.plan_id.id}`);
    for (const rule of phraseRules) if (rule.re.test(line)) out.push(`${at}: phrase rule ${rule.id}`);
  });
  return out;
}

function git(args) {
  return execFileSync('git', args, {
    cwd: REPO,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function trackedFiles() {
  const listed = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean);
  return [...new Set(listed)]
    .filter((f) => existsSync(join(REPO, f)))
    .filter((f) => !WORDS.skip_files.includes(f))
    .filter((f) => !WORDS.skip_dirs.some((d) => f.startsWith(d)))
    .filter((f) => !WORDS.binary_extensions.some((e) => f.toLowerCase().endsWith(e)))
    .sort();
}

function scanFiles(files, phraseRules) {
  const out = [];
  for (const file of files) {
    const text = readFileSync(join(REPO, file), 'utf8');
    if (text.includes('\0')) continue;
    out.push(...findings(text, file, phraseRules, { file }));
  }
  return out;
}

function defaultRange() {
  const base = process.env.GITHUB_BASE_REF;
  if (base) return `origin/${base}..HEAD`;
  const before = process.env.EVER_PUSH_BEFORE;
  if (before) {
    const hasParent = (() => {
      try {
        git(['rev-parse', '--verify', '--quiet', 'HEAD~1']);
        return true;
      } catch {
        return false;
      }
    })();
    const lastOnly = hasParent ? 'HEAD~1..HEAD' : 'HEAD';
    if (/^0+$/.test(before)) return lastOnly;
    try {
      git(['cat-file', '-e', `${before}^{commit}`]);
      return `${before}..HEAD`;
    } catch {
      return lastOnly;
    }
  }
  try {
    git(['rev-parse', '--verify', '--quiet', 'origin/develop']);
    return 'origin/develop..HEAD';
  } catch {
    return null;
  }
}

function scanCommits(range, phraseRules) {
  let log;
  try {
    log = git(['log', '--format=%H%n%B%n--end-of-commit--', range]);
  } catch {
    process.stdout.write(`check-public-safe: commit range ${range} not available: commit messages skipped\n`);
    return [];
  }
  const out = [];
  for (const block of log.split('--end-of-commit--\n').filter((b) => b.trim() !== '')) {
    const [sha = '', ...body] = block.split('\n');
    out.push(...findings(body.join('\n'), `commit ${sha.slice(0, 12)}`, phraseRules, { file: COMMIT_MESSAGE }));
  }
  return out;
}

function branchName() {
  if (process.env.GITHUB_HEAD_REF) return process.env.GITHUB_HEAD_REF;
  if (process.env.GITHUB_REF_NAME) return process.env.GITHUB_REF_NAME;
  try {
    return git(['rev-parse', '--abbrev-ref', 'HEAD']).trim();
  } catch {
    return '';
  }
}

function loadPhraseRules() {
  const env = process.env.EVER_BANNED_PHRASES_JSON;
  if (env && env.trim() !== '') return { source: 'the CI secret', rules: compilePhraseList(JSON.parse(env)) };
  if (existsSync(LOCAL_LIST)) return { source: 'the local file', rules: compilePhraseList(JSON.parse(readFileSync(LOCAL_LIST, 'utf8'))) };
  return { source: null, rules: [] };
}

function selfTest() {
  const expectFail = {
    'bad-network-noun.md': 'N1',
    'bad-plan-id.md': 'PID',
    'bad-draft-marker.md': 'M1',
    'bad-internal-host.md': 'H1',
    'bad-task-id.md': 'PID',
    'bad-section-sign.md': 'S1',
    'bad-design-doc.md': 'C1',
  };
  const problems = [];
  for (const [name, rule] of Object.entries(expectFail)) {
    const text = readFileSync(join(FIXTURES, name), 'utf8');
    const found = findings(text, name, [], { file: `docs/${name}` });
    if (!found.some((f) => f.endsWith(`: ${rule}`))) problems.push(`${name} did not fail rule ${rule}`);
  }
  // The technical uses pass inside the egress harness and fail everywhere else.
  const ok = readFileSync(join(FIXTURES, 'ok-docker-network.md'), 'utf8');
  const okFound = findings(ok, 'ok-docker-network.md', [], { file: 'tools/egress-audit/ok-docker-network.md' });
  if (okFound.length > 0) problems.push(`ok-docker-network.md failed: ${okFound.join(', ')}`);
  const outside = findings(ok, 'ok-docker-network.md', [], { file: 'docs/ok-docker-network.md' });
  if (!outside.some((f) => f.endsWith(': N1'))) problems.push('ok-docker-network.md passed outside tools/egress-audit/');
  // A commit message may name the technical terms, and only those.
  if (findings(ok, 'commit', [], { file: COMMIT_MESSAGE }).length > 0) problems.push('a technical commit message failed');
  const noun = readFileSync(join(FIXTURES, 'bad-network-noun.md'), 'utf8');
  if (!findings(noun, 'commit', [], { file: COMMIT_MESSAGE }).some((f) => f.endsWith(': N1')))
    problems.push('a commit message with the noun passed');
  // A private phrase is caught and never printed.
  const phrases = compilePhraseList({ phrases: ['planted phrase'], patterns: [{ pattern: 'secret\\s+word' }] });
  const planted = findings('A Planted  Phrase and a secret word.', 'planted', phrases, { file: 'docs/x.md' });
  if (planted.filter((f) => f.includes('phrase rule')).length !== 2) problems.push('a private phrase was missed');
  if (planted.some((f) => /planted phrase|secret/i.test(f))) problems.push('a finding printed the matched text');
  // A signature blob never trips the identifier rule; a real identifier in prose does.
  const blob = `${'x'.repeat(30)}-${['D', '12'].join('-')}-${'y'.repeat(30)}`;
  if (findings(blob, 'blob', [], { file: 'contracts/x.json' }).length > 0) problems.push('a base64url blob was flagged');
  if (problems.length > 0) {
    process.stderr.write(`check-public-safe self-test FAILED:\n  ${problems.join('\n  ')}\n`);
    process.exit(1);
  }
  process.stdout.write(
    `check-public-safe self-test: ok (${Object.keys(expectFail).length} bad fixtures fail, the technical fixture passes only inside the harness)\n`,
  );
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) return selfTest();
  const { source, rules } = loadPhraseRules();
  process.stdout.write(
    source
      ? `check-public-safe: ${rules.length} private phrase rule(s) from ${source}\n`
      : 'check-public-safe: no private phrase list (EVER_BANNED_PHRASES_JSON unset): phrase rules skipped\n',
  );
  const out = [];
  const filesAt = args.indexOf('--files');
  const files = filesAt >= 0 ? args.slice(filesAt + 1).filter((a) => !a.startsWith('--')) : trackedFiles();
  out.push(...scanFiles(files, rules));
  if (filesAt < 0) {
    const commitsAt = args.indexOf('--commits');
    const range = commitsAt >= 0 ? args[commitsAt + 1] : defaultRange();
    if (range) out.push(...scanCommits(range, rules));
    const branch = branchName();
    if (branch) out.push(...findings(branch, 'branch name', rules, { file: '' }));
  }
  if (out.length > 0) {
    process.stderr.write(`check-public-safe: ${out.length} finding(s):\n  ${out.join('\n  ')}\n`);
    process.exit(1);
  }
  process.stdout.write(`check-public-safe: ok (${files.length} file(s))\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
