#!/usr/bin/env node
/**
 * copy-draft: copies the public documentation drafts of the Ever Platform modules from a checkout
 * of the platform repository into docs/:
 *
 *   ever-connect-outbound-calls.md    -> docs/outbound-calls.md
 *   anonymous-stats.md                -> docs/stats-schema.md
 *   integrations-and-data-scopes.md   -> docs/integrations.md
 *
 * Only a file whose first line carries the public-safe marker of the drafts is copied; anything else is
 * refused. Every HTML comment is stripped. The corrections where the contract wins over a draft are
 * applied (each one must apply, or already be applied upstream; a draft that changed under a
 * correction stops the copy). The blocks tools/generate.mjs fills become empty regions: run
 * `node tools/generate.mjs` afterwards.
 *
 *   EVER_PLATFORM_REPO=<platform checkout> node tools/copy-draft.mjs           write docs/
 *   EVER_PLATFORM_REPO=<platform checkout> node tools/copy-draft.mjs --check   compare (regions aside)
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, writeText } from './lib/common.mjs';

const MARKER = ['PUBLIC-SAFE', 'DRAFT'].join(' ');
const DRAFT_DIR = 'docs/docs-drafts';
const region = (name) => [`<!-- generated:${name} -->`, `<!-- /generated:${name} -->`];

const NOTHING_ELSE =
  "**Nothing else.** A row that names an integration runs only while that integration has an active consent recorded by Ever Platform, given on app.ever.co or in the product after a fresh Ever ID sign-in; the integrations that act for the whole installation also need the operator to accept them on the installation. Apart from the connect calls themselves, every connection-module row runs only while connected; row 17 runs only while statistics are enabled. This table is generated from the SDK's operation table in continuous integration, so a request the SDK can make and this page does not list fails the build.";

export const DRAFTS = [
  {
    from: 'ever-connect-outbound-calls.md',
    to: 'docs/outbound-calls.md',
    regions: [
      { heading: 'The table', block: 'intro', name: 'outbound-intro' },
      { heading: 'The table', block: 'table', name: 'outbound-calls' },
      { heading: 'Rows grouped by what they are for', block: 'table', name: 'outbound-groups' },
    ],
    fixes: [
      [
        'To verify yourself: Docker Compose and `tcpdump` (see §7).',
        'To verify yourself: Docker Compose and `tcpdump` (see *How to verify yourself* below).',
      ],
      ['the non-Ever hosts listed in §1;', 'the non-Ever hosts listed under *When nothing is sent*;'],
      [/^\*\*Nothing else\.\*\*.*$/m, NOTHING_ELSE],
      [
        /the `code` is stable: [^\n]*?\. The modules log/,
        `the \`code\` is stable. The codes the modules can receive on the calls above:\n${region('outbound-problems').join('\n')}\n\nThe modules log`,
      ],
      [
        /Turn on the connection module(?:,| and) connect, and you will see rows [^\n]*$/m,
        'Turn on the connection module and connect, and you will see rows 1, 3, 4, 6, 7, 8 and 9: the key manifest, the redeem, the token, then the heartbeat, the event feed, the entitlement and the integration states. `ever-egress-audit` in this repository automates the recipe (see `tools/egress-audit/README.md`).',
      ],
    ],
  },
  {
    from: 'anonymous-stats.md',
    to: 'docs/stats-schema.md',
    regions: [{ heading: 'What is sent', block: 'code', name: 'stats-example' }],
    fixes: [
      [
        /Example \(Ever Gauzy; the same document as the SDK's golden fixture [^\n]*\):/,
        "Example (Ever Gauzy), generated from the SDK's golden fixture `contracts/fixtures/stats/valid/gauzy.json`:",
      ],
      ['you can reset it (§5)', 'you can reset it (see *How to see what was sent*)'],
      ['The schema is published in the open-source SDK', 'The schema is published in the SDK'],
      [
        /The signature uses a key pair your installation generated on first boot; [^\n]*?The key proves continuity, not identity: the platform learns nothing about who you are from it\./,
        "The signature uses the statistics key, an Ed25519 key pair your installation generates on first boot for statistics only; the platform remembers the public key on first sight so that nobody else can submit reports under your `instance_id`. It is separate from the key of an Ever Platform connection: the connection key only authenticates the connection's calls and rotates on its own, and rotating it changes nothing here. The statistics key proves continuity, not identity: the platform learns nothing about who you are from it.",
      ],
      [
        /generates a new `instance_id` and key pair; the old series can no longer be continued; if the installation is connected to Ever Platform it is disconnected at the same time/,
        'generates a new statistics `instance_id` and statistics key; the old series can no longer be continued; an Ever Platform connection is not affected (its key is separate)',
      ],
    ],
  },
  {
    from: 'integrations-and-data-scopes.md',
    to: 'docs/integrations.md',
    regions: [{ heading: 'Catalog (v1)', block: 'table', name: 'integrations-catalog' }],
    fixes: [
      [
        '(`instance_url`, `stats_link`, `ever_id_login`, `webhooks`)',
        '(`instance_url`, `stats_link`, `ever_id_login`, `webhooks`, `managed_operations`)',
      ],
      [
        '*What this installation sends, and when* (rows 9–15, 18 and 20–24)',
        '*What this installation sends, and when* (every row that names an integration)',
      ],
    ],
  },
];

export function stripComments(text) {
  return `${text
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/^\s*\n/, '')
    .replace(/\n{3,}/g, '\n\n')
    .trimEnd()}\n`;
}

/** Applies one correction: it must apply once, or its result must already be there. */
export function applyFix(text, [find, replace], where) {
  const present = typeof find === 'string' ? text.includes(find) : find.test(text);
  if (present) {
    if (typeof find === 'string' && text.split(find).length > 2)
      throw new Error(`${where}: the correction for "${find.slice(0, 50)}" matches more than once`);
    return typeof find === 'string' ? text.split(find).join(replace) : text.replace(find, () => replace);
  }
  if (text.includes(replace)) return text;
  throw new Error(`${where}: neither the text to correct nor its correction is there: ${String(find).slice(0, 80)}`);
}

const headingText = (line) =>
  line
    .replace(/^#{1,6}\s+/, '')
    .replace(/^[0-9.]+\s+/, '')
    .trim();

/** Replaces a block under a heading (its intro paragraph, first table or first code block) with an empty region. */
export function markRegion(text, { heading, block, name }, where) {
  const lines = text.split('\n');
  const h = lines.findIndex((l) => /^#{1,6}\s/.test(l) && headingText(l) === heading);
  if (h < 0) throw new Error(`${where}: no heading "${heading}"`);
  const isHeading = (l) => /^#{1,6}\s/.test(l);
  let i = h + 1;
  let start;
  let end;
  if (block === 'table') {
    while (i < lines.length && !lines[i].startsWith('|')) {
      if (isHeading(lines[i])) throw new Error(`${where}: no table under "${heading}"`);
      i += 1;
    }
    start = i;
    while (i < lines.length && lines[i].startsWith('|')) i += 1;
    end = i;
  } else if (block === 'code') {
    while (i < lines.length && !lines[i].startsWith('```')) i += 1;
    start = i;
    i += 1;
    while (i < lines.length && !lines[i].startsWith('```')) i += 1;
    end = i + 1;
  } else if (block === 'intro') {
    while (i < lines.length && lines[i].trim() === '') i += 1;
    if (lines[i]?.startsWith('|') || lines[i]?.startsWith('<!--') || isHeading(lines[i] ?? ''))
      throw new Error(`${where}: no paragraph under "${heading}"`);
    start = i;
    while (i < lines.length && lines[i].trim() !== '') i += 1;
    end = i;
  } else throw new Error(`unknown block ${block}`);
  if (start >= lines.length || end > lines.length) throw new Error(`${where}: no ${block} under "${heading}"`);
  lines.splice(start, end - start, ...region(name));
  return lines.join('\n');
}

export function copyDraft(source, draft) {
  const first = source.split('\n')[0];
  if (!first.includes(MARKER)) throw new Error(`${draft.from} is not marked public-safe: refused`);
  let text = stripComments(source);
  for (const r of draft.regions) text = markRegion(text, r, draft.from);
  for (const fix of draft.fixes) text = applyFix(text, fix, draft.from);
  return text;
}

/** Empties every generated region, so a copy compares with a doc whose regions were filled. */
export const withoutRegions = (text) => text.replace(/(<!-- generated:([a-z-]+) -->)[\s\S]*?(<!-- \/generated:\2 -->)/g, '$1\n$3');

function main() {
  const platform = process.env.EVER_PLATFORM_REPO;
  if (!platform || !existsSync(join(platform, DRAFT_DIR))) {
    process.stderr.write(`copy-draft: set EVER_PLATFORM_REPO to a checkout of the platform repository (with ${DRAFT_DIR})\n`);
    return 2;
  }
  const check = process.argv.includes('--check');
  const differing = [];
  for (const draft of DRAFTS) {
    const out = copyDraft(readFileSync(join(platform, DRAFT_DIR, draft.from), 'utf8'), draft);
    const target = join(REPO, draft.to);
    if (check) {
      const current = existsSync(target) ? readFileSync(target, 'utf8') : '';
      if (withoutRegions(current) !== withoutRegions(out)) differing.push(draft.to);
    } else writeText(target, out);
  }
  if (check && differing.length > 0) {
    process.stderr.write(
      `copy-draft: ${differing.join(', ')} differ from the drafts; run node tools/copy-draft.mjs, then node tools/generate.mjs\n`,
    );
    return 1;
  }
  process.stdout.write(check ? 'copy-draft: ok\n' : `copy-draft: ${DRAFTS.length} docs written; now run node tools/generate.mjs\n`);
  return 0;
}

if (process.argv[1]?.endsWith('copy-draft.mjs')) process.exit(main());
