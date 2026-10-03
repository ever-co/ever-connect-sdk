#!/usr/bin/env node
/**
 * sync-contract: refreshes the contract this repository is built from, out of an ever-co/platform
 * checkout (EVER_PLATFORM_REPO):
 *
 *   contracts/openapi/ever-platform.v1.yaml   the instance-facing subset of the Ever Platform API,
 *                                             every operation stamped with its outbound-call row
 *   contracts/schemas/**, contracts/integrations/catalog.v1.json, contracts/fixtures/lookup/…,
 *   contracts/fixtures/connect/vectors/**, contracts/fixtures/stats/**,
 *   contracts/fixtures/entitlement-platform/**
 *                                             the vendored schemas, catalog, vectors and fixtures
 *   contracts/VENDOR.json                     where each file came from, its sha256, and which
 *                                             sources are still provisional
 *
 *   EVER_PLATFORM_REPO=../platform node tools/sync-contract.mjs           write
 *   EVER_PLATFORM_REPO=../platform node tools/sync-contract.mjs --check   regenerate and compare
 *
 * The check fails on any difference and names the operations (or files) that differ.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { join, relative } from 'node:path';
import YAML from 'yaml';
import { diffOutputs, platformRepo, REPO, readJson, sha256, stableJson, walk, writeText } from './lib/common.mjs';
import { buildSubset, METHODS, subsetYaml } from './lib/openapi-subset.mjs';
import { CONNECT_VECTORS, ENTITLEMENT_FIXTURES, STATS_FIXTURES, vendor } from './lib/vendor.mjs';

const SPEC_PATH = 'contracts/openapi/ever-platform.v1.yaml';
const VENDOR_PATH = 'contracts/VENDOR.json';

export function loadRows() {
  const doc = readJson(join(REPO, 'contracts/openapi/rows.json'));
  return doc;
}

/** Row checks shared with the generator: numbering, operations and pending rows. */
export function checkRows(rowsDoc, operationIds, pending) {
  const problems = [];
  const rows = rowsDoc.rows;
  rows.forEach((r, i) => {
    if (r.row !== i + 1) problems.push(`rows.json: row ${r.row} is out of order (expected ${i + 1})`);
  });
  const byOp = new Map();
  for (const r of rows) {
    // Every row tells the operator what triggers it, what it carries, how often and how to stop it.
    for (const field of ['title', 'module', 'group', 'trigger', 'payload', 'cadence', 'disable'])
      if (typeof r[field] !== 'string' || r[field].trim() === '') problems.push(`row ${r.row} has no ${field}`);
    if (!Number.isInteger(r.phase)) problems.push(`row ${r.row} has no phase`);
    if (r.products !== 'all' && !(Array.isArray(r.products) && r.products.length > 0) && !r.integration)
      problems.push(`row ${r.row} names no products`);
    for (const id of r.operation_ids) {
      if (byOp.has(id)) problems.push(`operation ${id} is named by rows ${byOp.get(id)} and ${r.row}`);
      byOp.set(id, r.row);
      if (!operationIds.has(id)) problems.push(`row ${r.row} names ${id}, which is not an operation of the contract`);
    }
    if (r.pending_upstream) {
      if (r.operation_ids.length > 0) problems.push(`row ${r.row} is pending upstream but names operations`);
      if (!pending.operations.some((p) => p.row === r.row))
        problems.push(`row ${r.row} is pending upstream but has no entry in pending-upstream.json`);
    } else if (r.operation_ids.length === 0) {
      problems.push(`row ${r.row} names no operation`);
    }
  }
  for (const id of operationIds) if (!byOp.has(id)) problems.push(`operation ${id} has no row in rows.json`);
  for (const p of pending.operations) {
    const row = rows.find((r) => r.row === p.row);
    if (!row?.pending_upstream) problems.push(`pending-upstream.json names row ${p.row}, which is not marked pending_upstream`);
  }
  return { problems, byOp };
}

function platformCommit(platform) {
  try {
    return execFileSync('git', ['-C', platform, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return 'unknown';
  }
}

/** Builds every output in memory: {files: {path: text}, report}. */
export function build(platform) {
  const config = readJson(join(REPO, 'contracts/openapi/sync.config.json'));
  const pending = readJson(join(REPO, 'contracts/openapi/pending-upstream.json'));
  const rowsDoc = loadRows();
  const version = readFileSync(join(REPO, 'contracts/VERSION'), 'utf8').trim();
  const rowsByOperation = new Map(rowsDoc.rows.flatMap((r) => r.operation_ids.map((id) => [id, r.row])));

  const subset = buildSubset({
    platform,
    config,
    rowsByOperation,
    version,
    securityOverrides: pending.security_overrides ?? {},
    title: 'Ever Platform API: instance-facing contract',
    description:
      'The calls an installation of an Ever product makes to Ever Platform: the operations that accept an instance token, the public operations a product calls (key manifest, connect, statistics, lookup salt) and the two Ever ID reads a product makes with the token of a person who signed in. Every operation carries `x-ever-row`, its row in the outbound-call table. Errors are `application/problem+json` with a stable `code`.',
  });

  // Recorded overrides of design schemas (each with its reason in pending-upstream.json). The
  // pinned contract is the server's truth: once it defines a schema, an override of it is stale.
  const pinnedSchemas = readJson(join(platform, config.pinned)).components?.schemas ?? {};
  for (const [name, override] of Object.entries(pending.schema_overrides ?? {})) {
    if (pinnedSchemas[name] !== undefined)
      throw new Error(`schema override ${name}: the pinned contract defines it now; drop the override from pending-upstream.json`);
    if (!subset.spec.components.schemas[name]) throw new Error(`schema override ${name}: no such schema in the subset`);
    subset.spec.components.schemas[name] = override.schema;
  }
  const refs = JSON.stringify(subset.spec).match(/#\/components\/schemas\/[A-Za-z0-9_.-]+/g) ?? [];
  for (const ref of new Set(refs)) {
    if (!subset.spec.components.schemas[ref.split('/').pop()]) throw new Error(`dangling reference ${ref}`);
  }

  const operationIds = new Set(subset.selected.map((o) => o.operationId));
  const { problems } = checkRows(rowsDoc, operationIds, pending);
  if (problems.length > 0) throw new Error(`rows do not match the contract:\n  ${problems.join('\n  ')}`);

  const header = '# Generated by tools/sync-contract.mjs from the Ever Platform API contract. Do not edit by hand.\n';
  const specText = subsetYaml(subset.spec, header);
  const vendored = vendor(platform);

  const pinnedPath = join(platform, config.pinned);
  const designHashes = subset.designFiles.map((f) => `${relative(platform, f).split('\\').join('/')} ${sha256(readFileSync(f))}`);
  const vendorDoc = {
    description:
      'Where every contract file of this repository comes from. Written by tools/sync-contract.mjs; checked by tools/check-schema-drift.mjs. `provisional` sources are drafts the platform has not published yet: tools/check-schema-drift.mjs --strict refuses them.',
    platform: { repository: 'ever-co/platform', commit: platformCommit(platform) },
    openapi: {
      target: SPEC_PATH,
      sha256: sha256(specText),
      pinned: { source: config.pinned, sha256: sha256(readFileSync(pinnedPath)) },
      design: { source: config.design.replace(/\/[^/]+$/, ''), sha256: sha256(designHashes.join('\n')), files: designHashes.length },
      operations: subset.selected.length,
      provisional_operations: subset.provisional,
      shape_differences: subset.shapeDifferences,
      renamed_schemas: subset.collisions,
      schema_overrides: Object.keys(pending.schema_overrides ?? {}).sort(),
      security_overrides: Object.keys(pending.security_overrides ?? {}).sort(),
      pending_upstream_rows: [...new Set(pending.operations.map((p) => p.row))].sort((a, b) => a - b),
    },
    events: vendored.events,
    files: vendored.entries,
    authored: [
      { path: 'contracts/schemas/ever.consent.v1.json', until: 'the platform publishes the consent record schema' },
      { path: 'contracts/schemas/ever.key-manifest.v1.json', until: 'the platform publishes the key manifest schema' },
      ...(vendored.entries.some((e) => e.path.startsWith(`${CONNECT_VECTORS.path}/`))
        ? []
        : [{ path: `${CONNECT_VECTORS.path}/`, until: 'the platform publishes its client-assertion vectors' }]),
      ...(vendored.entries.some((e) => e.path.startsWith(`${STATS_FIXTURES.path}/`))
        ? []
        : [{ path: `${STATS_FIXTURES.path}/`, until: 'the platform publishes the statistics fixtures and expected outcomes' }]),
    ],
  };

  const files = { [SPEC_PATH]: specText, ...vendored.files, [VENDOR_PATH]: stableJson(vendorDoc, { sort: false }) };
  return { files, subset, vendorDoc };
}

/** The operationIds whose generated YAML differs between two spec texts. */
function changedOperations(expectedText, actualText) {
  const parse = (t) => {
    try {
      return YAML.parse(t) ?? {};
    } catch {
      return {};
    }
  };
  const a = parse(expectedText);
  const b = parse(actualText);
  const ops = (doc) => {
    const out = new Map();
    for (const [path, item] of Object.entries(doc.paths ?? {}))
      for (const m of METHODS) if (item?.[m]) out.set(item[m].operationId ?? `${m} ${path}`, JSON.stringify(item[m]));
    return out;
  };
  const ea = ops(a);
  const eb = ops(b);
  const ids = [...new Set([...ea.keys(), ...eb.keys()])].filter((id) => ea.get(id) !== eb.get(id)).sort();
  const schemas = (doc) => doc.components?.schemas ?? {};
  const sa = schemas(a);
  const sb = schemas(b);
  const names = [...new Set([...Object.keys(sa), ...Object.keys(sb)])]
    .filter((n) => JSON.stringify(sa[n]) !== JSON.stringify(sb[n]))
    .sort();
  return { ids, names };
}

function main() {
  const check = process.argv.includes('--check');
  const platform = platformRepo();
  const { files, vendorDoc } = build(platform);
  const current = {};
  // Files written before but no longer produced (an event schema that left the instance audience,
  // an authored vector or fixture the platform's published set replaces).
  const ownedDirs = ['contracts/schemas/events'];
  for (const vendored of [CONNECT_VECTORS, STATS_FIXTURES, ENTITLEMENT_FIXTURES])
    if (vendorDoc.files.some((e) => e.path.startsWith(`${vendored.path}/`))) ownedDirs.push(vendored.path);
  for (const dir of ownedDirs)
    for (const path of walk(join(REPO, dir)).map((p) => relative(REPO, p).split('\\').join('/')))
      if (!(path in files)) current[path] = readFileSync(join(REPO, path), 'utf8');
  for (const path of Object.keys(files)) {
    try {
      current[path] = readFileSync(join(REPO, path), 'utf8');
    } catch {
      current[path] = undefined;
    }
  }
  // The platform commit alone is not drift: a later checkout with identical sources passes.
  const normalise = (path, text) => (path === VENDOR_PATH && text ? text.replace(/"commit": "[^"]*"/, '"commit": "-"') : text);
  const expected = Object.fromEntries(Object.entries(files).map(([p, t]) => [p, normalise(p, t)]));
  const actual = Object.fromEntries(Object.entries(current).map(([p, t]) => [p, normalise(p, t)]));
  const differing = diffOutputs(expected, actual);
  if (check) {
    if (differing.length === 0) {
      process.stdout.write(`sync-contract: ok (${vendorDoc.openapi.operations} operations, ${vendorDoc.files.length} vendored files)\n`);
      return;
    }
    const lines = [];
    for (const path of differing) {
      if (path === SPEC_PATH) {
        const { ids, names } = changedOperations(files[path], current[path] ?? '');
        lines.push(`${path}: operations ${ids.join(', ') || '(none)'}; schemas ${names.join(', ') || '(none)'}`);
      } else {
        lines.push(`${path}: ${files[path] === undefined ? 'no longer produced' : current[path] === undefined ? 'missing' : 'differs'}`);
      }
    }
    process.stderr.write(
      `sync-contract: the committed contract differs from the platform checkout:\n  ${lines.join('\n  ')}\nRun: EVER_PLATFORM_REPO=<checkout> node tools/sync-contract.mjs\n`,
    );
    process.exit(1);
  }
  for (const [path, text] of Object.entries(files)) writeText(join(REPO, path), text);
  for (const path of Object.keys(current)) if (!(path in files)) rmSync(join(REPO, path));
  process.stdout.write(
    `sync-contract: wrote ${Object.keys(files).length} files (${vendorDoc.openapi.operations} operations, ${vendorDoc.openapi.provisional_operations.length} provisional; platform ${vendorDoc.platform.commit.slice(0, 12)})\n`,
  );
}

if (process.argv[1]?.endsWith('sync-contract.mjs')) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`sync-contract: ${error.message}\n`);
    process.exit(1);
  }
}
