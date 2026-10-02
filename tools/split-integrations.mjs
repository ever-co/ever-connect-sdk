#!/usr/bin/env node
/**
 * split-integrations: one definition file per integration key, and the contract-derived fields of
 * contracts/constants.json.
 *
 *   contracts/integrations/<key>.json   one row of the vendored catalog (hidden keys get none),
 *                                       with the corrections of contracts/integrations/overrides.json
 *   contracts/constants.json            contracts_version, code patterns, install_sources, products,
 *                                       stats_headers (from the statistics operation's headers),
 *                                       feed_event_types (instance audience of the event catalog),
 *                                       integration_keys and the TEST root in root_keys
 *
 *   node tools/split-integrations.mjs           write
 *   node tools/split-integrations.mjs --check   regenerate and compare
 */
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { diffOutputs, REPO, readJson, stableJson, writeText } from './lib/common.mjs';
import { testRootEntry } from './mock-platform/src/keys.mjs';

export const TEST_ROOT_ISSUER = 'http://mock-platform:8080';
const INTEGRATIONS_DIR = 'contracts/integrations';
const KEEP = new Set(['catalog.v1.json', 'overrides.json']);

export function entitlementFeatures() {
  const schema = readJson(join(REPO, 'contracts/schemas/ever.entitlement.v1.json'));
  return Object.keys(schema.properties.ever.properties.features.properties);
}

function spec() {
  return YAML.parse(readFileSync(join(REPO, 'contracts/openapi/ever-platform.v1.yaml'), 'utf8'));
}

/** The operation object by operationId. */
export function operation(doc, id) {
  for (const item of Object.values(doc.paths)) for (const op of Object.values(item)) if (op?.operationId === id) return op;
  throw new Error(`operation ${id} is not in the contract`);
}

export function build() {
  const catalog = readJson(join(REPO, INTEGRATIONS_DIR, 'catalog.v1.json'));
  const overrides = readJson(join(REPO, INTEGRATIONS_DIR, 'overrides.json'));
  const features = new Set(entitlementFeatures());
  const doc = spec();
  const products = doc.components.schemas.ProductCode.enum;
  const problems = [];
  const files = {};
  const keys = [];

  for (const row of catalog.integrations) {
    if (row.status === 'hidden') continue;
    const def = structuredClone(row);
    if (def.requires_feature !== null && def.requires_feature !== undefined && !features.has(def.requires_feature)) {
      const fix = overrides.requires_feature[def.requires_feature];
      if (!fix) problems.push(`${row.key}: requires_feature ${def.requires_feature} is not an entitlement feature and has no override`);
      else def.requires_feature = fix.to;
    }
    if (def.requires_feature !== null && !features.has(def.requires_feature))
      problems.push(`${row.key}: requires_feature ${def.requires_feature} is not a key of the entitlement features`);
    for (const p of def.products) if (!products.includes(p)) problems.push(`${row.key}: unknown product ${p}`);
    def.docs_anchor = row.key;
    files[`${INTEGRATIONS_DIR}/${row.key}.json`] = stableJson(def, { sort: false });
    keys.push(row.key);
  }
  if (problems.length > 0) throw new Error(problems.join('\n'));

  // Constants: refresh the fields read from the contract, keep everything else.
  const constants = readJson(join(REPO, 'contracts/constants.json'));
  const stats = operation(doc, 'ingestStatsReport');
  const headers = (stats.parameters ?? []).filter((p) => p.in === 'header').map((p) => p.name);
  const pick = (suffix) => {
    const found = headers.find((h) => h.endsWith(suffix) && !(suffix === '-Key' && h.endsWith('-Key-Id')));
    if (!found) throw new Error(`the statistics operation has no header ending in ${suffix}`);
    return found;
  };
  const vendorDoc = readJson(join(REPO, 'contracts/VENDOR.json'));
  constants.contracts_version = readFileSync(join(REPO, 'contracts/VERSION'), 'utf8').trim();
  constants.connect_code_pattern = doc.components.schemas.ConnectCode.pattern;
  constants.link_code_pattern = doc.components.schemas.LinkCode.pattern;
  constants.install_sources = doc.components.schemas.InstallSource.pattern;
  constants.products = products;
  constants.stats_headers = { key: pick('-Key'), signature: pick('-Signature'), key_id: pick('-Key-Id') };
  constants.feed_event_types = vendorDoc.events.instance_types;
  constants.integration_keys = keys;
  constants.root_keys = [testRootEntry(TEST_ROOT_ISSUER)];
  files['contracts/constants.json'] = stableJson(constants, { sort: false });
  return files;
}

function main() {
  const check = process.argv.includes('--check');
  const files = build();
  const dir = join(REPO, INTEGRATIONS_DIR);
  const current = {};
  for (const name of readdirSync(dir)) {
    if (KEEP.has(name)) continue;
    current[`${INTEGRATIONS_DIR}/${name}`] = readFileSync(join(dir, name), 'utf8');
  }
  for (const path of Object.keys(files)) current[path] = existsSync(join(REPO, path)) ? readFileSync(join(REPO, path), 'utf8') : undefined;
  const differing = diffOutputs(files, current);
  if (check) {
    if (differing.length > 0) {
      process.stderr.write(`split-integrations: out of date: ${differing.join(', ')}\nRun: node tools/split-integrations.mjs\n`);
      process.exit(1);
    }
    process.stdout.write(`split-integrations: ok (${Object.keys(files).length - 1} definitions)\n`);
    return;
  }
  for (const path of differing) {
    if (files[path] === undefined) rmSync(join(REPO, path));
    else writeText(join(REPO, path), files[path]);
  }
  process.stdout.write(`split-integrations: ${differing.length} file(s) updated (${Object.keys(files).length - 1} definitions)\n`);
}

if (process.argv[1]?.endsWith('split-integrations.mjs')) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`split-integrations: ${error.message}\n`);
    process.exit(1);
  }
}
