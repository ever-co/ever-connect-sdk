// contracts/constants.json agrees with the contract: header names, code patterns, products, the
// event feed types, integration keys and the TEST root.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import { REPO, readJson } from '../lib/common.mjs';
import { testKey } from '../mock-platform/src/keys.mjs';
import { entitlementFeatures } from '../split-integrations.mjs';

const constants = readJson(join(REPO, 'contracts/constants.json'));
const spec = YAML.parse(readFileSync(join(REPO, 'contracts/openapi/ever-platform.v1.yaml'), 'utf8'));
const opById = (id) =>
  Object.values(spec.paths)
    .flatMap((i) => Object.values(i))
    .find((o) => o?.operationId === id);

test('the statistics header names come from the statistics operation', () => {
  const headers = opById('ingestStatsReport').parameters.filter((p) => p.in === 'header');
  assert.deepEqual(constants.stats_headers, { key: 'Ever-Stats-Key', signature: 'Ever-Stats-Signature', key_id: 'Ever-Stats-Key-Id' });
  for (const name of Object.values(constants.stats_headers))
    assert.ok(
      headers.some((h) => h.name === name),
      `${name} is not a header of the operation`,
    );
  assert.equal(headers.find((h) => h.name === constants.stats_headers.key).required, true);
  assert.equal(headers.find((h) => h.name === constants.stats_headers.signature).required, true);
  for (const h of headers) assert.ok(!/^x-/i.test(h.name), 'no X- prefix');
});

test('code patterns, install sources and products equal the contract schemas where it states them', () => {
  const s = spec.components.schemas;
  // The pinned contract describes the connect code as the code resource (no pattern), so the
  // published pattern stays; a contract that states a pattern again wins.
  const stated = (name) => (typeof s[name]?.pattern === 'string' ? s[name].pattern : null);
  const codeSchema = stated('ConnectCodeValue') ?? stated('ConnectCode');
  if (codeSchema) assert.equal(constants.connect_code_pattern, codeSchema);
  if (stated('LinkCode')) assert.equal(constants.link_code_pattern, stated('LinkCode'));
  assert.equal(constants.install_sources, s.InstallSource.pattern);
  assert.ok(new RegExp(constants.link_code_pattern).test('EVL-TEST-0000-0002'));
  assert.deepEqual(constants.products, s.ProductCode.enum);
  assert.ok(constants.products.includes('demand'), 'demand is a product code (it answers product_not_supported)');
  const code = new RegExp(constants.connect_code_pattern);
  assert.ok(code.test('EVC-TEST-0000-0001'));
  assert.ok(!code.test('EVC-ILOU-0000-0001'), 'I, L, O and U are not Crockford symbols');
  assert.ok(new RegExp(constants.install_sources).test('partner:railway'));
});

test('feed event types are the instance audience of the vendored catalog', () => {
  const vendor = readJson(join(REPO, 'contracts/VENDOR.json'));
  assert.deepEqual(constants.feed_event_types, vendor.events.instance_types);
  assert.ok(constants.feed_event_types.includes('ever.registry.managed_operation.requested'));
  assert.ok(constants.feed_event_types.every((t) => /^ever\.[a-z_]+\.[a-z_]+\.[a-z_]+$/.test(t)));
});

test('integration keys are the non-hidden catalog keys and requires_feature names an entitlement feature', () => {
  const catalog = readJson(join(REPO, 'contracts/integrations/catalog.v1.json'));
  const visible = catalog.integrations.filter((i) => i.status !== 'hidden').map((i) => i.key);
  assert.deepEqual(constants.integration_keys, visible);
  assert.ok(
    catalog.integrations.every((i) => i.status !== 'hidden'),
    'the vendored catalog lists no hidden row',
  );
  const features = new Set(entitlementFeatures());
  for (const key of constants.integration_keys) {
    const def = readJson(join(REPO, 'contracts/integrations', `${key}.json`));
    assert.equal(def.key, key);
    assert.ok(def.requires_feature === null || features.has(def.requires_feature), `${key}: ${def.requires_feature}`);
  }
});

test('root_keys: the TEST root first, then the Ever Platform roots, each pinned to one issuer', () => {
  const [root, ...pinned] = constants.root_keys;
  assert.ok(root.kid.startsWith('test-'), 'a release refuses test- roots');
  assert.equal(root.x, testKey('root').x);
  assert.equal(constants.root_keys_file_env, 'EVER_PLATFORM_ROOT_KEYS_FILE');
  const kids = new Set();
  for (const key of pinned) {
    // ever-<yyyymm>-<4 hex of sha256 of x>: the platform's key id form, the root included.
    assert.match(key.kid, /^ever-[0-9]{6}-[0-9a-f]{4}$/);
    assert.equal(key.kid.slice(-4), createHash('sha256').update(key.x).digest('hex').slice(0, 4), key.kid);
    assert.equal(Buffer.from(key.x, 'base64url').length, 32, key.kid);
    assert.match(key.iss, /^https:\/\/[a-z0-9.-]+$/, key.kid);
    assert.deepEqual([key.kty, key.crv, key.use, key.alg], ['OKP', 'Ed25519', 'sig', 'EdDSA']);
    assert.ok(!kids.has(key.kid), key.kid);
    kids.add(key.kid);
  }
  assert.deepEqual(
    pinned.map((k) => k.iss),
    ['https://api-dev.ever.co', 'https://api-stage.ever.co'],
    'the development and staging roots (the production root comes with its own reviewed change)',
  );
});

test('the configurable numbers keep their documented defaults', () => {
  assert.deepEqual(constants.entitlement, { validity_s: 604800, refresh_after_s: 21600, grace_s: 2592000, max_reads_per_hour: 6 });
  assert.equal(constants.token_refresh_after_s, 3000);
  assert.equal(constants.heartbeat_interval_s, 86400);
  assert.equal(constants.assertion_max_ttl_s, 300);
  assert.equal(constants.stats.max_bytes, 16384);
  assert.equal(constants.lookup.max_hashes_per_query, 100);
  assert.equal(constants.step_up_max_age_s, 300);
});
