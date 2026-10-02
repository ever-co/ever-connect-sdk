// The instance-facing contract: every row is covered, nothing internal is left, pending rows stay
// out of the spec, and the row checks catch a missing or unknown operation.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import { checkPins, checkScope, pinLines } from '../check-schema-drift.mjs';
import { REPO, readJson } from '../lib/common.mjs';
import { applyTransform, CATALOG_PINS } from '../lib/vendor.mjs';
import { checkRows } from '../sync-contract.mjs';

const spec = YAML.parse(readFileSync(join(REPO, 'contracts/openapi/ever-platform.v1.yaml'), 'utf8'));
const rowsDoc = readJson(join(REPO, 'contracts/openapi/rows.json'));
const pending = readJson(join(REPO, 'contracts/openapi/pending-upstream.json'));
const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
const ops = Object.entries(spec.paths).flatMap(([path, item]) =>
  METHODS.filter((m) => item[m]).map((m) => ({ method: m, path, op: item[m] })),
);

test('the table has 34 contiguous rows and every row is covered by the spec or pending upstream', () => {
  assert.equal(rowsDoc.rows.length, 34);
  rowsDoc.rows.forEach((r, i) => assert.equal(r.row, i + 1));
  for (const r of rowsDoc.rows) {
    if (r.pending_upstream) {
      assert.ok(
        pending.operations.some((p) => p.row === r.row),
        `row ${r.row} has no pending-upstream entry`,
      );
      continue;
    }
    for (const id of r.operation_ids) {
      const found = ops.find((o) => o.op.operationId === id);
      assert.ok(found, `row ${r.row}: ${id} is not in the spec`);
      assert.equal(found.op['x-ever-row'], r.row, `${id} carries the wrong x-ever-row`);
    }
  }
});

test('every operation carries a row', () => {
  for (const { method, path, op } of ops) assert.ok(Number.isInteger(op['x-ever-row']), `${method} ${path} has no x-ever-row`);
});

test('no staff, internal or person-session operation is left', () => {
  for (const { path, op } of ops) {
    assert.ok(!path.startsWith('/v1/staff'), `${path} is a staff route`);
    assert.ok(!path.startsWith('/internal'), `${path} is an internal route`);
    const schemes = (op.security ?? []).flatMap((s) => Object.keys(s));
    for (const banned of [
      'personSession',
      'staffSession',
      'orgApiKey',
      'onboardingToken',
      'deletionLinkToken',
      'everIdToken',
      'webhookSignature',
    ])
      assert.ok(!schemes.includes(banned), `${op.operationId} accepts ${banned}`);
  }
  for (const banned of ['personSession', 'staffSession', 'orgApiKey'])
    assert.ok(!(banned in (spec.components.securitySchemes ?? {})), `the spec defines ${banned}`);
});

test('the installation address (row 18) and the other pending rows are only in pending-upstream.json', () => {
  for (const p of pending.operations) {
    assert.ok(!spec.paths[p.path]?.[p.method.toLowerCase()], `${p.method} ${p.path} is in the spec although pending upstream`);
  }
  const row18 = pending.operations.filter((p) => p.row === 18);
  assert.deepEqual(row18.map((p) => `${p.method} ${p.path}`).sort(), [
    'DELETE /v1/instances/me/public-url',
    'PUT /v1/instances/me/public-url',
  ]);
  assert.deepEqual(Object.keys(row18.find((p) => p.method === 'PUT').request.properties), ['base_url']);
});

test('the redeem body carries no address and every request body is closed', () => {
  const redeem = spec.components.schemas.RedeemRequest;
  assert.equal(redeem.additionalProperties, false);
  for (const banned of ['public_url', 'url', 'base_url', 'instance_url']) assert.ok(!(banned in redeem.properties));
  for (const { op } of ops) {
    const ref = op.requestBody?.content?.['application/json']?.schema?.$ref;
    if (!ref) continue;
    const schema = spec.components.schemas[ref.split('/').pop()];
    assert.equal(schema.additionalProperties, false, `${op.operationId}: ${ref} is not closed`);
  }
});

test('operationIds are kept verbatim from the platform', () => {
  const ids = new Set(ops.map((o) => o.op.operationId));
  for (const id of [
    'get_key_manifest',
    'connectRedeem',
    'instanceToken',
    'ingestStatsReport',
    'getLookupSalt',
    'instanceHeartbeat',
    'instancePollEvents',
  ])
    assert.ok(ids.has(id), `${id} is missing`);
});

test('the row checks catch an operation without a row and a row naming a missing operation', () => {
  const ids = new Set(ops.map((o) => o.op.operationId));
  assert.deepEqual(checkRows(rowsDoc, ids, pending).problems, []);
  const extra = new Set([...ids, 'instanceUnlistedCall']);
  assert.ok(checkRows(rowsDoc, extra, pending).problems.some((p) => p.includes('instanceUnlistedCall has no row')));
  const mutated = structuredClone(rowsDoc);
  mutated.rows[5].operation_ids.push('instanceDoesNotExist');
  assert.ok(checkRows(mutated, ids, pending).problems.some((p) => p.includes('instanceDoesNotExist')));
});

test('the committed contract matches the platform checkout (when EVER_PLATFORM_REPO is set)', async (t) => {
  if (!process.env.EVER_PLATFORM_REPO) {
    t.skip('EVER_PLATFORM_REPO is unset');
    return;
  }
  const { execFileSync } = await import('node:child_process');
  execFileSync(process.execPath, ['tools/sync-contract.mjs', '--check'], { cwd: REPO, stdio: 'pipe' });
});

test('the vendored schemas match the checksums the platform pins (contracts/SCHEMAS.sha256)', () => {
  const files = readJson(join(REPO, 'contracts/VENDOR.json')).files;
  const pinned = ['contracts/schemas/ever.entitlement.v1.json', 'contracts/schemas/ever.usage.v1.json'].map((p) =>
    files.find((f) => f.path === p),
  );
  const pins = `# comment\n${pinned.map((f) => `${f.sha256}  ${f.source}`).join('\n')}\n`;
  assert.deepEqual(checkPins(pins, files), []);
  assert.match(checkPins(pins.replace(pinned[1].sha256, '0'.repeat(64)), files)[0], /the platform pins/);
  assert.match(checkPins(`${'1'.repeat(64)}  contracts/other/x.json\n`, files)[0], /not vendored/);
});

test('--strict=stats: the statistics schema, fixtures and calls are published and vendored byte for byte', () => {
  const vendorDoc = readJson(join(REPO, 'contracts/VENDOR.json'));
  assert.deepEqual(checkScope('stats', vendorDoc), []);
  const fixtures = vendorDoc.files.filter((e) => e.path.startsWith('contracts/fixtures/stats/')).map((e) => e.path);
  assert.equal(fixtures.length, 19, 'expected.json, 5 valid and 13 invalid reports');
  const mutate = (fn) => {
    const doc = structuredClone(vendorDoc);
    fn(doc);
    return checkScope('stats', doc);
  };
  const entry = (doc, path) => doc.files.find((e) => e.path === path);
  assert.match(mutate((d) => Object.assign(entry(d, fixtures[0]), { provisional: true, upstream: 'x' }))[0], /provisional/);
  assert.match(mutate((d) => Object.assign(entry(d, 'contracts/schemas/ever.stats.v1.json'), { transform: 't' }))[0], /transform/);
  assert.match(mutate((d) => d.authored.push({ path: 'contracts/fixtures/stats/', until: 'x' }))[0], /still authored/);
  assert.match(mutate((d) => d.openapi.provisional_operations.push('ingestStatsReport'))[0], /ingestStatsReport/);
  assert.match(
    mutate((d) => {
      d.files = d.files.filter((e) => e.path !== fixtures[1]);
    })[0],
    /not in VENDOR\.json/,
  );
  const extra = 'contracts/fixtures/stats/invalid/99-local.json';
  assert.match(checkScope('stats', vendorDoc, { present: [...fixtures, extra] })[0], /99-local/);
  assert.match(checkScope('nope', vendorDoc)[0], /no such scope/);
  const sha = entry(vendorDoc, 'contracts/schemas/ever.stats.v1.json').sha256;
  const pins = pinLines(['# comment', `${sha}  contracts/stats/ever.stats.v1.schema.json`, ''].join('\n'));
  assert.equal(pins.get('contracts/stats/ever.stats.v1.schema.json'), sha);
});

test('the catalog transform pins public names and statuses and drops hidden rows', () => {
  const seed = YAML.stringify({
    integrations: [
      { key: 'managed_operations', name: 'Working name', status: 'coming_soon' },
      { key: 'counterparty_lookup', name: 'Lookup', status: 'active' },
      { key: 'reserved_key', name: 'Reserved', status: 'hidden' },
    ],
  });
  const doc = JSON.parse(applyTransform('catalog-yaml', seed));
  assert.deepEqual(
    doc.integrations.map((r) => [r.key, r.name, r.status]),
    [
      ['managed_operations', CATALOG_PINS.name.managed_operations, 'coming_soon'],
      ['counterparty_lookup', 'Lookup', 'coming_soon'],
    ],
  );
  const vendored = readJson(join(REPO, 'contracts/integrations/catalog.v1.json')).integrations;
  for (const [key, name] of Object.entries(CATALOG_PINS.name)) {
    assert.equal(vendored.find((r) => r.key === key)?.name, name, `${key} carries its public name in the vendored catalog`);
    assert.equal(readJson(join(REPO, `contracts/integrations/${key}.json`)).name, name, `${key} carries its public name in its definition`);
  }
});
