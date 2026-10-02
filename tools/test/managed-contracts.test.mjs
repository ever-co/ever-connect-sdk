// Managed operations: the two event types, the result call as its own row, the per-kind fixtures
// and the integration definition.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import { REPO, readJson } from '../lib/common.mjs';
import { validateComponent, validateEventData } from '../mock-platform/src/validate.mjs';

const KINDS = ['update', 'backup', 'restore-check', 'health-report'];
const fixture = (p) => readJson(join(REPO, 'contracts/fixtures', p));

test('both managed-operation event types are vendored and on the instance feed', () => {
  const constants = readJson(join(REPO, 'contracts/constants.json'));
  for (const type of ['ever.registry.managed_operation.requested', 'ever.registry.managed_operation.state_changed']) {
    assert.ok(constants.feed_event_types.includes(type), type);
    assert.ok(existsSync(join(REPO, 'contracts/schemas/events', `${type}.v1.schema.json`)), type);
  }
});

test('one valid request per kind; an unknown or missing param fails at its path', () => {
  const type = 'ever.registry.managed_operation.requested';
  for (const kind of KINDS) {
    const page = fixture(`feed/managed-operation-requested.${kind}.json`);
    assert.equal(validateEventData(type, page.events[0].data).ok, true, kind);
    for (const [suffix, path] of [
      ['unknown-param', /^\/params\//],
      ['missing-params', /^\/params$/],
    ]) {
      const bad = fixture(`feed/managed-operation-requested.${kind}.invalid-${suffix}.json`).events[0].data;
      const r = validateEventData(type, bad);
      assert.equal(r.ok, false, `${kind} ${suffix}`);
      assert.match(r.errors[0].path, path, `${kind} ${suffix}`);
    }
  }
});

test('the result body carries status and size only; a file name or an unknown status fails', () => {
  assert.equal(validateComponent('ManagedOperationResult', fixture('requests/managed-operation-result.json')).ok, true);
  const fileName = validateComponent('ManagedOperationResult', fixture('requests/managed-operation-result.invalid-file-name.json'));
  assert.equal(fileName.ok, false);
  assert.equal(fileName.errors[0].path, '/file_name');
  const status = validateComponent('ManagedOperationResult', fixture('requests/managed-operation-result.invalid-bad-status.json'));
  assert.equal(status.errors[0].path, '/status');
  const spec = YAML.parse(readFileSync(join(REPO, 'contracts/openapi/ever-platform.v1.yaml'), 'utf8'));
  assert.deepEqual(Object.keys(spec.components.schemas.ManagedOperationResult.properties).sort(), [
    'artefact_ref',
    'size_bytes',
    'status',
    'version',
  ]);
});

test('the result call is its own row, gated by the managed_operations integration', () => {
  const rows = readJson(join(REPO, 'contracts/openapi/rows.json')).rows;
  const row = rows.find((r) => r.operation_ids.includes('instanceReportManagedOperationResult'));
  assert.equal(row.row, 34);
  assert.equal(row.integration, 'managed_operations');
  assert.equal(row.operation_ids.length, 1);
  const spec = YAML.parse(readFileSync(join(REPO, 'contracts/openapi/ever-platform.v1.yaml'), 'utf8'));
  const op = spec.paths['/v1/instances/me/managed-operations/{operation}/result'].post;
  assert.equal(op['x-ever-row'], 34);
  assert.equal(op['x-ever-integration'], 'managed_operations');
  const calls = readJson(join(REPO, 'contracts/generated/outbound-calls.json')).rows;
  assert.equal(calls.find((r) => r.row === 34).endpoints[0].path, '/v1/instances/me/managed-operations/{operation}/result');
});

test('the managed_operations definition is shipped as coming soon, self-hosted only', () => {
  const def = readJson(join(REPO, 'contracts/integrations/managed_operations.json'));
  assert.equal(def.status, 'coming_soon');
  assert.equal(def.availability.cloud, 'not_applicable');
  assert.equal(def.availability.self_hosted, 'available');
  assert.equal(def.defaults.self_hosted, false);
});

test('the outbound-call page lists the result row (once the docs page exists)', (t) => {
  const page = join(REPO, 'docs/outbound-calls.md');
  if (!existsSync(page)) {
    t.skip('docs/outbound-calls.md not written yet');
    return;
  }
  assert.match(readFileSync(page, 'utf8'), /\| 34 \| `POST \/v1\/instances\/me\/managed-operations\/\{operation\}\/result`/);
});
