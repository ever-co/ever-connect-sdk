// The scope_version rule: a definition whose scope changes needs a higher scope_version (the change
// needs a new consent), and a scope_version never goes down. The committed lock pins every scope.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { REPO } from '../lib/common.mjs';
import { SCOPE_LOCK, scopeLock } from '../split-integrations.mjs';

const def = (scope_version, fields) => ({
  key: 'example_integration',
  scope_version,
  scope: fields.map((field_path) => ({ field_path, direction: 'to_ever', form: 'clear', frequency: 'once' })),
});

test('an unchanged scope keeps its version', () => {
  const { lock } = scopeLock([def(1, ['org.name'])]);
  assert.deepEqual(scopeLock([def(1, ['org.name'])], lock).problems, []);
});

test('a changed scope without a higher scope_version is refused', () => {
  const { lock } = scopeLock([def(1, ['org.name'])]);
  const r = scopeLock([def(1, ['org.name', 'org.website'])], lock);
  assert.match(r.problems.join(), /example_integration: the scope changed but scope_version stayed 1/);
});

test('a changed scope with a higher scope_version passes and moves the pin', () => {
  const { lock } = scopeLock([def(1, ['org.name'])]);
  const r = scopeLock([def(2, ['org.name', 'org.website'])], lock);
  assert.deepEqual(r.problems, []);
  assert.equal(r.lock.example_integration.scope_version, 2);
  assert.notEqual(r.lock.example_integration.scope_sha256, lock.example_integration.scope_sha256);
});

test('a scope_version never goes down', () => {
  const { lock } = scopeLock([def(3, ['org.name'])]);
  assert.match(scopeLock([def(2, ['org.name'])], lock).problems.join(), /went down from 3/);
});

test('the committed lock pins every published definition', () => {
  const lock = JSON.parse(readFileSync(join(REPO, 'contracts/integrations', SCOPE_LOCK), 'utf8')).integrations;
  const constants = JSON.parse(readFileSync(join(REPO, 'contracts/constants.json'), 'utf8'));
  assert.deepEqual(Object.keys(lock).sort(), [...constants.integration_keys].sort());
  for (const key of constants.integration_keys) {
    const definition = JSON.parse(readFileSync(join(REPO, 'contracts/integrations', `${key}.json`), 'utf8'));
    assert.equal(lock[key].scope_version, definition.scope_version, key);
  }
});
