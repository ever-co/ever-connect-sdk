// The conformance runner: every case passes against the mock (the mock against itself), and the
// comparison reports a status, a problem code or a required field that differs.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildRequest, compare, loadCases, run } from '../conformance/run.mjs';

test('every case passes against the mock, with the mock as the other side', async () => {
  const results = await run({ target: 'mock', againstMock: true });
  // target_only cases (the published schema) are asked of a running platform only.
  assert.equal(results.length, loadCases().filter((c) => !c.target_only).length);
  assert.ok(loadCases().some((c) => c.id === 'stats-fixture:invalid/13-sent-at-with-time'));
  for (const r of results) assert.deepEqual(r.diffs, [], r.id);
});

test('with issuance off, a well-formed redeem is 404 and a malformed one stays 422', async () => {
  const results = await run({ target: 'mock', againstMock: true, profile: { issuance: 'off' }, modules: ['connect'] });
  assert.ok(results.every((r) => r.module === 'connect'));
  for (const r of results) assert.deepEqual(r.diffs, [], r.id);
  assert.equal(results.find((r) => r.id === 'redeem-unknown-code').target, '404 not_found');
  assert.equal(results.find((r) => r.id === 'redeem-malformed').target, '422 validation_failed');
});

test('the cases stay non-destructive: no connect code that works, no organization change', () => {
  for (const c of loadCases()) {
    const req = buildRequest(c, 'http://127.0.0.1:1');
    assert.ok(['GET', 'POST'].includes(req.method), c.id);
    assert.doesNotMatch(String(req.body ?? ''), /EVC-TEST-|EVL-/, c.id);
    assert.ok(!req.path.startsWith('/v1/orgs'), c.id);
  }
});

test('a differing status, code or field is reported', () => {
  const c = { id: 'x', expect: { status: 422, code: 'code_invalid', required: ['errors'] } };
  assert.deepEqual(compare(c, { status: 422, code: 'code_invalid', body: { errors: [] } }), []);
  assert.deepEqual(compare(c, { status: 400, code: 'validation_failed', body: {} }), [
    'status 400, expected 422',
    'code validation_failed, expected code_invalid',
    'no errors in the answer',
  ]);
  assert.deepEqual(compare(c, { status: 422, code: 'code_invalid', body: { errors: [] } }, { status: 404, code: 'not_found' }), [
    'status 422, the other side 404',
    'code code_invalid, the other side not_found',
  ]);
});
