// The positive_managed control on the call log recorded by a real harness run: after the managed
// operation was requested (the mark), only the feed read (row 7) and the result call (row 34).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { checkCallLog, loadModes } from '../assert-call-log.mjs';

const recorded = JSON.parse(readFileSync(new URL('./samples/positive-managed.requests.json', import.meta.url), 'utf8'));
const MARK = 5; // the call-log length when the operation was requested in that run
const mode = loadModes().positive_managed;

test('the recorded run holds only the feed read and the result call after the request', () => {
  const after = [...new Set(recorded.slice(MARK).map((e) => e.row))].sort((a, b) => a - b);
  assert.deepEqual(after, [7, 34]);
  const r = checkCallLog(recorded, mode, { mark: MARK });
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.rows, [1, 3, 4, 7, 34]);
});

test('an extra call after the request fails the run', () => {
  const heartbeat = { ...recorded[MARK], method: 'POST', path_template: '/v1/instances/me/heartbeat', row: 6 };
  const r = checkCallLog([...recorded, heartbeat], mode, { mark: MARK });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /row 6 was called after the trigger; only 7, 34 may be/.test(p)));
});

test('a call outside the mode at all fails, before or after the request', () => {
  const stats = { ...recorded[0], method: 'POST', path_template: '/v1/stats/reports', row: 17, status: 202 };
  assert.ok(checkCallLog([stats, ...recorded], mode, { mark: MARK + 1 }).problems.some((p) => /row 17 is not allowed/.test(p)));
});

test('no result call after the request fails; so does a run whose trigger never ran', () => {
  const noResult = recorded.filter((e) => e.row !== 34);
  assert.ok(checkCallLog(noResult, mode, { mark: MARK }).problems.some((p) => /row 34 was not called after the trigger/.test(p)));
  assert.ok(checkCallLog(recorded, mode, { mark: null }).problems.some((p) => /trigger never ran/.test(p)));
});
