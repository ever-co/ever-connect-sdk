// assert-call-log.mjs: the recorded calls equal what each mode allows (positive_connect exactly
// rows 1, 3, 4, 6, 7, 8 and 9; every_trigger exactly the generated list; positive_stats an
// accepted report and nothing else).
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { checkCallLog, generatedRows, loadModes, main, parseJsonl } from '../assert-call-log.mjs';

const sample = (name) => JSON.parse(readFileSync(new URL(`./samples/${name}`, import.meta.url), 'utf8'));
const outbound = JSON.parse(readFileSync(new URL('../../mock-platform/contracts/generated/outbound-calls.json', import.meta.url), 'utf8'));
const modes = loadModes();
const entry = (row, method = 'GET', path = '/x', status = 200) => ({
  ts: '2026-10-02T04:10:09Z',
  method,
  path_template: path,
  row,
  status,
});

test('positive_connect: exactly rows 1, 3, 4, 6, 7, 8 and 9 pass', () => {
  const r = checkCallLog(sample('positive-connect.requests.json'), modes.positive_connect);
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.rows, [1, 3, 4, 6, 7, 8, 9]);
});

test('positive_connect: a call log with an extra row fails', () => {
  const log = [...sample('positive-connect.requests.json'), entry(17, 'POST', '/v1/stats/reports', 202)];
  const r = checkCallLog(log, modes.positive_connect);
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /row 17 is not allowed/.test(p)));
  assert.ok(r.problems.some((p) => /not exactly 1, 3, 4, 6, 7, 8, 9/.test(p)));
});

test('positive_connect: a missing row and a call outside the table fail', () => {
  const missing = sample('positive-connect.requests.json').filter((e) => e.row !== 8);
  assert.ok(checkCallLog(missing, modes.positive_connect).problems.some((p) => /row 8 was required/.test(p)));
  const unknown = [...sample('positive-connect.requests.json'), entry(null, 'GET', '/v1/unknown')];
  assert.ok(
    checkCallLog(unknown, modes.positive_connect).problems.some((p) => /outside the outbound-call table: GET \/v1\/unknown/.test(p)),
  );
});

test('positive_stats: one accepted report passes; a refused one or another row fails', () => {
  const log = sample('positive-stats.requests.json');
  assert.deepEqual(checkCallLog(log, modes.positive_stats).problems, []);
  const refused = log.map((e) => ({ ...e, status: 422 }));
  assert.ok(checkCallLog(refused, modes.positive_stats).problems.some((p) => /no statistics report was accepted/.test(p)));
  assert.ok(checkCallLog([...log, entry(6, 'POST')], modes.positive_stats).problems.some((p) => /row 6 is not allowed/.test(p)));
});

test('every_trigger: the call log must equal the generated list row for row', () => {
  const generated = generatedRows(outbound, 'gauzy', { phase: 2 });
  assert.ok(generated.length > 10);
  assert.ok(generated.includes(17));
  // Rows of a later phase join the list only when the product's config raises `phase`.
  assert.ok(!generated.includes(34) && generatedRows(outbound, 'gauzy', { phase: 3 }).includes(34));
  assert.ok(!generatedRows(outbound, 'teams', { phase: 2 }).includes(25));
  const full = generated.map((row) => (row === 17 ? entry(17, 'POST', '/v1/stats/reports', 202) : entry(row)));
  assert.deepEqual(checkCallLog(full, modes.every_trigger, { generated }).problems, []);
  const short = full.filter((e) => e.row !== generated[0]);
  assert.equal(checkCallLog(short, modes.every_trigger, { generated }).ok, false);
  const excluded = generatedRows(outbound, 'gauzy', { phase: 2, exclude: [generated[0]] });
  assert.ok(!excluded.includes(generated[0]));
});

test('the off and loaded_off modes allow no call at all', () => {
  for (const name of ['off', 'loaded_off']) {
    assert.deepEqual(checkCallLog([], modes[name]).problems, []);
    assert.equal(checkCallLog([entry(1)], modes[name]).ok, false);
  }
});

test('the CLI answers 0, 1 and 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-call-log-'));
  const good = join(dir, 'good.jsonl');
  writeFileSync(
    good,
    `${sample('positive-connect.requests.json')
      .map((e) => JSON.stringify(e))
      .join('\n')}\n`,
  );
  assert.equal(parseJsonl(readFileSync(good, 'utf8')).length, 8);
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify([...sample('positive-connect.requests.json'), entry(17)]));
  const quiet = { write: () => true };
  const out = process.stdout.write;
  const err = process.stderr.write;
  process.stdout.write = quiet.write;
  process.stderr.write = quiet.write;
  try {
    assert.equal(main(['--mode', 'positive_connect', '--log', good]), 0);
    assert.equal(main(['--mode', 'positive_connect', '--log', bad]), 1);
    assert.equal(main(['--mode', 'no_such_mode', '--log', good]), 2);
  } finally {
    process.stdout.write = out;
    process.stderr.write = err;
  }
});
