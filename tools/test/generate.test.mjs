// The generator is deterministic and its check catches drift: two runs are byte-identical, a
// changed table or a hand edit of a generated region fails `--check`.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { generateAll } from '../generate.mjs';
import { REPO, readJson } from '../lib/common.mjs';

const check = (env = {}) =>
  spawnSync(process.execPath, ['tools/generate.mjs', '--check'], { cwd: REPO, encoding: 'utf8', env: { ...process.env, ...env } });

test('two runs are byte-identical', { timeout: 600000 }, async () => {
  const first = await generateAll();
  const second = await generateAll();
  assert.deepEqual(Object.keys(first).sort(), Object.keys(second).sort());
  for (const path of Object.keys(first)) assert.equal(first[path], second[path], `${path} differs between runs`);
  for (const [path, text] of Object.entries(first)) {
    assert.ok(!text.includes('\r\n'), `${path} has CRLF line endings`);
    assert.ok(!/\b20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z\b/.test(path.endsWith('.lock') ? text : ''), 'no timestamp in the lock');
  }
});

test('--check passes on the committed tree', { timeout: 600000 }, () => {
  const r = check();
  assert.equal(r.status, 0, r.stderr);
});

test('a changed outbound-call table makes --check fail', { timeout: 600000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-rows-'));
  try {
    const rows = readJson(join(REPO, 'contracts/openapi/rows.json'));
    rows.rows[5].trigger = `${rows.rows[5].trigger} (changed)`;
    const file = join(dir, 'rows.json');
    writeFileSync(file, JSON.stringify(rows));
    const r = check({ EVER_SDK_ROWS_JSON: file });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /outbound-calls\.json/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a row naming a missing operation, or an operation without a row, fails the check', { timeout: 600000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-rows-'));
  try {
    const rows = readJson(join(REPO, 'contracts/openapi/rows.json'));
    rows.rows[5].operation_ids.push('instanceDoesNotExist');
    const file = join(dir, 'missing.json');
    writeFileSync(file, JSON.stringify(rows));
    const missing = check({ EVER_SDK_ROWS_JSON: file });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /instanceDoesNotExist/);
    const orphan = readJson(join(REPO, 'contracts/openapi/rows.json'));
    orphan.rows[5].operation_ids = orphan.rows[5].operation_ids.filter((id) => id !== 'getInstanceSelf');
    const file2 = join(dir, 'orphan.json');
    writeFileSync(file2, JSON.stringify(orphan));
    const r2 = check({ EVER_SDK_ROWS_JSON: file2 });
    assert.notEqual(r2.status, 0);
    assert.match(r2.stderr, /getInstanceSelf has no row/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a hidden integration never reaches the output', { timeout: 600000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-rows-'));
  try {
    const rows = readJson(join(REPO, 'contracts/openapi/rows.json'));
    rows.rows[11].integration = 'ever_agent';
    const file = join(dir, 'hidden.json');
    writeFileSync(file, JSON.stringify(rows));
    const r = check({ EVER_SDK_ROWS_JSON: file });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /hidden integration ever_agent/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a hand edit inside a generated docs region fails the check', { timeout: 600000 }, (t) => {
  const page = join(REPO, 'docs/outbound-calls.md');
  if (!existsSync(page)) {
    t.skip('docs/outbound-calls.md not written yet');
    return;
  }
  const original = readFileSync(page, 'utf8');
  try {
    writeFileSync(page, original.replace('| 6 |', '| 6 (edited) |'));
    const r = check();
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /docs\/outbound-calls\.md/);
  } finally {
    writeFileSync(page, original);
  }
});
