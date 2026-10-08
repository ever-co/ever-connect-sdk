// The bundle runs on its own: both bins answer --help from dist/, the harness finds the bundled mock
// and its contract files, no test, sample or dependency directory is shipped, and the subpath
// exports reach the bundled modules.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { bundle } from '../scripts/bundle.mjs';

const DIST = fileURLToPath(new URL('../dist', import.meta.url));
const files = bundle();
const run = (...args) => spawnSync(process.execPath, args, { encoding: 'utf8', cwd: DIST });

test('ever-egress-audit --help from the bundle lists the five modes', () => {
  const r = run(join(DIST, 'egress-audit', 'run.mjs'), '--help');
  assert.equal(r.status, 0, r.stderr);
  for (const mode of ['off', 'loaded_off', 'positive_stats', 'positive_connect', 'every_trigger'])
    assert.match(r.stdout, new RegExp(`^ {2}${mode} `, 'm'));
});

test('ever-mock-platform --help from the bundle', () => {
  const r = run(join(DIST, 'mock-platform', 'bin', 'ever-mock-platform.mjs'), '--help');
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /ever-mock-platform \[--port 8080\]/);
});

test('the harness finds the bundled mock and its contract files', () => {
  for (const f of [
    'mock-platform/Dockerfile',
    'mock-platform/contracts/constants.json',
    'mock-platform/contracts/generated/outbound-calls.json',
    'mock-platform/contracts/generated/ever-platform.v1.json',
    'egress-audit/selftest/stats-sender/report.json',
    'egress-audit/compose.audit.yml',
    'egress-audit/Corefile',
    'egress-audit/ever-hosts.json',
    'egress-audit/browser.mjs',
    'egress-audit/lib/dom-refs.mjs',
    'egress-audit/routes/angular.mjs',
    'egress-audit/presets/signin-only.json',
    'egress-audit/selftest/ui-leaky/index.html',
  ])
    assert.ok(existsSync(join(DIST, f)), f);
});

test('the browser leg runs from the bundle: --legs in the help, playwright-core found next to the harness', async () => {
  const r = run(join(DIST, 'egress-audit', 'run.mjs'), '--help');
  assert.match(r.stdout, /--legs api,browser/);
  const { playwrightCoreDir } = await import('@ever-co/connect-tools/egress-audit/runner');
  const pkg = JSON.parse(readFileSync(join(playwrightCoreDir(), 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'playwright-core');
  const { isNeverAllowed } = await import('@ever-co/connect-tools/egress-audit/hosts');
  assert.ok(isNeverAllowed('app.ever.co'));
});

test('no tests, samples or node_modules are shipped', () => {
  assert.ok(files.length > 50);
  for (const f of files) assert.doesNotMatch(f, /(^|\/)(test|node_modules)\//, f);
});

test('every subpath export names a bundled module, and a product reaches the mock through them', async () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  for (const [subpath, target] of Object.entries(pkg.exports)) {
    if (subpath.includes('*') || subpath === './package.json') continue;
    assert.ok(existsSync(fileURLToPath(new URL(`../${target}`, import.meta.url))), subpath);
  }
  const keys = await import('@ever-co/connect-tools/mock-platform/keys');
  assert.equal(typeof keys.testRootEntry, 'function');
  assert.equal(typeof keys.signRotationProof, 'function');
  const mock = await import('@ever-co/connect-tools/mock-platform');
  assert.equal(typeof mock.createMockPlatform, 'function');
});
