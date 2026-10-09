// The never-allowed list: what it matches, that no configuration can allow one of its names, and
// that a product's opt-in list relaxes the static scan only.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  hostOfUrl,
  hostsInText,
  isEverOwned,
  isNeverAllowed,
  loadEverHosts,
  loadOptinHosts,
  matchNeverAllowed,
  neverAllowedPattern,
  normaliseHost,
} from '../hosts.mjs';
import { loadConfig, UsageError } from '../lib/runner.mjs';
import { scanHostnames } from '../static-hostnames.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const OPTIN = join(HERE, 'fixtures', 'optin-hosts.json');
const configSchema = JSON.parse(readFileSync(new URL('../config.schema.json', import.meta.url), 'utf8'));

test('every listed name matches itself and every name under it, in any case and with a trailing dot', () => {
  for (const name of [
    'data.githands.com',
    'eu.i.posthog.com',
    'API.EVER.CO.',
    'app.ever.co',
    'ever.sh',
    'cdn.everdemand.co',
    'o1.ingest.sentry.io',
    'www.googletagmanager.com',
  ])
    assert.ok(isNeverAllowed(name), name);
  for (const name of ['ever.co.example.net', 'example.com', 'never.co', 'everdemand.com', 'githands.co', 'localhost', ''])
    assert.ok(!isNeverAllowed(name), name);
  assert.deepEqual(matchNeverAllowed('Analytics.Gauzy.Co'), { entry: 'gauzy.co', category: 'ever_owned' });
  assert.deepEqual(matchNeverAllowed('eu.i.posthog.com'), { entry: 'posthog.com', category: 'analytics_sinks' });
});

test('names are compared in their ASCII form, without a port or brackets', () => {
  assert.equal(normaliseHost('Bücher.Example.'), 'xn--bcher-kva.example');
  assert.equal(normaliseHost('app.ever.co:443'), 'app.ever.co');
  assert.equal(normaliseHost('[::1]'), '::1');
  assert.equal(hostOfUrl('https://user@App.Ever.Co:8443/x?y=1'), 'app.ever.co');
  assert.equal(hostOfUrl('mailto:someone@gauzy.co?subject=hi'), 'gauzy.co');
  assert.equal(hostOfUrl('//ever.team/logo.png'), 'ever.team');
  assert.equal(hostOfUrl('/relative'), null);
  assert.deepEqual(hostsInText('see https://api.ever.co/v1 and admin@ever.team, not ever.co.example.net'), [
    'api.ever.co',
    'ever.team',
    'ever.co.example.net',
  ]);
});

test('the analytics sinks are never allowed, but only the Ever-owned names are what the static scan looks for', () => {
  assert.ok(isNeverAllowed('sentry.io'));
  assert.ok(!isEverOwned('sentry.io'));
  assert.ok(isEverOwned('www.githands.com'));
});

test('EVER_EGRESS_EXTRA_HOSTS adds names to the list for a run; nothing removes one', () => {
  const lists = loadEverHosts({ env: { EVER_EGRESS_EXTRA_HOSTS: 'extra.example, Second.Example.' } });
  assert.deepEqual(lists.extra, ['extra.example', 'second.example']);
  assert.deepEqual(matchNeverAllowed('a.extra.example', lists), { entry: 'extra.example', category: 'extra' });
  assert.ok(isNeverAllowed('app.ever.co', lists));
  assert.deepEqual(loadEverHosts({ env: { EVER_EGRESS_EXTRA_HOSTS: '["json.example"]' } }).extra, ['json.example']);
  assert.throws(() => loadEverHosts({ env: { EVER_EGRESS_EXTRA_HOSTS: 'not a host!' } }), /not a host name/);
});

test('config.schema.json refuses exactly the listed names in allowed_external_hosts (its pattern is generated from the list)', () => {
  assert.equal(configSchema.properties.allowed_external_hosts.items.not.pattern, neverAllowedPattern());
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(configSchema);
  const base = {
    product: 'gauzy',
    compose: ['c.yml'],
    api_service: 'api',
    process_services: ['api'],
    health_url: 'http://api:3000/h',
    module_routes: ['/x'],
    // The API leg alone, stated: a product with a UI names its web service or says why not.
    web_service: null,
    no_web_reason: 'the API leg of this test',
  };
  for (const host of ['app.ever.co', 'ever.co', 'eu.i.posthog.com', 'data.githands.com', 'sentry.io', 'x.ever.sh'])
    assert.equal(validate({ ...base, allowed_external_hosts: [host] }), false, host);
  for (const host of ['github.com', 'api.github.com', 'ever.co.example.net'])
    assert.equal(validate({ ...base, allowed_external_hosts: [host] }), true, host);
});

test('ever-egress-audit refuses to start with a listed name in allowed_external_hosts (usage error, exit 2)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-hosts-'));
  const base = {
    product: 'gauzy',
    compose: ['c.yml'],
    api_service: 'api',
    process_services: ['api'],
    health_url: 'http://api:3000/h',
    module_routes: ['/x'],
    web_service: null,
    no_web_reason: 'the API leg of this test',
  };
  writeFileSync(join(dir, 'bad.json'), JSON.stringify({ ...base, allowed_external_hosts: ['app.ever.co'] }));
  assert.throws(
    () => loadConfig(join(dir, 'bad.json')),
    (e) => e instanceof UsageError && /allowed_external_hosts/.test(e.message),
  );
  writeFileSync(join(dir, 'ok.json'), JSON.stringify({ ...base, allowed_external_hosts: ['api.github.com'] }));
  assert.deepEqual(loadConfig(join(dir, 'ok.json')).config.allowed_external_hosts, ['api.github.com']);
});

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), 'ever-optin-'));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

test('an opt-in host passes the static scan, any other Ever host still fails, and the list itself stays unchanged', () => {
  const optin = loadOptinHosts(OPTIN);
  assert.deepEqual([...optin], ['updates.gauzy.co']);
  const named = tree({ 'apps/desktop/src/update.ts': "const feed = 'https://updates.gauzy.co/latest.json';\n" });
  assert.deepEqual(scanHostnames(named, [], {}), ['apps/desktop/src/update.ts:1']);
  assert.deepEqual(scanHostnames(named, [], { optinHosts: optin }), []);
  const other = tree({
    'apps/desktop/src/update.ts': "const api = 'https://api.ever.co/v1';\n",
    'apps/web/src/a.ts': "link('https://ever.team')\n",
  });
  assert.deepEqual(scanHostnames(other, [], { optinHosts: optin }).sort(), ['apps/desktop/src/update.ts:1', 'apps/web/src/a.ts:1']);
  // The capture checks never read the opt-in list: the host stays never-allowed.
  assert.ok(isNeverAllowed('updates.gauzy.co'));
});

test('the static scan reads built output with --all-files, and the analytics sinks are not its findings', () => {
  const root = tree({
    'static/chunks/app.js': 'var a="https://app.ever.co/x";var b="https://o1.ingest.sentry.io";',
    'static/chunks/plain.js': 'var c="https://example.com";',
  });
  assert.deepEqual(scanHostnames(root, [], { allFiles: true }), ['static/chunks/app.js:1']);
});

test('an opt-in list with a host that is not Ever-owned, or without its setting, is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-optin-bad-'));
  writeFileSync(join(dir, 'a.json'), JSON.stringify({ hosts: [{ host: 'sentry.io', setting: 'X', reason: 'r' }] }));
  assert.throws(() => loadOptinHosts(join(dir, 'a.json')), /not under an Ever-owned name/);
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ hosts: [{ host: 'updates.gauzy.co', reason: 'r' }] }));
  assert.throws(() => loadOptinHosts(join(dir, 'b.json')), /not a valid opt-in list/);
});
