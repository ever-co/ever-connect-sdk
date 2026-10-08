// The audit overlay and the CoreDNS configuration built for a product, the mode environment, the
// config schema (Ever hosts can never be allowed) and the CLI help.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { addressing, buildOverlay, composeNames, corefile, modeEnv, productModel, SNIFFER_FILTER } from '../lib/overlay.mjs';
import { defaultSubnet, HARNESS_DIR, loadConfig, UsageError } from '../lib/runner.mjs';

const product = productModel({
  services: {
    api: {
      image: 'example/api',
      ports: ['3000:3000'],
      hostname: 'api',
      networks: { default: {}, backend: { aliases: ['api-internal'] } },
      depends_on: ['db'],
    },
    worker: { image: 'example/api', networks: ['backend'] },
    db: { image: 'postgres:16', networks: ['backend'], container_name: 'example-db' },
  },
  networks: { backend: {} },
});

const parse = (text) => YAML.parse(text, { customTags: [{ tag: '!reset', resolve: () => '!reset' }] });

test('every compose network is sealed and each process gets a holder, a sniffer and the holder namespace', () => {
  const text = buildOverlay({
    project: 'ever-audit-example-off',
    subnet: '10.231.40.0/24',
    dnsImage: 'ever-audit-dns:test',
    product,
    processServices: ['api', 'worker'],
    env: { EVER_STATS_ENABLED: 'false' },
    mock: null,
  });
  const doc = parse(text);
  assert.equal(doc.networks.default.internal, true);
  assert.equal(doc.networks.default.name, 'ever-audit-example-off-audit');
  assert.deepEqual(doc.networks.default.ipam.config, [{ subnet: '10.231.40.0/24', ip_range: '10.231.40.0/25' }]);
  assert.deepEqual(doc.networks.backend, { internal: true });
  assert.equal(doc.services['ever-audit-dns'].networks.default.ipv4_address, '10.231.40.253');
  assert.ok('backend' in doc.services['ever-audit-dns'].networks);
  for (const svc of ['api', 'worker']) {
    const holder = doc.services[`ever-audit-ns-${svc}`];
    const sniffer = doc.services[`ever-audit-sniffer-${svc}`];
    assert.deepEqual(holder.networks.default.aliases, [svc]);
    assert.match(holder.command.join(' '), /nameserver 10\.231\.40\.253/);
    assert.equal(sniffer.network_mode, `service:ever-audit-ns-${svc}`);
    assert.deepEqual(sniffer.cap_add, ['NET_RAW', 'NET_ADMIN']);
    assert.ok(sniffer.command.join(' ').includes(SNIFFER_FILTER));
    assert.match(sniffer.command.join(' '), /ip route replace default via 10\.231\.40\.253/);
    assert.equal(doc.services[svc].network_mode, `service:ever-audit-ns-${svc}`);
    assert.equal(doc.services[svc].networks, '!reset');
    assert.deepEqual(doc.services[svc].environment, { EVER_STATS_ENABLED: 'false' });
    assert.deepEqual(doc.services[svc].depends_on[`ever-audit-sniffer-${svc}`], { condition: 'service_started' });
  }
  assert.ok('backend' in doc.services['ever-audit-ns-api'].networks);
  assert.deepEqual(doc.services['ever-audit-ns-worker'].networks.backend.aliases, ['worker']);
  // Settings Docker refuses with a shared namespace are reset; the product's dependencies stay.
  assert.equal(doc.services.api.ports, '!reset');
  assert.equal(doc.services.api.hostname, '!reset');
  assert.deepEqual(doc.services.api.depends_on.db, { condition: 'service_started' });
  assert.equal(doc.services['mock-platform'], undefined);
  assert.match(text, /ports: !reset null/);
});

test('the mock platform joins only when asked, with its configuration in the environment', () => {
  const doc = parse(
    buildOverlay({
      project: 'p',
      subnet: '10.231.41.0/24',
      dnsImage: 'd',
      product,
      processServices: ['api'],
      env: {},
      mock: { image: 'ever-mock-platform:audit-local', config: { clock: { real: true } } },
    }),
  );
  assert.equal(doc.services['mock-platform'].image, 'ever-mock-platform:audit-local');
  assert.deepEqual(doc.services['mock-platform'].networks.default.aliases, ['mock-platform']);
  // A fixed private address: the SDK accepts plain http from a local address only, never from a bare name.
  assert.equal(doc.services['mock-platform'].networks.default.ipv4_address, '10.231.41.252');
  assert.deepEqual(JSON.parse(doc.services['mock-platform'].environment.EVER_MOCK_CONFIG_JSON), { clock: { real: true } });
});

test('a process service that is missing or brings its own namespace is refused', () => {
  const base = { project: 'p', subnet: '10.231.42.0/24', dnsImage: 'd', env: {}, mock: null };
  assert.throws(() => buildOverlay({ ...base, product, processServices: ['nope'] }), /not in the compose files/);
  const host = productModel({ services: { api: { network_mode: 'host' } } });
  assert.throws(() => buildOverlay({ ...base, product: host, processServices: ['api'] }), /sets network_mode/);
});

test('what the overlay cannot seal is refused: host or another namespace on any service, an external Docker network', () => {
  const base = { project: 'p', subnet: '10.231.42.0/24', dnsImage: 'd', env: {}, mock: null, processServices: ['api'] };
  const withSidecar = (sidecar, networks = {}) =>
    productModel({ services: { api: { image: 'example/api' }, sidecar: { image: 'example/side', ...sidecar } }, networks });
  for (const mode of ['host', 'bridge', 'container:outside', 'service:nope'])
    assert.throws(() => buildOverlay({ ...base, product: withSidecar({ network_mode: mode }) }), /sidecar sets network_mode/, mode);
  assert.throws(
    () => buildOverlay({ ...base, product: withSidecar({ networks: ['ext'] }, { ext: { external: true, name: 'proxy' } }) }),
    /Docker network ext is external/,
  );
  for (const mode of ['none', 'service:api'])
    assert.doesNotThrow(() => buildOverlay({ ...base, product: withSidecar({ network_mode: mode }) }), mode);
});

test('CoreDNS answers the compose names and NXDOMAIN for everything else', () => {
  const names = composeNames({ ...product.services, 'mock-platform': {} });
  assert.deepEqual(names, ['api', 'api-internal', 'db', 'example-db', 'mock-platform', 'worker']);
  const text = corefile(names);
  assert.match(text, /^api\. api-internal\. db\. example-db\. mock-platform\. worker\. \{\n {2}log\n {2}forward \. 127\.0\.0\.11\n\}/m);
  assert.match(text, /^\. \{\n {2}log\n {2}errors\n {2}template ANY ANY \{\n {4}rcode NXDOMAIN/m);
});

test('addressing and the per-project subnet', () => {
  assert.deepEqual(addressing('10.231.7.0/24'), {
    subnet: '10.231.7.0/24',
    ipRange: '10.231.7.0/25',
    dnsIp: '10.231.7.253',
    mockIp: '10.231.7.252',
  });
  assert.throws(() => addressing('10.0.0.0/16'), /must be a \/24/);
  assert.match(defaultSubnet('ever-audit-gauzy-off'), /^10\.231\.\d{1,3}\.0\/24$/);
  assert.notEqual(defaultSubnet('ever-audit-gauzy-off'), defaultSubnet('ever-audit-gauzy-positive_stats'));
});

test('mode environment: the product prefix replaces EVER_, null is set empty', () => {
  assert.deepEqual(modeEnv({ EVER_CONNECT_ENABLED: null, EVER_STATS_ENABLED: 'false', OTHER: 1 }), {
    EVER_CONNECT_ENABLED: '',
    EVER_STATS_ENABLED: 'false',
    OTHER: '1',
  });
  assert.deepEqual(modeEnv({ EVER_CONNECT_ENABLED: 'true' }, 'TR_EVER_'), { TR_EVER_CONNECT_ENABLED: 'true' });
});

test('mode environment: the mock address and issuer placeholders, for every mode that uses the mock', () => {
  const mock = { url: 'http://10.231.7.252:8080', issuer: 'https://mock-platform.test' };
  assert.deepEqual(
    modeEnv({ EVER_PLATFORM_API_URL: '__MOCK_URL__', EVER_PLATFORM_ISSUER: '__MOCK_ISSUER__', OTHER: '__MOCK_URL__/v1' }, 'TR_EVER_', mock),
    {
      TR_EVER_PLATFORM_API_URL: 'http://10.231.7.252:8080',
      TR_EVER_PLATFORM_ISSUER: 'https://mock-platform.test',
      OTHER: 'http://10.231.7.252:8080/v1',
    },
  );
  const modes = JSON.parse(readFileSync(join(HARNESS_DIR, 'modes.json'), 'utf8')).modes;
  for (const [name, mode] of Object.entries(modes)) {
    const env = modeEnv(mode.env, 'EVER_', mock);
    // No mode names the mock by its compose name: the SDK would refuse http to a name that is not local.
    assert.ok(!JSON.stringify(env).includes('mock-platform:'), name);
    if (env.EVER_PLATFORM_API_URL) {
      assert.equal(env.EVER_PLATFORM_API_URL, mock.url, name);
      assert.equal(env.EVER_PLATFORM_ISSUER, mock.issuer, name);
      assert.equal(env.EVER_PLATFORM_ROOT_KEYS_FILE, '/ever-audit/roots.json', name);
    }
    if (env.EVER_STATS_API_URL) assert.equal(env.EVER_STATS_API_URL, mock.url, name);
  }
});

test('the config schema refuses Ever hosts in the allow-list; the self-test config is valid', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-audit-config-'));
  const base = {
    product: 'gauzy',
    compose: ['docker-compose.yml'],
    api_service: 'api',
    process_services: ['api'],
    health_url: 'http://api:3000/api/health',
    module_routes: ['/api/ever-connect/status'],
  };
  const write = (name, value) => {
    const file = join(dir, name);
    writeFileSync(file, JSON.stringify(value));
    return file;
  };
  assert.equal(loadConfig(write('ok.json', { ...base, allowed_external_hosts: ['registry.npmjs.org'] })).config.product, 'gauzy');
  for (const host of ['api.ever.co', 'ever.co', 'cdn.gauzy.co', 'x.ever.works', 'rec.so', 'app.traduora.co', 'ever.team'])
    assert.throws(() => loadConfig(write('bad.json', { ...base, allowed_external_hosts: [host] })), UsageError, host);
  assert.throws(() => loadConfig(write('api.json', { ...base, process_services: ['worker'] })), /must be one of process_services/);
  assert.equal(loadConfig(join(HARNESS_DIR, 'selftest', 'egress-audit.config.json')).config.product, 'selftest');
  // The off mode's 404 proof needs at least one route.
  assert.throws(() => loadConfig(write('routes.json', { ...base, module_routes: [] })), UsageError);
  // A product adds modes; it never redefines the harness's own.
  const off = { env: {}, mock: false, module_routes: 'any', allowed_rows: [], required_rows: [] };
  for (const name of ['off', 'loaded_off', 'positive_stats'])
    assert.throws(() => loadConfig(write('modes.json', { ...base, modes: { [name]: off } })), /redefines a mode of the harness/, name);
  assert.equal(loadConfig(write('extra.json', { ...base, modes: { connect_off_sign_in_on: off } })).config.product, 'gauzy');
});

test('--help lists the five modes (and the managed-operation control)', () => {
  const run = fileURLToPath(new URL('../run.mjs', import.meta.url));
  const r = spawnSync(process.execPath, [run, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  for (const mode of ['off', 'loaded_off', 'positive_stats', 'positive_connect', 'every_trigger', 'positive_managed'])
    assert.match(r.stdout, new RegExp(`^ {2}${mode} `, 'm'));
  const bad = spawnSync(process.execPath, [run, '--config', join(HARNESS_DIR, 'selftest', 'egress-audit.config.json'), '--mode', 'nope'], {
    encoding: 'utf8',
  });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown mode nope/);
});
