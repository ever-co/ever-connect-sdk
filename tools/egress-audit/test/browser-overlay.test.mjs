// The browser leg in the overlay and the runner: its holder, sniffer and browser services, the
// legs of a run, and what the browser walks (route list, idle pages, positive control).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import { routeOf, routeUrl, webBase } from '../browser.mjs';
import { fragmentRoute, redactRouteUrl } from '../lib/har.mjs';
import { BROWSER, buildOverlay, productModel, SNIFFER_FILTER } from '../lib/overlay.mjs';
import { HARNESS_DIR, loadBrowserInputs, loadConfig, resolveLegs } from '../lib/runner.mjs';

const parse = (text) => YAML.parse(text, { customTags: [{ tag: '!reset', resolve: () => '!reset' }] });
const web = productModel({
  services: { app: { image: 'example/web', ports: ['8080:8080'] }, api: { image: 'example/api', networks: ['backend'] } },
  networks: { backend: {} },
});
const overlay = (extra = {}) =>
  buildOverlay({
    project: 'p',
    subnet: '10.231.43.0/24',
    dnsImage: 'd',
    product: web,
    processServices: ['app'],
    env: {},
    mock: null,
    ...extra,
  });

test('the browser leg: a holder with a fixed address and the audit resolver, its own sniffer, and the browser in that namespace', () => {
  const doc = parse(overlay({ browser: { image: 'ever-audit-browser:p', webService: 'app' } }));
  const holder = doc.services[BROWSER.holder];
  const sniffer = doc.services[BROWSER.sniffer];
  const browser = doc.services[BROWSER.service];
  // Only the sealed default network (the web service's own), at the fixed address the CoreDNS log is read by.
  assert.deepEqual(Object.keys(holder.networks), ['default']);
  assert.equal(holder.networks.default.ipv4_address, '10.231.43.251');
  assert.deepEqual(holder.dns, ['10.231.43.253']);
  assert.match(holder.command.join(' '), /nameserver 10\.231\.43\.253/);
  assert.equal(sniffer.network_mode, `service:${BROWSER.holder}`);
  assert.deepEqual(sniffer.cap_add, ['NET_RAW', 'NET_ADMIN']);
  assert.ok(sniffer.command.join(' ').includes(SNIFFER_FILTER));
  assert.match(sniffer.command.join(' '), /\/captures\/browser\.pcap/);
  assert.match(sniffer.command.join(' '), /ip route replace default via 10\.231\.43\.253/);
  assert.equal(browser.image, 'ever-audit-browser:p');
  assert.equal(browser.network_mode, `service:${BROWSER.holder}`);
  assert.deepEqual(browser.profiles, ['ever-audit-browser']);
  assert.equal(browser.ports, undefined);
  assert.equal(browser.networks, undefined);
  assert.equal(doc.networks.default.internal, true);
  // Without a web service there is no browser at all; an unknown one is refused.
  assert.equal(parse(overlay()).services[BROWSER.service], undefined);
  assert.throws(() => overlay({ browser: { image: 'b', webService: 'nope' } }), /web_service nope/);
});

const composeMissing = spawnSync('docker', ['compose', 'version']).status !== 0;

test('docker compose accepts the generated overlay, with the browser on the sealed network only', {
  skip: composeMissing && 'docker compose is not available',
}, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-audit-compose-'));
  const file = join(dir, 'compose.audit.generated.yml');
  writeFileSync(
    file,
    buildOverlay({
      project: 'ever-audit-config-check',
      subnet: '10.231.44.0/24',
      dnsImage: 'ever-audit-dns:x',
      driverImage: 'ever-audit-driver:x',
      product: productModel({ services: { app: { image: 'x' } } }),
      processServices: ['app'],
      env: { EVER_STATS_ENABLED: 'false' },
      mock: null,
      browser: { image: 'ever-audit-browser:x', webService: 'app' },
    }),
  );
  const selftest = join(HARNESS_DIR, 'selftest', 'docker-compose.yml');
  const r = spawnSync(
    'docker',
    [
      'compose',
      '-p',
      'ever-audit-config-check',
      '-f',
      selftest,
      '-f',
      file,
      '--profile',
      'ever-audit-browser',
      'config',
      '--format',
      'json',
    ],
    { encoding: 'utf8', env: { ...process.env, EVER_SELFTEST_FIXTURE: 'ui-quiet' } },
  );
  assert.equal(r.status, 0, r.stderr);
  const cfg = JSON.parse(r.stdout);
  for (const s of [BROWSER.holder, BROWSER.sniffer, BROWSER.service]) assert.ok(cfg.services[s], s);
  assert.deepEqual(Object.keys(cfg.services[BROWSER.holder].networks), ['default']);
  assert.equal(cfg.services[BROWSER.service].network_mode, `service:${BROWSER.holder}`);
  assert.equal(cfg.services[BROWSER.sniffer].network_mode, `service:${BROWSER.holder}`);
  assert.equal(cfg.networks.default.internal, true);
});

test('legs: api always, browser on top of it and only with a web service', () => {
  const api = {};
  const withWeb = { web_service: 'app' };
  assert.deepEqual(resolveLegs(api), ['api']);
  assert.deepEqual(resolveLegs(withWeb), ['api', 'browser']);
  assert.deepEqual(resolveLegs(withWeb, ['api']), ['api']);
  assert.throws(() => resolveLegs(withWeb, ['browser']), /runs on top of the API leg/);
  assert.throws(() => resolveLegs(api, ['api', 'browser']), /needs web_service/);
  assert.throws(() => resolveLegs(withWeb, ['api', 'dom']), /unknown leg dom/);
});

test('browser inputs: the route list, idle pages that are in it, and a positive control for a positive mode', () => {
  const { config, configDir } = loadConfig(join(HARNESS_DIR, 'selftest', 'egress-audit.config.json'));
  const modes = JSON.parse(readFileSync(join(HARNESS_DIR, 'modes.json'), 'utf8')).modes;
  const inputs = loadBrowserInputs(config, configDir, 'positive_stats', modes.positive_stats);
  assert.deepEqual(
    inputs.routes.map((r) => r.path),
    ['/', '/about', '/items/:id', '/settings'],
  );
  assert.deepEqual(inputs.expected, ['GET /api/ever-stats/status']);
  assert.deepEqual(inputs.baseline, []);
  assert.throws(() => loadBrowserInputs({ ...config, idle_pages: ['/nope'] }, configDir, 'off', modes.off), /idle page \/nope/);
  assert.throws(
    () => loadBrowserInputs({ ...config, ui_expected_requests: {} }, configDir, 'positive_stats', modes.positive_stats),
    /ui_expected_requests\.positive_stats/,
  );
  assert.throws(() => loadBrowserInputs({ ...config, ui_routes: 'missing.json' }, configDir, 'off', modes.off), /needs a route list/);
  assert.equal(loadBrowserInputs({ ...config, ui_baseline: 'ui-baseline.link.json' }, configDir, 'off', modes.off).baseline.length, 4);
  // The modes that run the browser leg.
  assert.deepEqual(
    Object.entries(modes)
      .filter(([, m]) => m.browser)
      .map(([n, m]) => `${n}:${m.browser}`),
    ['off:negative', 'loaded_off:negative', 'positive_stats:positive'],
  );
});

test('a config with a web service needs its address, and the reverse', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-audit-web-'));
  const base = {
    product: 'teams',
    compose: ['c.yml'],
    api_service: 'web',
    process_services: ['web'],
    health_url: 'http://web:3030/h',
    module_routes: ['/x'],
  };
  writeFileSync(join(dir, 'a.json'), JSON.stringify({ ...base, web_service: 'web' }));
  assert.throws(() => loadConfig(join(dir, 'a.json')), /web_service needs web_url/);
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ ...base, web_url: 'http://web:3030' }));
  assert.throws(() => loadConfig(join(dir, 'b.json')), /web_url needs web_service/);
});

test('hash routing: ui_routing in the config, a web_url that ends in # read as hash routing, a fragment that says otherwise refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-audit-hash-'));
  const base = {
    product: 'gauzy',
    compose: ['c.yml'],
    api_service: 'webapp',
    process_services: ['webapp'],
    health_url: 'http://webapp:4200/h',
    module_routes: ['/x'],
    web_service: 'webapp',
  };
  const load = (name, extra) => {
    writeFileSync(join(dir, name), JSON.stringify({ ...base, ...extra }));
    return () => loadConfig(join(dir, name));
  };
  assert.equal(
    load('a.json', { web_url: 'http://webapp:4200', ui_routing: 'hash', ui_sign_in_route: '/auth/login' })().config.ui_routing,
    'hash',
  );
  assert.doesNotThrow(load('b.json', { web_url: 'http://webapp:4200/#' }));
  assert.doesNotThrow(load('c.json', { web_url: 'http://webapp:4200/#/', ui_routing: 'hash' }));
  assert.throws(
    load('d.json', { web_url: 'http://webapp:4200/#', ui_routing: 'path' }),
    /ends in a fragment \(hash routing\) but ui_routing is "path"/,
  );
  assert.throws(
    load('e.json', { web_url: 'http://webapp:4200/#/pages' }),
    /has a fragment: give the bare address and set "ui_routing": "hash"/,
  );
  assert.throws(load('f.json', { web_url: 'http://webapp:4200', ui_routing: 'fragment' }), /ui_routing/);
  assert.throws(load('g.json', { web_url: 'http://webapp:4200', ui_sign_in_route: 'auth/login' }), /ui_sign_in_route/);
  assert.throws(load('h.json', { web_service: null, no_web_reason: 'x', ui_routing: 'hash' }), /ui_routing goes with web_service/);
});

test('hash routing: web_url read for the walk, the URL of a route, the route of a URL (redacted, fragment query cut to names)', () => {
  assert.deepEqual(webBase('http://webapp:4200/#'), { base: 'http://webapp:4200', routing: 'hash' });
  assert.deepEqual(webBase('http://webapp:4200/#/', 'auto'), { base: 'http://webapp:4200', routing: 'hash' });
  assert.deepEqual(webBase('http://webapp:4200/', 'hash'), { base: 'http://webapp:4200', routing: 'hash' });
  assert.deepEqual(webBase('http://web:3030'), { base: 'http://web:3030', routing: null });
  assert.deepEqual(webBase('http://web:3030/app/', 'path'), { base: 'http://web:3030/app', routing: 'path' });
  assert.equal(routeUrl('http://webapp:4200', '/pages/organizations/edit/7', 'hash'), 'http://webapp:4200/#/pages/organizations/edit/7');
  assert.equal(routeUrl('http://web:3030', '/settings', 'path'), 'http://web:3030/settings');
  const r = (u, routing) => routeOf(redactRouteUrl(u), routing);
  assert.equal(r('http://webapp:4200/#/auth/login?returnUrl=%2Fpages', 'hash'), '/auth/login');
  assert.equal(r('http://webapp:4200/', 'hash'), '/');
  assert.equal(r('http://webapp:4200/#/pages/x/', 'hash'), '/pages/x');
  assert.equal(r('http://webapp:4200/pages/x#/auth/login', 'path'), '/pages/x');
  assert.equal(
    redactRouteUrl('http://webapp:4200/#/reset/a@b.test?token=secret&token=again'),
    'http://webapp:4200/#/reset/[redacted]?token=',
  );
  assert.equal(redactRouteUrl('http://web:3030/docs#section'), 'http://web:3030/docs');
  assert.equal(fragmentRoute('http://web:3030/docs#section'), null);
  assert.equal(fragmentRoute('http://webapp:4200/#/'), '/');
});
