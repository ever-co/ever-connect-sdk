// assert.mjs on the browser leg's evidence: (e) the browser's DNS queries and capture, (f) the HAR
// and the request log against the never-allowed list (no allow-list or opt-in list can excuse an
// entry), (g) the DOM references against the baseline, the positive control, and the shrink-only
// baseline.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { evaluate } from '../assert.mjs';
import { loadModes } from '../assert-call-log.mjs';
import { addedEntries, main as shrinkMain } from '../check-baseline-shrink.mjs';
import { harEntries, redactUrl, sanitizeHar } from '../lib/har.mjs';

const fixture = (name) => readFileSync(new URL(`./fixtures/browser/${name}`, import.meta.url), 'utf8');
const json = (name) => JSON.parse(fixture(name));
const modes = loadModes();
const APP_SNIFFER = 'listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes\n';

function evidence({ browser = {}, coredns = fixture('coredns.txt'), allowedHosts = [], mode = 'off' } = {}) {
  return {
    mode: modes[mode],
    modeName: mode,
    subnets: ['10.231.50.0/24'],
    composeNames: ['app'],
    allowedHosts,
    coredns,
    sniffers: { app: APP_SNIFFER },
    logs: { app: '' },
    routes: [
      { path: '/api/ever-connect/status', status: 404 },
      { path: '/api/ever-stats/status', status: 404 },
    ],
    expectRoutes: mode === 'off',
    mockExpected: false,
    mockRecord: null,
    faults: [],
    browser: {
      enabled: true,
      required: true,
      positive: false,
      ips: ['10.231.50.251'],
      sniffer: fixture('browser.sniffer.txt'),
      har: json('clean.har'),
      requests: [],
      domRefs: [],
      visits: [{ route: '/', ok: true, status: 200 }],
      skipped: [],
      baseline: [],
      expected: [],
      faults: [],
      ...browser,
    },
  };
}

const rules = (report) => report.violations.map((v) => v.rule).sort();

test('a clean browser run passes, and its CoreDNS lines are told apart from the product processes by address', () => {
  const report = evaluate(evidence());
  assert.deepEqual(report.violations, []);
  assert.deepEqual(report.faults, []);
  assert.equal(report.exit, 0);
  const b = report.summary.browser;
  assert.equal(b.leg, 'ran');
  // The browser's own line and its sniffer's question; the product's line stays in the API leg.
  assert.equal(b.checks.e.dns_queries, 2);
  assert.equal(b.checks.e.outside, 0);
  assert.equal(report.summary.dns_queries, 1);
  assert.equal(b.checks.f.entries, 3);
});

test('(e) a never-allowed name, an unexpected name and a connection attempt from the browser all fail', () => {
  const report = evaluate(evidence({ coredns: fixture('coredns-leaky.txt'), browser: { sniffer: fixture('browser-leaky.sniffer.txt') } }));
  assert.equal(report.exit, 1);
  const dns = report.violations
    .filter((v) => v.check === 'e' && v.rule.startsWith('browser_dns'))
    .map((v) => `${v.rule}|${v.name}|${v.source}`);
  assert.deepEqual(dns.sort(), [
    'browser_dns_never_allowed|app.ever.co|coredns:browser',
    'browser_dns_never_allowed|app.ever.co|sniffer:browser',
    'browser_dns_unexpected|fonts.example.net|coredns:browser',
  ]);
  assert.deepEqual(
    report.violations.filter((v) => v.rule === 'browser_egress_attempt').map((v) => `${v.proto} ${v.dst}:${v.port}`),
    ['tcp 203.0.113.10:443'],
  );
  // None of it is charged to the product processes.
  assert.ok(!report.violations.some((v) => v.rule === 'dns_ever_host' || v.rule === 'egress_attempt'));
});

test('(e) an allowed external name passes from the browser too; a listed one never does', () => {
  const coredns = `${fixture('coredns.txt')}[INFO] 10.231.50.251:40009 - 9 "A IN api.github.com. udp 30 false 512" NXDOMAIN qr,aa,rd 30 0.0002s\n`;
  assert.equal(evaluate(evidence({ coredns, allowedHosts: ['api.github.com'] })).exit, 0);
  assert.equal(evaluate(evidence({ coredns })).exit, 1);
});

test('(f) a HAR entry to app.ever.co fails even when the allow-list names it, and an opt-in host fails as well', () => {
  for (const allowedHosts of [[], ['app.ever.co', 'updates.gauzy.co']]) {
    const report = evaluate(evidence({ allowedHosts, browser: { har: json('leaky.har') } }));
    assert.equal(report.exit, 1);
    const f = report.violations.filter((v) => v.rule === 'har_never_allowed');
    assert.deepEqual(f.map((v) => v.host).sort(), ['app.ever.co', 'updates.gauzy.co']);
    assert.ok(f.every((v) => v.check === 'f' && v.list === 'ever_owned'));
  }
});

test('(f) the request log counts like the HAR (a WebSocket or a request the HAR missed)', () => {
  const report = evaluate(
    evidence({ browser: { requests: [{ method: 'WS', url: 'wss://realtime.ever.team/socket', resource: 'websocket', status: 0 }] } }),
  );
  assert.deepEqual(rules(report), ['har_never_allowed']);
  assert.equal(report.violations[0].host, 'realtime.ever.team');
});

test('(g) an unbaselined DOM reference to a listed host fails; the same {route, attribute, url} in the baseline passes', () => {
  const domRefs = json('dom-refs.json');
  const report = evaluate(evidence({ browser: { domRefs } }));
  assert.deepEqual(report.violations.map((v) => `${v.rule} ${v.route} ${v.attribute} ${v.url}`).sort(), [
    'dom_never_allowed / href https://app.ever.co/',
    'dom_never_allowed /settings srcset https://cdn.gauzy.co/logo-2x.png',
  ]);
  const baseline = [
    { route: '/', attribute: 'href', url: 'https://app.ever.co/', reason: 'footer link' },
    { route: '/settings', attribute: 'srcset', url: 'https://cdn.gauzy.co/logo-2x.png', reason: 'logo' },
    { route: '/old', attribute: 'href', url: 'https://ever.co/', reason: 'a page that no longer renders it' },
  ];
  const ok = evaluate(evidence({ browser: { domRefs, baseline } }));
  assert.equal(ok.exit, 0);
  assert.equal(ok.summary.browser.checks.g.baselined, 2);
  assert.deepEqual(ok.summary.browser.stale_baseline, [{ route: '/old', attribute: 'href', url: 'https://ever.co/' }]);
  // Another route or attribute is not the baselined reference.
  const moved = evaluate(evidence({ browser: { domRefs, baseline: [{ ...baseline[0], route: '/about' }, baseline[1]] } }));
  assert.deepEqual(rules(moved), ['dom_never_allowed']);
  // The baseline never excuses a request.
  const har = evaluate(evidence({ browser: { har: json('leaky.har'), baseline } }));
  assert.ok(har.violations.some((v) => v.rule === 'har_never_allowed' && v.host === 'app.ever.co'));
});

test('the positive control: the expected request seen from the browser passes, a missing one fails', () => {
  const positive = { positive: true, expected: ['GET /api/ever-stats/status'] };
  const seen = evaluate(evidence({ mode: 'positive_stats', browser: positive }));
  assert.deepEqual(seen.summary.browser.expected, [{ request: 'GET /api/ever-stats/status', seen: true }]);
  assert.ok(!seen.violations.some((v) => v.rule === 'browser_expected_missing'));
  const har = json('clean.har');
  har.log.entries = har.log.entries.filter((e) => !e.request.url.endsWith('/status'));
  const missing = evaluate(evidence({ mode: 'positive_stats', browser: { ...positive, har } }));
  assert.ok(missing.violations.some((v) => v.rule === 'browser_expected_missing' && v.request === 'GET /api/ever-stats/status'));
  // The request must go to a compose service: the same path on an outside host does not count.
  har.log.entries.push({ request: { method: 'GET', url: 'https://example.net/api/ever-stats/status' }, response: { status: 0 } });
  const outside = evaluate(evidence({ mode: 'positive_stats', browser: { ...positive, har } }));
  assert.ok(outside.violations.some((v) => v.rule === 'browser_expected_missing'));
});

test('an unproven browser leg never passes: left out, no capture, a page that never loaded', () => {
  const left = evidence();
  left.browser = { enabled: false, required: true, reason: 'the browser leg was left out (--legs api): this run proves the API side only' };
  const r1 = evaluate(left);
  assert.equal(r1.exit, 2);
  assert.match(r1.faults.join(), /left out/);
  const r2 = evaluate(evidence({ browser: { sniffer: '' } }));
  assert.equal(r2.exit, 2);
  assert.match(r2.faults.join(), /no sniffer output from the browser/);
  const r3 = evaluate(evidence({ browser: { faults: ['route /settings did not load after one retry: timeout'] } }));
  assert.equal(r3.exit, 2);
  // A proven violation still fails the run with a fault beside it.
  const r4 = evaluate(evidence({ browser: { har: json('leaky.har'), faults: ['route /x did not load after one retry: timeout'] } }));
  assert.equal(r4.exit, 1);
});

test('the HAR keeps which request went where and nothing else: no body, cookie, header value, query value or fragment', () => {
  const raw = {
    log: {
      version: '1.2',
      creator: { name: 'Playwright', version: '1.62.1' },
      pages: [{ id: 'page@1', title: 'Jane Doe - settings', startedDateTime: 't', pageTimings: {} }],
      entries: [
        {
          startedDateTime: 't',
          time: 1,
          request: {
            method: 'POST',
            url: 'http://app:8080/sign-in?next=/settings&token=abc#frag',
            headers: [
              { name: 'Cookie', value: 'session=s3cr3t' },
              { name: 'Authorization', value: 'Bearer t0k3n' },
              { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
              { name: 'Referer', value: 'http://app:8080/sign-in?code=123' },
            ],
            cookies: [{ name: 'session', value: 's3cr3t' }],
            queryString: [{ name: 'token', value: 'abc' }],
            postData: {
              mimeType: 'application/x-www-form-urlencoded',
              text: 'email=a%40b&password=hunter2',
              params: [{ name: 'password', value: 'hunter2' }],
            },
          },
          response: {
            status: 303,
            headers: [
              { name: 'Set-Cookie', value: 'session=s3cr3t' },
              { name: 'Location', value: '/?welcome=jane' },
            ],
            cookies: [{ name: 'session', value: 's3cr3t' }],
            content: { size: 10, mimeType: 'text/plain', text: 'secret body' },
            redirectURL: '/?welcome=jane',
          },
        },
      ],
    },
  };
  const text = JSON.stringify(sanitizeHar(raw));
  for (const secret of ['s3cr3t', 't0k3n', 'hunter2', 'abc', '123', 'jane', 'Jane', 'frag', 'secret body'])
    assert.ok(!text.includes(secret), secret);
  const [row] = harEntries(sanitizeHar(raw));
  assert.deepEqual(row, { method: 'POST', url: 'http://app:8080/sign-in?next=&token=', host: 'app', path: '/sign-in', status: 303 });
  assert.equal(redactUrl('mailto:jane@gauzy.co?subject=x'), 'mailto:[redacted]@gauzy.co');
  assert.equal(redactUrl('https://user:pw@app.ever.co/x?y=1#z'), 'https://app.ever.co/x?y=');
});

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'ever-baseline-'));
  const git = (...args) =>
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.test', ...args], { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  return { dir, git };
}

test('ui-baseline.json may only shrink: an entry added after the base commit fails, a removed one passes', () => {
  const entry = (url) => ({ route: '/', attribute: 'href', url, reason: 'footer' });
  const { dir, git } = repo();
  const file = join(dir, 'ui-baseline.json');
  writeFileSync(file, JSON.stringify({ entries: [entry('https://app.ever.co/'), entry('https://ever.team/')] }));
  git('add', '.');
  git('commit', '-q', '-m', 'baseline');
  const quiet = { write: () => true };
  const out = process.stdout.write;
  const err = process.stderr.write;
  const run = () => {
    process.stdout.write = quiet.write;
    process.stderr.write = quiet.write;
    try {
      return shrinkMain(['--base', 'HEAD', '--file', file]);
    } finally {
      process.stdout.write = out;
      process.stderr.write = err;
    }
  };
  assert.equal(run(), 0);
  writeFileSync(file, JSON.stringify({ entries: [entry('https://app.ever.co/')] }));
  assert.equal(run(), 0);
  writeFileSync(file, JSON.stringify({ entries: [entry('https://app.ever.co/'), entry('https://gauzy.co/')] }));
  assert.equal(run(), 1);
  assert.deepEqual(
    addedEntries({ entries: [entry('https://gauzy.co/?a=1')] }, { entries: [entry('https://gauzy.co/?a=2')] }),
    [],
    'URLs are compared without their query values',
  );
});
