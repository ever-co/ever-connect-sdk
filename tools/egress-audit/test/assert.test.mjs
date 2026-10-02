// assert.mjs on evidence recorded by real harness runs (test/samples): the quiet fixture product,
// the leaky failing control and the managed-operation run.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { corednsQueries, errorHost, evaluate, isInside, reverseAddress, snifferEvents } from '../assert.mjs';
import { loadModes } from '../assert-call-log.mjs';

const sample = (name) => readFileSync(new URL(`./samples/${name}`, import.meta.url), 'utf8');
const modes = loadModes();
const ROUTES_404 = [
  { path: '/api/ever-connect/status', status: 404 },
  { path: '/api/ever-stats/status', status: 404 },
];

function offEvidence({ subnet, sniffer, coredns, logs = '', routes = ROUTES_404, allowedHosts = [] }) {
  return {
    mode: modes.off,
    modeName: 'off',
    subnets: [subnet],
    composeNames: ['app'],
    allowedHosts,
    coredns,
    sniffers: { app: sniffer },
    logs: { app: logs },
    routes,
    expectRoutes: true,
    mockExpected: false,
    mockRecord: null,
    faults: [],
  };
}

const leakyLines = (keep) =>
  sample('leaky.sniffer.txt')
    .split('\n')
    .filter((l) => !/^\d\d:/.test(l) || keep(l))
    .join('\n');

test('a clean run passes (recorded quiet fixture)', () => {
  const report = evaluate(
    offEvidence({ subnet: '10.231.121.0/24', sniffer: sample('clean.sniffer.txt'), coredns: sample('clean.coredns.txt') }),
  );
  assert.deepEqual(report.violations, []);
  assert.deepEqual(report.faults, []);
  assert.equal(report.exit, 0);
});

test('an api.ever.co query fails, whatever the allow-list says', () => {
  const sniffer = leakyLines((l) => /api\.ever\.co/.test(l));
  for (const allowedHosts of [[], ['api.ever.co']]) {
    const report = evaluate(offEvidence({ subnet: '10.231.31.0/24', sniffer, coredns: sample('leaky.coredns.txt'), allowedHosts }));
    assert.equal(report.exit, 1);
    const names = report.violations.filter((v) => v.rule === 'dns_ever_host').map((v) => `${v.name}|${v.source}`);
    assert.deepEqual(names.sort(), ['api.ever.co|coredns', 'api.ever.co|sniffer:app']);
  }
});

test('a SYN to 203.0.113.10 fails', () => {
  const sniffer = leakyLines((l) => /203\.0\.113\.10/.test(l));
  const report = evaluate(offEvidence({ subnet: '10.231.31.0/24', sniffer, coredns: sample('clean.coredns.txt') }));
  assert.equal(report.exit, 1);
  assert.ok(report.violations.length > 0);
  for (const v of report.violations)
    assert.deepEqual(v, { rule: 'egress_attempt', service: 'app', proto: 'tcp', dst: '203.0.113.10', port: 443 });
});

test('the recorded leaky control fails on every rule it breaks', () => {
  const report = evaluate(
    offEvidence({
      subnet: '10.231.31.0/24',
      sniffer: sample('leaky.sniffer.txt'),
      coredns: sample('leaky.coredns.txt'),
      logs: sample('leaky.product.txt'),
    }),
  );
  assert.equal(report.exit, 1);
  assert.deepEqual(Object.keys(report.summary.rules).sort(), ['dns_ever_host', 'egress_attempt', 'resolver_error']);
});

test('inbound connections to the product and DNS answers are not attempts', () => {
  const e = snifferEvents(sample('clean.sniffer.txt'), 'app');
  assert.deepEqual(e.connections, []);
  const m = snifferEvents(sample('positive-managed.sniffer.txt'), 'app');
  assert.ok(m.connections.length > 0);
  for (const c of m.connections) assert.ok(isInside(c.dst, ['10.231.108.0/24']), c.line);
  assert.ok(m.queries.every((q) => q.name === 'mock-platform'));
});

test('a name outside the compose services fails unless allowed; an Ever name never is', () => {
  const line = '04:03:44.837211 eth0  Out IP 10.231.31.2.58694 > 10.231.31.253.53: 15700+ A? registry.npmjs.org. (36)';
  const sniffer = `listening on any\n${line}`;
  assert.equal(evaluate(offEvidence({ subnet: '10.231.31.0/24', sniffer, coredns: '' })).violations[0].rule, 'dns_unexpected');
  assert.equal(evaluate(offEvidence({ subnet: '10.231.31.0/24', sniffer, coredns: '', allowedHosts: ['registry.npmjs.org'] })).exit, 0);
  const gauzy = `listening on any\n${line.replace('registry.npmjs.org', 'api.gauzy.co')}`;
  assert.equal(
    evaluate(offEvidence({ subnet: '10.231.31.0/24', sniffer: gauzy, coredns: '', allowedHosts: ['api.gauzy.co'] })).violations[0].rule,
    'dns_ever_host',
  );
});

test('reverse lookups: inside the sealed networks pass, outside fail', () => {
  assert.equal(reverseAddress('9.7.231.10.in-addr.arpa'), '10.231.7.9');
  const ptr = (name) => `listening on any\n04:00:00.000000 eth0  Out IP 10.231.7.2.40000 > 10.231.7.253.53: 1+ PTR? ${name}. (44)`;
  assert.equal(evaluate(offEvidence({ subnet: '10.231.7.0/24', sniffer: ptr('9.7.231.10.in-addr.arpa'), coredns: '' })).exit, 0);
  assert.equal(evaluate(offEvidence({ subnet: '10.231.7.0/24', sniffer: ptr('10.113.0.203.in-addr.arpa'), coredns: '' })).exit, 1);
});

test('UDP out of the sealed networks fails; every project subnet is inside', () => {
  const udp = 'listening on any\n04:00:00.000000 eth0  Out IP 10.231.7.2.40000 > 203.0.113.20.123: UDP, length 48';
  const report = evaluate(offEvidence({ subnet: '10.231.7.0/24', sniffer: udp, coredns: '' }));
  assert.deepEqual(report.violations, [{ rule: 'egress_attempt', service: 'app', proto: 'udp', dst: '203.0.113.20', port: 123 }]);
  assert.ok(isInside('172.18.0.5', ['10.231.7.0/24', '172.18.0.0/16']));
  assert.ok(!isInside('172.19.0.5', ['10.231.7.0/24', '172.18.0.0/16']));
  assert.ok(isInside('127.0.0.11', []));
  assert.ok(!isInside('2001:db8::1', ['10.231.7.0/24']));
});

test('resolver errors: compose names are tolerated, other hosts fail', () => {
  const base = { subnet: '10.231.7.0/24', sniffer: sample('clean.sniffer.txt'), coredns: '' };
  assert.equal(evaluate(offEvidence({ ...base, logs: 'Error: connect ECONNREFUSED app:8080\ngetaddrinfo EAI_AGAIN app' })).exit, 0);
  const r = evaluate(offEvidence({ ...base, logs: 'Error: getaddrinfo ENOTFOUND telemetry.example.com' }));
  assert.equal(r.violations[0].rule, 'resolver_error');
});

// Lines recorded by real runs of probe products against the harness.
const DNS_NULL_OUT = '05:50:04.223196 eth0  Out IP 10.231.32.2.59732 > 198.51.100.53.53: 4660+ NULL? api.ever.co. (29)';
const DNS_COMPOSE_OUT = '05:50:44.680049 eth0  Out IP 10.231.32.2.40211 > 198.51.100.53.53: 4660+ A? app. (21)';
const DNS_TO_AUDIT = '05:27:22.543555 eth0  Out IP 10.231.32.2.42831 > 10.231.32.253.53: 38088+ A? app. (21)';

test('a DNS question sent straight to a resolver outside the sealed networks fails, whatever its type', () => {
  const base = { subnet: '10.231.32.0/24', coredns: '' };
  const nul = evaluate(offEvidence({ ...base, sniffer: `listening on any\n${DNS_NULL_OUT}` }));
  assert.equal(nul.exit, 1);
  assert.ok(nul.violations.some((v) => v.rule === 'egress_attempt' && v.proto === 'udp' && v.dst === '198.51.100.53' && v.port === 53));
  assert.ok(nul.violations.some((v) => v.rule === 'dns_ever_host' && v.name === 'api.ever.co'));
  const compose = evaluate(offEvidence({ ...base, sniffer: `listening on any\n${DNS_COMPOSE_OUT}` }));
  assert.deepEqual(compose.violations, [{ rule: 'egress_attempt', service: 'app', proto: 'udp', dst: '198.51.100.53', port: 53 }]);
  // The same question to the audit resolver stays inside.
  assert.equal(evaluate(offEvidence({ ...base, sniffer: `listening on any\n${DNS_TO_AUDIT}` })).exit, 0);
});

test('a SYN is an attempt whatever other flags it carries; a SYN-ACK or received multicast is not', () => {
  const syn = (flags) => `04:00:00.000000 eth0  Out IP 10.231.7.2.40000 > 203.0.113.10.443: Flags [${flags}], seq 1, win 64240, length 0`;
  for (const flags of ['S', 'SEW', 'SE'])
    assert.deepEqual(
      snifferEvents(syn(flags), 'app').connections.map((c) => [c.proto, c.dst, c.dport]),
      [['tcp', '203.0.113.10', 443]],
      flags,
    );
  assert.deepEqual(snifferEvents(syn('S.'), 'app').connections, []);
  const multicast = '04:00:00.000000 eth0  M   IP 10.231.7.9.5353 > 224.0.0.251.5353: 0 [1q] PTR (QM)? _ipp._tcp.local. (32)';
  assert.deepEqual(snifferEvents(multicast, 'app').connections, []);
});

test('resolver errors: an address inside the sealed networks is tolerated; an IPv6 attempt without a packet fails', () => {
  const base = { subnet: '10.231.32.0/24', sniffer: sample('clean.sniffer.txt'), coredns: '' };
  assert.equal(errorHost('2026-10-02T05:52:46.222Z connect ECONNREFUSED 10.231.32.253:5432'), '10.231.32.253');
  assert.equal(errorHost('connect ENETUNREACH 2001:db8::10:443 - Local (:::0)'), '2001:db8::10');
  assert.equal(errorHost('getaddrinfo ENOTFOUND api.ever.co'), 'api.ever.co');
  const inside = evaluate(offEvidence({ ...base, logs: '2026-10-02T05:52:46.222Z connect ECONNREFUSED 10.231.32.253:5432' }));
  assert.equal(inside.exit, 0);
  const v6 = evaluate(offEvidence({ ...base, logs: '2026-10-02T05:52:03.773Z connect ENETUNREACH 2001:db8::10:443 - Local (:::0)' }));
  assert.equal(v6.exit, 1);
  assert.equal(v6.violations[0].rule, 'resolver_error');
  const host = evaluate(offEvidence({ ...base, logs: 'connect EHOSTUNREACH 203.0.113.10:443' }));
  assert.equal(host.violations[0].rule, 'resolver_error');
});

test('a module route answering in the off mode fails; no probe at all is a fault', () => {
  const base = { subnet: '10.231.121.0/24', sniffer: sample('clean.sniffer.txt'), coredns: sample('clean.coredns.txt') };
  const answered = evaluate(offEvidence({ ...base, routes: [{ path: '/api/ever-connect/status', status: 200 }] }));
  assert.deepEqual(answered.violations, [{ rule: 'module_route_answered', path: '/api/ever-connect/status', status: 200 }]);
  const none = evaluate(offEvidence({ ...base, routes: [] }));
  assert.equal(none.exit, 2);
});

test('no capture is a harness fault (2); a proven violation still fails (1)', () => {
  const quiet = evaluate(offEvidence({ subnet: '10.231.7.0/24', sniffer: '', coredns: '' }));
  assert.equal(quiet.exit, 2);
  assert.match(quiet.faults.join(), /no sniffer output/);
  const leaky = evaluate({ ...offEvidence({ subnet: '10.231.31.0/24', sniffer: '', coredns: sample('leaky.coredns.txt') }) });
  assert.equal(leaky.exit, 1);
});

test('CoreDNS log lines give the queried names', () => {
  assert.deepEqual(
    corednsQueries(sample('leaky.coredns.txt')).map((q) => q.name),
    ['api.ever.co', 'api.ever.co'],
  );
});

test('a positive mode checks the recorded calls', () => {
  const evidence = {
    mode: modes.positive_stats,
    modeName: 'positive_stats',
    subnets: ['10.231.204.0/24'],
    composeNames: ['app', 'mock-platform'],
    coredns: '',
    sniffers: { app: 'listening on any' },
    logs: {},
    mockExpected: true,
    mockRecord: JSON.parse(sample('positive-stats.requests.json')),
    faults: [],
  };
  assert.equal(evaluate(evidence).exit, 0);
  assert.equal(evaluate({ ...evidence, mockRecord: [] }).exit, 1);
  assert.equal(evaluate({ ...evidence, mockRecord: null }).exit, 2);
});
