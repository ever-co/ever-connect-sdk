// Names added with EVER_EGRESS_EXTRA_HOSTS (CI passes them from a secret) are checked like every
// listed name, and never printed: a report, a violation and a message name them extra#<n>.
// Each test sets the variable and restores it (the tests of this directory share one process).
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { evaluate } from '../assert.mjs';
import { loadModes } from '../assert-call-log.mjs';
import { entryLabel, hideExtraHosts, matchNeverAllowed } from '../hosts.mjs';
import { loadConfig } from '../lib/runner.mjs';

/** Runs fn with EVER_EGRESS_EXTRA_HOSTS set, then puts the variable back as it was. */
function withExtra(fn) {
  const before = process.env.EVER_EGRESS_EXTRA_HOSTS;
  process.env.EVER_EGRESS_EXTRA_HOSTS = 'hidden-name.example,second-hidden.example';
  try {
    return fn();
  } finally {
    if (before === undefined) delete process.env.EVER_EGRESS_EXTRA_HOSTS;
    else process.env.EVER_EGRESS_EXTRA_HOSTS = before;
  }
}

const modes = loadModes();
const SNIFFER = 'listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes\n';

test('an extra name is found, and the report names it extra#<n>', () =>
  withExtra(() => {
    const coredns = [
      '[INFO] 10.231.50.7:51000 - 11 "A IN api.hidden-name.example. udp 40 false 512" NXDOMAIN qr,rd,ra 40 0.0002s',
      '[INFO] 10.231.50.7:51001 - 12 "A IN Second-Hidden.example. udp 40 false 512" NXDOMAIN qr,rd,ra 40 0.0002s',
    ].join('\n');
    const report = evaluate({
      mode: modes.off,
      modeName: 'off',
      subnets: ['10.231.50.0/24'],
      composeNames: ['app'],
      allowedHosts: [],
      coredns,
      sniffers: { app: SNIFFER },
      logs: { app: '' },
      routes: [{ path: '/x', status: 404 }],
      expectRoutes: true,
      mockExpected: false,
      mockRecord: null,
      faults: [],
    });
    assert.equal(report.exit, 1);
    const hits = report.violations.filter((v) => v.rule === 'dns_ever_host');
    assert.deepEqual(
      hits.map((v) => `${v.name} ${v.list} ${v.entry}`),
      ['api.extra#1 extra extra#1', 'extra#2 extra extra#2'],
    );
    assert.doesNotMatch(JSON.stringify(report), /hidden/i);
  }));

test('the labels, and a config that tries to allow an extra name', () =>
  withExtra(() => {
    assert.equal(entryLabel(matchNeverAllowed('x.second-hidden.example')), 'extra#2');
    assert.equal(entryLabel(matchNeverAllowed('app.ever.co')), 'ever.co');
    assert.deepEqual(hideExtraHosts({ a: ['see HIDDEN-NAME.example'], 'k.hidden-name.example': 1 }), {
      a: ['see extra#1'],
      'k.extra#1': 1,
    });
    const dir = mkdtempSync(join(tmpdir(), 'ever-extra-'));
    const file = join(dir, 'c.json');
    writeFileSync(
      file,
      JSON.stringify({
        product: 'demand',
        compose: ['c.yml'],
        api_service: 'api',
        process_services: ['api'],
        health_url: 'http://api:3000/h',
        module_routes: ['/x'],
        allowed_external_hosts: ['cdn.hidden-name.example'],
      }),
    );
    assert.throws(
      () => loadConfig(file),
      (e) =>
        /allowed_external_hosts: cdn\.extra#1 is on the never-allowed list \(extra: extra#1\)/.test(e.message) && !/hidden/.test(e.message),
    );
  }));
