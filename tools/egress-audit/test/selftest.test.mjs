// The self-test's verdict on a run: the failing control must show each kind of attempt it makes.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { judge, SELFTEST_RUNS } from '../lib/selftest.mjs';

const leaky = SELFTEST_RUNS.find((r) => r.name === 'off/leaky');
const attempt = (proto, dst, port) => ({ rule: 'egress_attempt', service: 'app', proto, dst, port });
const DNS = { rule: 'dns_ever_host', name: 'api.ever.co', source: 'coredns' };

test('the failing control passes the self-test only with the DNS query, the SYN and both datagrams', () => {
  const all = [DNS, attempt('tcp', '203.0.113.10', 443), attempt('udp', '203.0.113.10', 443), attempt('udp', '198.51.100.53', 53)];
  assert.deepEqual(judge(leaky, { exit: 1, violations: all }), []);
  const noDatagram = all.filter((v) => v.proto !== 'udp');
  assert.deepEqual(judge(leaky, { exit: 1, violations: noDatagram }), [
    'no udp attempt to 203.0.113.10:443 was seen',
    'no udp attempt to 198.51.100.53:53 was seen',
  ]);
  assert.match(judge(leaky, { exit: 0, violations: [] }).join(), /exit 0, expected 1/);
});
