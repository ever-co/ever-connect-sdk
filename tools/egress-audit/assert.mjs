#!/usr/bin/env node
/**
 * assert: evaluates the evidence of one audit run and writes report.json.
 *
 * Evidence: the DNS queries (the CoreDNS log and the queries each sniffer saw in its product's
 * network namespace), the connection attempts each sniffer saw (TCP SYN, and every UDP datagram,
 * DNS queries included), the product logs, the module route answers and, in positive modes, the
 * mock platform's record.
 *
 * Fails (exit 1) when:
 *   (a) a DNS name outside the compose services and allowed_external_hosts was queried; any name
 *       under an Ever domain always fails, whatever the allow-list says;
 *   (b) a connection attempt left the sealed networks (loopback excepted), a DNS query sent to a
 *       resolver outside them included;
 *   (c) a product log shows a resolver or connection error (ENOTFOUND, ECONNREFUSED, EAI_AGAIN,
 *       ENETUNREACH, EHOSTUNREACH) for a host outside the compose services and the sealed networks;
 *   (d) in an off mode, a module route answered anything but 404;
 *   (e) in a positive mode, the recorded calls differ from the mode's rows (assert-call-log).
 * A harness fault (no evidence where some was expected) is exit 2 when nothing was violated: an
 * unproven run proves nothing.
 *
 *   ever-egress-audit assert --evidence <evidence.json> [--out report.json]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { checkCallLog } from './assert-call-log.mjs';

export const EVER_DOMAINS = /(^|\.)(ever\.co|ever\.team|gauzy\.co|ever\.works|rec\.so|traduora\.co)$/i;
// ENETUNREACH and EHOSTUNREACH: an attempt that failed inside the namespace without a packet to
// capture, such as a connection to an IPv6 address (the sealed networks have no IPv6 route).
const RESOLVER_ERRORS = /\b(ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|EHOSTUNREACH)\b/;

const normalise = (name) => name.toLowerCase().replace(/\.$/, '');

/** DNS names from a CoreDNS `log` plugin output. */
export function corednsQueries(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const m = /"(\w+) IN (\S+?) (udp|tcp) /.exec(line);
    if (m) out.push({ name: normalise(m[2]), type: m[1], source: 'coredns' });
  }
  return out;
}

/**
 * DNS queries and connection attempts from a sniffer's tcpdump text (`-i any -nn -l`). Packets
 * received (`In`, such as the driver opening the product's port, and broadcast or multicast
 * received) are not the product's attempts.
 */
export function snifferEvents(text, service) {
  const queries = [];
  const connections = [];
  for (const line of text.split('\n')) {
    if (/^\S+\s+\S+\s+(In|B|M|P)\s+IP6? /.test(line)) continue;
    // A DNS question of any type (tcpdump decodes DNS on port 53 only).
    const dns = /\s([A-Za-z][A-Za-z0-9]*)\? (\S+?)\.? \(/.exec(line);
    if (dns) queries.push({ name: normalise(dns[2]), type: dns[1], source: `sniffer:${service}` });
    const packet = /\bIP6? (\S+)\.(\d+) > (\S+)\.(\d+): /.exec(line);
    if (!packet) continue;
    const attempt = { service, src: packet[1], dst: packet[3], dport: Number(packet[4]), line: line.trim() };
    // TCP: the capture keeps SYN without ACK only, whatever other flags it carries (ECN: [SEW]).
    const flags = /: Flags \[([^\]]*)\]/.exec(line)?.[1];
    if (flags !== undefined) {
      if (flags.includes('S') && !flags.includes('.')) connections.push({ ...attempt, proto: 'tcp' });
      continue;
    }
    // UDP, DNS queries included: a query to the audit resolver stays inside the sealed networks,
    // one sent to any other resolver is an attempt out, whatever its type.
    connections.push({ ...attempt, proto: 'udp' });
  }
  return { queries, connections };
}

/** The host or address a Node resolver or connection error names, without its port. */
export function errorHost(line) {
  const raw = /(?:getaddrinfo|connect) \w+ (\S+)/.exec(line)?.[1];
  return raw ? raw.replace(/:\d+$/, '') : null;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function inSubnet(ip, subnet) {
  const [base, bits] = subnet.split('/');
  const b = ipv4ToInt(base);
  if (b === null) return false;
  const mask = bits === '0' ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
  return (ip & mask) >>> 0 === (b & mask) >>> 0;
}

/** Whether a destination stays inside the audit: a sealed network, loopback or IPv6 link-local. */
export function isInside(dst, subnets) {
  if (dst.includes(':')) return dst === '::1' || /^fe80:/i.test(dst);
  const ip = ipv4ToInt(dst);
  if (ip === null) return false;
  if (ip >>> 24 === 127) return true;
  return [subnets]
    .flat()
    .filter(Boolean)
    .some((s) => inSubnet(ip, s));
}

/** The address a reverse (PTR) name asks about, or null. */
export function reverseAddress(name) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/.exec(name);
  return m ? `${m[4]}.${m[3]}.${m[2]}.${m[1]}` : null;
}

/**
 * Evaluates the evidence; answers {exit, mode, violations, faults, summary}.
 * evidence: {mode, modeName, subnets[], composeNames[], allowedHosts[], searchDomains[], coredns,
 *            sniffers{svc: text}, logs{svc: text}, routes[{path, status}], expectRoutes,
 *            mockRecord[]|null, mockExpected, mark, generated[], faults[]}
 */
export function evaluate(evidence) {
  const violations = [];
  const faults = [...(evidence.faults ?? [])];
  const subnets = evidence.subnets ?? [evidence.subnet].filter(Boolean);
  const names = new Set([...(evidence.composeNames ?? []), ...(evidence.allowedHosts ?? []), 'localhost'].map(normalise));
  const queries = [...corednsQueries(evidence.coredns ?? '')];
  const connections = [];
  for (const [svc, text] of Object.entries(evidence.sniffers ?? {})) {
    const e = snifferEvents(text, svc);
    queries.push(...e.queries);
    connections.push(...e.connections);
  }
  // A compose name expanded with a search domain of the containers' resolv.conf is the same lookup;
  // a reverse lookup of an address inside the sealed networks reaches nothing outside them.
  const search = (evidence.searchDomains ?? []).map(normalise).filter(Boolean);
  const known = (name) => {
    if (names.has(name)) return true;
    if (search.some((d) => name.endsWith(`.${d}`) && names.has(name.slice(0, -(d.length + 1))))) return true;
    const reverse = reverseAddress(name);
    return reverse !== null && isInside(reverse, subnets);
  };
  const seen = new Set();
  for (const q of queries) {
    const key = `${q.name}|${q.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (EVER_DOMAINS.test(q.name)) violations.push({ rule: 'dns_ever_host', name: q.name, source: q.source });
    else if (!known(q.name)) violations.push({ rule: 'dns_unexpected', name: q.name, source: q.source });
  }
  for (const c of connections)
    if (!isInside(c.dst, subnets))
      violations.push({ rule: 'egress_attempt', service: c.service, proto: c.proto, dst: c.dst, port: c.dport });
  for (const [svc, text] of Object.entries(evidence.logs ?? {})) {
    for (const line of text.split('\n')) {
      if (!RESOLVER_ERRORS.test(line)) continue;
      // A compose name, or an address inside the sealed networks (a database not up yet), is not out.
      const host = errorHost(line);
      if (host && (names.has(normalise(host)) || isInside(host, subnets))) continue;
      violations.push({ rule: 'resolver_error', service: svc, line: line.trim().slice(0, 200) });
    }
  }
  if (evidence.mode.module_routes === '404') {
    for (const r of evidence.routes ?? [])
      if (r.status !== 404) violations.push({ rule: 'module_route_answered', path: r.path, status: r.status });
    if ((evidence.routes ?? []).length === 0 && (evidence.expectRoutes ?? true)) faults.push('no module route was probed');
  }
  let calls = null;
  if (evidence.mockExpected) {
    if (!Array.isArray(evidence.mockRecord)) faults.push('the mock platform was expected but its record could not be read');
    else {
      calls = checkCallLog(evidence.mockRecord, evidence.mode, { generated: evidence.generated ?? [], mark: evidence.mark ?? null });
      for (const p of calls.problems) violations.push({ rule: 'call_log', problem: p });
    }
  }
  if (Object.keys(evidence.sniffers ?? {}).length === 0 || Object.values(evidence.sniffers).every((t) => !/listening on/.test(t)))
    faults.push('no sniffer output: the capture did not run');
  // A proven violation fails the run even when part of it faulted; a run with neither a violation
  // nor its full evidence proves nothing (2).
  const exit = violations.length > 0 ? 1 : faults.length > 0 ? 2 : 0;
  return {
    exit,
    mode: evidence.modeName,
    violations,
    faults,
    summary: {
      rules: Object.fromEntries([...new Set(violations.map((v) => v.rule))].map((r) => [r, violations.filter((v) => v.rule === r).length])),
      dns_queries: queries.length,
      connection_attempts: connections.length,
      routes: evidence.routes ?? [],
      calls: calls ? calls.rows : null,
    },
  };
}

function main(argv) {
  const at = argv.indexOf('--evidence');
  const out = argv.indexOf('--out');
  if (at < 0) {
    process.stderr.write('assert: --evidence <evidence.json> is required\n');
    return 2;
  }
  const evidence = JSON.parse(readFileSync(argv[at + 1], 'utf8'));
  const report = evaluate(evidence);
  if (out >= 0) writeFileSync(argv[out + 1], `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return report.exit;
}

export { main };

if (process.argv[1] && process.argv[1].endsWith('assert.mjs')) process.exit(main(process.argv.slice(2)));
