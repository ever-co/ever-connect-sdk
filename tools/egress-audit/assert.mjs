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
 *   (a) a DNS name outside the compose services and allowed_external_hosts was queried; a name of
 *       the never-allowed list (ever-hosts.json) always fails, whatever the allow-list says;
 *   (b) a connection attempt left the sealed networks (loopback excepted), a DNS query sent to a
 *       resolver outside them included;
 *   (c) a product log shows a resolver or connection error (ENOTFOUND, ECONNREFUSED, EAI_AGAIN,
 *       ENETUNREACH, EHOSTUNREACH) for a host outside the compose services and the sealed networks;
 *   (d) in an off mode, a module route answered anything but 404;
 *   in a positive mode, the recorded calls differ from the mode's rows (assert-call-log);
 * and, for the browser leg (a product UI walked by browser.mjs):
 *   (e) the browser's DNS queries (the CoreDNS log lines from its address and its sniffer) follow
 *       (a), and its capture follows (b);
 *   (f) no HAR entry (nor any request or WebSocket the browser opened) goes to a never-allowed
 *       host, whatever allowed_external_hosts or the product's opt-in list says;
 *   (g) no DOM reference (href, src, srcset, action, ...) points at a never-allowed host, unless
 *       ui-baseline.json lists the same {route, attribute, url};
 *   in a positive browser mode, every request of the product's ui_expected_requests was made.
 * A harness fault (no evidence where some was expected) is exit 2 when nothing was violated: an
 * unproven run proves nothing.
 *
 *   ever-egress-audit assert --evidence <evidence.json> [--out report.json]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { checkCallLog } from './assert-call-log.mjs';
import { entryLabel, hideExtraHosts, hostOfUrl, matchNeverAllowed } from './hosts.mjs';
import { harEntries, redactUrl } from './lib/har.mjs';

/** The Ever domains of the first version, kept for importers; the checks read ever-hosts.json (hosts.mjs). */
export const EVER_DOMAINS = /(^|\.)(ever\.co|ever\.team|gauzy\.co|ever\.works|rec\.so|traduora\.co)$/i;
// ENETUNREACH and EHOSTUNREACH: an attempt that failed inside the namespace without a packet to
// capture, such as a connection to an IPv6 address (the sealed networks have no IPv6 route).
const RESOLVER_ERRORS = /\b(ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|EHOSTUNREACH)\b/;

const normalise = (name) => name.toLowerCase().replace(/\.$/, '');

/** DNS names from a CoreDNS `log` plugin output, each with the client address that asked. */
export function corednsQueries(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const m = /"(\w+) IN (\S+?) (udp|tcp) /.exec(line);
    if (!m) continue;
    const client = /\]\s+\[?([0-9a-f.:]+?)\]?:\d+ - /i.exec(line)?.[1] ?? null;
    out.push({ name: normalise(m[2]), type: m[1], source: 'coredns', client });
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

/** A list match as a violation field: {list: category, entry}. */
const listOf = (match) => ({ list: match.category, entry: entryLabel(match) });

/** The {route, attribute, url} key of a DOM reference or a baseline entry (URLs compared without their secrets). */
const refKey = (r) => `${r.route}|${r.attribute}|${redactUrl(r.url)}`;

/**
 * The browser leg: (e) its DNS queries and capture, (f) HAR entries and requests, (g) DOM
 * references, and the positive control. Pushes onto violations and faults; answers the summary.
 * browser: {enabled, required, positive, ips[], sniffer, har, requests[], domRefs[], visits[],
 *           skipped[], baseline[], expected[], faults[]}
 */
function evaluateBrowser(browser, { violations, faults, known, subnets, corednsLines, composeNames }) {
  if (!browser) return null;
  if (!browser.enabled) {
    if (browser.required) faults.push(browser.reason ?? 'the browser leg did not run');
    return { leg: 'not run' };
  }
  for (const f of browser.faults ?? []) faults.push(`browser: ${f}`);
  const ips = new Set(browser.ips ?? []);
  // (e) DNS: the CoreDNS lines from the browser's address and the questions its sniffer saw.
  const queries = corednsLines.filter((q) => q.client && ips.has(q.client)).map((q) => ({ ...q, source: 'coredns:browser' }));
  const sniffed = snifferEvents(browser.sniffer ?? '', 'browser');
  queries.push(...sniffed.queries);
  if (!/listening on/.test(browser.sniffer ?? '')) faults.push('no sniffer output from the browser: its capture did not run');
  const seen = new Set();
  let outside = 0;
  for (const q of queries) {
    const key = `${q.name}|${q.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const match = matchNeverAllowed(q.name);
    if (match) violations.push({ rule: 'browser_dns_never_allowed', check: 'e', name: q.name, source: q.source, ...listOf(match) });
    else if (!known(q.name)) violations.push({ rule: 'browser_dns_unexpected', check: 'e', name: q.name, source: q.source });
    if (match || !known(q.name)) outside += 1;
  }
  let attempts = 0;
  for (const c of sniffed.connections)
    if (!isInside(c.dst, subnets)) {
      attempts += 1;
      violations.push({ rule: 'browser_egress_attempt', check: 'e', proto: c.proto, dst: c.dst, port: c.dport });
    }
  // (f) every HAR entry, request and WebSocket: never a listed host, whatever the configuration says.
  const rows = [
    ...harEntries(browser.har).map((e) => ({ ...e, from: 'har' })),
    ...(browser.requests ?? []).map((r) => ({ method: r.method, url: r.url, host: hostOfUrl(r.url) ?? '', from: 'requests' })),
  ];
  const flagged = new Set();
  for (const r of rows) {
    const match = r.host ? matchNeverAllowed(r.host) : null;
    if (!match) continue;
    const key = `${r.method} ${r.url}`;
    if (flagged.has(key)) continue;
    flagged.add(key);
    violations.push({ rule: 'har_never_allowed', check: 'f', method: r.method, url: r.url, host: r.host, ...listOf(match) });
  }
  // (g) DOM references, minus the product's baseline of references that pre-date the modules.
  const baseline = new Set((browser.baseline ?? []).map(refKey));
  const used = new Set();
  let domHits = 0;
  let baselined = 0;
  const domSeen = new Set();
  for (const r of browser.domRefs ?? []) {
    const host = hostOfUrl(r.url);
    const match = host ? matchNeverAllowed(host) : null;
    if (!match) continue;
    const key = refKey(r);
    if (domSeen.has(key)) continue;
    domSeen.add(key);
    if (baseline.has(key)) {
      baselined += 1;
      used.add(key);
      continue;
    }
    domHits += 1;
    violations.push({ rule: 'dom_never_allowed', check: 'g', route: r.route, attribute: r.attribute, url: r.url, host, ...listOf(match) });
  }
  // The positive control: the requests the product's UI must make to a compose service.
  const inside = (host) => composeNames.has(normalise(host)) || isInside(host, subnets);
  const expected = (browser.expected ?? []).map((spec) => {
    const [method, path] = spec.split(' ');
    const hit = rows.some(
      (r) =>
        r.method === method &&
        r.host &&
        inside(r.host) &&
        (() => {
          try {
            return new URL(r.url).pathname === path;
          } catch {
            return false;
          }
        })(),
    );
    if (!hit) violations.push({ rule: 'browser_expected_missing', request: spec });
    return { request: spec, seen: hit };
  });
  if (browser.positive && expected.length === 0) faults.push('the browser leg is positive in this mode but no request is expected of it');
  const visits = browser.visits ?? [];
  return {
    leg: 'ran',
    visits: visits.length,
    loaded: visits.filter((v) => v.ok).length,
    status_4xx: visits.filter((v) => v.ok && v.status >= 400).map((v) => `${v.route} ${v.status}`),
    // Routes that ended somewhere else than they were asked for (a redirect, the sign-in page).
    sign_in_path: browser.signInPath ?? null,
    // How routes were opened and read: "path", or "hash" (a route is the path of a #/ fragment).
    routing: browser.routing ?? null,
    redirected: visits.filter((v) => v.ok && v.final_path && v.path && v.final_path !== v.path).map((v) => `${v.route} -> ${v.final_path}`),
    route_list: browser.routeCheck ?? null,
    skipped: browser.skipped ?? [],
    checks: {
      e: { dns_queries: queries.length, outside, attempts },
      f: { entries: rows.length, never_allowed: flagged.size },
      g: { refs: (browser.domRefs ?? []).length, never_allowed: domHits, baselined },
    },
    expected,
    stale_baseline: (browser.baseline ?? [])
      .filter((b) => !used.has(refKey(b)))
      .map((b) => ({ route: b.route, attribute: b.attribute, url: b.url })),
  };
}

/**
 * Evaluates the evidence; answers {exit, mode, violations, faults, summary}.
 * evidence: {mode, modeName, subnets[], composeNames[], allowedHosts[], searchDomains[], coredns,
 *            sniffers{svc: text}, logs{svc: text}, routes[{path, status}], expectRoutes,
 *            mockRecord[]|null, mockExpected, mark, generated[], faults[], browser?}
 */
export function evaluate(evidence) {
  const violations = [];
  const faults = [...(evidence.faults ?? [])];
  const subnets = evidence.subnets ?? [evidence.subnet].filter(Boolean);
  const composeNames = new Set([...(evidence.composeNames ?? []), 'localhost'].map(normalise));
  const names = new Set([...(evidence.composeNames ?? []), ...(evidence.allowedHosts ?? []), 'localhost'].map(normalise));
  const browserIps = new Set(evidence.browser?.enabled ? (evidence.browser.ips ?? []) : []);
  const corednsLines = corednsQueries(evidence.coredns ?? '');
  // The browser's lines are its own leg (e); every other line is the product processes'.
  const queries = corednsLines.filter((q) => !(q.client && browserIps.has(q.client)));
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
    const match = matchNeverAllowed(q.name);
    if (match) violations.push({ rule: 'dns_ever_host', name: q.name, source: q.source, ...listOf(match) });
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
  const browser = evaluateBrowser(evidence.browser, { violations, faults, known, subnets, corednsLines, composeNames });
  // A proven violation fails the run even when part of it faulted; a run with neither a violation
  // nor its full evidence proves nothing (2).
  const exit = violations.length > 0 ? 1 : faults.length > 0 ? 2 : 0;
  // Names added with EVER_EGRESS_EXTRA_HOSTS are printed as extra#<n>, never by name.
  return hideExtraHosts({
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
      ...(browser ? { browser } : {}),
    },
  });
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
