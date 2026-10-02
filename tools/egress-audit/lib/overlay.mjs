// Builds the audit overlay (compose.audit.yml filled in) and the CoreDNS configuration of one run.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const RESET = '__EVER_AUDIT_RESET__';

/** TCP SYN without ACK, and UDP (DNS included, to read the queried names). */
export const SNIFFER_FILTER = '(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0) or udp';

/** Settings Docker refuses together with a shared network namespace. */
export const NAMESPACE_CONFLICTS = [
  'hostname',
  'domainname',
  'ports',
  'expose',
  'dns',
  'dns_search',
  'dns_opt',
  'extra_hosts',
  'links',
  'mac_address',
];

function template() {
  return YAML.parse(readFileSync(join(here, '..', 'compose.audit.yml'), 'utf8'), {
    customTags: [{ tag: '!reset', resolve: () => RESET }],
  });
}

function fill(node, values) {
  if (Array.isArray(node)) return node.map((n) => fill(n, values));
  if (node && typeof node === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[fill(k, values)] = fill(v, values);
    return out;
  }
  if (typeof node === 'string') return node.replace(/__([A-Z_]+)__/g, (m, name) => (name in values ? String(values[name]) : m));
  return node;
}

/** Addressing of the sealed default network: dynamic addresses in the lower half. */
export function addressing(subnet = '10.231.7.0/24') {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/.exec(subnet);
  if (!m) throw new Error(`the audit subnet must be a /24 (got ${subnet})`);
  const prefix = `${m[1]}.${m[2]}.${m[3]}`;
  return { subnet, ipRange: `${prefix}.0/25`, dnsIp: `${prefix}.253` };
}

/**
 * The product model from `docker compose config --format json` (or an equivalent object):
 * {services: {name: service}, networks: [keys]}.
 */
export function productModel(config) {
  const networks = new Set(['default']);
  for (const n of Object.keys(config.networks ?? {})) networks.add(n);
  return { services: config.services ?? {}, networks: [...networks] };
}

export const serviceNetworks = (svc) => {
  if (!svc?.networks) return ['default'];
  return Array.isArray(svc.networks) ? svc.networks : Object.keys(svc.networks);
};

/** Every name a compose service answers to: service names, network aliases and container names. */
export function composeNames(services) {
  const names = new Set();
  for (const [name, svc] of Object.entries(services)) {
    names.add(name);
    if (svc?.container_name) names.add(svc.container_name);
    if (svc?.networks && !Array.isArray(svc.networks))
      for (const n of Object.values(svc.networks)) for (const a of n?.aliases ?? []) names.add(a);
  }
  return [...names].map((n) => n.toLowerCase()).sort();
}

/** The CoreDNS configuration: the compose names forwarded to Docker's resolver, NXDOMAIN for the rest. */
export function corefile(names) {
  const zones = names.map((n) => `${n}.`).join(' ');
  return readFileSync(join(here, '..', 'Corefile'), 'utf8').replace('__COMPOSE_NAMES__', zones);
}

function dependsOn(svc) {
  if (!svc?.depends_on) return {};
  if (Array.isArray(svc.depends_on)) return Object.fromEntries(svc.depends_on.map((d) => [d, { condition: 'service_started' }]));
  return svc.depends_on;
}

/**
 * The overlay as YAML text.
 * opts: {project, subnet, dnsImage, product{services, networks}, processServices[], env{},
 *        mock{image, config}|null}
 */
export function buildOverlay(opts) {
  const t = template();
  const { subnet, ipRange, dnsIp } = addressing(opts.subnet);
  const values = {
    PROJECT: opts.project,
    SUBNET: subnet,
    IP_RANGE: ipRange,
    DNS_IP: dnsIp,
    DNS_IMAGE: opts.dnsImage,
    FILTER: SNIFFER_FILTER,
  };
  const services = {};
  const dns = fill(t.services['ever-audit-dns'], values);
  // CoreDNS joins every product network, so Docker's resolver of its container knows every service.
  for (const n of opts.product.networks) if (n !== 'default') dns.networks[n] = {};
  services['ever-audit-dns'] = dns;
  for (const name of opts.processServices) {
    const original = opts.product.services[name];
    if (!original) throw new Error(`process service ${name} is not in the compose files`);
    if (original.network_mode)
      throw new Error(`process service ${name} sets network_mode (${original.network_mode}); the audit needs its own namespace`);
    const v = { ...values, SERVICE: name, HOLDER: `ever-audit-ns-${name}`, SNIFFER: `ever-audit-sniffer-${name}` };
    const holder = fill(t.services.__HOLDER__, v);
    // The holder joins every compose network the service was on, with the service's name as its alias.
    const nets = new Set(['default', ...serviceNetworks(original)]);
    holder.networks = Object.fromEntries([...nets].map((n) => [n, { aliases: [name] }]));
    services[v.HOLDER] = holder;
    services[v.SNIFFER] = { ...fill(t.services.__SNIFFER__, v), depends_on: [v.HOLDER] };
    const product = fill(t.services.__SERVICE__, v);
    for (const key of NAMESPACE_CONFLICTS) if (original[key] !== undefined) product[key] = RESET;
    product.environment = opts.env;
    product.depends_on = { ...dependsOn(original), [v.SNIFFER]: { condition: 'service_started' } };
    services[name] = product;
  }
  if (opts.mock)
    services['mock-platform'] = fill(t.services['mock-platform'], {
      ...values,
      MOCK_IMAGE: opts.mock.image,
      MOCK_CONFIG: JSON.stringify(opts.mock.config ?? {}),
    });
  const networks = { default: fill(t.networks.default, values) };
  for (const n of opts.product.networks) if (n !== 'default') networks[n] = { internal: true };
  const text = YAML.stringify({ services, networks }, { lineWidth: 0 });
  return text.replace(new RegExp(`: ${RESET}$`, 'gm'), ': !reset null');
}

/**
 * The environment of a mode: the leading EVER_ of each name becomes the product prefix; null
 * values are set empty, which the modules read as unset.
 */
export function modeEnv(values, prefix = 'EVER_') {
  const out = {};
  for (const [k, v] of Object.entries(values)) {
    const name = k.startsWith('EVER_') ? `${prefix}${k.slice('EVER_'.length)}` : k;
    out[name] = v === null || v === undefined ? '' : String(v);
  }
  return out;
}
