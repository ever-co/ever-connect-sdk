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

/**
 * Addressing of the sealed default network: dynamic addresses in the lower half, fixed ones for
 * CoreDNS and the mock platform. The mock has a fixed address because the SDK takes plain http,
 * extra root keys and another issuer from a local address only (an address of a private range),
 * never from a bare name such as `mock-platform`: the products are pointed at `http://<mockIp>:8080`.
 */
export function addressing(subnet = '10.231.7.0/24') {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/.exec(subnet);
  if (!m) throw new Error(`the audit subnet must be a /24 (got ${subnet})`);
  const prefix = `${m[1]}.${m[2]}.${m[3]}`;
  return { subnet, ipRange: `${prefix}.0/25`, dnsIp: `${prefix}.253`, mockIp: `${prefix}.252`, browserIp: `${prefix}.251` };
}

/** The services of the browser leg: the namespace holder, its sniffer and the browser. */
export const BROWSER = {
  holder: 'ever-audit-browser-ns',
  sniffer: 'ever-audit-browser-sniffer',
  service: 'ever-audit-browser',
  capture: 'browser',
};

/** The port the mock platform listens on in its image. */
export const MOCK_PORT = 8080;

/**
 * The product model from `docker compose config --format json` (or an equivalent object):
 * {services: {name: service}, networks: [keys]}.
 */
export function productModel(config) {
  const networks = new Set(['default']);
  for (const n of Object.keys(config.networks ?? {})) networks.add(n);
  const external = Object.entries(config.networks ?? {})
    .filter(([, n]) => n?.external)
    .map(([key]) => key);
  return { services: config.services ?? {}, networks: [...networks], external };
}

/**
 * Refuses what the overlay cannot seal: a Docker network that exists outside the project
 * (`external`), and a service on the host's or another container's namespace. `network_mode: none`
 * and `service:<compose service>` stay inside the sealed networks.
 */
export function checkSealable(product) {
  for (const n of product.external ?? [])
    throw new Error(`Docker network ${n} is external: the audit seals only the compose networks the files create`);
  for (const [name, svc] of Object.entries(product.services)) {
    const mode = svc?.network_mode;
    if (mode === undefined || mode === null || mode === 'none') continue;
    const target = /^service:(.+)$/.exec(mode)?.[1];
    if (target && product.services[target]) continue;
    throw new Error(`service ${name} sets network_mode ${mode}: the audit can seal only the compose networks`);
  }
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
 * opts: {project, subnet, dnsImage, driverImage?, product{services, networks}, processServices[], env{},
 *        mock{image, config}|null, browser{image, webService}|null}
 */
export function buildOverlay(opts) {
  checkSealable(opts.product);
  const t = template();
  const { subnet, ipRange, dnsIp, mockIp, browserIp } = addressing(opts.subnet);
  const values = {
    PROJECT: opts.project,
    SUBNET: subnet,
    IP_RANGE: ipRange,
    DNS_IP: dnsIp,
    MOCK_IP: mockIp,
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
  if (opts.driverImage)
    services['ever-audit-driver'] = fill(t.services['ever-audit-driver'], { ...values, DRIVER_IMAGE: opts.driverImage });
  if (opts.browser) {
    const web = opts.product.services[opts.browser.webService];
    if (!web) throw new Error(`web_service ${opts.browser.webService} is not in the compose files`);
    const v = { ...values, SERVICE: BROWSER.capture, HOLDER: BROWSER.holder, SNIFFER: BROWSER.sniffer };
    // The browser's holder: a fixed address on the sealed default network (the CoreDNS log names
    // its queries by that address) and every other sealed network the web service is on.
    const holder = fill(t.services.__HOLDER__, v);
    const nets = Object.fromEntries(
      serviceNetworks(web)
        .filter((n) => n !== 'default')
        .map((n) => [n, {}]),
    );
    holder.networks = { default: { ipv4_address: browserIp }, ...nets };
    services[BROWSER.holder] = holder;
    services[BROWSER.sniffer] = { ...fill(t.services.__SNIFFER__, v), depends_on: [BROWSER.holder] };
    services[BROWSER.service] = fill(t.services[BROWSER.service], { ...values, BROWSER_IMAGE: opts.browser.image });
  }
  if (opts.mock)
    services['mock-platform'] = fill(t.services['mock-platform'], {
      ...values,
      MOCK_IMAGE: opts.mock.image,
      // Compose interpolates `$` in values; the configuration passes through as written.
      MOCK_CONFIG: JSON.stringify(opts.mock.config ?? {})
        .split('$')
        .join('$$'),
    });
  const networks = { default: fill(t.networks.default, values) };
  for (const n of opts.product.networks) if (n !== 'default') networks[n] = { internal: true };
  const text = YAML.stringify({ services, networks }, { lineWidth: 0 });
  return text.replace(new RegExp(`: ${RESET}$`, 'gm'), ': !reset null');
}

/**
 * The environment of a mode: the leading EVER_ of each name becomes the product prefix; null
 * values are set empty, which the modules read as unset. In every value, `__MOCK_URL__` becomes the
 * mock platform's address (`mock.url`, a local address the SDK accepts over plain http) and
 * `__MOCK_ISSUER__` the issuer its documents name (`mock.issuer`, https).
 */
export function modeEnv(values, prefix = 'EVER_', mock = null) {
  const out = {};
  for (const [k, v] of Object.entries(values)) {
    const name = k.startsWith('EVER_') ? `${prefix}${k.slice('EVER_'.length)}` : k;
    let value = v === null || v === undefined ? '' : String(v);
    if (mock) value = value.split('__MOCK_URL__').join(mock.url).split('__MOCK_ISSUER__').join(mock.issuer);
    out[name] = value;
  }
  return out;
}
