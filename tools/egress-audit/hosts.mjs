// The never-allowed list (ever-hosts.json) and its matcher, shared by the API leg, the browser leg,
// static-hostnames and the config check. Every entry matches the name itself and every name under
// it. Names are compared lower-cased, without a trailing dot and in their ASCII (punycode) form.
//
// EVER_EGRESS_EXTRA_HOSTS (comma-separated names, or a JSON array) adds names to the list for a run;
// nothing can remove one.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { domainToASCII, fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const here = dirname(fileURLToPath(import.meta.url));
export const EVER_HOSTS_FILE = join(here, 'ever-hosts.json');
const NAME = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
export const CATEGORIES = ['ever_owned', 'analytics_sinks', 'reference', 'extra'];

/** Lower case, no trailing dot, no brackets or port, ASCII form of an internationalised name. */
export function normaliseHost(name) {
  let h = String(name ?? '')
    .trim()
    .toLowerCase();
  if (h.startsWith('[')) {
    const close = h.indexOf(']');
    return close < 0 ? h.slice(1) : h.slice(1, close);
  }
  const colon = h.lastIndexOf(':');
  if (colon >= 0 && colon < h.length - 1 && [...h.slice(colon + 1)].every((c) => c >= '0' && c <= '9')) h = h.slice(0, colon);
  let end = h.length;
  while (end > 0 && h[end - 1] === '.') end -= 1;
  h = h.slice(0, end);
  if (/[^\x00-\x7f]/.test(h)) {
    const ascii = domainToASCII(h);
    if (ascii) h = ascii;
  }
  return h;
}

function extraHosts(env = process.env) {
  const raw = (env.EVER_EGRESS_EXTRA_HOSTS ?? '').trim();
  if (!raw) return [];
  let names;
  try {
    names = raw.startsWith('[') ? JSON.parse(raw) : raw.split(/[\s,]+/);
  } catch {
    throw new Error('EVER_EGRESS_EXTRA_HOSTS is neither a JSON array nor a comma-separated list');
  }
  const out = names.map(normaliseHost).filter(Boolean);
  for (const n of out)
    if (!NAME.test(n)) throw new Error(`EVER_EGRESS_EXTRA_HOSTS has an entry that is not a host name (${n.length} characters)`);
  return out;
}

let cached = null;

/** The list: {ever_owned[], analytics_sinks[], reference[], extra[]} (extra from EVER_EGRESS_EXTRA_HOSTS). */
export function loadEverHosts({ file = EVER_HOSTS_FILE, env = process.env } = {}) {
  if (file === EVER_HOSTS_FILE && env === process.env && cached) return cached;
  const data = JSON.parse(readFileSync(file, 'utf8'));
  const schema = JSON.parse(readFileSync(join(here, 'hosts.schema.json'), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  if (!validate(data))
    throw new Error(`${file} is not a valid host list: ${validate.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ')}`);
  const lists = {
    ever_owned: data.ever_owned,
    analytics_sinks: data.analytics_sinks,
    reference: data.reference,
    extra: extraHosts(env),
  };
  if (file === EVER_HOSTS_FILE && env === process.env) cached = lists;
  return lists;
}

/** The entry a name falls under, or null: {entry, category}. */
export function matchNeverAllowed(name, lists = loadEverHosts()) {
  const host = normaliseHost(name);
  if (!host) return null;
  for (const category of CATEGORIES)
    for (const entry of lists[category] ?? []) if (host === entry || host.endsWith(`.${entry}`)) return { entry, category };
  return null;
}

/** Whether a name is on the never-allowed list (an entry or any name under it). */
export const isNeverAllowed = (name, lists = loadEverHosts()) => matchNeverAllowed(name, lists) !== null;

/** Whether a name is under an Ever-owned entry (what static-hostnames looks for). */
export function isEverOwned(name, lists = loadEverHosts()) {
  const host = normaliseHost(name);
  return lists.ever_owned.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

const quote = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The JSON Schema pattern of every listed name (entries and every name under them), as
 * config.schema.json uses it in allowed_external_hosts (`not`). A test keeps the two equal.
 */
export function neverAllowedPattern(lists = loadEverHosts()) {
  const entries = [...lists.ever_owned, ...lists.analytics_sinks, ...lists.reference];
  return `(^|\\.)(${entries.map(quote).join('|')})\\.?$`;
}

/** The host a URL (or a mailto: address) names, normalised; null when it names none. */
export function hostOfUrl(value) {
  const text = String(value ?? '').trim();
  const mail = /^mailto:([^?]+)/i.exec(text);
  if (mail) {
    const at = mail[1].split(',')[0].lastIndexOf('@');
    return at >= 0 ? normaliseHost(decodeURIComponent(mail[1].split(',')[0].slice(at + 1))) : null;
  }
  try {
    const u = new URL(text.startsWith('//') ? `https:${text}` : text);
    return u.hostname ? normaliseHost(u.hostname) : null;
  } catch {
    return null;
  }
}

/** Host-shaped tokens of a line of text (for the static scan): `a.b.c` runs of letters, digits and dashes. */
export function hostsInText(line) {
  const out = [];
  for (const m of line.matchAll(/(?<![a-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![a-z0-9-])/gi))
    out.push(m[1].toLowerCase());
  return out;
}

/**
 * A product's opt-in hosts (optin-hosts.json): the Set of hosts the static scan accepts. Each must be
 * under an ever_owned entry. Throws on a file that does not follow optin-hosts.schema.json.
 */
export function loadOptinHosts(file, lists = loadEverHosts()) {
  const data = JSON.parse(readFileSync(file, 'utf8'));
  const schema = JSON.parse(readFileSync(join(here, 'optin-hosts.schema.json'), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  if (!validate(data))
    throw new Error(`${file} is not a valid opt-in list: ${validate.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ')}`);
  const hosts = new Set();
  for (const { host } of data.hosts) {
    const h = normaliseHost(host);
    if (!isEverOwned(h, lists)) throw new Error(`${file}: ${h} is not under an Ever-owned name of ever-hosts.json`);
    if (isPlatformServiceHost(h))
      throw new Error(`${file}: ${h} is an Ever Platform service name; an opt-in is an older default-off feature, never the platform itself`);
    hosts.add(h);
  }
  return hosts;
}

/**
 * How a report or a message names a list entry: the entry itself, or `extra#<n>` for a name added
 * with EVER_EGRESS_EXTRA_HOSTS. Those names are kept out of public files on purpose (CI passes them
 * from a secret), so no report, violation or message prints them.
 */
export function entryLabel(match, lists = loadEverHosts()) {
  if (!match || match.category !== 'extra') return match?.entry;
  return `extra#${lists.extra.indexOf(match.entry) + 1}`;
}

/** A copy of value (strings, arrays and plain objects, deep) with every EVER_EGRESS_EXTRA_HOSTS name replaced by its label. */
export function hideExtraHosts(value, lists = loadEverHosts()) {
  const extra = lists.extra ?? [];
  if (extra.length === 0) return value;
  // Longest first, so a name never leaves part of a longer one behind.
  const order = extra.map((name, i) => ({ name, label: `extra#${i + 1}` })).sort((a, b) => b.name.length - a.name.length);
  const hide = (text) => order.reduce((t, { name, label }) => t.replace(new RegExp(quote(name), 'gi'), label), text);
  const walk = (v) => {
    if (typeof v === 'string') return hide(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [hide(k), walk(x)]));
    return v;
  };
  return walk(value);
}

/**
 * The platform's own service names: never an operator opt-in. An opt-in is a feature that existed
 * before the modules (an update check, a news feed), never the platform API, app or sign-in.
 */
export const PLATFORM_SERVICE_HOSTS = ['ever.co', 'api.ever.co', 'app.ever.co', 'auth.ever.co', 'apps.ever.co'];

/** Whether a name is one of the platform's service names or under api., app., auth. or apps.ever.co. */
export function isPlatformServiceHost(name) {
  const host = normaliseHost(name);
  return PLATFORM_SERVICE_HOSTS.some((p) => host === p || (p !== 'ever.co' && host.endsWith(`.${p}`)));
}
