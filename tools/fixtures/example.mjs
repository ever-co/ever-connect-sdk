// Builds a deterministic, schema-valid example document from a JSON Schema whose shared event
// definitions were inlined (`#/$defs/common_<name>`). Values come from the definition name first,
// then from the property name or the pattern; the caller validates the result against the
// original schema.
import { hex64, iso, NOW, ulid, uuid } from './ids.mjs';

const BY_DEF = {
  ulid: (label) => ulid(label),
  uuid: (label) => uuid(label),
  datetime: () => iso(NOW),
  hex64: (label) => hex64(label),
  handle: () => 'acme',
  install_source: () => 'self-hosted',
  field_name: () => 'organization.name',
  key: () => 'lookup',
  integration_key: () => 'stats_link',
  period: () => '2026-11',
  country: () => 'BG',
  currency: () => 'EUR',
  semver: () => '1.4.2',
  https_url: () => 'https://auth.ever.co',
  product_id: () => 'user-1',
  external_id: () => 'ext-1',
  slug: () => 'acme',
  vocab: () => 'default',
  dpa_version: () => '2026-10',
};

const BY_PROPERTY = {
  meter_key: 'lookup.queries',
  integration_key: 'stats_link',
  reason: 'owner',
};

const BY_PATTERN = new Map([
  ['^[0-9A-HJKMNP-TV-Z]{26}$', (label) => ulid(label)],
  ['^[0-9a-f]{64}$', (label) => hex64(label)],
  ['^[A-Za-z0-9._:-]{1,64}$', () => 'ext-1'],
  ['^[A-Za-z0-9_-]{11,64}$', () => 'aBcDeFgHiJk'],
]);

function resolve(node, root) {
  let n = node;
  while (n && typeof n.$ref === 'string') {
    const path = n.$ref.replace(/^#\//, '').split('/');
    n = path.reduce((o, k) => o?.[k], root);
    if (!n) throw new Error(`example: unresolved ${node.$ref}`);
  }
  return n;
}

const COMMON_PREFIX = '#/$defs/common_';
const defName = (node) =>
  typeof node?.$ref === 'string' && node.$ref.startsWith(COMMON_PREFIX) ? node.$ref.slice(COMMON_PREFIX.length) : null;

export function example(schema, root = schema, label = 'x', prop = null) {
  const common = defName(schema);
  if (common && BY_DEF[common]) return BY_DEF[common](`${label}/${prop ?? ''}`);
  const s = resolve(schema, root);
  if ('const' in s) return s.const;
  if (Array.isArray(s.enum)) return s.enum.find((v) => v !== null) ?? null;
  if (Array.isArray(s.examples) && s.examples.length > 0 && s !== root) return structuredClone(s.examples[0]);
  if (Array.isArray(s.oneOf)) return example(s.oneOf[0], root, label, prop);
  if (Array.isArray(s.anyOf)) return example(s.anyOf.find((b) => resolve(b, root).type !== 'null') ?? s.anyOf[0], root, label, prop);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== 'null') : s.type;
  if (type === 'object' || s.properties) {
    const out = {};
    for (const [k, v] of Object.entries(s.properties ?? {})) out[k] = example(v, root, `${label}/${k}`, k);
    return out;
  }
  if (type === 'array') return [example(s.items ?? {}, root, `${label}/0`, prop)];
  if (type === 'integer' || type === 'number') return Math.max(s.minimum ?? 1, 1);
  if (type === 'boolean') return true;
  if (type === 'string') {
    if (prop && prop in BY_PROPERTY) return BY_PROPERTY[prop];
    if (s.format === 'date-time') return iso(NOW);
    if (!s.pattern) return 'example';
    const make = BY_PATTERN.get(s.pattern);
    if (make) return make(label);
    throw new Error(`example: no value for string ${prop ?? label} with pattern ${s.pattern}`);
  }
  throw new Error(`example: cannot build ${label} (${JSON.stringify(s).slice(0, 80)})`);
}
