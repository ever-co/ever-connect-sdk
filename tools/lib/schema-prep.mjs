// Preparation of JSON Schemas for the type generators: inline the shared event definitions, hoist
// `$defs`, and (for the Rust generator) drop validation-only keywords so the types stay plain
// serde types. Validation always runs against the original schema files, never these copies.
const pascal = (s) =>
  s
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .split(' ')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join('');

export const typeName = (s) => pascal(s);

const clone = (v) => JSON.parse(JSON.stringify(v));

/**
 * An event schema with every `common.schema.json#/$defs/x` reference replaced by a local
 * `#/$defs/common_x` definition copied from the common schema.
 */
export function inlineCommon(schema, common) {
  const out = clone(schema);
  const needed = new Set();
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== 'object') return;
    if (typeof node.$ref === 'string' && node.$ref.startsWith('common.schema.json#/$defs/')) {
      const name = node.$ref.split('/').pop();
      needed.add(name);
      node.$ref = `#/$defs/common_${name}`;
    }
    Object.values(node).forEach(walk);
  };
  walk(out);
  // Common definitions may refer to each other.
  const pending = [...needed];
  const defs = {};
  while (pending.length > 0) {
    const name = pending.pop();
    if (defs[`common_${name}`]) continue;
    const def = clone(common.$defs[name]);
    if (!def) throw new Error(`common definition ${name} is missing`);
    const inner = (node) => {
      if (Array.isArray(node)) return node.forEach(inner);
      if (!node || typeof node !== 'object') return;
      if (typeof node.$ref === 'string' && node.$ref.startsWith('#/$defs/')) {
        const n = node.$ref.split('/').pop();
        node.$ref = `#/$defs/common_${n}`;
        pending.push(n);
      }
      Object.values(node).forEach(inner);
    };
    inner(def);
    defs[`common_${name}`] = def;
  }
  out.$defs = { ...(out.$defs ?? {}), ...defs };
  delete out.$id;
  return out;
}

const VALIDATION_ONLY = new Set([
  'pattern',
  'format',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'minItems',
  'maxItems',
  'uniqueItems',
  'minProperties',
  'maxProperties',
  'multipleOf',
  'propertyNames',
  'patternProperties',
  'if',
  'then',
  'else',
  'not',
  'examples',
  'example',
  '$comment',
  '$schema',
  '$id',
  'discriminator',
  'readOnly',
  'writeOnly',
  'deprecated',
  'externalDocs',
  'xml',
  'contentEncoding',
  'contentMediaType',
  'default',
]);

const SCHEMA_KEYS = ['type', 'properties', '$ref', 'oneOf', 'anyOf', 'allOf', 'enum', 'const', 'items', 'additionalProperties'];

/** A `$defs` member that only groups other definitions (no schema keyword of its own). */
const isGroup = (def) =>
  def !== null &&
  typeof def === 'object' &&
  !Array.isArray(def) &&
  !SCHEMA_KEYS.some((k) => k in def) &&
  Object.entries(def).every(([k, v]) => k.startsWith('$') || (v !== null && typeof v === 'object' && !Array.isArray(v)));

/**
 * A schema ready for the Rust generator: validation-only keywords removed, `$defs` hoisted into
 * one definitions map (names built from the definition path and prefixed with `prefix`, grouping
 * members flattened), references rewritten to `#/definitions/<Name>`. Conditional `allOf` members
 * (if/then) become empty and are dropped.
 */
export function forRust(schema, prefix, { rootName } = {}) {
  const defs = {};
  const rename = (path) => `${prefix}${path.map(pascal).join('')}`;
  const hoist = (path, def) => {
    if (isGroup(def)) {
      for (const [name, child] of Object.entries(def)) if (!name.startsWith('$')) hoist([...path, name], child);
      return;
    }
    defs[rename(path)] = strip(def);
  };
  function strip(node) {
    if (Array.isArray(node))
      return node.map(strip).filter((n) => !(n && typeof n === 'object' && !Array.isArray(n) && Object.keys(n).length === 0));
    if (!node || typeof node !== 'object') return node;
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      if (VALIDATION_ONLY.has(k)) continue;
      if (k === '$defs' || k === 'definitions') {
        for (const [name, def] of Object.entries(v)) hoist([name], def);
        continue;
      }
      if (k === '$ref') {
        const ref = String(v);
        if (ref.startsWith('#/$defs/') || ref.startsWith('#/definitions/')) out.$ref = `#/definitions/${rename(ref.split('/').slice(2))}`;
        else if (ref.startsWith('#/components/schemas/')) out.$ref = `#/definitions/${ref.split('/').pop()}`;
        else throw new Error(`unsupported $ref ${ref}`);
        continue;
      }
      if (k === 'properties' && v && typeof v === 'object') {
        out.properties = Object.fromEntries(Object.entries(v).map(([pk, pv]) => [pk, strip(pv)]));
        continue;
      }
      out[k] = v !== null && typeof v === 'object' ? strip(v) : v;
    }
    if (Array.isArray(out.allOf)) {
      out.allOf = out.allOf.filter((s) => s && Object.keys(s).length > 0);
      if (out.allOf.length === 0) delete out.allOf;
    }
    // `const` or a string `enum` without `type` leaves the value type open: state it.
    if ('const' in out && !('type' in out)) {
      const t = typeof out.const;
      if (t === 'string' || t === 'boolean') out.type = t;
      else if (Number.isInteger(out.const)) out.type = 'integer';
    }
    if (Array.isArray(out.enum) && !('type' in out) && out.enum.every((e) => typeof e === 'string')) out.type = 'string';
    return out;
  }
  const root = strip(schema);
  if (rootName) {
    delete root.title;
    defs[rootName] = root;
  }
  return defs;
}
