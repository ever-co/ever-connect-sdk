// The statistics schema is closed: every string is constrained, every object is closed or a typed
// keyed map, no free-string array. Both known-good controls must fail, or the walk proves nothing.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { REPO, readJson } from '../lib/common.mjs';

const FORBIDDEN_FORMATS = new Set(['email', 'uri', 'hostname', 'ipv4', 'ipv6']);
const MAX_STRING = 64;
const COMBINATORS = ['$ref', 'oneOf', 'anyOf', 'allOf', 'properties', 'const', 'enum'];

/** The closed-schema walk of the allow-list rule; answers the violations. */
export function closedSchemaViolations(schema) {
  const out = [];
  const walk = (node, path) => {
    if (Array.isArray(node)) {
      node.forEach((n, i) => walk(n, `${path}/${i}`));
      return;
    }
    if (!node || typeof node !== 'object') return;
    if ('const' in node || 'enum' in node) {
      for (const e of node.enum ?? [])
        if (typeof e === 'string' && e.length > MAX_STRING) out.push(`${path}: enum member longer than ${MAX_STRING}`);
    } else if (node.type === 'string') {
      if (!('pattern' in node)) out.push(`${path}: free string`);
      if (!Number.isInteger(node.maxLength) || node.maxLength > MAX_STRING) out.push(`${path}: no maxLength`);
      if (FORBIDDEN_FORMATS.has(node.format)) out.push(`${path}: forbidden format ${node.format}`);
    } else if (node.type === 'object') {
      const keyed = node.propertyNames?.pattern && node.additionalProperties && typeof node.additionalProperties === 'object';
      if (node.additionalProperties !== false && !keyed) out.push(`${path}: object not closed`);
    } else if (node.type === 'array') {
      if (!node.items || typeof node.items !== 'object') out.push(`${path}: array without items`);
      else if (node.items.type === 'string' && !node.items.enum && !node.items.pattern) out.push(`${path}: free-string array`);
    } else if (!('type' in node) && !COMBINATORS.some((k) => k in node)) {
      for (const [k, v] of Object.entries(node)) if (!k.startsWith('$') && typeof v === 'object') walk(v, `${path}/${k}`);
      return;
    }
    for (const key of ['properties', '$defs']) for (const [k, v] of Object.entries(node[key] ?? {})) walk(v, `${path}/${key}/${k}`);
    for (const key of ['items', 'additionalProperties', 'propertyNames'])
      if (node[key] && typeof node[key] === 'object') walk(node[key], `${path}/${key}`);
    for (const key of ['oneOf', 'anyOf', 'allOf']) if (node[key]) walk(node[key], `${path}/${key}`);
  };
  walk(schema, '#');
  return out;
}

const stats = readJson(join(REPO, 'contracts/schemas/ever.stats.v1.json'));

test('the statistics schema is closed at every level', () => {
  assert.deepEqual(closedSchemaViolations(stats), []);
});

test('control: a free-string version is caught', () => {
  const bad = structuredClone(stats);
  bad.properties.version = { type: 'string' };
  const v = closedSchemaViolations(bad);
  assert.ok(v.some((x) => x.includes('free string')));
  assert.ok(v.some((x) => x.includes('no maxLength')));
});

test('control: an open counts object is caught', () => {
  const bad = structuredClone(stats);
  delete bad.$defs.gauzy.counts.additionalProperties;
  assert.ok(closedSchemaViolations(bad).some((x) => x.includes('object not closed')));
});

test('additionalProperties is false on every object node of the statistics schema', () => {
  const objects = [];
  const walk = (n, p) => {
    if (Array.isArray(n)) return n.forEach((x, i) => walk(x, `${p}/${i}`));
    if (!n || typeof n !== 'object') return;
    if (n.type === 'object' && !n.propertyNames) objects.push([p, n.additionalProperties]);
    for (const [k, v] of Object.entries(n)) walk(v, `${p}/${k}`);
  };
  walk(stats, '#');
  assert.ok(objects.length > 10);
  for (const [p, ap] of objects) assert.equal(ap, false, `${p} is not closed`);
});

test('the entitlement, consent and key-manifest schemas are closed objects', () => {
  for (const file of ['ever.entitlement.v1.json', 'ever.consent.v1.json', 'ever.key-manifest.v1.json']) {
    const schema = readJson(join(REPO, 'contracts/schemas', file));
    const walk = (n, p) => {
      if (Array.isArray(n)) return n.forEach((x, i) => walk(x, `${p}/${i}`));
      if (!n || typeof n !== 'object') return;
      if (n.type === 'object' && n.properties && !n.propertyNames) assert.equal(n.additionalProperties, false, `${file}${p} is not closed`);
      // A condition (if/then/else) constrains the object the enclosing schema already closes.
      for (const [k, v] of Object.entries(n)) if (!['if', 'then', 'else'].includes(k)) walk(v, `${p}/${k}`);
    };
    walk(schema, '#');
  }
});
