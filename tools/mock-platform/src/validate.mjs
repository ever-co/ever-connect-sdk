// Validation against the closed contract schemas, with errors as problem `errors[]` entries
// ({path, code, message}; path is a JSON pointer into the body).
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { contract } from './contract.mjs';

const CONTRACT_ID = 'urn:ever-connect-sdk:contract';

function makeAjv() {
  const ajv = new Ajv2020({ strict: false, allErrors: true, allowUnionTypes: true, validateFormats: true });
  addFormats(ajv);
  return ajv;
}

let state = null;

function init() {
  if (state) return state;
  const c = contract();
  const ajv = makeAjv();
  ajv.addSchema({ $id: CONTRACT_ID, components: { schemas: c.spec.components.schemas } });
  for (const schema of Object.values(c.eventSchemas)) ajv.addSchema(schema);
  for (const schema of Object.values(c.schemas)) ajv.addSchema(schema);
  const pendingSchemas = {};
  for (const op of c.pending.operations)
    if (op.request) pendingSchemas[op.operation_id] = ajv.compile({ ...op.request, $id: `${CONTRACT_ID}:pending:${op.operation_id}` });
  state = { ajv, c, cache: new Map(), pendingSchemas };
  return state;
}

const ajvCode = (keyword) =>
  ({
    required: 'required',
    additionalProperties: 'unknown_field',
    unevaluatedProperties: 'unknown_field',
    type: 'invalid_shape',
    maxLength: 'too_long',
    maxItems: 'too_long',
    maxProperties: 'too_long',
    minimum: 'out_of_range',
    maximum: 'out_of_range',
    exclusiveMinimum: 'out_of_range',
    exclusiveMaximum: 'out_of_range',
    minItems: 'out_of_range',
    minLength: 'out_of_range',
  })[keyword] ?? 'invalid';

const escapePointer = (s) => String(s).replace(/~/g, '~0').replace(/\//g, '~1');

/** Ajv errors as field errors, the most specific first, without the combinator noise. */
export function fieldErrors(errors, data) {
  const out = [];
  const seen = new Set();
  for (const e of errors ?? []) {
    if (['oneOf', 'anyOf', 'if', 'allOf'].includes(e.keyword)) continue;
    let path = e.instancePath;
    if (e.keyword === 'required') path = `${path}/${escapePointer(e.params.missingProperty)}`;
    if (e.keyword === 'additionalProperties' || e.keyword === 'unevaluatedProperties')
      path = `${path}/${escapePointer(e.params.additionalProperty ?? e.params.unevaluatedProperty)}`;
    // A branch of a oneOf that does not apply (its discriminating const failed) is not the answer.
    if (e.keyword === 'const' && /\/oneOf\/\d+\//.test(e.schemaPath)) continue;
    const key = `${path}|${ajvCode(e.keyword)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      path,
      code: ajvCode(e.keyword),
      message: e.message ?? 'is invalid',
      depth: path.split('/').length,
      branch: branchOf(e.schemaPath),
    });
  }
  // Prefer the oneOf branch that matches the document (statistics: the report's product).
  const product = data && typeof data === 'object' ? data.product : undefined;
  const preferred = out.filter((f) => f.branch === null || f.branch === product);
  const pool = preferred.length > 0 ? preferred : out;
  pool.sort((a, b) => b.depth - a.depth);
  if (pool.length === 0 && (errors ?? []).length > 0) {
    const e = errors[0];
    return [{ path: e.instancePath, code: ajvCode(e.keyword), message: e.message ?? 'is invalid' }];
  }
  return pool.map(({ path, code, message }) => ({ path, code, message }));
}

// The statistics schema's oneOf branches are in product order.
const STATS_BRANCHES = ['gauzy', 'teams', 'works', 'rec', 'traduora'];
function branchOf(schemaPath) {
  const def = /#\/\$defs\/([a-z]+)\//.exec(schemaPath);
  if (def && STATS_BRANCHES.includes(def[1])) return def[1];
  const m = /#\/oneOf\/(\d+)\//.exec(schemaPath);
  if (!m) return null;
  return STATS_BRANCHES[Number(m[1])] ?? `branch-${m[1]}`;
}

function result(validate, data) {
  const ok = validate(data);
  return ok ? { ok: true, errors: [] } : { ok: false, errors: fieldErrors(validate.errors, data) };
}

/** Validates a body against a component schema of the contract (by name). */
export function validateComponent(name, data) {
  const s = init();
  if (!s.c.spec.components.schemas[name]) throw new Error(`no component schema ${name}`);
  let v = s.cache.get(`c:${name}`);
  if (!v) {
    v = s.ajv.getSchema(`${CONTRACT_ID}#/components/schemas/${name}`);
    s.cache.set(`c:${name}`, v);
  }
  return result(v, data);
}

/** Validates against one of the JSON Schemas: stats, entitlement, consent, keyManifest. */
export function validateSchema(key, data) {
  const s = init();
  const schema = s.c.schemas[key];
  if (!schema) throw new Error(`no schema ${key}`);
  return result(s.ajv.getSchema(schema.$id), data);
}

/** Validates the `data` of an event against its catalog schema (by event type). */
export function validateEventData(type, data) {
  const s = init();
  const file = Object.keys(s.c.eventSchemas).find((f) => f.startsWith(`${type}.v`));
  if (!file) return { ok: false, errors: [{ path: '/type', code: 'invalid', message: `unknown event type ${type}` }] };
  return result(s.ajv.getSchema(s.c.eventSchemas[file].$id), data);
}

/** Validates a full event envelope (shape only; `data` is checked by validateEventData). */
export function validateEnvelope(event) {
  const s = init();
  const envelope = s.c.eventSchemas['envelope.schema.json'];
  return result(s.ajv.getSchema(envelope.$id), event);
}

/** Validates a body of a call that is pending upstream (pending-upstream.json). */
export function validatePending(operationId, data) {
  const s = init();
  const v = s.pendingSchemas[operationId];
  if (!v) return { ok: true, errors: [] };
  return result(v, data);
}

/** The request body schema name of an operation, or null. */
export function requestSchemaName(op) {
  const ref = op?.requestBody?.content?.['application/json']?.schema?.$ref;
  return ref ? ref.split('/').pop() : null;
}
