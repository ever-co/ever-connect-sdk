// The checks Ever Platform runs on a statistics report body, in its order, with its answers: the
// size limit, a strict JSON reader (no fraction or exponent, no repeated key, no integer outside
// 64 bits, at most 16 levels), the published schema in two passes (the envelope without the
// per-product `oneOf`, then the product's own lists, so a foreign key is named where it stands),
// and the calendar date of `sent_at`. Every refusal names the field and a code from a closed list
// and never repeats a value that was sent.
//
// The schema checks cover the JSON Schema keywords the statistics schema uses; field errors are
// sorted by path and code, one per (path, code), at most 20.

export const MAX_REPORT_BYTES = 16 * 1024;
export const MAX_DEPTH = 16;
export const MAX_ERRORS = 20;

/** The field error codes of a refused report. */
export const STATS_ERROR_CODES = ['unknown_field', 'type', 'pattern', 'range', 'required', 'duplicate_key', 'schema_unknown', 'too_large'];

const MESSAGES = {
  syntax: 'the body is not a JSON document of the expected shape',
  fraction: 'numbers are integers: no fraction, no exponent',
  out_of_range: 'the integer is out of range',
  duplicate_key: 'a key may appear once in an object',
};
const OFFENCE_CODE = { syntax: 'type', fraction: 'type', out_of_range: 'range', duplicate_key: 'duplicate_key' };

class Offence extends Error {
  constructor(path, kind) {
    super(kind);
    this.path = path;
    this.kind = kind;
  }
}

const escapePointer = (s) => s.replace(/~/g, '~0').replace(/\//g, '~1');
const child = (path, key) => `${path}/${escapePointer(String(key))}`;
const I64_MIN = -(2n ** 63n);
const U64_MAX = 2n ** 64n - 1n;

/**
 * Parses a UTF-8 body strictly. Answers the value, or throws an Offence {path, kind} at the first
 * offence (kind: syntax, fraction, out_of_range, duplicate_key).
 */
export function strictParse(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Offence('', 'syntax');
  }
  let at = 0;
  const peek = () => text[at];
  const ws = () => {
    while (at < text.length && (text[at] === ' ' || text[at] === '\t' || text[at] === '\n' || text[at] === '\r')) at += 1;
  };
  const syntax = (path) => new Offence(path, 'syntax');

  const literal = (word, value, path) => {
    if (text.startsWith(word, at)) {
      at += word.length;
      return value;
    }
    throw syntax(path);
  };

  const hex4 = (path) => {
    const digits = text.slice(at, at + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(digits)) throw syntax(path);
    at += 4;
    return Number.parseInt(digits, 16);
  };

  const string = (path) => {
    at += 1;
    let out = '';
    for (;;) {
      const start = at;
      while (at < text.length) {
        const c = text.charCodeAt(at);
        if (c === 0x22 || c === 0x5c || c < 0x20) break;
        at += 1;
      }
      out += text.slice(start, at);
      if (at >= text.length) throw syntax(path);
      const c = text[at];
      if (c === '"') {
        at += 1;
        return out;
      }
      if (c !== '\\') throw syntax(path);
      at += 1;
      if (at >= text.length) throw syntax(path);
      const e = text[at];
      at += 1;
      if (e === '"') out += '"';
      else if (e === '\\') out += '\\';
      else if (e === '/') out += '/';
      else if (e === 'b') out += '\b';
      else if (e === 'f') out += '\f';
      else if (e === 'n') out += '\n';
      else if (e === 'r') out += '\r';
      else if (e === 't') out += '\t';
      else if (e === 'u') {
        const first = hex4(path);
        let scalar = first;
        if (first >= 0xd800 && first < 0xdc00) {
          if (text.slice(at, at + 2) !== '\\u') throw syntax(path);
          at += 2;
          const second = hex4(path);
          if (second < 0xdc00 || second >= 0xe000) throw syntax(path);
          scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
        } else if (first >= 0xdc00 && first < 0xe000) {
          throw syntax(path);
        }
        out += String.fromCodePoint(scalar);
      } else throw syntax(path);
    }
  };

  const number = (path) => {
    const start = at;
    if (peek() === '-') at += 1;
    if (peek() === '0') at += 1;
    else if (peek() >= '1' && peek() <= '9') while (peek() >= '0' && peek() <= '9') at += 1;
    else throw syntax(path);
    if (peek() === '.' || peek() === 'e' || peek() === 'E') throw new Offence(path, 'fraction');
    const digits = text.slice(start, at);
    const big = BigInt(digits);
    if (big < I64_MIN || big > U64_MAX) throw new Offence(path, 'out_of_range');
    return Number(digits);
  };

  const value = (path, depth) => {
    if (depth > MAX_DEPTH) throw syntax(path);
    const c = peek();
    if (c === '{') return object(path, depth);
    if (c === '[') return array(path, depth);
    if (c === '"') return string(path);
    if (c === 't') return literal('true', true, path);
    if (c === 'f') return literal('false', false, path);
    if (c === 'n') return literal('null', null, path);
    if (c === '-' || (c >= '0' && c <= '9')) return number(path);
    throw syntax(path);
  };

  const object = (path, depth) => {
    at += 1;
    const map = new Map();
    ws();
    if (peek() === '}') {
      at += 1;
      return toObject(map);
    }
    for (;;) {
      ws();
      if (peek() !== '"') throw syntax(path);
      const key = string(path);
      const here = child(path, key);
      ws();
      if (peek() !== ':') throw syntax(path);
      at += 1;
      ws();
      const v = value(here, depth + 1);
      if (map.has(key)) throw new Offence(here, 'duplicate_key');
      map.set(key, v);
      ws();
      if (peek() === ',') at += 1;
      else if (peek() === '}') {
        at += 1;
        return toObject(map);
      } else throw syntax(path);
    }
  };

  const array = (path, depth) => {
    at += 1;
    const items = [];
    ws();
    if (peek() === ']') {
      at += 1;
      return items;
    }
    for (;;) {
      ws();
      items.push(value(child(path, items.length), depth + 1));
      ws();
      if (peek() === ',') at += 1;
      else if (peek() === ']') {
        at += 1;
        return items;
      } else throw syntax(path);
    }
  };

  ws();
  const doc = value('', 0);
  ws();
  if (at !== text.length) throw syntax('');
  return doc;
}

function toObject(map) {
  // A null prototype: a `__proto__` key is a key like any other.
  const out = Object.create(null);
  for (const [k, v] of map) out[k] = v;
  return out;
}

// ----------------------------------------------------------------------------- schema checks

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.hasOwn(o, k);

function typeMatches(expected, v) {
  switch (expected) {
    case 'object':
      return isObject(v);
    case 'array':
      return Array.isArray(v);
    case 'string':
      return typeof v === 'string';
    case 'boolean':
      return typeof v === 'boolean';
    case 'null':
      return v === null;
    case 'number':
      return typeof v === 'number';
    case 'integer':
      return typeof v === 'number' && Number.isInteger(v);
    default:
      return false;
  }
}

function equal(a, b) {
  if (a === b) return true;
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((x, i) => equal(x, b[i]));
  if (isObject(a)) {
    if (!isObject(b)) return false;
    const ka = Object.keys(a);
    return ka.length === Object.keys(b).length && ka.every((k) => has(b, k) && equal(a[k], b[k]));
  }
  return false;
}

/** Keys in byte order of their UTF-8 form (how the platform walks an object). */
const byteOrder = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

const REGEX = new Map();
function regex(pattern) {
  let r = REGEX.get(pattern);
  if (!r) {
    r = new RegExp(pattern, 'u');
    REGEX.set(pattern, r);
  }
  return r;
}

function resolve(root, ref) {
  const [doc, fragment = ''] = ref.split('#');
  if (doc !== '') return undefined;
  if (fragment === '') return root;
  return fragment
    .split('/')
    .slice(1)
    .reduce((node, raw) => (node === undefined ? undefined : node[raw.replace(/~1/g, '/').replace(/~0/g, '~')]), root);
}

function check(root, schema, v, at, out) {
  if (!isObject(schema)) {
    if (schema === false) out.push({ path: at, kind: 'unknown_field', message: 'no value is allowed here' });
    return;
  }
  if (typeof schema.$ref === 'string') {
    const target = resolve(root, schema.$ref);
    if (target === undefined) out.push({ path: at, kind: 'shape', message: 'unresolvable reference' });
    else check(root, target, v, at, out);
  }
  const push = (kind, message) => out.push({ path: at, kind, message });
  if (typeof schema.type === 'string' && !typeMatches(schema.type, v)) {
    push('type', `expected ${schema.type}`);
    return;
  }
  if (Array.isArray(schema.type) && !schema.type.some((t) => typeMatches(t, v))) {
    push('type', 'matches none of the allowed types');
    return;
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((e) => equal(e, v))) push('pattern', 'not one of the allowed values');
  if (has(schema, 'const') && !equal(schema.const, v)) push('pattern', 'not the required constant');
  if (typeof v === 'string') {
    const length = [...v].length;
    if (Number.isInteger(schema.maxLength) && length > schema.maxLength) push('pattern', `longer than ${schema.maxLength} characters`);
    if (Number.isInteger(schema.minLength) && length < schema.minLength) push('pattern', `shorter than ${schema.minLength} characters`);
    if (typeof schema.pattern === 'string' && !regex(schema.pattern).test(v)) push('pattern', 'does not match the pattern');
  }
  if (typeof v === 'number') {
    if (typeof schema.minimum === 'number' && v < schema.minimum) push('range', `below the minimum ${schema.minimum}`);
    if (typeof schema.maximum === 'number' && v > schema.maximum) push('range', `above the maximum ${schema.maximum}`);
  }
  if (Array.isArray(v)) {
    if (Number.isInteger(schema.maxItems) && v.length > schema.maxItems) push('range', `more than ${schema.maxItems} items`);
    if (Number.isInteger(schema.minItems) && v.length < schema.minItems) push('range', `fewer than ${schema.minItems} items`);
    if (schema.uniqueItems === true && v.some((item, i) => v.slice(0, i).some((prev) => equal(prev, item))))
      push('range', 'items are not unique');
    if (schema.items !== undefined) v.forEach((item, i) => check(root, schema.items, item, child(at, i), out));
  }
  if (isObject(v)) checkObject(root, schema, v, at, out);
  if (Array.isArray(schema.allOf)) for (const sub of schema.allOf) check(root, sub, v, at, out);
  if (Array.isArray(schema.anyOf) && schema.anyOf.every((sub) => fails(root, sub, v))) push('shape', 'matches none of anyOf');
  if (Array.isArray(schema.oneOf)) {
    const matching = schema.oneOf.filter((sub) => !fails(root, sub, v)).length;
    if (matching !== 1) push('shape', `matches ${matching} of oneOf, not exactly one`);
  }
  if (schema.if !== undefined) {
    const branch = fails(root, schema.if, v) ? schema.else : schema.then;
    if (branch !== undefined) check(root, branch, v, at, out);
  }
}

function fails(root, schema, v) {
  const scratch = [];
  check(root, schema, v, '', scratch);
  return scratch.length > 0;
}

function checkObject(root, schema, fields, at, out) {
  const keys = Object.keys(fields).sort(byteOrder);
  if (Number.isInteger(schema.maxProperties) && keys.length > schema.maxProperties)
    out.push({ path: at, kind: 'range', message: `more than ${schema.maxProperties} properties` });
  if (Number.isInteger(schema.minProperties) && keys.length < schema.minProperties)
    out.push({ path: at, kind: 'range', message: `fewer than ${schema.minProperties} properties` });
  if (Array.isArray(schema.required))
    for (const name of schema.required)
      if (typeof name === 'string' && !has(fields, name)) out.push({ path: child(at, name), kind: 'required', message: 'required' });
  const properties = isObject(schema.properties) ? schema.properties : null;
  for (const name of keys) {
    const here = child(at, name);
    if (schema.propertyNames !== undefined && fails(root, schema.propertyNames, name)) {
      out.push({ path: here, kind: 'unknown_field', message: 'this key is not allowed here' });
      continue;
    }
    if (properties && has(properties, name)) check(root, properties[name], fields[name], here, out);
    else if (schema.additionalProperties === false)
      out.push({ path: here, kind: 'unknown_field', message: 'not allowed (the object is closed)' });
    else if (isObject(schema.additionalProperties)) check(root, schema.additionalProperties, fields[name], here, out);
  }
}

/**
 * The field errors of a parsed report against the statistics schema: [{path, code, message}],
 * sorted by path and code (byte order), one per (path, code), at most 20.
 */
export function statsSchemaErrors(schema, document) {
  const envelope = { ...schema };
  delete envelope.oneOf;
  const found = [];
  check(schema, envelope, document, '', found);
  const products = schema.properties?.product?.enum ?? [];
  const product = isObject(document) ? document.product : undefined;
  if (typeof product === 'string' && products.includes(product) && isObject(schema.$defs?.[product])) {
    const lists = schema.$defs[product];
    for (const section of ['counts', 'features', 'aggregates'])
      if (isObject(document[section]) && lists[section] !== undefined)
        check(schema, lists[section], document[section], `/${section}`, found);
  }
  const seen = new Set();
  const errors = [];
  for (const v of found) {
    const code = v.path === '/schema' && v.kind !== 'required' ? 'schema_unknown' : v.kind === 'shape' ? 'type' : v.kind;
    const key = `${v.path}\u0000${code}`;
    if (seen.has(key)) continue;
    seen.add(key);
    errors.push({ path: v.path, code, message: v.message });
  }
  errors.sort((a, b) => byteOrder(a.path, b.path) || byteOrder(a.code, b.code));
  return errors.slice(0, MAX_ERRORS);
}

/** Whether `YYYY-MM-DD` names a day that exists. */
export function isCalendarDate(text) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (mo < 1 || mo > 12 || d < 1) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  return d <= days;
}

/**
 * Checks a report body as Ever Platform does before it looks at the key pin and the day window.
 * Answers {ok: true, report} or {ok: false, status, code, errors}: 413 validation_failed (too_large)
 * or 422 schema_violation with the field errors.
 */
export function checkStatsReport(schema, bytes) {
  const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (body.length > MAX_REPORT_BYTES)
    return {
      ok: false,
      status: 413,
      code: 'validation_failed',
      errors: [{ path: '', code: 'too_large', message: `the body is larger than ${MAX_REPORT_BYTES} bytes` }],
    };
  let document;
  try {
    document = strictParse(body);
  } catch (error) {
    if (!(error instanceof Offence)) throw error;
    return {
      ok: false,
      status: 422,
      code: 'schema_violation',
      errors: [{ path: error.path, code: OFFENCE_CODE[error.kind], message: MESSAGES[error.kind] }],
    };
  }
  const errors = statsSchemaErrors(schema, document);
  if (errors.length === 0 && !isCalendarDate(String(document.sent_at)))
    errors.push({ path: '/sent_at', code: 'range', message: 'not a calendar date' });
  if (errors.length > 0) return { ok: false, status: 422, code: 'schema_violation', errors };
  return { ok: true, report: document };
}
