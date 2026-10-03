// Reference verifiers for the fixture tests: the key manifest and entitlement rules, written out
// once so the expected outcomes of the fixtures are checked, not just asserted. The SDK's own
// verifiers are separate code (in both languages); these exist to prove the fixtures say what they
// claim, and their answers are the ones the SDK suites must reproduce.
import { canonicalJson, sha256Hex, verifyBytes } from '../../mock-platform/src/crypto.mjs';
import { validateSchema } from '../../mock-platform/src/validate.mjs';

const MANIFEST_TYP = 'ever-key-manifest+jwt';
const ENTITLEMENT_TYP = 'ever-entitlement+jwt';
const SKEW = 300;
const MAX_SAFE = 9007199254740991n;

// The 14 encodings of the eight points of small order (the canonical ones, the sign bit set on x = 0,
// and y + p where it fits in 255 bits): written out from their y coordinates, independently of the
// SDK's point arithmetic.
const P = 2n ** 255n - 19n;
const Y8 = 2707385501144840649318225287225658788936804267575313519463743609750303402022n;
const encode = (y, sign) => {
  const b = Buffer.alloc(32);
  let v = y;
  for (let i = 0; i < 32; i += 1) {
    b[i] = Number(v & 255n);
    v >>= 8n;
  }
  if (sign) b[31] |= 0x80;
  return b.toString('hex');
};
const SMALL_ORDER = new Set(
  [1n, P - 1n, 0n, Y8, P - Y8, P, P + 1n].flatMap((y) => [encode(y, 0), encode(y, 1)]).filter((h, i, all) => all.indexOf(h) === i),
);
/** The encodings of the small-order points, as lower-case hex. */
export const SMALL_ORDER_ENCODINGS = [...SMALL_ORDER].sort();
const smallOrder = (bytes) => SMALL_ORDER.has(Buffer.from(bytes).toString('hex'));

/** Whether 32 bytes encode a curve point: (y^2 - 1) / (d y^2 + 1) is a square modulo p. */
function isPoint(bytes) {
  if (bytes.length !== 32) return false;
  const b = Buffer.from(bytes);
  b[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt(b[i]);
  const m = (a) => ((a % P) + P) % P;
  const pow = (base, e) => {
    let r = 1n;
    let x = m(base);
    for (let k = e; k > 0n; k >>= 1n) {
      if (k & 1n) r = m(r * x);
      x = m(x * x);
    }
    return r;
  };
  const d = m(-121665n * pow(121666n, P - 2n));
  const yy = m(y * y);
  const q = m(m(yy - 1n) * pow(m(d * yy + 1n), P - 2n));
  const legendre = pow(q, (P - 1n) / 2n);
  return legendre === 0n || legendre === 1n;
}

/** The manifest payload: exactly {iss, iat, exp, keys_sha256, root_kid} of the right types. */
function payloadShape(p) {
  const keys = Object.keys(p).sort().join(',');
  const int = (v) => Number.isSafeInteger(v) && v >= 0;
  return (
    keys === 'exp,iat,iss,keys_sha256,root_kid' &&
    typeof p.iss === 'string' &&
    p.iss.length <= 256 &&
    int(p.iat) &&
    int(p.exp) &&
    /^[0-9a-f]{64}$/.test(p.keys_sha256) &&
    /^[A-Za-z0-9._-]{1,64}$/.test(p.root_kid)
  );
}

/** A UTC time `YYYY-MM-DDTHH:MM:SS[.f]Z` naming a day that exists, as Unix seconds; else null. */
export function utcSeconds(text) {
  if (typeof text !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/.exec(text);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  const date = new Date(0);
  date.setUTCFullYear(y, mo - 1, d);
  date.setUTCHours(h, mi, s, 0);
  if (date.getUTCFullYear() !== y || date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) return null;
  return Math.floor(date.getTime() / 1000);
}

/**
 * The JSON text again, with every number kept as the token it was written as: a small recursive
 * descent over text JSON.parse already accepted. Members given twice keep the last value, as
 * JSON.parse does. Answers {tree, depth}: `tree` mirrors the value with numbers as {token}.
 */
function tokenTree(text) {
  let i = 0;
  let deepest = 0;
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i += 1;
  };
  const string = () => {
    const start = i;
    for (i += 1; text[i] !== '"'; i += text[i] === '\\' ? 2 : 1);
    i += 1;
    return JSON.parse(text.slice(start, i));
  };
  const value = (depth) => {
    ws();
    const c = text[i];
    if (c === '{' || c === '[') {
      deepest = Math.max(deepest, depth + 1);
      const array = c === '[';
      const out = array ? [] : {};
      i += 1;
      ws();
      if (text[i] === (array ? ']' : '}')) {
        i += 1;
        return out;
      }
      for (;;) {
        if (array) out.push(value(depth + 1));
        else {
          ws();
          const key = string();
          ws();
          i += 1; // :
          Object.defineProperty(out, key, { value: value(depth + 1), enumerable: true, configurable: true, writable: true });
        }
        ws();
        if (text[i++] !== ',') return out;
      }
    }
    if (c === '"') return string();
    const literal = /^(true|false|null|-?[0-9][0-9.eE+-]*)/.exec(text.slice(i))[0];
    i += literal.length;
    return /^[-0-9]/.test(literal) ? { token: literal } : JSON.parse(literal);
  };
  const tree = value(0);
  return { tree, depth: deepest };
}

/** The token a number was written as, at a JSON pointer of a token tree; undefined otherwise. */
function tokenAt(tree, pointer) {
  let node = tree;
  for (const raw of pointer.split('/').slice(1)) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, key)) return undefined;
    node = node[key];
  }
  return node !== null && typeof node === 'object' && typeof node.token === 'string' ? node.token : undefined;
}

/** An I-JSON integer as written: no fraction, no exponent, not -0, within plus or minus 2^53 - 1. */
const integerToken = (token) => /^(0|-?[1-9][0-9]*)$/.test(token) && BigInt(token) <= MAX_SAFE && BigInt(token) >= -MAX_SAFE;

/** Every number finite (a number past a double does not parse). */
function finite(v) {
  if (typeof v === 'number') return Number.isFinite(v);
  if (Array.isArray(v)) return v.every(finite);
  if (v && typeof v === 'object') return Object.values(v).every(finite);
  return true;
}

const loneSurrogate = (s) => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
function wellFormed(v) {
  if (typeof v === 'string') return !loneSurrogate(v);
  if (Array.isArray(v)) return v.every(wellFormed);
  if (v && typeof v === 'object') return Object.entries(v).every(([k, x]) => !loneSurrogate(k) && wellFormed(x));
  return true;
}

/**
 * A compact JWS, strictly: at most 64 KiB; three canonical base64url parts (no padding, no stray
 * bits); header and payload JSON objects in valid UTF-8; numbers that fit a double; no lone
 * surrogate; at most 127 levels. Anything else is `null` (malformed). The payload's token tree
 * comes with it, to read how its numbers are written.
 */
function decodeJws(token) {
  if (typeof token !== 'string' || token.length > 65536) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const bytes = (part) => {
    if (!/^[A-Za-z0-9_-]*$/.test(part)) return null;
    const b = Buffer.from(part, 'base64url');
    return b.toString('base64url') === part ? b : null;
  };
  const object = (part) => {
    const b = bytes(part);
    if (!b) return null;
    try {
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b);
      const v = JSON.parse(text);
      if (v === null || typeof v !== 'object' || Array.isArray(v) || !wellFormed(v) || !finite(v)) return null;
      const { tree, depth } = tokenTree(text);
      return depth <= 127 ? { v, tree } : null;
    } catch {
      return null;
    }
  };
  const header = object(parts[0]);
  const payload = object(parts[1]);
  if (!header || !payload || !bytes(parts[2])) return null;
  return { header: header.v, payload: payload.v, tokens: payload.tree, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] };
}

/** Ed25519 under the strict rule: no small-order key, no small-order R. */
function verifyStrict(x, input, signature) {
  const key = Buffer.from(x, 'base64url');
  const sig = Buffer.from(signature, 'base64url');
  if (key.length !== 32 || sig.length !== 64 || smallOrder(key) || smallOrder(sig.subarray(0, 32))) return false;
  return verifyBytes(x, input, signature);
}

const origin = (url) => {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
};

/**
 * Verifies a key manifest body for one issuer against roots pinned per issuer, in the SDK's order
 * and with its codes: {ok, keys, issuer} or {ok: false, code}.
 */
export function verifyManifest(body, roots, issuer, now) {
  const expected = origin(issuer);
  if (!validateSchema('keyManifest', body).ok) return { ok: false, code: 'schema_violation' };
  const keysOk = body.keys.every(
    (k) =>
      utcSeconds(k.not_before) !== null &&
      (k.not_after == null || utcSeconds(k.not_after) !== null) &&
      !smallOrder(Buffer.from(k.x, 'base64url')) &&
      isPoint(Buffer.from(k.x, 'base64url')),
  );
  if (!keysOk) return { ok: false, code: 'schema_violation' };
  const decoded = decodeJws(body.manifest);
  if (!decoded) return { ok: false, code: 'malformed' };
  if (decoded.header.typ !== MANIFEST_TYP) return { ok: false, code: 'bad_typ' };
  if (decoded.header.alg !== 'EdDSA' || 'crit' in decoded.header) return { ok: false, code: 'bad_alg' };
  const root = roots.find(
    (r) =>
      r.kid === decoded.header.kid &&
      typeof r.iss === 'string' &&
      origin(r.iss) === expected &&
      expected !== null &&
      !smallOrder(Buffer.from(r.x, 'base64url')),
  );
  if (!root) return { ok: false, code: 'unknown_root' };
  if (!verifyStrict(root.x, decoded.signingInput, decoded.signature)) return { ok: false, code: 'bad_signature' };
  const p = decoded.payload;
  const written = ['/iat', '/exp'].every((at) => integerToken(tokenAt(decoded.tokens, at) ?? ''));
  if (!payloadShape(p) || !written || p.root_kid !== root.kid) return { ok: false, code: 'malformed' };
  if (p.iss !== expected) return { ok: false, code: 'issuer_mismatch' };
  if (p.iat > now + SKEW) return { ok: false, code: 'manifest_not_yet_valid' };
  if (now >= p.exp) return { ok: false, code: 'manifest_expired' };
  if (sha256Hex(canonicalJson(body.keys)) !== p.keys_sha256) return { ok: false, code: 'keys_sha256_mismatch' };
  return { ok: true, keys: body.keys, issuer: expected, issuedAt: p.iat, expiresAt: p.exp };
}

/** The key `kid` for `purpose` at `now` (state and window); null otherwise. */
function findKey(keys, kid, purpose, now) {
  const key = keys.find((k) => k.kid === kid);
  if (!key || key.ever_purpose !== purpose || !['active', 'previous'].includes(key.state)) return null;
  const nb = utcSeconds(key.not_before);
  if (nb === null || now + SKEW < nb) return null;
  if (key.not_after != null) {
    const na = utcSeconds(key.not_after);
    if (na === null || now > na + SKEW) return null;
  }
  return key;
}

/**
 * Verifies an entitlement document in the order of the entitlement verification rules (the
 * contract's): typ, alg, the manifest not past its exp, kid (purpose entitlement, inside its
 * window), signature, schema id, iss (the expected issuer and the key set's), aud, the closed
 * schema with the integer claims written as I-JSON integers, instance and subject (a link
 * document names its link), iat/nbf, seq. Answers
 * {ok, claims, kid} or {ok: false, code, refreshSuggested}.
 */
export function verifyEntitlement(jws, { keys, keysIssuer, manifestExpiresAt, issuer, instanceId, subject, cached, now }) {
  const expected = origin(issuer);
  const decoded = decodeJws(jws);
  if (!decoded) return { ok: false, code: 'malformed' };
  const { header, payload } = decoded;
  if (header.typ !== ENTITLEMENT_TYP) return { ok: false, code: 'bad_typ' };
  if (header.alg !== 'EdDSA' || 'crit' in header) return { ok: false, code: 'bad_alg' };
  if (manifestExpiresAt !== undefined && now >= manifestExpiresAt) return { ok: false, code: 'manifest_expired' };
  const kid = typeof header.kid === 'string' ? header.kid : null;
  const key = kid === null ? null : findKey(keys, kid, 'entitlement', now);
  if (!key) return { ok: false, code: 'unknown_kid', refreshSuggested: kid !== null && !keys.some((k) => k.kid === kid) };
  if (!verifyStrict(key.x, decoded.signingInput, decoded.signature)) return { ok: false, code: 'bad_signature' };
  const ever = payload.ever !== null && typeof payload.ever === 'object' && !Array.isArray(payload.ever) ? payload.ever : null;
  if (ever?.schema !== 'ever.entitlement.v1') return { ok: false, code: 'schema_violation' };
  if (expected === null || payload.iss !== expected || (keysIssuer ?? expected) !== expected) return { ok: false, code: 'issuer_mismatch' };
  if (payload.aud !== 'ever-connect') return { ok: false, code: 'audience_mismatch' };
  const schema = validateSchema('entitlement', payload);
  const claimForms = ['/exp', '/ever/grace_s', '/ever/seq', '/iat', '/nbf'].filter((at) => {
    const token = tokenAt(decoded.tokens, at);
    return token !== undefined && !integerToken(token);
  });
  if (!schema.ok || claimForms.length > 0) return { ok: false, code: 'schema_violation' };
  if (payload.ever.instance_id !== instanceId) return { ok: false, code: 'instance_mismatch' };
  if (payload.sub !== subject) return { ok: false, code: 'subject_mismatch' };
  const linked = payload.ever.tenant_link_id !== undefined || payload.ever.tenant !== undefined;
  if (payload.sub.startsWith('link:') ? payload.ever.tenant_link_id !== payload.sub.slice(5) : linked)
    return { ok: false, code: 'subject_mismatch' };
  if (payload.iat > now + SKEW) return { ok: false, code: 'iat_in_future' };
  if (payload.nbf > now + SKEW) return { ok: false, code: 'nbf_in_future' };
  if (cached && (payload.ever.seq < cached.seq || (payload.ever.seq === cached.seq && payload.iat <= cached.iat)))
    return { ok: false, code: 'entitlement_stale' };
  const status = now < payload.exp ? 'valid' : now < payload.exp + payload.ever.grace_s ? 'stale' : 'paused';
  return { ok: true, claims: payload, kid: key.kid, status };
}
