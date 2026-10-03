/**
 * Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037) only, and RFC 8785 canonical JSON for
 * the one shape the key manifest needs (arrays and objects of strings, integers and nulls).
 *
 * A JWS is decoded by one rule in both SDKs: at most 64 KiB; three canonical base64url parts;
 * header and payload are JSON objects in valid UTF-8 (a leading byte-order mark is not
 * whitespace); every number is an integer token (no fraction, no exponent, no negative zero)
 * within plus or minus 2^53 - 1; no string or member name holds a lone surrogate; at most 127
 * nested arrays and objects. Anything else is `malformed`.
 */
import { createPublicKey, verify as edVerify, type KeyObject } from 'node:crypto';
import { isSmallOrder } from './ed25519';
import { b64url, fromB64url } from './encoding';

/** The longest compact JWS a verifier reads. */
export const MAX_JWS_LENGTH = 65536;
/** The deepest nesting of arrays and objects a JWS part may have. */
const MAX_DEPTH = 127;
const MAX_SAFE = 9007199254740991n;
const INTEGER_TOKEN = /^(0|-?[1-9][0-9]*)$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Whether the JSON text (already known to parse) uses only safe integer number tokens and nests at
 * most MAX_DEPTH arrays and objects.
 */
export function jsonTokensAreStrict(text: string): boolean {
  let depth = 0;
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === '"') {
      i += 1;
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      i += 1;
      continue;
    }
    if (c === '[' || c === '{') {
      depth += 1;
      if (depth > MAX_DEPTH) return false;
    } else if (c === ']' || c === '}') depth -= 1;
    else if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i + 1;
      while (j < text.length && /[0-9eE.+-]/.test(text[j] as string)) j += 1;
      const token = text.slice(i, j);
      if (!INTEGER_TOKEN.test(token)) return false;
      const n = BigInt(token);
      if (n > MAX_SAFE || n < -MAX_SAFE) return false;
      i = j;
      continue;
    }
    i += 1;
  }
  return true;
}

/** Whether every string and member name of a parsed value is well formed (no lone surrogate). */
function wellFormed(value: unknown): boolean {
  if (typeof value === 'string') return !LONE_SURROGATE.test(value);
  if (Array.isArray(value)) return value.every(wellFormed);
  if (value !== null && typeof value === 'object') return Object.entries(value).every(([k, v]) => !LONE_SURROGATE.test(k) && wellFormed(v));
  return true;
}

/** A decoded compact JWS. */
export interface DecodedJws {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  /** `base64url(header) "." base64url(payload)`, the bytes the signature covers. */
  readonly signingInput: string;
  readonly signature: Uint8Array;
}

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

function json(part: string): Record<string, unknown> | null {
  const bytes = fromB64url(part);
  if (!bytes) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const value: unknown = JSON.parse(text);
    return isRecord(value) && jsonTokensAreStrict(text) && wellFormed(value) ? value : null;
  } catch {
    return null;
  }
}

/** Splits and decodes a compact JWS; null unless it is exactly three canonical base64url parts with JSON objects. */
export function decodeJws(token: unknown): DecodedJws | null {
  if (typeof token !== 'string' || token.length > MAX_JWS_LENGTH) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  const header = json(h);
  const payload = json(p);
  const signature = fromB64url(s);
  if (!header || !payload || !signature) return null;
  return { header, payload, signingInput: `${h}.${p}`, signature };
}

/** Public keys already imported (public data; bounded). */
const KEYS = new Map<string, KeyObject>();

/**
 * Whether `signature` is a valid Ed25519 signature by the key `x` (base64url, 32 bytes) over
 * `message`, under the strict rule: a small-order public key or a small-order `R` never verifies
 * (as `verify_strict` in the Rust crate and on the platform).
 */
export function verifyEd25519(x: string, message: string | Uint8Array, signature: Uint8Array): boolean {
  const raw = fromB64url(x);
  if (raw?.length !== 32 || signature.length !== 64) return false;
  if (isSmallOrder(raw) || isSmallOrder(signature.subarray(0, 32))) return false;
  try {
    let key = KEYS.get(x);
    if (!key) {
      key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
      if (KEYS.size >= 64) KEYS.clear();
      KEYS.set(x, key);
    }
    return edVerify(null, typeof message === 'string' ? Buffer.from(message, 'utf8') : message, key, signature);
  } catch {
    return false;
  }
}

/** Signs a compact JWS (`alg: EdDSA`) with a signer of raw bytes. */
export async function signJws(
  sign: (bytes: Uint8Array) => Promise<Uint8Array> | Uint8Array,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const input = `${b64url(JSON.stringify({ alg: 'EdDSA', ...header }))}.${b64url(JSON.stringify(payload))}`;
  const signature = await sign(new TextEncoder().encode(input));
  return `${input}.${b64url(signature)}`;
}

/** UTF-16 code unit order of two strings (RFC 8785 sorts member names this way). */
function utf16Order(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * RFC 8785 canonical JSON of a value made of objects, arrays, strings, booleans, nulls and
 * integers; throws for any other number (refused rather than mis-canonicalised).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('canonical JSON: only integers are supported');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    const names = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort(utf16Order);
    return `{${names.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError('canonical JSON: unsupported value');
}
