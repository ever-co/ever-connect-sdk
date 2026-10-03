/**
 * Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037) only, and RFC 8785 canonical JSON for
 * the one shape the key manifest needs (arrays and objects of strings, integers and nulls).
 */
import { createPublicKey, verify as edVerify, type KeyObject } from 'node:crypto';
import { b64url, fromB64url } from './encoding';

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
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

/** Splits and decodes a compact JWS; null unless it is exactly three canonical base64url parts with JSON objects. */
export function decodeJws(token: unknown): DecodedJws | null {
  if (typeof token !== 'string') return null;
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

/** Whether `signature` is a valid Ed25519 signature by the key `x` (base64url, 32 bytes) over `message`. */
export function verifyEd25519(x: string, message: string | Uint8Array, signature: Uint8Array): boolean {
  const raw = fromB64url(x);
  if (raw?.length !== 32 || signature.length !== 64) return false;
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
