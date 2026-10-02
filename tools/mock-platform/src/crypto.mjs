// Ed25519, compact JWS (EdDSA) and RFC 8785 canonical JSON with node:crypto only.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
export const fromB64url = (text) => Buffer.from(text, 'base64url');
export const sha256 = (data) => createHash('sha256').update(data).digest();
export const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');

/** An Ed25519 key pair from a 32-byte seed. */
export function keyPairFromSeed(seed) {
  if (seed.length !== 32) throw new Error('an Ed25519 seed is 32 bytes');
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const { x } = createPublicKey(privateKey).export({ format: 'jwk' });
  return { privateKey, x };
}

const P = 2n ** 255n - 19n;
const mod = (a) => ((a % P) + P) % P;
function modPow(base, exp) {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}
const EDWARDS_D = mod(-121665n * modPow(121666n, P - 2n));

/**
 * Whether 32 bytes encode a point of the Ed25519 curve (the y coordinate, with the sign of x in
 * the top bit): x² = (y² - 1) / (d·y² + 1) must have a root. A verifier refuses any other key
 * before it looks at a signature; node:crypto alone does not check it.
 */
export function isEd25519Point(raw) {
  if (raw.length !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt(i === 31 ? raw[i] & 0x7f : raw[i]);
  const y2 = mod(y * y);
  const ratio = mod((y2 - 1n) * modPow(EDWARDS_D * y2 + 1n, P - 2n));
  return ratio === 0n || modPow(ratio, (P - 1n) / 2n) === 1n;
}

/** A public key object from the JWK `x` member; throws on anything that is not 32 bytes. */
export function publicKeyFromX(x) {
  if (typeof x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(x)) throw new Error('not an Ed25519 public key');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
}

/** The instance key id: base64url of the first 8 bytes of SHA-256 over the raw public key. */
export const instanceKid = (x) => b64url(sha256(fromB64url(x)).subarray(0, 8));

/** The RFC 7638 thumbprint of an Ed25519 public key (the `cnf.jkt` of a rotation proof). */
export const thumbprint = (x) => b64url(sha256(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`));

export const signBytes = (privateKey, bytes) => b64url(edSign(null, Buffer.from(bytes), privateKey));

export function verifyBytes(x, bytes, signature) {
  try {
    const sig = fromB64url(signature);
    if (sig.length !== 64 || b64url(sig) !== signature) return false;
    return edVerify(null, Buffer.from(bytes), publicKeyFromX(x), sig);
  } catch {
    return false;
  }
}

/** Signs `payload` as a compact JWS; `header` gets `alg: EdDSA` unless it names another alg. */
export function signJws(privateKey, header, payload) {
  const h = b64url(JSON.stringify({ alg: 'EdDSA', ...header }));
  const p = b64url(JSON.stringify(payload));
  return `${h}.${p}.${signBytes(privateKey, `${h}.${p}`)}`;
}

/** Decodes a compact JWS without verifying it; null when malformed. */
export function decodeJws(token) {
  if (typeof token !== 'string' || token.length > 65536) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(fromB64url(parts[0]).toString('utf8'));
    const payload = JSON.parse(fromB64url(parts[1]).toString('utf8'));
    if (!header || typeof header !== 'object' || Array.isArray(header)) return null;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] };
  } catch {
    return null;
  }
}

/** Verifies a compact JWS against a public key (`x`); answers the decoded token or null. */
export function verifyJws(token, x, { typ } = {}) {
  const decoded = decodeJws(token);
  if (!decoded) return null;
  if (decoded.header.alg !== 'EdDSA' || 'crit' in decoded.header) return null;
  if (typ !== undefined && decoded.header.typ !== typ) return null;
  return verifyBytes(x, decoded.signingInput, decoded.signature) ? decoded : null;
}

/** RFC 8785 canonical JSON for documents without non-integer numbers. */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('canonical JSON: non-integer numbers are not supported');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort((a, b) => {
    // UTF-16 code unit order, as RFC 8785 requires.
    for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
      const d = a.charCodeAt(i) - b.charCodeAt(i);
      if (d !== 0) return d;
    }
    return a.length - b.length;
  });
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}
