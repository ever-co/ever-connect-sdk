// TEST keys of the mock platform and the fixtures. Every key is derived at run time from a public
// seed (sha256 of a fixed label), so signed fixtures regenerate byte for byte and no private key
// file exists anywhere. These keys sign nothing anyone trusts: their ids start with `test-`, and a
// release refuses any `test-` root.
import { b64url, canonicalJson, instanceKid, keyPairFromSeed, sha256, sha256Hex, signJws } from './crypto.mjs';

export const MANIFEST_TYP = 'ever-key-manifest+jwt';
export const ENTITLEMENT_TYP = 'ever-entitlement+jwt';
export const INTENT_TYP = 'ever-intent+jwt';
export const STATS_LINK_TYP = 'ever-stats-link+jwt';
export const MANIFEST_LIFETIME_S = 30 * 24 * 3600;

const DEFS = {
  root: { kid: 'test-root-1', label: 'test-root/1' },
  unknownRoot: { kid: 'test-root-9', label: 'test-root/9' },
  entitlement: { kid: 'test-entitlement-1', label: 'test-entitlement/1', purpose: 'entitlement' },
  entitlementNext: { kid: 'test-entitlement-2', label: 'test-entitlement/2', purpose: 'entitlement' },
  assertion: { kid: 'test-assertion-1', label: 'test-assertion/1', purpose: 'assertion' },
  intent: { kid: 'test-intent-1', label: 'test-intent/1', purpose: 'intent' },
  identity: { kid: 'test-identity-1', label: 'test-identity/1' },
  // Product-side keys used by fixtures and tests: an installation's connect and statistics keys.
  connect: { label: 'test-connect/1' },
  connectNext: { label: 'test-connect/2' },
  stats: { label: 'test-stats/1' },
  statsOther: { label: 'test-stats/2' },
  stranger: { label: 'test-stranger/1' },
};

const cache = new Map();

/** A TEST key by name: {name, kid, purpose?, privateKey, x, publicJwk, seedLabel}. */
export function testKey(name) {
  if (cache.has(name)) return cache.get(name);
  const def = DEFS[name];
  if (!def) throw new Error(`no TEST key named ${name}`);
  const seed = sha256(`ever-connect-sdk/${def.label}`);
  const { privateKey, x } = keyPairFromSeed(seed);
  const kid = def.kid ?? instanceKid(x);
  const key = {
    name,
    kid,
    purpose: def.purpose ?? null,
    privateKey,
    x,
    seedLabel: `ever-connect-sdk/${def.label}`,
    publicJwk: { kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' },
  };
  cache.set(name, key);
  return key;
}

export const testKeyNames = () => Object.keys(DEFS);

/** The TEST root as a JWKS entry for EVER_PLATFORM_ROOT_KEYS_FILE and constants.root_keys. */
export function testRootEntry(issuer) {
  const root = testKey('root');
  return { kid: root.kid, iss: issuer, kty: 'OKP', crv: 'Ed25519', x: root.x, use: 'sig', alg: 'EdDSA' };
}

const rfc3339 = (s) => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

/** One manifest key entry in the platform's member order. */
export function manifestEntry(key, { state = 'active', notBefore, notAfter = null }) {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    kid: key.kid,
    x: key.x,
    use: 'sig',
    alg: 'EdDSA',
    ever_purpose: key.purpose,
    state,
    not_before: rfc3339(notBefore),
    not_after: notAfter === null ? null : rfc3339(notAfter),
  };
}

export const keysSha256 = (keys) => sha256Hex(canonicalJson(keys));

/** The body of GET /.well-known/ever-keys.json signed by `root` (default: the TEST root). */
export function signManifest({ issuer, iat, keys, root = testKey('root'), keysShaOverride = null }) {
  const payload = {
    iss: issuer,
    iat,
    exp: iat + MANIFEST_LIFETIME_S,
    keys_sha256: keysShaOverride ?? keysSha256(keys),
    root_kid: root.kid,
  };
  return { manifest: signJws(root.privateKey, { kid: root.kid, typ: MANIFEST_TYP }, payload), keys };
}

export function signEntitlement(claims, key = testKey('entitlement'), header = {}) {
  return signJws(key.privateKey, { kid: key.kid, typ: ENTITLEMENT_TYP, ...header }, claims);
}

/** The two-key statistics link statement, signed with the statistics key. */
export function signStatsLinkStatement({ statsInstanceId, statsKey = testKey('stats'), iat }) {
  const stats_public_jwk = { kty: 'OKP', crv: 'Ed25519', x: statsKey.x };
  const payload = { stats_instance_id: statsInstanceId, stats_public_jwk, iat };
  return {
    stats_instance_id: statsInstanceId,
    stats_public_jwk,
    statement_sig: signJws(statsKey.privateKey, { typ: STATS_LINK_TYP }, payload),
  };
}

/** An RFC 7523 client assertion signed with an installation's connect key. */
export function signClientAssertion({ key = testKey('connect'), instanceId, audience, iat, ttl = 300, jti, header = {} }) {
  const claims = { iss: instanceId, sub: instanceId, aud: audience, jti: jti ?? b64url(sha256(`${instanceId}:${iat}:${audience}`).subarray(0, 16)), iat, exp: iat + ttl };
  return signJws(key.privateKey, { kid: key.kid, typ: 'JWT', ...header }, claims);
}
