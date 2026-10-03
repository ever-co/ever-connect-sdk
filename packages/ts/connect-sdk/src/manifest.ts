/**
 * The key manifest (`GET /.well-known/ever-keys.json`): the platform's signing keys, vouched for by
 * a compact JWS signed by a pinned root key. No key of a manifest is trusted unless every check
 * below passes; the checks run in this order and the first failure is the answer:
 *
 *   1. the body is `{manifest, keys}` under the closed `ever.key-manifest.v1` schema  schema_violation
 *   2. `manifest` is a compact JWS of three canonical base64url parts with JSON objects  malformed
 *   3. header `typ` is `ever-key-manifest+jwt`                                          bad_typ
 *   4. header `alg` is `EdDSA` and there is no `crit`                                   bad_alg
 *   5. header `kid` is a pinned root (pinned for this issuer when the root names one)   unknown_root
 *   6. the Ed25519 signature of the root over `header.payload`                          bad_signature
 *   7. the payload is `{iss, iat, exp, keys_sha256, root_kid}` with `root_kid` = header `kid`  malformed
 *   8. payload `iss` is the expected issuer (an origin)                                 issuer_mismatch
 *   9. `iat <= now + 300`                                                               manifest_not_yet_valid
 *  10. `now < exp`                                                                      manifest_expired
 *  11. `keys_sha256` is the hex SHA-256 of the RFC 8785 canonical JSON of `keys`        keys_sha256_mismatch
 */
import { CONSTANTS, SCHEMAS } from '@ever-co/connect-contracts';
import { sha256Hex } from './encoding';
import { KeyManifestError } from './errors';
import { canonicalJson, decodeJws, verifyEd25519 } from './jws';
import { originOf } from './local';
import { schemaViolations } from './schema';

/** Seconds of clock difference tolerated on `iat` and on a key's validity window. */
export const CLOCK_SKEW_S = 300;

/** A pinned root public key (`CONSTANTS.root_keys` entries; `iss` pins it to one issuer). */
export interface RootKey {
  readonly kid: string;
  readonly x: string;
  readonly iss?: string;
  readonly kty?: string;
  readonly crv?: string;
  readonly use?: string;
  readonly alg?: string;
}

/** A signing key the manifest lists. */
export interface ManifestKey {
  readonly kty: 'OKP';
  readonly crv: 'Ed25519';
  readonly kid: string;
  readonly x: string;
  readonly use: 'sig';
  readonly alg: 'EdDSA';
  readonly ever_purpose: 'assertion' | 'intent' | 'entitlement';
  readonly state: 'active' | 'previous';
  readonly not_before: string;
  readonly not_after?: string | null;
}

/** The served body of the key manifest endpoint. */
export interface KeyManifestDocument {
  readonly manifest: string;
  readonly keys: readonly ManifestKey[];
}

/** A key manifest that passed every check. */
export interface VerifiedKeyManifest {
  readonly keys: readonly ManifestKey[];
  readonly rootKid: string;
  /** The issuer origin the manifest names. */
  readonly issuer: string;
  /** Unix seconds. */
  readonly issuedAt: number;
  /** Unix seconds; the manifest is not trusted from then on. */
  readonly expiresAt: number;
  /** The body as served, for the product to store and verify again offline. */
  readonly document: KeyManifestDocument;
}

/** Options of {@link verifyKeyManifest}. */
export interface VerifyKeyManifestOptions {
  /**
   * The roots to trust. Default: the pinned `CONSTANTS.root_keys`. Passing roots replaces the
   * pinned ones for this call (tests and offline tools); the client adds extra roots only for a
   * local base URL (see `resolveRootKeys`).
   */
  readonly rootKeys?: readonly RootKey[];
  /**
   * The issuer the payload must name (the API origin). Default: the `iss` the matched root is
   * pinned to; a root without `iss` then requires this option.
   */
  readonly issuer?: string;
  /** Unix seconds. */
  readonly now?: number;
}

const MANIFEST_SCHEMA = SCHEMAS.keyManifest as unknown as { readonly [key: string]: unknown };
const PAYLOAD_SCHEMA = (MANIFEST_SCHEMA.$defs as { payload: unknown }).payload;

/** The pinned root keys of this SDK release. */
export const pinnedRootKeys = (): readonly RootKey[] => CONSTANTS.root_keys as readonly RootKey[];

/** Lower-case hex SHA-256 of the RFC 8785 canonical JSON of a key list (`keys_sha256`). */
export const keysSha256 = (keys: unknown): string => sha256Hex(canonicalJson(keys));

/**
 * Verifies a key manifest body. Answers the keys it vouches for, or throws
 * {@link KeyManifestError} with the code of the first failed check.
 */
export function verifyKeyManifest(body: unknown, options?: VerifyKeyManifestOptions): VerifiedKeyManifest;
/** The positional form: `verifyKeyManifest(body, rootKeys?, now?)`. */
export function verifyKeyManifest(body: unknown, rootKeys?: readonly RootKey[], now?: number): VerifiedKeyManifest;
export function verifyKeyManifest(
  body: unknown,
  second?: VerifyKeyManifestOptions | readonly RootKey[],
  third?: number,
): VerifiedKeyManifest {
  const o: VerifyKeyManifestOptions = Array.isArray(second)
    ? { rootKeys: second as readonly RootKey[], now: third }
    : ((second as VerifyKeyManifestOptions | undefined) ?? {});
  const roots = o.rootKeys ?? pinnedRootKeys();
  const now = Math.floor(o.now ?? Date.now() / 1000);

  // 1. The closed schema of the served body.
  if (schemaViolations(MANIFEST_SCHEMA, body).length > 0) throw new KeyManifestError('schema_violation');
  const doc = body as KeyManifestDocument;
  // 2. Three canonical base64url parts with JSON objects.
  const jws = decodeJws(doc.manifest);
  if (!jws) throw new KeyManifestError('malformed');
  const { header, payload } = jws;
  // 3-4. Type, then algorithm (before any key is looked at).
  if (header.typ !== CONSTANTS.key_manifest_typ) throw new KeyManifestError('bad_typ');
  if (header.alg !== 'EdDSA' || 'crit' in header) throw new KeyManifestError('bad_alg');
  // 5. A pinned root, pinned to this issuer when the root names one.
  const expected = o.issuer === undefined ? undefined : originOf(o.issuer);
  if (o.issuer !== undefined && expected === null) throw new KeyManifestError('issuer_mismatch');
  const root = roots.find(
    (r) =>
      typeof header.kid === 'string' &&
      r.kid === header.kid &&
      (r.iss === undefined || expected === undefined || originOf(r.iss) === expected),
  );
  if (!root) throw new KeyManifestError('unknown_root');
  // 6. The root's signature.
  if (!verifyEd25519(root.x, jws.signingInput, jws.signature)) throw new KeyManifestError('bad_signature');
  // 7. The payload shape; the payload names the root that signed it.
  if (schemaViolations(MANIFEST_SCHEMA, payload, PAYLOAD_SCHEMA).length > 0 || payload.root_kid !== header.kid)
    throw new KeyManifestError('malformed');
  const p = payload as { iss: string; iat: number; exp: number; keys_sha256: string; root_kid: string };
  // 8. The issuer.
  const issuer = expected ?? (root.iss === undefined ? null : originOf(root.iss));
  if (issuer === null || p.iss !== issuer) throw new KeyManifestError('issuer_mismatch');
  // 9-10. The validity window.
  if (p.iat > now + CLOCK_SKEW_S) throw new KeyManifestError('manifest_not_yet_valid');
  if (now >= p.exp) throw new KeyManifestError('manifest_expired');
  // 11. The served keys are the keys the root signed.
  if (keysSha256(doc.keys) !== p.keys_sha256) throw new KeyManifestError('keys_sha256_mismatch');

  return Object.freeze({
    keys: Object.freeze(doc.keys.map((k) => Object.freeze({ ...k }))),
    rootKid: root.kid,
    issuer,
    issuedAt: p.iat,
    expiresAt: p.exp,
    document: { manifest: doc.manifest, keys: doc.keys },
  });
}
