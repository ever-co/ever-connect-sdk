/**
 * The entitlement document verifier (`ever.entitlement.v1`), the one implementation every product
 * uses. The checks run in this order and fail closed at the first one that does not pass:
 *
 *   0. the key set was verified for the expected issuer (a key set of one issuer
 *      never vouches for a document of another)                                   issuer_mismatch
 *   1. a compact JWS (the decoding rule of `decodeJws`: 64 KiB, canonical parts,
 *      safe integers only, well-formed strings, 127 levels)                       malformed
 *   2. header `typ` is `ever-entitlement+jwt`                                     bad_typ
 *   3. header `alg` is `EdDSA` and there is no `crit` (before any key lookup)     bad_alg
 *   4. header `kid` is in the root-verified key set, purpose `entitlement`,
 *      state `active` or `previous`, inside its validity window                   unknown_kid
 *   5. the Ed25519 signature over `header.payload` (strict: no small-order point)  bad_signature
 *   6. `ever.schema` is `ever.entitlement.v1`                                     schema_violation
 *   7. `iss` is the origin of the expected issuer                                 issuer_mismatch
 *   8. `aud` is `ever-connect`                                                    audience_mismatch
 *   9. the closed schema of the whole payload                                     schema_violation
 *  10. `ever.instance_id` is this installation's Registry id                      instance_mismatch
 *  11. `sub` is the expected subject (`instance:<id>` or `link:<id>`); a link
 *      document names its own link (`ever.tenant_link_id`), an instance document
 *      carries no link member                                                     subject_mismatch
 *  12. `iat <= now + 300`                                                         iat_in_future
 *  13. `nbf <= now + 300`                                                         nbf_in_future
 *  14. against the cached document: a lower `seq`, or the same `seq` without a
 *      later `iat`                                                                entitlement_stale
 *
 * `exp` is never a failure: it feeds {@link entitlementStatus} only. No error carries the token or
 * a claim value.
 */
import { CONSTANTS, type EntitlementV1, SCHEMAS } from '@ever-co/connect-contracts';
import { EntitlementError } from './errors';
import { decodeJws, verifyEd25519 } from './jws';
import { KeySet } from './keyset';
import { originOf } from './local';
import { CLOCK_SKEW_S } from './manifest';
import { isObject, schemaViolations } from './schema';

/** The last verified document of a subject, as the product stores it. */
export interface CachedEntitlement {
  readonly seq: number;
  readonly iat: number;
}

/** Options of {@link verifyEntitlement}. */
export interface VerifyEntitlementOptions {
  /** The root-verified keys, verified for `expectedIssuer` (`KeySet.verify` or `KeySet.restore`). */
  readonly keySet: KeySet;
  /** The API origin (`EVER_PLATFORM_API_URL`); only its origin is compared, with the key set's and the document's. */
  readonly expectedIssuer: string;
  /** This installation's Registry id (a ULID). */
  readonly expectedInstanceId: string;
  /** `instance:<registry id>` or `link:<tenant link id>`. */
  readonly expectedSubject: string;
  /**
   * The cached document of the same subject, when a newer one is being verified. Leave it out to
   * verify the stored document itself again.
   */
  readonly cached?: CachedEntitlement | null;
  /** Unix seconds. */
  readonly now?: number;
}

/** A verified entitlement document. */
export interface VerifiedEntitlement {
  readonly claims: EntitlementV1;
  readonly kid: string;
  readonly seq: number;
  /** The document exactly as received: store these bytes. */
  readonly jws: string;
  /** The ladder status at the verification time. */
  readonly status: EntitlementStatus;
}

/** `valid` before `exp`; `stale` within `grace_s` after it; `paused` past the grace or without a document. */
export type EntitlementStatus = 'valid' | 'stale' | 'paused';

const ENTITLEMENT_SCHEMA = SCHEMAS.entitlement as unknown as { readonly [key: string]: unknown };
const fail = (code: EntitlementError['code'], refreshSuggested = false, path?: string): never => {
  throw new EntitlementError(code, refreshSuggested, path);
};

/**
 * Verifies an entitlement document. Answers the claims, or throws {@link EntitlementError}: keep the
 * previous document then. On `unknown_kid` with `refreshSuggested`, refresh the key set once (see
 * {@link KeySet.unknownKidRefreshAllowed}) and verify again; a second `unknown_kid` is final.
 */
export function verifyEntitlement(jws: string, o: VerifyEntitlementOptions): VerifiedEntitlement {
  const now = Math.floor(o.now ?? Date.now() / 1000);
  const keySet = o?.keySet;
  if (!KeySet.isKeySet(keySet)) throw new TypeError('verifyEntitlement needs a KeySet (KeySet.verify or KeySet.restore)');
  const issuer = originOf(o.expectedIssuer);

  // 0. The key set is the expected issuer's.
  if (issuer === null || keySet.issuer !== issuer) return fail('issuer_mismatch');
  // 1. A compact JWS.
  const decoded = decodeJws(jws);
  if (!decoded) return fail('malformed');
  const { header, payload } = decoded;
  // 2-3. Type, then algorithm, before any key is looked up.
  if (header.typ !== CONSTANTS.entitlement_typ) return fail('bad_typ');
  if (header.alg !== 'EdDSA' || 'crit' in header) return fail('bad_alg');
  // 4. A trusted entitlement key.
  const kid = typeof header.kid === 'string' ? header.kid : null;
  const key = kid === null ? null : keySet.find(kid, 'entitlement', now);
  if (!key) return fail('unknown_kid', kid !== null && !keySet.has(kid));
  // 5. Its signature.
  if (!verifyEd25519(key.x, decoded.signingInput, decoded.signature)) return fail('bad_signature');
  // 6-8. Schema id, issuer, audience.
  const ever = isObject(payload.ever) ? payload.ever : null;
  if (ever?.schema !== 'ever.entitlement.v1') return fail('schema_violation', false, '/ever/schema');
  if (payload.iss !== issuer) return fail('issuer_mismatch');
  if (payload.aud !== CONSTANTS.entitlement_aud) return fail('audience_mismatch');
  // 9. The closed schema.
  const violations = schemaViolations(ENTITLEMENT_SCHEMA, payload);
  if (violations.length > 0) return fail('schema_violation', false, violations[0]?.path);
  const claims = payload as unknown as EntitlementV1;
  // 10-11. This installation, this subject.
  if (claims.ever.instance_id !== o.expectedInstanceId) return fail('instance_mismatch');
  if (claims.sub !== o.expectedSubject) return fail('subject_mismatch');
  const linked = claims.ever.tenant_link_id !== undefined || claims.ever.tenant !== undefined;
  if (claims.sub.startsWith('link:') ? claims.ever.tenant_link_id !== claims.sub.slice(5) : linked) return fail('subject_mismatch');
  // 12-13. Not from the future.
  if (claims.iat > now + CLOCK_SKEW_S) return fail('iat_in_future');
  if (claims.nbf > now + CLOCK_SKEW_S) return fail('nbf_in_future');
  // 14. Never older than the cached document.
  const cached = o.cached;
  if (cached && (claims.ever.seq < cached.seq || (claims.ever.seq === cached.seq && claims.iat <= cached.iat)))
    return fail('entitlement_stale');

  return Object.freeze({ claims, kid: key.kid, seq: claims.ever.seq, jws, status: entitlementStatus(claims, now) });
}

/**
 * The status ladder, from the cached document only (never from the state of the connection):
 * `valid` while `now < exp`, `stale` while `now < exp + grace_s`, then `paused`. With no document
 * the status is `paused`. Only Ever Platform features pause; the product keeps working.
 */
export function entitlementStatus(
  claims: (Pick<EntitlementV1, 'exp'> & { ever: Pick<EntitlementV1['ever'], 'grace_s'> }) | null | undefined,
  now: number = Math.floor(Date.now() / 1000),
  graceS?: number,
): EntitlementStatus {
  if (!claims) return 'paused';
  if (now < claims.exp) return 'valid';
  const grace = graceS ?? claims.ever.grace_s ?? CONSTANTS.entitlement.grace_s;
  return now < claims.exp + grace ? 'stale' : 'paused';
}
