// Reference verifiers for the fixture tests: the key manifest and entitlement rules, written out
// once so the expected outcomes of the fixtures are checked, not just asserted. The SDK's own
// verifiers are separate code; these exist to prove the fixtures say what they claim.
import { canonicalJson, sha256Hex, verifyBytes } from '../../mock-platform/src/crypto.mjs';
import { validateSchema } from '../../mock-platform/src/validate.mjs';

const MANIFEST_TYP = 'ever-key-manifest+jwt';
const ENTITLEMENT_TYP = 'ever-entitlement+jwt';

/**
 * A compact JWS, strictly: three canonical base64url parts (no padding, no stray bits), header and
 * payload JSON objects in valid UTF-8. Anything else is `null` (malformed).
 */
function decodeJws(token) {
  if (typeof token !== 'string') return null;
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
      const v = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b));
      return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
    } catch {
      return null;
    }
  };
  const header = object(parts[0]);
  const payload = object(parts[1]);
  if (!header || !payload || !bytes(parts[2])) return null;
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] };
}

/**
 * Verifies a key manifest body against pinned roots, in the SDK's order and with its codes:
 * {ok, keys} or {ok: false, code}.
 */
export function verifyManifest(body, roots, issuer, now) {
  if (!validateSchema('keyManifest', body).ok) return { ok: false, code: 'schema_violation' };
  const decoded = decodeJws(body.manifest);
  if (!decoded) return { ok: false, code: 'malformed' };
  if (decoded.header.typ !== MANIFEST_TYP) return { ok: false, code: 'bad_typ' };
  if (decoded.header.alg !== 'EdDSA' || 'crit' in decoded.header) return { ok: false, code: 'bad_alg' };
  const root = roots.find((r) => r.kid === decoded.header.kid && r.iss === issuer);
  if (!root) return { ok: false, code: 'unknown_root' };
  if (!verifyBytes(root.x, decoded.signingInput, decoded.signature)) return { ok: false, code: 'bad_signature' };
  const p = decoded.payload;
  if (p.root_kid !== root.kid) return { ok: false, code: 'malformed' };
  if (p.iss !== issuer) return { ok: false, code: 'issuer_mismatch' };
  if (p.iat > now + 300) return { ok: false, code: 'manifest_not_yet_valid' };
  if (now >= p.exp) return { ok: false, code: 'manifest_expired' };
  if (sha256Hex(canonicalJson(body.keys)) !== p.keys_sha256) return { ok: false, code: 'keys_sha256_mismatch' };
  return { ok: true, keys: body.keys };
}

/**
 * Verifies an entitlement document in the order of the entitlement verification rules:
 * typ, alg, kid (purpose entitlement, inside its window), signature, schema/iss/aud, instance and
 * subject, iat/nbf, seq. Answers {ok, claims} or {ok: false, code}.
 */
export function verifyEntitlement(jws, { keys, issuer, instanceId, subject, cached, now }) {
  const decoded = decodeJws(jws);
  if (!decoded) return { ok: false, code: 'malformed' };
  const { header, payload } = decoded;
  if (header.typ !== ENTITLEMENT_TYP) return { ok: false, code: 'bad_typ' };
  if (header.alg !== 'EdDSA' || 'crit' in header) return { ok: false, code: 'bad_alg' };
  const key = keys.find((k) => k.kid === header.kid);
  if (key?.ever_purpose !== 'entitlement' || !['active', 'previous'].includes(key.state)) return { ok: false, code: 'unknown_kid' };
  if (!verifyBytes(key.x, decoded.signingInput, decoded.signature)) return { ok: false, code: 'bad_signature' };
  if (payload.ever?.schema !== 'ever.entitlement.v1') return { ok: false, code: 'schema_violation' };
  if (payload.iss !== issuer) return { ok: false, code: 'issuer_mismatch' };
  if (payload.aud !== 'ever-connect') return { ok: false, code: 'audience_mismatch' };
  const schema = validateSchema('entitlement', payload);
  if (!schema.ok) return { ok: false, code: 'schema_violation', path: schema.errors[0].path };
  if (payload.ever.instance_id !== instanceId) return { ok: false, code: 'instance_mismatch' };
  if (payload.sub !== subject) return { ok: false, code: 'subject_mismatch' };
  if (payload.iat > now + 300) return { ok: false, code: 'iat_in_future' };
  if (payload.nbf > now + 300) return { ok: false, code: 'nbf_in_future' };
  if (cached && (payload.ever.seq < cached.seq || (payload.ever.seq === cached.seq && payload.iat <= cached.iat)))
    return { ok: false, code: 'entitlement_stale' };
  return { ok: true, claims: payload, kid: key.kid };
}
