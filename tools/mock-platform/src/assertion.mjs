// RFC 7523 client-assertion verification, as the platform specifies it: EdDSA only; the
// installation looked up by `iss`; the current connect key, or the previous one inside the 7-day
// overlap; iss = sub = the installation ULID (a UUID never authenticates); aud = the token
// endpoint; typ, when present, JWT; exp at most 300 s after iat and iat within 300 s of the clock;
// nbf, when present, not in the future; jti 16-128 visible characters, never seen before.
// Every failure is the same `invalid_client` to the caller; `reason` is for logs and tests only.
import { decodeJws, verifyBytes } from './crypto.mjs';

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/**
 * @param {string} token the compact JWS
 * @param {object} ctx {now, audience, instanceFor(iss) -> {current_key, previous_key, rotated_at}|null,
 *                      seenJti(jti) -> boolean, overlapS, maxTtlS, maxSkewS}
 * @returns {{ok: true, instanceId: string, kid: string, jti: string, exp: number} | {ok: false, reason: string}}
 */
export function verifyAssertion(token, ctx) {
  const { now, audience, overlapS = 604800, maxTtlS = 300, maxSkewS = 300 } = ctx;
  const decoded = decodeJws(token);
  if (!decoded) return { ok: false, reason: 'malformed' };
  const { header, payload } = decoded;
  if (header.alg !== 'EdDSA' || 'crit' in header) return { ok: false, reason: 'algorithm' };
  if ('typ' in header && header.typ !== 'JWT') return { ok: false, reason: 'type' };
  if (typeof payload.iss !== 'string' || !ULID.test(payload.iss)) return { ok: false, reason: 'issuer_not_an_instance_id' };
  if (payload.sub !== payload.iss) return { ok: false, reason: 'subject_differs' };
  const instance = ctx.instanceFor(payload.iss);
  if (!instance) return { ok: false, reason: 'unknown_instance' };
  const keys = [instance.current_key];
  if (instance.previous_key && instance.rotated_at !== null && instance.rotated_at !== undefined && now < instance.rotated_at + overlapS)
    keys.push(instance.previous_key);
  const key = keys.find((k) => verifyBytes(k.x, decoded.signingInput, decoded.signature));
  if (!key) return { ok: false, reason: 'signature' };
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(audience)) return { ok: false, reason: 'audience' };
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) return { ok: false, reason: 'times' };
  if (payload.exp - payload.iat > maxTtlS) return { ok: false, reason: 'lifetime' };
  if (Math.abs(now - payload.iat) > maxSkewS) return { ok: false, reason: 'skew' };
  if (now >= payload.exp) return { ok: false, reason: 'expired' };
  if ('nbf' in payload && (!Number.isInteger(payload.nbf) || payload.nbf > now)) return { ok: false, reason: 'not_yet_valid' };
  if (typeof payload.jti !== 'string' || !/^[\x21-\x7e]{16,128}$/.test(payload.jti)) return { ok: false, reason: 'jti' };
  if (ctx.seenJti(payload.jti)) return { ok: false, reason: 'replay' };
  return {
    ok: true,
    instanceId: payload.iss,
    kid: key.kid ?? header.kid,
    jti: payload.jti,
    exp: payload.exp,
    jkt: payload.cnf?.jkt ?? null,
  };
}

/**
 * The two proofs of a key rotation, as the platform checks them: `currentKeyProof` signed with
 * the installation's current connect key only (never the key a rotation replaced, even inside its
 * overlap), `newKeyProof` signed with the new key, both for the rotation endpoint, both binding the
 * new key (`cnf.jkt` is its RFC 7638 thumbprint), with two different `jti` never seen before.
 *
 * @param {object} ctx {now, audience, instanceId, currentKey {x, kid}, newKey {x, kid}, thumbprint, seenJti?}
 *   (the platform records the two jti after this check; `seenJti` lets a vector check a replay here)
 * @returns {{ok: true, jtis: string[], exp: number[]} | {ok: false, reason: string}}
 */
export function verifyRotation(currentKeyProof, newKeyProof, ctx) {
  const proof = (token, key) => {
    const r = verifyAssertion(token, {
      now: ctx.now,
      audience: ctx.audience,
      instanceFor: (iss) => (iss === ctx.instanceId ? { current_key: key, previous_key: null, rotated_at: null } : null),
      seenJti: ctx.seenJti ?? (() => false),
    });
    if (!r.ok) return r.reason === 'unknown_instance' ? { ok: false, reason: 'issuer' } : r;
    if (r.jkt !== ctx.thumbprint) return { ok: false, reason: 'binding' };
    return r;
  };
  const current = proof(currentKeyProof, ctx.currentKey);
  if (!current.ok) return current;
  const next = proof(newKeyProof, ctx.newKey);
  if (!next.ok) return next;
  if (next.jti === current.jti) return { ok: false, reason: 'jti' };
  return { ok: true, jtis: [current.jti, next.jti], exp: [current.exp, next.exp] };
}
