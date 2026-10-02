// RFC 7523 client-assertion verification, as the platform specifies it: EdDSA only; the
// installation looked up by `iss`; the current connect key, or the previous one inside the 7-day
// overlap; iss = sub = the installation ULID (a UUID never authenticates); aud = the token
// endpoint; exp at most 300 s after iat and iat within 300 s of the clock; jti never seen before.
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
  if (typeof payload.iss !== 'string' || !ULID.test(payload.iss)) return { ok: false, reason: 'issuer_not_an_instance_id' };
  if (payload.sub !== payload.iss) return { ok: false, reason: 'subject_differs' };
  const instance = ctx.instanceFor(payload.iss);
  if (!instance) return { ok: false, reason: 'unknown_instance' };
  const keys = [instance.current_key];
  if (instance.previous_key && instance.rotated_at !== null && instance.rotated_at !== undefined && now <= instance.rotated_at + overlapS)
    keys.push(instance.previous_key);
  const key = keys.find((k) => verifyBytes(k.x, decoded.signingInput, decoded.signature));
  if (!key) return { ok: false, reason: 'signature' };
  if (payload.aud !== audience) return { ok: false, reason: 'audience' };
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) return { ok: false, reason: 'times' };
  if (payload.exp - payload.iat > maxTtlS) return { ok: false, reason: 'lifetime' };
  if (Math.abs(now - payload.iat) > maxSkewS) return { ok: false, reason: 'skew' };
  if (now >= payload.exp) return { ok: false, reason: 'expired' };
  if (typeof payload.jti !== 'string' || payload.jti.length < 16) return { ok: false, reason: 'jti' };
  if (ctx.seenJti(payload.jti)) return { ok: false, reason: 'replay' };
  return { ok: true, instanceId: payload.iss, kid: key.kid ?? header.kid, jti: payload.jti, exp: payload.exp };
}
