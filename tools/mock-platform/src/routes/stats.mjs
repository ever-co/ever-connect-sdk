// Row 17: the anonymous statistics report. No credential: the body is signed with the
// installation's statistics key, carried in the signature headers, and pinned on first sight.
import { instanceKid, publicKeyFromX, verifyBytes } from '../crypto.mjs';
import { rawJsonOffence } from '../json.mjs';
import { fail } from '../problem.mjs';
import { validateSchema } from '../validate.mjs';

const KEY = 'ever-stats-key';
const SIGNATURE = 'ever-stats-signature';
const KEY_ID = 'ever-stats-key-id';

function headerError(name, message) {
  fail(400, 'validation_failed', message, { errors: [{ path: `#${name}`, code: 'invalid', message }] });
}

export const statsHandlers = {
  ingestStatsReport({ state, headers, raw }) {
    const key = headers[KEY];
    const signature = headers[SIGNATURE];
    if (typeof key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(key))
      headerError('Ever-Stats-Key', 'the base64url Ed25519 public key (43 characters) is required');
    try {
      publicKeyFromX(key);
    } catch {
      headerError('Ever-Stats-Key', 'not an Ed25519 public key');
    }
    if (typeof signature !== 'string' || !/^ed25519=[A-Za-z0-9_-]{86}$/.test(signature))
      headerError('Ever-Stats-Signature', 'ed25519=<base64url signature> is required');
    const keyId = headers[KEY_ID];
    if (keyId !== undefined && keyId !== instanceKid(key)) headerError('Ever-Stats-Key-Id', 'the key id does not match Ever-Stats-Key');
    if (!verifyBytes(key, raw, signature.slice('ed25519='.length))) fail(400, 'signature_invalid');

    let report;
    const text = raw.toString('utf8');
    try {
      report = JSON.parse(text);
    } catch {
      fail(422, 'schema_violation', 'the body is not JSON', { errors: [{ path: '', code: 'invalid_shape', message: 'not JSON' }] });
    }
    const offence = rawJsonOffence(text);
    if (offence) fail(422, 'schema_violation', undefined, { errors: [{ path: offence.path, code: 'invalid', message: offence.reason }] });
    const v = validateSchema('stats', report);
    if (!v.ok) fail(422, 'schema_violation', undefined, { errors: v.errors });

    const pin = state.statsPins.get(report.instance_id);
    if (pin && pin.x !== key) fail(409, 'key_mismatch');
    const day = state.iso().slice(0, 10);
    const count = state.statsReports.filter((r) => r.instance_id === report.instance_id && r.day === day).length;
    if (count >= state.config.limits.stats_reports_per_day)
      fail(429, 'rate_limited', undefined, { retry_after_s: 86400 - (state.now() % 86400) });
    if (!pin) state.statsPins.set(report.instance_id, { x: key, pinned_at: state.now() });
    const superseded = state.statsReports.some((r) => r.instance_id === report.instance_id && r.period === report.period && r.day === day);
    state.statsReports.push({
      instance_id: report.instance_id,
      period: report.period,
      day,
      product: report.product,
      accepted_at: state.now(),
    });
    return { status: 202, body: superseded ? { accepted: true, superseded: true } : { accepted: true } };
  },
};
