// Row 17: the anonymous statistics report. No credential: the body is signed with the
// installation's statistics key, carried in the signature headers, and pinned on first sight.
// The checks run in the platform's order, with its answers: the media type (415), the size
// (413), the key, the signature's shape, the key id and the signature itself (400), the strict JSON
// reader and the schema (422), the key pin (409; a first sight draws from the new-id budgets, 429),
// the same report again the same day (202, nothing changes), the day window and the two months a
// day an id may store (429).

import { contract } from '../contract.mjs';
import { fromB64url, instanceKid, isEd25519Point, publicKeyFromX, verifyBytes } from '../crypto.mjs';
import { fail } from '../problem.mjs';
import { checkStatsReport, MAX_REPORT_BYTES } from '../stats-ingest.mjs';

const KEY = 'ever-stats-key';
const SIGNATURE = 'ever-stats-signature';
const KEY_ID = 'ever-stats-key-id';
const PREFIX = 'ed25519=';

const REFUSALS = {
  key: ['validation_failed', 'Ever-Stats-Key', 'Ever-Stats-Key must carry the base64url Ed25519 public key (43 characters)'],
  shape: [
    'signature_invalid',
    'Ever-Stats-Signature',
    'Ever-Stats-Signature must be ed25519= followed by the base64url signature (86 characters)',
  ],
  keyId: ['signature_invalid', 'Ever-Stats-Key-Id', 'Ever-Stats-Key-Id does not name the key in Ever-Stats-Key'],
  mismatch: ['signature_invalid', 'Ever-Stats-Signature', 'the signature does not verify over the request body'],
};

function refuse(which) {
  const [code, header, message] = REFUSALS[which];
  fail(400, code, message, { errors: [{ path: `#${header}`, code: 'invalid', message }] });
}

const base64url = (value, length) => typeof value === 'string' && value.length === length && /^[A-Za-z0-9_-]+$/.test(value);

/** The verified key (`x`), or a 400 in the platform's order: key, signature shape, key id, signature. */
function verifySignature(headers, raw) {
  const key = headers[KEY];
  if (!base64url(key, 43)) refuse('key');
  try {
    publicKeyFromX(key);
  } catch {
    refuse('key');
  }
  if (!isEd25519Point(fromB64url(key))) refuse('key');
  const signature = headers[SIGNATURE];
  const sig = typeof signature === 'string' && signature.startsWith(PREFIX) ? signature.slice(PREFIX.length) : null;
  if (!base64url(sig, 86)) refuse('shape');
  const keyId = headers[KEY_ID];
  if (keyId !== undefined && keyId !== instanceKid(key)) refuse('keyId');
  if (!verifyBytes(key, raw, sig)) refuse('mismatch');
  return key;
}

/** Seconds until the next UTC day. */
const secondsToNextDay = (now) => 86400 - (now % 86400);

export const statsHandlers = {
  ingestStatsReport({ state, req, headers, raw, tooLarge }) {
    const type = String(headers['content-type'] ?? '')
      .split(';')[0]
      .trim()
      .toLowerCase();
    if (type !== 'application/json') fail(415, 'unsupported_media_type', 'a report is application/json');
    if (tooLarge || raw.length > MAX_REPORT_BYTES)
      fail(413, 'validation_failed', `a report is at most ${MAX_REPORT_BYTES} bytes`, {
        errors: [{ path: '', code: 'too_large', message: `the body is larger than ${MAX_REPORT_BYTES} bytes` }],
      });
    const key = verifySignature(headers, raw);

    const checked = checkStatsReport(contract().schemas.stats, raw);
    if (!checked.ok) fail(checked.status, checked.code, undefined, { errors: checked.errors });
    const report = checked.report;

    const limits = state.config.limits;
    const now = state.now();
    const day = state.iso().slice(0, 10);
    const pin = state.statsPins.get(report.instance_id);
    if (pin && pin.x !== key)
      fail(409, 'key_mismatch', 'this statistics id is pinned to another key; reset the instance identity to report under a new id');
    if (!pin) {
      // A new statistics id: the source address's hourly budget, then the day's ceiling.
      const hourKey = `address|${Math.floor(now / 3600)}|${req.socket.remoteAddress ?? 'unknown'}`;
      const dayKey = `day|${day}`;
      if ((state.statsNewIds.get(hourKey) ?? 0) >= limits.stats_new_ids_per_address_hour)
        fail(429, 'rate_limited', 'this source address registered its new statistics ids for this hour', {
          retry_after_s: 3600 - (now % 3600),
        });
      if ((state.statsNewIds.get(dayKey) ?? 0) >= limits.stats_new_ids_per_day)
        fail(429, 'rate_limited', 'Ever Platform takes no more new statistics ids today', { retry_after_s: secondsToNextDay(now) });
      state.statsNewIds.set(hourKey, (state.statsNewIds.get(hourKey) ?? 0) + 1);
      state.statsNewIds.set(dayKey, (state.statsNewIds.get(dayKey) ?? 0) + 1);
      state.statsPins.set(report.instance_id, { x: key, pinned_at: now });
    }
    const today = state.statsReports.filter((r) => r.instance_id === report.instance_id && r.day === day);
    // The same report again today (a retry after a lost answer, or a replay): accepted, nothing written, no slot taken.
    if (pin && today.some((r) => r.report_id === report.report_id)) return { status: 202, body: { accepted: true } };
    if (today.length >= limits.stats_reports_per_day)
      fail(429, 'rate_limited', 'this statistics id sent its reports for today', { retry_after_s: secondsToNextDay(now) });
    if (new Set(today.filter((r) => r.period !== report.period).map((r) => r.period)).size >= limits.stats_periods_per_day)
      fail(429, 'rate_limited', 'this statistics id stored reports for two months today', { retry_after_s: secondsToNextDay(now) });
    const superseded = today.some((r) => r.period === report.period);
    state.statsReports.push({
      instance_id: report.instance_id,
      report_id: report.report_id,
      period: report.period,
      day,
      product: report.product,
      accepted_at: now,
    });
    return { status: 202, body: superseded ? { accepted: true, superseded: true } : { accepted: true } };
  },
};
