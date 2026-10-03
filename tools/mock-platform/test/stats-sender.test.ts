// The statistics signer and sender of @ever-co/connect-sdk against the mock: the goldens are
// accepted and then superseded, a second key is told to reset the identity, and for every platform
// fixture the SDK's own verdict on the bytes equals the answer the mock gives when they are sent
// anyway. The mock's recorder sees row 17 only, never a body.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  type SignedStatsReport,
  STATS_HEADERS,
  sendStatsReport,
  signStatsReport,
  statsSignerFromSeed,
  validateStatsReportBytes,
} from '@ever-co/connect-sdk';
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './helpers.mjs';

const STATS = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..', 'contracts', 'fixtures', 'stats');
const expected: Record<string, { status: number; code?: string; path?: string; error?: string }> = JSON.parse(
  readFileSync(join(STATS, 'expected.json'), 'utf8'),
).fixtures;
const seed = (label: string) => new Uint8Array(createHash('sha256').update(`ever-connect-sdk/stats/${label}`).digest());
const USER_AGENT = 'ever-connect-sdk/0.0.0-test (gauzy/96.2.1)';

type Env = Awaited<ReturnType<typeof startMock>>;
let env: Env | null = null;
afterEach(async () => {
  await env?.close();
  env = null;
});

describe('the statistics sender against the mock', () => {
  it('sends every golden (accepted; the same report again changes nothing; a later one supersedes it), and a second key resets the identity', async () => {
    env = await startMock();
    const signer = statsSignerFromSeed(seed('sender-key'));
    for (const product of ['gauzy', 'teams', 'works', 'rec', 'traduora']) {
      const report = JSON.parse(readFileSync(join(STATS, 'valid', `${product}.json`), 'utf8'));
      const signed = signStatsReport(report, signer, { keyId: true });
      expect(await sendStatsReport(signed, { baseUrl: env.url, userAgent: USER_AGENT })).toEqual({
        kind: 'accepted',
        status: 202,
        superseded: false,
      });
      // The same report again (a retry after a lost answer) changes nothing.
      expect(await sendStatsReport(signed, { baseUrl: env.url, userAgent: USER_AGENT })).toEqual({
        kind: 'accepted',
        status: 202,
        superseded: false,
      });
      // A later report of the same month the same day replaces it.
      const later = signStatsReport({ ...report, report_id: `${report.report_id.slice(0, 24)}000000000002` }, signer);
      expect(await sendStatsReport(later, { baseUrl: env.url, userAgent: USER_AGENT })).toEqual({
        kind: 'accepted',
        status: 202,
        superseded: true,
      });
    }
    const gauzy = JSON.parse(readFileSync(join(STATS, 'valid', 'gauzy.json'), 'utf8'));
    const other = signStatsReport(gauzy, statsSignerFromSeed(seed('other-key')));
    expect(await sendStatsReport(other, { baseUrl: env.url })).toEqual({ kind: 'reset_identity', status: 409, code: 'key_mismatch' });
    const log = (await env.call('GET', '/__mock/requests')).body as Array<Record<string, unknown>>;
    expect(new Set(log.map((e) => e.row))).toEqual(new Set([17]));
    expect(JSON.stringify(log)).not.toContain('"counts"');
  });

  it('refuses locally exactly what the platform refuses: for every fixture the verdicts agree', async () => {
    env = await startMock();
    const signer = statsSignerFromSeed(seed('parity-key'));
    for (const [file, e] of Object.entries(expected)) {
      const bytes = new Uint8Array(readFileSync(join(STATS, file)));
      const local = validateStatsReportBytes(bytes);
      // Sent anyway, signed over the same bytes, to see the platform's answer.
      const forced: SignedStatsReport = {
        body: bytes,
        headers: {
          'content-type': 'application/json',
          [STATS_HEADERS.key]: signer.publicKey,
          [STATS_HEADERS.signature]: `ed25519=${Buffer.from(signer.sign(bytes)).toString('base64url')}`,
        },
      };
      if (bytes.length > 16384) {
        // The sender itself never posts an oversize body; the mock is asked directly.
        await expect(sendStatsReport(forced, { baseUrl: env.url })).rejects.toThrow(TypeError);
        const r = await env.call('POST', '/v1/stats/reports', { raw: Buffer.from(bytes), headers: forced.headers });
        expect(local.ok || [local.error.status, local.error.errors[0]?.code], file).toEqual([r.status, r.body.errors[0].code]);
        continue;
      }
      const answer = await sendStatsReport(forced, { baseUrl: env.url });
      if (e.status === 202) {
        expect(local.ok, file).toBe(true);
        expect(answer.kind, file).toBe('accepted');
        continue;
      }
      expect(local.ok, file).toBe(false);
      if (local.ok || answer.kind !== 'dropped') throw new Error(`${file}: ${answer.kind}`);
      expect([answer.status, answer.code, answer.errors[0]?.path, answer.errors[0]?.code], file).toEqual([
        local.error.status,
        local.error.code,
        local.error.errors[0]?.path,
        local.error.errors[0]?.code,
      ]);
      expect([answer.status, answer.code, answer.errors[0]?.path, answer.errors[0]?.code], file).toEqual([
        e.status,
        e.code,
        e.path,
        e.error,
      ]);
    }
  });
});
