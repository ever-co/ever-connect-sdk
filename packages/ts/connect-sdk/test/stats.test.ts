import { createHash, createPublicKey, verify } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import {
  classifyStatsAnswer,
  generateStatsKey,
  MAX_STATS_REPORT_BYTES,
  STATS_HEADERS,
  StatsValidationError,
  sendStatsReport,
  signStatsReport,
  signStatsReportBytes,
  statsKeyId,
  statsReportsUrl,
  statsSignerFromSeed,
  validateStatsReport,
  validateStatsReportBytes,
  walkStrings,
} from '../src/index';

const STATS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'contracts', 'fixtures', 'stats');
const raw = (file: string) => new Uint8Array(readFileSync(join(STATS, file)));
const golden = (product = 'gauzy') => JSON.parse(readFileSync(join(STATS, 'valid', `${product}.json`), 'utf8'));
const expected: Record<string, { status: number; code?: string; path?: string; error?: string; layer: string }> = JSON.parse(
  readFileSync(join(STATS, 'expected.json'), 'utf8'),
).fixtures;

// A key from a public seed: it signs nothing anyone trusts. The Rust tests sign with the same seed
// and must produce the same headers (Ed25519 is deterministic).
const SEED = new Uint8Array(createHash('sha256').update('ever-connect-sdk/stats/test-key').digest());
const VECTOR = {
  key: 'lxnswCzOKr-SXURHbwO3utNZKbsjn3XpqslZ3kuQw6M',
  keyId: 'fIrSg8WJjiY',
  signature: 'ed25519=VHq-yNMEasHuMwgKw7ZzTco7J-8ZjglKKuaPYi1aORjNEa_qcGh6tHWGfNUWn8gURIDKu87ymAT3b6_WEQLVCw',
};
const CANARY = 'Jane Doe <jane@example.com>';

const verifies = (publicKey: string, body: Uint8Array, header: string) =>
  verify(
    null,
    body,
    createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' }),
    Buffer.from(header.slice('ed25519='.length), 'base64url'),
  );

describe('the platform fixtures', () => {
  it('lists every fixture file, and answers each one as the platform does (status, code, path, field error)', () => {
    const files = ['valid', 'invalid'].flatMap((d) => readdirSync(join(STATS, d)).map((f) => `${d}/${f}`));
    expect(Object.keys(expected).sort()).toEqual(files.sort());
    expect(files).toHaveLength(18);
    for (const [file, e] of Object.entries(expected)) {
      const r = validateStatsReportBytes(raw(file));
      if (e.status === 202) {
        expect(r.ok, file).toBe(true);
        continue;
      }
      expect(r.ok, file).toBe(false);
      if (r.ok) continue;
      expect([r.error.status, r.error.code, r.error.errors[0]?.path, r.error.errors[0]?.code], file).toEqual([
        e.status,
        e.code,
        e.path,
        e.error,
      ]);
    }
  });

  it('signs every golden over exactly the bytes it returns, with the pinned header names', () => {
    const signer = statsSignerFromSeed(SEED);
    for (const product of ['gauzy', 'teams', 'works', 'rec', 'traduora']) {
      const signed = signStatsReport(golden(product), signer);
      expect(new TextDecoder().decode(signed.body)).toBe(JSON.stringify(golden(product)));
      expect(signed.headers[STATS_HEADERS.key]).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(signed.headers[STATS_HEADERS.signature]).toMatch(/^ed25519=[A-Za-z0-9_-]{86}$/);
      expect(signed.headers[STATS_HEADERS.key_id]).toBeUndefined();
      expect(verifies(signer.publicKey, signed.body, signed.headers[STATS_HEADERS.signature] as string)).toBe(true);
    }
    expect(STATS_HEADERS).toEqual({ key: 'Ever-Stats-Key', signature: 'Ever-Stats-Signature', key_id: 'Ever-Stats-Key-Id' });
  });

  it('signs the gauzy golden file as the shared vector says (the Rust signer gives the same headers)', () => {
    const signed = signStatsReportBytes(raw('valid/gauzy.json'), statsSignerFromSeed(SEED), { keyId: true });
    expect(signed.headers).toEqual({
      'content-type': 'application/json',
      'Ever-Stats-Key': VECTOR.key,
      'Ever-Stats-Signature': VECTOR.signature,
      'Ever-Stats-Key-Id': VECTOR.keyId,
    });
    expect(statsKeyId(VECTOR.key)).toBe(VECTOR.keyId);
    expect(() => statsKeyId('short')).toThrow(TypeError);
  });
});

describe('a poisoned report yields no bytes and never shows the value', () => {
  it('refuses the canary in every string position, naming the position only', () => {
    const report = golden('gauzy');
    const positions = walkStrings(report).filter((s) => s.kind === 'value');
    expect(positions.map((p) => p.path)).toContain('/country');
    for (const { path } of positions) {
      const poisoned = structuredClone(report);
      const segments = path.split('/').slice(1);
      let node = poisoned;
      for (const s of segments.slice(0, -1)) node = node[s];
      node[segments[segments.length - 1] as string] = CANARY;
      let thrown: unknown;
      let bytes: unknown;
      try {
        bytes = signStatsReport(poisoned, statsSignerFromSeed(SEED));
      } catch (error) {
        thrown = error;
      }
      expect(bytes, path).toBeUndefined();
      expect(thrown, path).toBeInstanceOf(StatsValidationError);
      const error = thrown as StatsValidationError;
      expect(error.errors[0]?.path, path).toBe(path);
      for (const text of [error.message, String(error), JSON.stringify(error.errors), JSON.stringify(error), inspect(error)])
        expect(text, path).not.toMatch(/Jane|jane@/);
    }
  });

  it('refuses the canary as a key: at the top, inside a closed map, and inside a currency map; the logged forms show * instead', () => {
    type Report = {
      [key: string]: unknown;
      counts: { integrations_in_use: Record<string, number> };
      aggregates: { invoiced_minor: Record<string, number> };
    };
    const cases: Array<[(r: Report) => void, string]> = [
      [(r) => (r[CANARY] = 1), `/${CANARY}`],
      [(r) => (r.counts.integrations_in_use[CANARY] = 1), `/counts/integrations_in_use/${CANARY}`],
      [(r) => (r.aggregates.invoiced_minor[CANARY] = 1), `/aggregates/invoiced_minor/${CANARY}`],
    ];
    for (const [plant, path] of cases) {
      const report = golden('gauzy');
      plant(report);
      const r = validateStatsReport(report);
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      // The exact path, as the platform answers it (an unknown key is its own path)...
      expect(r.error.errors.map((e) => [e.path, e.code])).toEqual([[path, 'unknown_field']]);
      // ...and every form a product would log names the key as *.
      for (const text of [r.error.message, String(r.error), JSON.stringify(r.error), inspect(r.error)])
        expect(text).not.toMatch(/Jane|jane@/);
      expect(JSON.stringify(r.error)).toContain(path.replace(CANARY, '*'));
    }
  });

  it('refuses an oversize report (413 too_large), a value JSON cannot carry, a day that does not exist and a fraction', () => {
    const big = { ...golden('gauzy'), padding: 'x'.repeat(MAX_STATS_REPORT_BYTES) };
    const oversize = validateStatsReport(big);
    expect(oversize.ok || [oversize.error.status, oversize.error.code, oversize.error.errors[0]]).toEqual([
      413,
      'validation_failed',
      { path: '', code: 'too_large', message: 'the body is larger than 16384 bytes' },
    ]);
    const bigint = validateStatsReport({ ...golden('gauzy'), counts: { users: 10n } });
    expect(bigint.ok || bigint.error.errors[0]?.code).toBe('type');
    const feb = validateStatsReport({ ...golden('gauzy'), sent_at: '2026-02-30' });
    expect(feb.ok || feb.error.errors).toEqual([{ path: '/sent_at', code: 'range', message: 'not a calendar date' }]);
    const leap = validateStatsReport({ ...golden('gauzy'), sent_at: '2028-02-29' });
    expect(leap.ok).toBe(true);
    const fraction = validateStatsReport({ ...golden('gauzy'), aggregates: { ...golden('gauzy').aggregates, invoices: 2.5 } });
    expect(fraction.ok || fraction.error.errors[0]).toMatchObject({ path: '/aggregates/invoices', code: 'type' });
    const v2 = validateStatsReport({ ...golden('gauzy'), schema: 'ever.stats.v2' });
    expect(v2.ok || v2.error.errors[0]).toMatchObject({ path: '/schema', code: 'schema_unknown' });
  });

  it('lists at most 20 field errors, sorted by path', () => {
    const report = golden('gauzy');
    for (let i = 0; i < 30; i += 1) report[`extra_${String(i).padStart(2, '0')}`] = 1;
    const r = validateStatsReport(report);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.errors).toHaveLength(20);
    const paths = r.error.errors.map((e) => e.path);
    expect([...paths].sort()).toEqual(paths);
  });
});

describe('strict JSON on the bytes', () => {
  const body = (text: string) => new TextEncoder().encode(text);
  it('names the offence where it stands', () => {
    const cases: Array<[string, string, string]> = [
      ['{"aggregates": {"invoices": 214.0}}', '/aggregates/invoices', 'type'],
      ['{"a": [1, 2E3]}', '/a/1', 'type'],
      ['{"a": 99999999999999999999}', '/a', 'range'],
      ['{"country": "ZZ", "countr\\u0079": "BG"}', '/country', 'duplicate_key'],
      ['{"a": {"x/y": 1, "x/y": 2}}', '/a/x~1y', 'duplicate_key'],
      ['', '', 'type'],
      ['{"a":1,}', '', 'type'],
      ['﻿{}', '', 'type'],
      ['"\\ud800"', '', 'type'],
      [`${'['.repeat(18)}1${']'.repeat(18)}`, '/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0', 'type'],
    ];
    for (const [text, path, code] of cases) {
      const r = validateStatsReportBytes(body(text));
      expect(r.ok, text).toBe(false);
      if (r.ok) continue;
      expect([r.error.errors[0]?.path, r.error.errors[0]?.code], text).toEqual([path, code]);
    }
    const bad = validateStatsReportBytes(new Uint8Array([0xff, 0x7b, 0x7d]));
    expect(bad.ok || bad.error.errors[0]).toMatchObject({ path: '', code: 'type' });
  });
});

describe('walkStrings', () => {
  it('lists every key and string value at its JSON pointer', () => {
    expect(walkStrings({ a: 'x', 'b/c': [{ d: 'y' }, 3], e: true })).toEqual([
      { path: '/a', value: 'a', kind: 'key' },
      { path: '/a', value: 'x', kind: 'value' },
      { path: '/b~1c', value: 'b/c', kind: 'key' },
      { path: '/b~1c/0/d', value: 'd', kind: 'key' },
      { path: '/b~1c/0/d', value: 'y', kind: 'value' },
      { path: '/e', value: 'e', kind: 'key' },
    ]);
  });
});

describe('keys', () => {
  it('generates a key whose signer shows its public half only', () => {
    const { seed, signer } = generateStatsKey();
    expect(seed).toHaveLength(32);
    expect(statsSignerFromSeed(seed).publicKey).toBe(signer.publicKey);
    const hex = Buffer.from(seed).toString('hex');
    const b64 = Buffer.from(seed).toString('base64url');
    for (const text of [JSON.stringify(signer), String(signer), JSON.stringify({ signer })]) {
      expect(text).not.toContain(hex);
      expect(text).not.toContain(b64);
    }
    expect(() => statsSignerFromSeed(new Uint8Array(31))).toThrow(TypeError);
  });
});

describe('sending', () => {
  it('posts exactly the signed bytes, its headers, no credential, to the report path', async () => {
    const signed = signStatsReport(golden('rec'), statsSignerFromSeed(SEED), { keyId: true });
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const fake = (async (url: string, init: RequestInit) => {
      seen.push({ url, init });
      return new Response(JSON.stringify({ accepted: true, superseded: true }), {
        status: 202,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const outcome = await sendStatsReport(signed, {
      baseUrl: 'https://api.example.test/',
      fetch: fake,
      userAgent: 'ever-connect-sdk/1.0.0 (rec/2.1.0)',
    });
    expect(outcome).toEqual({ kind: 'accepted', status: 202, superseded: true });
    expect(seen).toHaveLength(1);
    const [{ url, init }] = seen as [{ url: string; init: RequestInit }];
    expect(url).toBe('https://api.example.test/v1/stats/reports');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(signed.body);
    expect(init.redirect).toBe('manual');
    expect(init.credentials).toBe('omit');
    const headers = init.headers as Record<string, string>;
    expect(
      Object.keys(headers)
        .map((h) => h.toLowerCase())
        .sort(),
    ).toEqual(['content-type', 'ever-stats-key', 'ever-stats-key-id', 'ever-stats-signature', 'user-agent']);
  });

  it('turns a failed connection into a retry and never throws', async () => {
    const failing = (async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const signed = signStatsReport(golden('rec'), statsSignerFromSeed(SEED));
    expect(await sendStatsReport(signed, { baseUrl: 'https://api.example.test', fetch: failing, attempt: 2 })).toEqual({
      kind: 'retry',
      status: null,
      code: null,
      retryAfterS: 43200,
    });
  });

  it('classifies every answer of the report call', () => {
    expect(classifyStatsAnswer(202, { accepted: true })).toEqual({ kind: 'accepted', status: 202, superseded: false });
    expect(classifyStatsAnswer(429, { code: 'rate_limited' }, '50000', 0)).toEqual({
      kind: 'retry',
      status: 429,
      code: 'rate_limited',
      retryAfterS: 50000,
    });
    expect(classifyStatsAnswer(503, null, null, 9)).toMatchObject({ kind: 'retry', retryAfterS: 86400 });
    expect(classifyStatsAnswer(409, { code: 'key_mismatch' })).toEqual({ kind: 'reset_identity', status: 409, code: 'key_mismatch' });
    expect(classifyStatsAnswer(422, { code: 'schema_violation', errors: [{ path: '/country', code: 'pattern', message: 'm' }] })).toEqual({
      kind: 'dropped',
      status: 422,
      code: 'schema_violation',
      errors: [{ path: '/country', code: 'pattern' }],
    });
    for (const [status, code] of [
      [400, 'signature_invalid'],
      [400, 'validation_failed'],
      [413, 'validation_failed'],
      [415, 'unsupported_media_type'],
    ] as const)
      expect(classifyStatsAnswer(status, { code })).toMatchObject({ kind: 'dropped', status, code });
  });

  it('accepts an http(s) origin only, with no credential, query or fragment', () => {
    expect(statsReportsUrl('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080/v1/stats/reports');
    expect(statsReportsUrl('https://api.ever.co/')).toBe('https://api.ever.co/v1/stats/reports');
    for (const bad of ['ftp://x.test', 'https://u:p@x.test', 'https://x.test/?a=1', 'https://x.test/#f'])
      expect(() => statsReportsUrl(bad), bad).toThrow(TypeError);
  });
});
