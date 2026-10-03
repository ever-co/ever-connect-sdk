import { describe, expect, it } from 'vitest';
import { EntitlementError, entitlementStatus, KeySet, type RootKey, verifyEntitlement } from '../src/index';
import { fixture, fixtureText, signRaw } from './helpers';

const ctx = fixture<{
  expected_issuer: string;
  expected_instance_id: string;
  expected_subject: string;
  expected_subject_by_file: Record<string, string>;
  cached: { seq: number; iat: number };
  cached_by_file: Record<string, null>;
  now: number;
}>('entitlement/context.json');
const keysCtx = fixture<{ issuer: string; now: number }>('keys/context.json');
const roots = fixture<{ keys: RootKey[] }>('keys/roots.json').keys;
const keySet = KeySet.verify(fixture('keys/manifest.valid.json'), { rootKeys: roots, issuer: keysCtx.issuer, now: keysCtx.now });
const expected = fixture<{
  fixtures: Record<
    string,
    { valid: boolean; code?: string; also_acceptable?: string[]; kid?: string; seq?: number; subject?: string; status?: string }
  >;
}>('entitlement/expected.json').fixtures;

const options = (file: string, patch: Record<string, unknown> = {}) => ({
  keySet,
  expectedIssuer: ctx.expected_issuer,
  expectedInstanceId: ctx.expected_instance_id,
  expectedSubject: ctx.expected_subject_by_file[file] ?? ctx.expected_subject,
  cached: file in ctx.cached_by_file ? ctx.cached_by_file[file] : ctx.cached,
  now: ctx.now,
  ...patch,
});
const codeOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    if (error instanceof EntitlementError) return error.code;
    throw error;
  }
  return 'ok';
};

describe('verifyEntitlement over contracts/fixtures/entitlement/expected.json', () => {
  it('covers the tampered kid, seq and instance id, alg none, an unmanifested key and the status cases', () => {
    for (const name of [
      'invalid/tampered-kid.jws',
      'invalid/tampered-seq.jws',
      'invalid/tampered-instance-id.jws',
      'invalid/alg-none.jws',
      'invalid/unmanifested-key.jws',
      'valid/expired-in-grace.jws',
      'valid/expired-past-grace.jws',
      'valid/skew-plus-299.jws',
    ])
      expect(expected).toHaveProperty([name]);
  });
  for (const [file, e] of Object.entries(expected)) {
    it(`${file}: ${e.valid ? `verifies (${e.status})` : e.code}`, () => {
      const jws = fixtureText(`entitlement/${file}`).trim();
      if (e.valid) {
        const r = verifyEntitlement(jws, options(file));
        expect(r.kid).toBe(e.kid);
        expect(r.seq).toBe(e.seq);
        expect(r.claims.sub).toBe(e.subject);
        expect(r.status).toBe(e.status);
        expect(r.jws).toBe(jws);
        expect(r.claims).toEqual(fixture(`entitlement/${file.replace(/\.jws$/, '.claims.json')}`));
      } else {
        // This verifier runs the steps in the contract order: the primary code, never an alternative.
        expect(codeOf(() => verifyEntitlement(jws, options(file)))).toBe(e.code);
      }
    });
  }
});

describe('the steps', () => {
  const instance = fixtureText('entitlement/valid/instance.jws').trim();
  const claims = fixture('entitlement/valid/instance.claims.json');
  const sign = (header: Record<string, unknown>, payload: Record<string, unknown> = claims, label = 'test-entitlement/1') =>
    signRaw(label, { alg: 'EdDSA', kid: 'test-entitlement-1', typ: 'ever-entitlement+jwt', ...header }, payload);
  const opts = options('valid/instance.jws');

  it('an unknown kid suggests one key-set refresh; a known kid of another purpose does not', () => {
    const unknown = (() => {
      try {
        verifyEntitlement(fixtureText('entitlement/invalid/unknown-kid.jws').trim(), opts);
      } catch (error) {
        return error as EntitlementError;
      }
    })();
    expect(unknown?.code).toBe('unknown_kid');
    expect(unknown?.refreshSuggested).toBe(true);
    const purpose = (() => {
      try {
        verifyEntitlement(fixtureText('entitlement/invalid/wrong-purpose.jws').trim(), opts);
      } catch (error) {
        return error as EntitlementError;
      }
    })();
    expect(purpose?.code).toBe('unknown_kid');
    expect(purpose?.refreshSuggested).toBe(false);
  });
  it('alg is checked before the kid: an RS256 header with an unknown kid is bad_alg', () => {
    expect(codeOf(() => verifyEntitlement(sign({ alg: 'RS256', kid: 'nobody' }), opts))).toBe('bad_alg');
    expect(codeOf(() => verifyEntitlement(sign({ crit: ['exp'] }), opts))).toBe('bad_alg');
    expect(codeOf(() => verifyEntitlement(sign({ typ: 'ever-entitlement+jwt', alg: 'HS256' }), opts))).toBe('bad_alg');
  });
  it('malformed: not three parts, a non-object part, non-canonical base64url', () => {
    const [h, p, s] = instance.split('.');
    expect(codeOf(() => verifyEntitlement(`${h}.${p}`, opts))).toBe('malformed');
    expect(codeOf(() => verifyEntitlement(`${h}.${p}.${s}.`, opts))).toBe('malformed');
    expect(codeOf(() => verifyEntitlement(`${h}=.${p}.${s}`, opts))).toBe('malformed');
    expect(codeOf(() => verifyEntitlement(`${Buffer.from('"x"').toString('base64url')}.${p}.${s}`, opts))).toBe('malformed');
    expect(codeOf(() => verifyEntitlement('', opts))).toBe('malformed');
  });
  it('the issuer is compared as an origin', () => {
    expect(verifyEntitlement(instance, { ...opts, expectedIssuer: `${ctx.expected_issuer}/` }).seq).toBe(3);
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, expectedIssuer: 'https://mock-platform.test:8443' }))).toBe(
      'issuer_mismatch',
    );
  });
  it('a schema violation names the first path, never a value', () => {
    let error: EntitlementError | undefined;
    try {
      verifyEntitlement(fixtureText('entitlement/invalid/extra-claim.jws').trim(), opts);
    } catch (e) {
      error = e as EntitlementError;
    }
    expect(error?.code).toBe('schema_violation');
    expect(error?.path).toBe('/extra');
    expect(error?.message).toBe('entitlement document refused: schema_violation');
  });
  it('seq: lower is stale, equal with a later iat is accepted, equal with the same iat is stale', () => {
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, cached: { seq: 4, iat: 0 } }))).toBe('entitlement_stale');
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, cached: { seq: 3, iat: claims.iat } }))).toBe('entitlement_stale');
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, cached: { seq: 3, iat: claims.iat - 1 } }))).toBe('ok');
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, cached: { seq: 2, iat: claims.iat + 999 } }))).toBe('ok');
  });
  it('iat and nbf: 300 s of skew, not 301', () => {
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, now: claims.iat - 300 }))).toBe('ok');
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, now: claims.iat - 301 }))).toBe('iat_in_future');
  });
  it('a verified manifest works as well as a key set', () => {
    expect(verifyEntitlement(instance, { ...opts, keySet: undefined, manifest: keySet.manifest }).kid).toBe('test-entitlement-1');
  });
});

describe('entitlementStatus: the ladder', () => {
  const c = { exp: 1000, ever: { grace_s: 100 } };
  it('valid before exp, stale inside the grace, paused after it or without a document', () => {
    expect(entitlementStatus(c, 999)).toBe('valid');
    expect(entitlementStatus(c, 1000)).toBe('stale');
    expect(entitlementStatus(c, 1099)).toBe('stale');
    expect(entitlementStatus(c, 1100)).toBe('paused');
    expect(entitlementStatus(null, 0)).toBe('paused');
    expect(entitlementStatus(c, 1100, 1000)).toBe('stale');
  });
});
