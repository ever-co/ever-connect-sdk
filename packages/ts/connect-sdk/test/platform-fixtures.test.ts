// The platform's own signed entitlement fixtures (contracts/fixtures/entitlement-platform/, vendored
// byte for byte from ever-co/platform): the issuer signs them with its TEST keys, and every document
// must reach the platform's expected outcome here, as in the Rust suite.
import { describe, expect, it } from 'vitest';
import { EntitlementError, KeyManifestError, KeySet, type RootKey, verifyEntitlement } from '../src/index';
import { fixture, fixtureText } from './helpers';

const DIR = 'entitlement-platform';
const ctx = fixture<{
  expected_issuer: string;
  manifest: string;
  roots_file: string;
  now: number;
  now_by_file: Record<string, number>;
  expected_instance_id_by_file: Record<string, string>;
  expected_subject_by_file: Record<string, string>;
  cached_by_file: Record<string, { seq: number; iat: number }>;
}>(`${DIR}/context.json`);
const expected = fixture<{
  fixtures: Record<string, { valid: boolean; code?: string; kid?: string; seq?: number; subject?: string }>;
}>(`${DIR}/expected.json`).fixtures;
// The platform names each root's issuer as `issuer`; the SDK's roots carry it as `iss`.
const roots: RootKey[] = fixture<{ issuer: string; kid: string; x: string }[]>(`${DIR}/${ctx.roots_file}`).map((r) => ({
  kid: r.kid,
  x: r.x,
  iss: r.issuer,
  kty: 'OKP',
  crv: 'Ed25519',
}));
const keySet = KeySet.verify(fixture(`${DIR}/${ctx.manifest}`), { issuer: ctx.expected_issuer, unsafeRootKeys: roots, now: ctx.now });

describe('the platform entitlement fixtures', () => {
  it('has the published set: 3 valid and 14 invalid documents', () => {
    const files = Object.keys(expected);
    expect(files.filter((f) => expected[f]?.valid)).toHaveLength(3);
    expect(files.filter((f) => !expected[f]?.valid)).toHaveLength(14);
    expect(keySet.issuer).toBe(ctx.expected_issuer);
  });
  for (const [file, e] of Object.entries(expected))
    it(`${file}: ${e.valid ? 'verifies' : e.code}`, () => {
      const jws = fixtureText(`${DIR}/${file}`).trim();
      const run = () =>
        verifyEntitlement(jws, {
          keySet,
          expectedIssuer: ctx.expected_issuer,
          expectedInstanceId: ctx.expected_instance_id_by_file[file] as string,
          expectedSubject: ctx.expected_subject_by_file[file] as string,
          cached: ctx.cached_by_file[file] ?? null,
          now: ctx.now_by_file[file] ?? ctx.now,
        });
      if (e.valid) {
        const v = run();
        expect([v.kid, v.seq, v.claims.sub]).toEqual([e.kid, e.seq, e.subject]);
        expect(v.claims).toEqual(fixture(`${DIR}/${file.replace(/\.jws$/, '.claims.json')}`));
      } else {
        let code = 'ok';
        try {
          run();
        } catch (error) {
          if (!(error instanceof EntitlementError)) throw error;
          code = error.code;
        }
        expect(code).toBe(e.code);
      }
    });
});

// The platform's key-manifest bodies (keys/manifest.json and keys/invalid/): each reaches the
// platform's outcome at the context's time, against keys/roots.json unless another root file is named.
const mctx = fixture<{ manifests: { issuer: string; now: number; roots_file: string; roots_file_by_file: Record<string, string> } }>(
  `${DIR}/context.json`,
).manifests;
const manifests = fixture<{ manifests: Record<string, { valid: boolean; code?: string; keys?: number }> }>(
  `${DIR}/expected.json`,
).manifests;
const rootsOf = (file: string): RootKey[] =>
  fixture<{ issuer: string; kid: string; x: string }[]>(`${DIR}/${file}`).map((r) => ({
    kid: r.kid,
    x: r.x,
    iss: r.issuer,
    kty: 'OKP',
    crv: 'Ed25519',
  }));

describe('the platform key-manifest fixtures', () => {
  it('has the published set: 1 valid and 10 invalid manifests', () => {
    expect(Object.values(manifests).filter((m) => m.valid)).toHaveLength(1);
    expect(Object.values(manifests).filter((m) => !m.valid)).toHaveLength(10);
  });
  for (const [file, e] of Object.entries(manifests))
    it(`${file}: ${e.valid ? 'verifies' : e.code}`, () => {
      const run = () =>
        KeySet.verify(fixture(`${DIR}/${file}`), {
          issuer: mctx.issuer,
          unsafeRootKeys: rootsOf(mctx.roots_file_by_file[file] ?? mctx.roots_file),
          now: mctx.now,
        });
      if (e.valid) {
        expect(run().manifest.keys).toHaveLength(e.keys as number);
        return;
      }
      let code = 'ok';
      try {
        run();
      } catch (error) {
        if (!(error instanceof KeyManifestError)) throw error;
        code = error.code;
      }
      expect(code).toBe(e.code);
    });
});
