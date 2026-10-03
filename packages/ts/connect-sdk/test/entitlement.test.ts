import { createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { EntitlementError, entitlementStatus, KeySet, keysSha256, type RootKey, verifyEntitlement } from '../src/index';
import { fixture, fixtureText, signRaw, testPrivateKey } from './helpers';

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
const keySet = KeySet.verify(fixture('keys/manifest.valid.json'), { unsafeRootKeys: roots, issuer: keysCtx.issuer, now: keysCtx.now });
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
  // A document over exact payload text (to write numbers as JSON allows).
  const signText = (text: string) =>
    signRaw(
      'test-entitlement/1',
      { alg: 'EdDSA', kid: 'test-entitlement-1', typ: 'ever-entitlement+jwt' },
      text as unknown as Record<string, unknown>,
    );
  const errorOf = (fn: () => unknown): EntitlementError => {
    try {
      fn();
    } catch (error) {
      if (error instanceof EntitlementError) return error;
    }
    throw new Error('no EntitlementError');
  };

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
  it('only a key set built by KeySet verifies: no manifest, no object of the same shape', () => {
    expect(() => verifyEntitlement(instance, { ...opts, keySet: undefined as never })).toThrow(TypeError);
    expect(() => verifyEntitlement(instance, { ...opts, keySet: { ...keySet } as never })).toThrow(TypeError);
    const fake = Object.create(KeySet.prototype);
    expect(() => verifyEntitlement(instance, { ...opts, keySet: fake })).toThrow(TypeError);
  });
  it('a key set verifies documents of its own issuer only (at the issuer check, in the contract order)', () => {
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, expectedIssuer: 'https://api.ever.co' }))).toBe('issuer_mismatch');
    // A document of the other issuer signed with a key of this set: refused at the issuer check.
    const prod = sign({}, { ...claims, iss: 'https://api.ever.co' });
    expect(codeOf(() => verifyEntitlement(prod, { ...opts, expectedIssuer: 'https://api.ever.co' }))).toBe('issuer_mismatch');
    // The earlier checks come first.
    expect(codeOf(() => verifyEntitlement('not a document', { ...opts, expectedIssuer: 'https://api.ever.co' }))).toBe('malformed');
  });
  it('a stored key set whose manifest expired is restored, and verifies no new document', () => {
    const exp = keySet.manifest.expiresAt;
    const restored = KeySet.restore(keySet.toJSON(), { issuer: keysCtx.issuer, unsafeRootKeys: roots, now: exp + 86400 });
    expect(restored.needsRefresh(exp + 86400)).toBe(true);
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, keySet: restored, now: exp + 86400 }))).toBe('manifest_expired');
    expect(() => KeySet.verify(fixture('keys/manifest.valid.json'), { issuer: keysCtx.issuer, unsafeRootKeys: roots, now: exp })).toThrow(
      expect.objectContaining({ code: 'manifest_expired' }),
    );
  });
  it('an instance document carries no link member (the schema); a link document names its own link', () => {
    const linked = sign({}, { ...claims, ever: { ...claims.ever, tenant_link_id: '01JHGF4PAY0P5JJ7J2A56VSRZM' } });
    expect(codeOf(() => verifyEntitlement(linked, opts))).toBe('schema_violation');
    const link = fixture('entitlement/valid/link.claims.json');
    const elsewhere = sign({}, { ...link, ever: { ...link.ever, tenant_link_id: '01JHGF4PAY0P5JJ7J2A56VSRZN' } });
    expect(codeOf(() => verifyEntitlement(elsewhere, { ...options('valid/link.jws') }))).toBe('subject_mismatch');
  });
  it('keys of an expired manifest verify no new document (after alg, before the key lookup)', () => {
    const exp = opts.keySet.manifest.expiresAt;
    expect(verifyEntitlement(instance, { ...opts, now: exp - 1 }).status).toBe('stale');
    expect(codeOf(() => verifyEntitlement(instance, { ...opts, now: exp }))).toBe('manifest_expired');
    const unknown = sign({ kid: 'test-entitlement-9' }, claims);
    expect(codeOf(() => verifyEntitlement(unknown, { ...opts, now: exp }))).toBe('manifest_expired');
    expect(codeOf(() => verifyEntitlement(sign({ typ: 'JWT' }, claims), { ...opts, now: exp }))).toBe('bad_typ');
  });
  it('the integer claims are I-JSON integers as written; other numbers only meet the schema', () => {
    const text = (patch: (s: string) => string) => signText(patch(JSON.stringify(claims)));
    expect(
      codeOf(() =>
        verifyEntitlement(
          text((s) => s.replace('"seq":3', '"seq":3.0')),
          opts,
        ),
      ),
    ).toBe('schema_violation');
    expect(
      errorOf(() =>
        verifyEntitlement(
          text((s) => s.replace('"seq":3', '"seq":3.0')),
          opts,
        ),
      ).path,
    ).toBe('/ever/seq');
    expect(
      codeOf(() =>
        verifyEntitlement(
          text((s) => s.replace(/"iat":(\d+)/, '"iat":$1e0')),
          opts,
        ),
      ),
    ).toBe('schema_violation');
    expect(
      codeOf(() =>
        verifyEntitlement(
          text((s) => s.replace('"seq":3', '"seq":9007199254740992')),
          opts,
        ),
      ),
    ).toBe('schema_violation');
    expect(
      codeOf(() =>
        verifyEntitlement(
          text((s) => s.replace('"seq":3', '"seq":1e400')),
          opts,
        ),
      ),
    ).toBe('malformed');
    // A member given twice: the last one counts, as JSON.parse reads it.
    expect(
      verifyEntitlement(
        text((s) => s.replace('"seq":3', '"seq":3.0,"seq":3')),
        opts,
      ).seq,
    ).toBe(3);
    expect(
      verifyEntitlement(
        text((s) => s.replace('"api.rpm":600', '"api.rpm":600.0')),
        opts,
      ).seq,
    ).toBe(3);
  });
  it('a JWS over 64 KiB is malformed', () => {
    expect(codeOf(() => verifyEntitlement(`${instance}${'A'.repeat(65536)}`, opts))).toBe('malformed');
  });
});

describe('the review forgery (a TEST-root manifest and an attacker document for the production issuer)', () => {
  // The TEST root's private key is derivable from a public seed label: anyone can sign a key
  // manifest with it, listing their own key, and a document for any issuer with that key.
  const PROD = 'https://api.ever.co';
  const claims = fixture('entitlement/valid/instance.claims.json');
  const opts = options('valid/instance.jws');
  const attackerX = makeAttacker();
  const forgedManifest = (() => {
    const keys = [
      ...fixture('keys/manifest.valid.json').keys,
      { ...fixture('keys/manifest.valid.json').keys[1], kid: 'attacker-1', x: attackerX },
    ];
    const payload = { iss: PROD, iat: ctx.now, exp: ctx.now + 2592000, keys_sha256: keysSha256(keys), root_kid: 'test-root-1' };
    return { manifest: signRaw('test-root/1', { alg: 'EdDSA', kid: 'test-root-1', typ: 'ever-key-manifest+jwt' }, payload), keys };
  })();
  const forgedDocument = signRaw(
    'test-stranger/1',
    { alg: 'EdDSA', kid: 'attacker-1', typ: 'ever-entitlement+jwt' },
    { ...claims, iss: PROD, ever: { ...claims.ever, tier: 'bundle' } },
  );
  it('is refused on every path: verify, restore and update need the issuer; the TEST root is not pinned', () => {
    expect(() => KeySet.restore({ document: forgedManifest, fetchedAt: ctx.now }, {} as never)).toThrow(TypeError);
    for (const fn of [
      () => KeySet.restore({ document: forgedManifest, fetchedAt: ctx.now }, { issuer: PROD, now: ctx.now }),
      () => KeySet.verify(forgedManifest, { issuer: PROD, now: ctx.now }),
      () => KeySet.verify(forgedManifest, { issuer: PROD, unsafeRootKeys: roots, now: ctx.now }),
    ])
      expect(() => fn()).toThrow(expect.objectContaining({ code: 'unknown_root' }));
  });
  it('a key set of the TEST issuer never vouches for a production document', () => {
    const testIssuerSet = KeySet.verify(
      {
        ...forgedManifest,
        manifest: signRaw(
          'test-root/1',
          { alg: 'EdDSA', kid: 'test-root-1', typ: 'ever-key-manifest+jwt' },
          {
            iss: ctx.expected_issuer,
            iat: ctx.now,
            exp: ctx.now + 2592000,
            keys_sha256: keysSha256(forgedManifest.keys),
            root_kid: 'test-root-1',
          },
        ),
      },
      { issuer: ctx.expected_issuer, unsafeRootKeys: roots, now: ctx.now },
    );
    expect(codeOf(() => verifyEntitlement(forgedDocument, { ...opts, keySet: testIssuerSet, expectedIssuer: PROD }))).toBe(
      'issuer_mismatch',
    );
  });
});

function makeAttacker(): string {
  return createPublicKey(testPrivateKey('test-stranger/1')).export({ format: 'jwk' }).x as string;
}

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
