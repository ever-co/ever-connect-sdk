import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { isSmallOrder } from '../src/ed25519';
import {
  CONSTANTS,
  isVerifiedKeyManifest,
  KeyManifestError,
  KeySet,
  keysSha256,
  pinnedRootKeys,
  type RootKey,
  type VerifiedKeyManifest,
  verifyKeyManifest,
} from '../src/index';
import { originOf } from '../src/local';
import { parseUtcTime } from '../src/time';
import { fixture, signRaw } from './helpers';

const ctx = fixture<{ issuer: string; now: number }>('keys/context.json');
const roots = fixture<{ keys: RootKey[] }>('keys/roots.json').keys;
const expected = fixture<{ fixtures: Record<string, { valid: boolean; code?: string; trusted_kids?: string[] }> }>(
  'keys/expected.json',
).fixtures;
const valid = fixture('keys/manifest.valid.json');
const opts = (patch: Record<string, unknown> = {}) => ({ unsafeRootKeys: roots, issuer: ctx.issuer, now: ctx.now, ...patch });

const codeOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    if (error instanceof KeyManifestError) return error.code;
    throw error;
  }
  return 'ok';
};

/** A manifest body signed by the TEST root with an exact header and payload. */
const manifestWith = (header: Record<string, unknown>, payloadPatch: Record<string, unknown> = {}, keys = valid.keys) => {
  const payload = {
    iss: ctx.issuer,
    iat: ctx.now,
    exp: ctx.now + 2592000,
    keys_sha256: keysSha256(keys),
    root_kid: 'test-root-1',
    ...payloadPatch,
  };
  return { manifest: signRaw('test-root/1', header, payload), keys };
};
const HEADER = { alg: 'EdDSA', kid: 'test-root-1', typ: 'ever-key-manifest+jwt' };

describe('verifyKeyManifest: the SDK fixtures', () => {
  for (const [file, e] of Object.entries(expected)) {
    it(`${file}: ${e.valid ? 'verifies' : e.code}`, () => {
      const body = fixture(`keys/${file}`);
      if (e.valid) {
        const m = verifyKeyManifest(body, opts());
        expect(m.keys.map((k) => k.kid)).toEqual(e.trusted_kids);
        expect(m.rootKid).toBe('test-root-1');
        expect(m.issuer).toBe(ctx.issuer);
      } else expect(codeOf(() => verifyKeyManifest(body, opts()))).toBe(e.code);
    });
  }

  it('the issuer is required: there is no issuer-less path', () => {
    expect(() => verifyKeyManifest(valid, undefined as never)).toThrow(TypeError);
    expect(() => verifyKeyManifest(valid, { unsafeRootKeys: roots, now: ctx.now } as never)).toThrow(TypeError);
    expect(() => KeySet.verify(valid, {} as never)).toThrow(TypeError);
    expect(() => KeySet.restore({ document: valid, fetchedAt: ctx.now }, {} as never)).toThrow(TypeError);
  });

  it('JCS: the canonical key list hashes to the signed keys_sha256 (parity with the platform signer)', () => {
    const payload = JSON.parse(Buffer.from(valid.manifest.split('.')[1], 'base64url').toString('utf8'));
    expect(keysSha256(valid.keys)).toBe(payload.keys_sha256);
    // Member order of the served objects does not matter: JCS sorts them.
    const reordered = valid.keys.map((k: Record<string, unknown>) => Object.fromEntries(Object.entries(k).reverse()));
    expect(keysSha256(reordered)).toBe(payload.keys_sha256);
  });
});

describe('verifyKeyManifest: every check, in order', () => {
  const v = (body: unknown, now = ctx.now) => codeOf(() => verifyKeyManifest(body, opts({ now })));
  it('schema_violation: not the closed {manifest, keys} shape', () => {
    expect(v({ manifest: valid.manifest })).toBe('schema_violation');
    expect(v({ ...valid, extra: 1 })).toBe('schema_violation');
    expect(v({ manifest: valid.manifest, keys: [{ ...valid.keys[0], ever_purpose: 'root' }] })).toBe('schema_violation');
    expect(v(null)).toBe('schema_violation');
  });
  it('schema_violation: a key time that is not a UTC time that exists, a small-order or off-curve key', () => {
    const withKey = (edit: Record<string, unknown>) => ({ manifest: valid.manifest, keys: [{ ...valid.keys[1], ...edit }] });
    for (const t of ['2026-11-01T12:00:00+02:00', '2026-11-01 10:00:00Z', '2026-06-30T23:59:60Z', '2026-02-31T00:00:00Z', '2026-11-01'])
      expect(v(withKey({ not_before: t })), t).toBe('schema_violation');
    expect(v(withKey({ not_after: 'soon' }))).toBe('schema_violation');
    expect(v(withKey({ x: Buffer.from(`01${'00'.repeat(31)}`, 'hex').toString('base64url') }))).toBe('schema_violation');
  });
  it('malformed: not three canonical base64url parts with JSON objects', () => {
    const [h, p, s] = valid.manifest.split('.');
    expect(v({ ...valid, manifest: `${h}.${p}.${s}.${s}` })).toBe('schema_violation');
    expect(v({ ...valid, manifest: `${h}.${p}.${s.slice(0, -1)}${s.endsWith('A') ? 'B' : 'A'}` })).toMatch(/^(malformed|bad_signature)$/);
    expect(v({ ...valid, manifest: `${Buffer.from('{"alg":"EdDSA"').toString('base64url')}.${p}.${s}` })).toBe('malformed');
  });
  it('bad_typ, then bad_alg (before any root is looked at)', () => {
    expect(v(manifestWith({ ...HEADER, typ: 'JWT' }))).toBe('bad_typ');
    expect(v(manifestWith({ ...HEADER, alg: 'none' }))).toBe('bad_alg');
    expect(v(manifestWith({ ...HEADER, alg: 'RS256', kid: 'not-a-root' }))).toBe('bad_alg');
    expect(v(manifestWith({ ...HEADER, crit: ['exp'] }))).toBe('bad_alg');
  });
  it('unknown_root: a root vouches only for the issuer it names, and only when it names one', () => {
    const elsewhere = roots.map((r) => ({ ...r, iss: 'https://api.example.com' }));
    expect(codeOf(() => verifyKeyManifest(valid, opts({ unsafeRootKeys: elsewhere })))).toBe('unknown_root');
    const anywhere = roots.map(({ iss: _iss, ...r }) => r);
    expect(codeOf(() => verifyKeyManifest(valid, opts({ unsafeRootKeys: anywhere })))).toBe('unknown_root');
    // The pinned roots of this release hold no TEST root.
    expect(codeOf(() => verifyKeyManifest(valid, { issuer: ctx.issuer, now: ctx.now }))).toBe('unknown_root');
  });
  it('bad_signature', () => {
    const [h, p, s] = valid.manifest.split('.');
    const flipped = Buffer.from(s, 'base64url');
    flipped[0] ^= 1;
    expect(v({ ...valid, manifest: `${h}.${p}.${flipped.toString('base64url')}` })).toBe('bad_signature');
  });
  it('malformed payload: missing claims, or root_kid other than the signing root', () => {
    expect(v(manifestWith(HEADER, { root_kid: 'test-root-9' }))).toBe('malformed');
    expect(v(manifestWith(HEADER, { exp: 'later' }))).toBe('malformed');
  });
  it('issuer_mismatch, manifest_not_yet_valid (300 s skew), manifest_expired, keys_sha256_mismatch', () => {
    expect(v(manifestWith(HEADER, { iss: 'https://api.example.com' }))).toBe('issuer_mismatch');
    expect(v(manifestWith(HEADER, { iat: ctx.now + 300 }))).toBe('ok');
    expect(v(manifestWith(HEADER, { iat: ctx.now + 301 }))).toBe('manifest_not_yet_valid');
    expect(v(manifestWith(HEADER, { exp: ctx.now }))).toBe('manifest_expired');
    expect(v(manifestWith(HEADER, { exp: ctx.now + 1 }))).toBe('ok');
    expect(v(manifestWith(HEADER, { keys_sha256: '0'.repeat(64) }))).toBe('keys_sha256_mismatch');
  });
});

describe('a verified manifest cannot be forged', () => {
  it('only verifyKeyManifest makes one; an object of the same shape is refused', () => {
    const m = verifyKeyManifest(valid, opts());
    expect(isVerifiedKeyManifest(m)).toBe(true);
    const copy = JSON.parse(JSON.stringify(m)) as VerifiedKeyManifest;
    expect(isVerifiedKeyManifest(copy)).toBe(false);
    expect(() => KeySet.fromManifest(copy, ctx.now)).toThrow(TypeError);
    expect(() => KeySet.fromManifest({ ...m }, ctx.now)).toThrow(TypeError);
    expect(KeySet.fromManifest(m, ctx.now).issuer).toBe(ctx.issuer);
    expect(Object.isFrozen(m) && Object.isFrozen(m.keys) && Object.isFrozen(m.keys[0])).toBe(true);
  });
  it('a key set is built only by its factories', () => {
    const KeySetClass = KeySet as unknown as new (...args: unknown[]) => KeySet;
    expect(() => new KeySetClass(Symbol('KeySet'), verifyKeyManifest(valid, opts()), ctx.now)).toThrow(TypeError);
    const fake = Object.create(KeySet.prototype) as KeySet;
    expect(KeySet.isKeySet(fake)).toBe(false);
    expect(KeySet.isKeySet(KeySet.verify(valid, opts()))).toBe(true);
  });
});

describe('the pinned roots and the manifests Ever Platform serves', () => {
  const platform = fixture<{
    fixtures: Record<string, { issuer: string; root_kid: string; verify_at: number; expired_at: number; trusted_kids: string[] }>;
  }>('keys-platform/expected.json').fixtures;
  for (const [file, e] of Object.entries(platform)) {
    it(`${file} verifies with the pinned root of ${e.issuer} only`, () => {
      const body = fixture(`keys-platform/${file}`);
      const m = verifyKeyManifest(body, { issuer: e.issuer, now: e.verify_at });
      expect(m.rootKid).toBe(e.root_kid);
      expect(m.keys.map((k) => k.kid)).toEqual(e.trusted_kids);
      expect(codeOf(() => verifyKeyManifest(body, { issuer: 'https://api.ever.co', now: e.verify_at }))).toBe('unknown_root');
      expect(codeOf(() => verifyKeyManifest(body, { issuer: e.issuer, now: e.expired_at }))).toBe('manifest_expired');
    });
  }
  it('every pinned root names its issuer; no TEST root is pinned', () => {
    const pinned = pinnedRootKeys();
    expect(pinned).toEqual(CONSTANTS.root_keys);
    expect(pinned.some((r) => r.kid.startsWith('test-') || r.x === roots[0]?.x)).toBe(false);
    for (const r of pinned) {
      expect(r.iss).toMatch(/^https:\/\//);
      expect(r.kid.slice(-4)).toBe(createHash('sha256').update(r.x).digest('hex').slice(0, 4));
    }
  });
});

describe('KeySet', () => {
  const set = () => KeySet.verify(valid, opts());
  it('answers only active or previous keys of the purpose asked for', () => {
    const ks = set();
    expect(ks.issuer).toBe(ctx.issuer);
    expect(ks.find('test-entitlement-1', 'entitlement', ctx.now)?.kid).toBe('test-entitlement-1');
    expect(ks.find('test-assertion-1', 'entitlement', ctx.now)).toBeNull();
    expect(ks.find('test-intent-1', 'entitlement', ctx.now)).toBeNull();
    expect(ks.find('test-entitlement-9', 'entitlement', ctx.now)).toBeNull();
    expect(ks.has('test-entitlement-9')).toBe(false);
  });
  it('a key outside its window (300 s skew) is not answered', () => {
    const nb = parseUtcTime(valid.keys[1].not_before) as number;
    const ks = set();
    expect(ks.find('test-entitlement-1', 'entitlement', nb - 300)?.kid).toBe('test-entitlement-1');
    expect(ks.find('test-entitlement-1', 'entitlement', nb - 301)).toBeNull();
  });
  it('needs a refresh after 24 h or once the manifest expired; an unknown kid refreshes at most every 10 minutes', () => {
    const ks = set();
    expect(ks.needsRefresh(ctx.now + 86399)).toBe(false);
    expect(ks.needsRefresh(ctx.now + 86400)).toBe(true);
    expect(ks.unknownKidRefreshAllowed(ctx.now + 599)).toBe(false);
    expect(ks.unknownKidRefreshAllowed(ctx.now + 600)).toBe(true);
    expect(ks.unknownKidRefreshAllowed(ctx.now + 1199)).toBe(false);
    expect(ks.unknownKidRefreshAllowed(ctx.now + 1200)).toBe(true);
  });
  it('a refused manifest, one for another issuer, or an older one never replaces the set', () => {
    const ks = set();
    const refused = ks.update(fixture('keys/manifest.keys-sha256-mismatch.json'), opts());
    expect(refused.keySet).toBe(ks);
    expect(refused.replaced).toBe(false);
    expect(refused.error?.code).toBe('keys_sha256_mismatch');
    const other = ks.update(valid, opts({ issuer: 'https://api.ever.co' }));
    expect(other).toMatchObject({ replaced: false, error: { code: 'issuer_mismatch' } });
    expect(other.keySet).toBe(ks);
    const older = ks.update(manifestWith(HEADER, { iat: ctx.now - 10 }), opts());
    expect(older.replaced).toBe(false);
    expect(older.error).toBeNull();
    const newer = ks.update(manifestWith(HEADER, { iat: ctx.now + 10 }), opts({ now: ctx.now + 20 }));
    expect(newer.replaced).toBe(true);
    expect(newer.keySet.manifest.issuedAt).toBe(ctx.now + 10);
  });
  it('stores as the served body and restores for its issuer by verifying again; a future fetch time counts as now', () => {
    const ks = set();
    const stored = JSON.parse(JSON.stringify(ks));
    expect(stored).toEqual({ document: valid, fetchedAt: ctx.now });
    const back = KeySet.restore(stored, opts({ now: ctx.now + 60 }));
    expect(back.find('test-entitlement-1', 'entitlement', ctx.now)?.kid).toBe('test-entitlement-1');
    expect(() => KeySet.restore({ ...stored, document: { ...valid, keys: valid.keys.slice(1) } }, opts())).toThrow(KeyManifestError);
    expect(() => KeySet.restore(stored, opts({ issuer: 'https://api.ever.co' }))).toThrow(KeyManifestError);
    const future = KeySet.restore({ ...stored, fetchedAt: ctx.now + 10 ** 9 }, opts({ now: ctx.now + 60 }));
    expect(future.fetchedAt).toBe(ctx.now + 60);
    expect(future.needsRefresh(ctx.now + 60 + 86400)).toBe(true);
  });
});

describe('small-order points', () => {
  it('the eight small-order points are refused in every encoding, a real key is not', () => {
    const encodings = fixture<{ encodings: string[] }>('keys/small-order.json').encodings;
    expect(encodings.length).toBe(14);
    for (const h of encodings) expect(isSmallOrder(Buffer.from(h, 'hex')), h).toBe(true);
    expect(isSmallOrder(Buffer.from(roots[0]?.x as string, 'base64url'))).toBe(false);
  });
});

describe('the origin rule (keys/origins.json, shared with the Rust SDK)', () => {
  const { vectors } = fixture<{ vectors: { url: string; origin: string | null }[] }>('keys/origins.json');
  it('has the vectors', () => expect(vectors.length).toBeGreaterThan(50));
  for (const v of vectors) it(`${JSON.stringify(v.url)} -> ${v.origin}`, () => expect(originOf(v.url)).toBe(v.origin));
});
