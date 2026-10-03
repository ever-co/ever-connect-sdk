import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CONSTANTS, KeyManifestError, KeySet, keysSha256, pinnedRootKeys, type RootKey, verifyKeyManifest } from '../src/index';
import { fixture, signRaw } from './helpers';

const ctx = fixture<{ issuer: string; now: number }>('keys/context.json');
const roots = fixture<{ keys: RootKey[] }>('keys/roots.json').keys;
const expected = fixture<{ fixtures: Record<string, { valid: boolean; code?: string; trusted_kids?: string[] }> }>(
  'keys/expected.json',
).fixtures;
const valid = fixture('keys/manifest.valid.json');

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
        const m = verifyKeyManifest(body, { rootKeys: roots, issuer: ctx.issuer, now: ctx.now });
        expect(m.keys.map((k) => k.kid)).toEqual(e.trusted_kids);
        expect(m.rootKid).toBe('test-root-1');
        expect(m.issuer).toBe(ctx.issuer);
      } else expect(codeOf(() => verifyKeyManifest(body, { rootKeys: roots, issuer: ctx.issuer, now: ctx.now }))).toBe(e.code);
    });
  }

  it('the positional form takes the roots and the time; the issuer is the one the root is pinned to', () => {
    expect(verifyKeyManifest(valid, roots, ctx.now).issuer).toBe(ctx.issuer);
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
  const v = (body: unknown, now = ctx.now) => codeOf(() => verifyKeyManifest(body, { rootKeys: roots, issuer: ctx.issuer, now }));
  it('schema_violation: not the closed {manifest, keys} shape', () => {
    expect(v({ manifest: valid.manifest })).toBe('schema_violation');
    expect(v({ ...valid, extra: 1 })).toBe('schema_violation');
    expect(v({ manifest: valid.manifest, keys: [{ ...valid.keys[0], ever_purpose: 'root' }] })).toBe('schema_violation');
    expect(v(null)).toBe('schema_violation');
  });
  it('malformed: not three canonical base64url parts with JSON objects', () => {
    const [h, p, s] = valid.manifest.split('.');
    expect(v({ ...valid, manifest: `${h}.${p}.${s}.${s}` })).toBe('schema_violation');
    expect(v({ ...valid, manifest: `${h}.${p}.${s.slice(0, -1)}${s.endsWith('A') ? 'B' : 'A'}` })).toMatch(/^(malformed|bad_signature)$/);
    expect(v({ ...valid, manifest: `${Buffer.from('{"alg":"EdDSA"').toString('base64url')}.${p}.${s}` })).toBe('malformed');
    expect(v({ ...valid, manifest: `${Buffer.from('[1]').toString('base64url')}.${p}.${s}` })).toBe('malformed');
  });
  it('bad_typ, then bad_alg (before any root is looked at)', () => {
    expect(v(manifestWith({ ...HEADER, typ: 'JWT' }))).toBe('bad_typ');
    expect(v(manifestWith({ ...HEADER, alg: 'none' }))).toBe('bad_alg');
    expect(v(manifestWith({ ...HEADER, alg: 'RS256', kid: 'not-a-root' }))).toBe('bad_alg');
    expect(v(manifestWith({ ...HEADER, crit: ['exp'] }))).toBe('bad_alg');
  });
  it('unknown_root: a root pinned for another issuer is not a root here', () => {
    const elsewhere = roots.map((r) => ({ ...r, iss: 'https://api.example.com' }));
    expect(codeOf(() => verifyKeyManifest(valid, { rootKeys: elsewhere, issuer: ctx.issuer, now: ctx.now }))).toBe('unknown_root');
    expect(codeOf(() => verifyKeyManifest(valid, { now: ctx.now, issuer: ctx.issuer }))).toBe('unknown_root');
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
      expect(verifyKeyManifest(body, { now: e.verify_at }).issuer).toBe(e.issuer);
      expect(codeOf(() => verifyKeyManifest(body, { issuer: 'https://api.ever.co', now: e.verify_at }))).toBe('unknown_root');
      expect(codeOf(() => verifyKeyManifest(body, { issuer: e.issuer, now: e.expired_at }))).toBe('manifest_expired');
    });
  }
  it('every pinned root names its issuer; the TEST root is first, a release refuses it', () => {
    const pinned = pinnedRootKeys();
    expect(pinned).toEqual(CONSTANTS.root_keys);
    expect(pinned[0]?.kid.startsWith('test-')).toBe(true);
    for (const r of pinned) expect(r.iss).toMatch(/^https?:\/\//);
    for (const r of pinned.slice(1)) expect(r.kid.slice(-4)).toBe(createHash('sha256').update(r.x).digest('hex').slice(0, 4));
  });
});

describe('KeySet', () => {
  const set = () => KeySet.verify(valid, { rootKeys: roots, issuer: ctx.issuer, now: ctx.now });
  it('answers only active or previous keys of the purpose asked for', () => {
    const ks = set();
    expect(ks.find('test-entitlement-1', 'entitlement', ctx.now)?.kid).toBe('test-entitlement-1');
    expect(ks.find('test-assertion-1', 'entitlement', ctx.now)).toBeNull();
    expect(ks.find('test-intent-1', 'entitlement', ctx.now)).toBeNull();
    expect(ks.find('test-entitlement-9', 'entitlement', ctx.now)).toBeNull();
    expect(ks.has('test-entitlement-9')).toBe(false);
  });
  it('a key outside its window (300 s skew) is not answered', () => {
    const nb = Date.parse(valid.keys[1].not_before) / 1000;
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
  it('a refused manifest keeps the previous set; an older one never replaces it', () => {
    const ks = set();
    const refused = ks.update(fixture('keys/manifest.keys-sha256-mismatch.json'), { rootKeys: roots, issuer: ctx.issuer, now: ctx.now });
    expect(refused.keySet).toBe(ks);
    expect(refused.replaced).toBe(false);
    expect(refused.error?.code).toBe('keys_sha256_mismatch');
    const older = ks.update(manifestWith(HEADER, { iat: ctx.now - 10 }), { rootKeys: roots, issuer: ctx.issuer, now: ctx.now });
    expect(older.replaced).toBe(false);
    expect(older.error).toBeNull();
    const newer = ks.update(manifestWith(HEADER, { iat: ctx.now + 10 }), { rootKeys: roots, issuer: ctx.issuer, now: ctx.now + 20 });
    expect(newer.replaced).toBe(true);
    expect(newer.keySet.manifest.issuedAt).toBe(ctx.now + 10);
  });
  it('stores as the served body and restores by verifying again', () => {
    const ks = set();
    const stored = JSON.parse(JSON.stringify(ks));
    expect(stored).toEqual({ document: valid, fetchedAt: ctx.now });
    const back = KeySet.restore(stored, { rootKeys: roots, issuer: ctx.issuer, now: ctx.now + 60 });
    expect(back.find('test-entitlement-1', 'entitlement', ctx.now)?.kid).toBe('test-entitlement-1');
    expect(() =>
      KeySet.restore({ ...stored, document: { ...valid, keys: valid.keys.slice(1) } }, { rootKeys: roots, now: ctx.now }),
    ).toThrow(KeyManifestError);
  });
});
