// The compact JWS helpers a product uses outside the client: signCompactJws (EdDSA over Ed25519
// only) and claimsOfVerifiedJws (the claims of a document already verified; never verifies).
import { describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository tools (no type declarations).
import { verifyJws } from '../../../../tools/mock-platform/src/crypto.mjs';
import {
  CONSTANTS,
  claimsOfVerifiedJws,
  KeySet,
  MAX_JWS_LENGTH,
  makeNodeSigner,
  type RootKey,
  signCompactJws,
  statsSignerFromSeed,
  verifyEntitlement,
} from '../src/index';
import { fixture, fixtureText } from './helpers';

const STATS = statsSignerFromSeed(new Uint8Array(32).fill(7));
const CONNECT = makeNodeSigner(new Uint8Array(32).fill(11));
const CONNECT_X = Buffer.from(CONNECT.publicKeyRaw).toString('base64url');
const parts = (jws: string) => jws.split('.');
const headerOf = (jws: string) => JSON.parse(Buffer.from(parts(jws)[0] as string, 'base64url').toString('utf8'));

describe('signCompactJws', () => {
  it('signs the stats_link statement with the statistics key; an independent verifier accepts it', async () => {
    const claims = {
      stats_instance_id: '5f0c6f4e-2a4b-4c7e-9a51-3d2b1f0e9c11',
      stats_public_jwk: { kty: 'OKP', crv: 'Ed25519', x: STATS.publicKey },
      sub: '01JNE7V9J03J6XQ2WN8H0Z88R5',
      iat: 1793613600,
    };
    const jws = await signCompactJws(STATS, { typ: CONSTANTS.stats_link_typ }, claims);
    expect(headerOf(jws)).toEqual({ alg: 'EdDSA', typ: 'ever-stats-link+jwt' });
    const decoded = verifyJws(jws, STATS.publicKey, { typ: CONSTANTS.stats_link_typ });
    expect(decoded?.payload).toEqual(claims);
    // Another key does not verify it.
    expect(verifyJws(jws, CONNECT_X, { typ: CONSTANTS.stats_link_typ })).toBeNull();
  });

  it('takes an InstanceSigner, a StatsSigner or a function, sync or async', async () => {
    const payload = { sub: 'x', iat: 1 };
    const forms = [CONNECT, (bytes: Uint8Array) => CONNECT.sign(bytes), { sign: (bytes: Uint8Array) => CONNECT.sign(bytes) }] as const;
    const signed = await Promise.all(forms.map((s) => signCompactJws(s, { kid: CONNECT.kid }, payload)));
    // Ed25519 is deterministic: the same key over the same bytes gives the same JWS.
    expect(new Set(signed).size).toBe(1);
    expect(verifyJws(signed[0], CONNECT_X)).not.toBeNull();
    const fromStats = await signCompactJws((bytes) => STATS.sign(bytes), {}, payload);
    expect(verifyJws(fromStats, STATS.publicKey)).not.toBeNull();
  });

  it('alg is always EdDSA and comes first; another alg is refused, never relabelled', async () => {
    const jws = await signCompactJws(CONNECT, { typ: 'JWT', alg: 'EdDSA', kid: 'k' }, {});
    expect(parts(jws)[0]).toBe(Buffer.from('{"alg":"EdDSA","typ":"JWT","kid":"k"}').toString('base64url'));
    for (const alg of ['none', 'HS256', 'RS256', 'ES256', 'eddsa', '', null, 0])
      await expect(signCompactJws(CONNECT, { alg }, {})).rejects.toThrow(/alg EdDSA only/);
    await expect(signCompactJws(CONNECT, { crit: ['b64'], b64: false }, {})).rejects.toThrow(/crit/);
  });

  it('refuses what a verifier would not read: non-objects, lone surrogates, non-finite numbers, over 64 KiB', async () => {
    for (const [h, p] of [
      [[], {}],
      [{}, []],
      [null, {}],
      [{}, 'claims'],
    ])
      await expect(signCompactJws(CONNECT, h as never, p as never)).rejects.toThrow(/JSON object/);
    await expect(signCompactJws(CONNECT, {}, { name: 'a\uD800b' })).rejects.toThrow(/lone surrogate/);
    await expect(signCompactJws(CONNECT, { kid: '\uDC00' }, {})).rejects.toThrow(/lone surrogate/);
    await expect(signCompactJws(CONNECT, {}, { n: Number.NaN })).rejects.toThrow(/not finite/);
    await expect(signCompactJws(CONNECT, {}, { n: [Number.POSITIVE_INFINITY] })).rejects.toThrow(/not finite/);
    await expect(signCompactJws(CONNECT, {}, { blob: 'x'.repeat(MAX_JWS_LENGTH) })).rejects.toThrow(/would not decode/);
    let deep: Record<string, unknown> = {};
    for (let i = 0; i < 130; i += 1) deep = { d: deep };
    await expect(signCompactJws(CONNECT, {}, deep)).rejects.toThrow(/would not decode/);
  });

  it('refuses a signature that is not 64 bytes', async () => {
    await expect(signCompactJws(() => new Uint8Array(63), {}, {})).rejects.toThrow(/64 bytes/);
    await expect(signCompactJws(async () => new Uint8Array(65), {}, {})).rejects.toThrow(/64 bytes/);
    await expect(signCompactJws(() => 'signature' as never, {}, {})).rejects.toThrow(/64 bytes/);
  });

  it('a failing signer fails the call', async () => {
    await expect(
      signCompactJws(
        () => {
          throw new Error('key store unavailable');
        },
        {},
        {},
      ),
    ).rejects.toThrow('key store unavailable');
  });
});

describe('claimsOfVerifiedJws', () => {
  const ctx = fixture<{ expected_issuer: string; expected_instance_id: string; expected_subject: string; now: number }>(
    'entitlement/context.json',
  );
  const keysCtx = fixture<{ issuer: string; now: number }>('keys/context.json');
  const roots = fixture<{ keys: RootKey[] }>('keys/roots.json').keys;
  const keySet = KeySet.verify(fixture('keys/manifest.valid.json'), { unsafeRootKeys: roots, issuer: keysCtx.issuer, now: keysCtx.now });

  it('answers the claims the verifier accepted, for a document stored after verification', () => {
    const jws = fixtureText('entitlement/valid/instance.jws').trim();
    const verified = verifyEntitlement(jws, {
      keySet,
      expectedIssuer: ctx.expected_issuer,
      expectedInstanceId: ctx.expected_instance_id,
      expectedSubject: ctx.expected_subject,
      cached: null,
      now: ctx.now,
    });
    const claims = claimsOfVerifiedJws(verified.jws);
    expect(claims).toEqual(verified.claims);
    expect(claims).toEqual(fixture('entitlement/valid/instance.claims.json'));
    // A new object on every call: changing one changes nothing for the next reader.
    (claims as Record<string, unknown>).iss = 'changed';
    expect(claimsOfVerifiedJws(verified.jws)?.iss).toBe(ctx.expected_issuer);
  });

  it('never verifies: a forged signature, a foreign issuer or alg none still answer their claims', () => {
    // This is why it is only for documents the verifier accepted before: it checks nothing.
    const jws = fixtureText('entitlement/valid/instance.jws').trim();
    const [h, p] = parts(jws) as [string, string];
    const forged = `${h}.${p}.${Buffer.alloc(64, 1).toString('base64url')}`;
    expect(claimsOfVerifiedJws(forged)).toEqual(claimsOfVerifiedJws(jws));
    const alg = fixtureText('entitlement/invalid/alg-none.jws').trim();
    expect(claimsOfVerifiedJws(alg)).not.toBeNull();
  });

  it('reads by the verifiers decoding rule only; anything else is null', () => {
    const jws = fixtureText('entitlement/valid/instance.jws').trim();
    const [h, p, s] = parts(jws) as [string, string, string];
    const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
    for (const bad of [
      undefined,
      null,
      42,
      '',
      `${h}.${p}`,
      `${h}.${p}.${s}.${s}`,
      `${h}.${p}=.${s}`,
      `${h}.${p.slice(0, -1)}+.${s}`,
      `${h}.${b64('[1,2]')}.${s}`,
      `${h}.${b64('not json')}.${s}`,
      `${b64('[]')}.${p}.${s}`,
      `${h}.${b64({ blob: 'x'.repeat(MAX_JWS_LENGTH) })}.${s}`,
    ])
      expect(claimsOfVerifiedJws(bad), String(bad).slice(0, 40)).toBeNull();
  });
});
