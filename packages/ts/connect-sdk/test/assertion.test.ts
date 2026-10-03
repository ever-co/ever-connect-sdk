import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository tools (no type declarations).
import { verifyAssertion } from '../../../../tools/mock-platform/src/assertion.mjs';
import {
  AssertionError,
  generateInstanceKeyPair,
  keyIdFromPublicJwk,
  makeNodeSigner,
  NotConnectedError,
  publicJwkOf,
  signClientAssertion,
  subjectHash,
} from '../src/index';
import { FIXTURES, fixture } from './helpers';

// The platform's vectors (contracts/connect/vectors, vendored byte for byte) sign with keys from
// fixed seeds: the current connect key is 32 bytes of 11, the previous one 32 bytes of 12.
const CURRENT = makeNodeSigner(new Uint8Array(32).fill(11));
const PREVIOUS = makeNodeSigner(new Uint8Array(32).fill(12));
const VECTORS = readdirSync(join(FIXTURES, 'connect/vectors'))
  .filter((f) => f.startsWith('assertion-'))
  .sort();
type Vector = {
  assertion: string;
  description: string;
  context: {
    audience: string;
    instance_id: string;
    now: number;
    current_key: { kid: string; x: string };
    previous_key: { kid: string; x: string };
    rotated_at: number;
    overlap_s: number;
    seen_jti: string[];
  };
  expected: { status: number; code?: string };
};
const vector = (file: string) => fixture<Vector>(`connect/vectors/${file}`);
const platformVerdict = (token: string, c: Vector['context']) =>
  verifyAssertion(token, {
    now: c.now,
    audience: c.audience,
    instanceFor: (iss: string) =>
      iss === c.instance_id ? { current_key: c.current_key, previous_key: c.previous_key, rotated_at: c.rotated_at } : null,
    seenJti: (jti: string) => c.seen_jti.includes(jti),
  });

describe('client assertion against the platform vectors', () => {
  const valid = vector('assertion-valid.json');
  it('the key id is base64url of the first 8 bytes of SHA-256 over the raw key', () => {
    expect(keyIdFromPublicJwk(valid.context.current_key)).toBe(valid.context.current_key.kid);
    expect(keyIdFromPublicJwk(valid.context.previous_key)).toBe(valid.context.previous_key.kid);
    expect(CURRENT.kid).toBe(valid.context.current_key.kid);
    expect(publicJwkOf(CURRENT).x).toBe(valid.context.current_key.x);
  });
  it('with the vector key, clock and jti, the SDK writes the vector assertion byte for byte', async () => {
    const c = valid.context;
    const token = await signClientAssertion({
      signer: CURRENT,
      registryInstanceId: c.instance_id,
      audience: c.audience,
      now: c.now,
      jti: JSON.parse(Buffer.from(valid.assertion.split('.')[1] as string, 'base64url').toString()).jti,
    });
    expect(token).toBe(valid.assertion);
  });
  for (const file of VECTORS) {
    it(`${file}: the vector gets the platform's answer (${vector(file).expected.status})`, () => {
      const v = vector(file);
      expect(platformVerdict(v.assertion, v.context).ok ? 200 : 401).toBe(v.expected.status);
    });
  }
  it('an assertion the SDK builds (random jti) gets 200, with the current key and with the previous key inside the overlap', async () => {
    const c = valid.context;
    for (const signer of [CURRENT, PREVIOUS]) {
      const token = await signClientAssertion({ signer, registryInstanceId: c.instance_id, audience: c.audience, now: c.now });
      const r = platformVerdict(token, c);
      expect(r.ok, r.reason).toBe(true);
      const header = JSON.parse(Buffer.from(token.split('.')[0] as string, 'base64url').toString());
      expect(header).toEqual({ alg: 'EdDSA', kid: signer.kid, typ: 'JWT' });
      const claims = JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString());
      expect(claims.iss).toBe(c.instance_id);
      expect(claims.sub).toBe(c.instance_id);
      expect(claims.exp - claims.iat).toBe(300);
      expect(claims.jti).toMatch(/^[A-Za-z0-9_-]{22}$/);
    }
  });
  it('the lifetime is capped at 300 s', async () => {
    const token = await signClientAssertion({
      signer: CURRENT,
      registryInstanceId: valid.context.instance_id,
      audience: 'a',
      now: 10,
      ttlS: 3600,
    });
    const claims = JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString());
    expect(claims.exp).toBe(310);
  });
  it('no Registry id: NotConnectedError before signing; a UUID (the statistics id) is not a Registry id', async () => {
    let signed = 0;
    const counting = {
      ...CURRENT,
      sign: async (b: Uint8Array) => {
        signed += 1;
        return CURRENT.sign(b);
      },
    };
    await expect(signClientAssertion({ signer: counting, registryInstanceId: null, audience: 'a' })).rejects.toBeInstanceOf(
      NotConnectedError,
    );
    await expect(signClientAssertion({ signer: counting, registryInstanceId: '', audience: 'a' })).rejects.toBeInstanceOf(
      NotConnectedError,
    );
    const uuid = vector('assertion-uuid-issuer.json');
    const uuidId = JSON.parse(Buffer.from(uuid.assertion.split('.')[1] as string, 'base64url').toString()).iss;
    await expect(signClientAssertion({ signer: counting, registryInstanceId: uuidId, audience: 'a' })).rejects.toMatchObject({
      name: 'AssertionError',
      code: 'not_a_registry_id',
    });
    await expect(
      signClientAssertion({ signer: counting, registryInstanceId: '01jne7v9j03j6xq2wn8h0z88r5', audience: 'a' }),
    ).rejects.toBeInstanceOf(AssertionError);
    expect(signed).toBe(0);
  });
});

describe('keys', () => {
  it('a generated key pair: the PKCS#8 key signs as the public key says', async () => {
    const pair = generateInstanceKeyPair();
    const signer = makeNodeSigner(pair.privateKeyPkcs8Der);
    expect(signer.kid).toBe(pair.kid);
    expect(publicJwkOf(signer)).toEqual(pair.publicJwk);
    expect((await signer.sign(new Uint8Array([1, 2, 3]))).length).toBe(64);
  });
  it('a signer shows its key id only', () => {
    expect(JSON.stringify(CURRENT)).toBe(JSON.stringify({ kid: CURRENT.kid }));
    expect(String(CURRENT)).toBe(`InstanceSigner(${CURRENT.kid})`);
  });
});

describe('subjectHash', () => {
  it('is sha256 of "<issuer>#<subject>" (the platform test vector)', () => {
    expect(subjectHash('https://auth.ever.co', '3300')).toBe('9934771655649d0033a8169970eae18571059176b896eee2c56db921c866c471');
  });
});
