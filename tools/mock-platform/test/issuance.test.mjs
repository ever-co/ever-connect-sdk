// A deployment with connect-code issuance off, as the platform behaves: a malformed body still
// gets 422; a well-formed redeem or link-code redemption gets 404; connected installations keep
// minting tokens. Also the assertion rules the platform added (typ, nbf, jti length).
import { describe, expect, test } from 'vitest';
import { verifyAssertion } from '../src/assertion.mjs';
import { signClientAssertion, testKey } from '../src/keys.mjs';
import { expectOk, expectProblem, ISSUER, startMock } from './helpers.mjs';

const redeem = (code = 'EVC-TEST-0000-0001', extra = {}) => ({
  code,
  product: 'gauzy',
  version: '96.2.1',
  install_source: 'self-hosted',
  public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connectNext').x },
  ...extra,
});

describe('issuance off', () => {
  test('a malformed body is 422, a well-formed redeem 404, and tokens keep working', async () => {
    const env = await startMock();
    try {
      const { instanceId, token } = await env.connect();
      await env.admin('faults', { connect_issuance_off: true });
      const malformed = await env.call('POST', '/v1/connect/redeem', {
        body: { code: 'EVC-TEST-0000-0001', version: '1.0.0', install_source: 'self-hosted' },
        headers: { 'idempotency-key': 'off-1' },
      });
      expectProblem(expect, malformed, 422, 'validation_failed');
      expectProblem(
        expect,
        await env.call('POST', '/v1/connect/redeem', { body: redeem(), headers: { 'idempotency-key': 'off-2' } }),
        404,
        'not_found',
      );
      // An invalid product in a well-formed body: issuance is checked first, as the platform does.
      expectProblem(
        expect,
        await env.call('POST', '/v1/connect/redeem', {
          body: redeem('EVC-TEST-0000-0001', { product: 'nope' }),
          headers: { 'idempotency-key': 'off-3' },
        }),
        404,
        'not_found',
      );
      const link = await env.call('POST', '/v1/instances/me/tenant-links', {
        token,
        body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 't9' },
        headers: { 'idempotency-key': 'off-4' },
      });
      expectProblem(expect, link, 404, 'not_found');
      const minted = await env.token(instanceId);
      expect(minted).toMatch(/^evit_/);
    } finally {
      await env.close();
    }
  });

  test('with issuance on, a well-formed body with an invalid field is refused before the code is looked at', async () => {
    const env = await startMock();
    try {
      const badVersion = await env.call('POST', '/v1/connect/redeem', {
        body: redeem('EVC-AAAA-BBBB-CCCC', { version: 'v1' }),
        headers: { 'idempotency-key': 'on-1' },
      });
      expectProblem(expect, badVersion, 422, 'validation_failed');
      expect(badVersion.body.errors[0].path).toBe('/version');
      const badKey = await env.call('POST', '/v1/connect/redeem', {
        body: redeem('EVC-AAAA-BBBB-CCCC', { public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connectNext').x, d: 'private' } }),
        headers: { 'idempotency-key': 'on-2' },
      });
      expectProblem(expect, badKey, 422, 'public_jwk_invalid');
      const ok = await env.call('POST', '/v1/connect/redeem', { body: redeem(), headers: { 'idempotency-key': 'on-3' } });
      expectOk(expect, ok, 201, 'connectRedeem');
      expect(Object.keys(ok.body).sort()).toEqual([
        'entitlement_endpoint',
        'feed_endpoint',
        'instance_id',
        'kid',
        'status',
        'token_endpoint',
      ]);
    } finally {
      await env.close();
    }
  });
});

describe('assertion rules', () => {
  const now = 1793613600;
  const key = testKey('connect');
  const ctx = (overrides = {}) => ({
    now,
    audience: `${ISSUER}/v1/instances/token`,
    instanceFor: () => ({ current_key: { x: key.x, kid: key.kid }, previous_key: null, rotated_at: null }),
    seenJti: () => false,
    ...overrides,
  });
  const sign = (header = {}, jti = 'conformance-jti-000001') =>
    signClientAssertion({ key, instanceId: '01JNE7V9J03J6XQ2WN8H0Z88R5', audience: `${ISSUER}/v1/instances/token`, iat: now, jti, header });

  test('typ, when present, is JWT', () => {
    expect(verifyAssertion(sign(), ctx()).ok).toBe(true);
    expect(verifyAssertion(sign({ typ: 'at+jwt' }), ctx())).toEqual({ ok: false, reason: 'type' });
  });

  test('jti is 16 to 128 visible characters', () => {
    expect(verifyAssertion(sign({}, 'short'), ctx()).reason).toBe('jti');
    expect(verifyAssertion(sign({}, 'x'.repeat(129)), ctx()).reason).toBe('jti');
    expect(verifyAssertion(sign({}, 'has a space in it 0000'), ctx()).reason).toBe('jti');
  });
});
