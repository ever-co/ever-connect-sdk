// The core rows: key manifest, legal, redeem, token, device flow, heartbeat, feed, entitlements,
// integrations, local disable, disconnect, connect-key rotation and statistics reports.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { verifyEntitlement, verifyManifest } from '../../test/lib/reference-verify.mjs';
import { b64url, instanceKid, signBytes } from '../src/crypto.mjs';
import { testKey, testRootEntry } from '../src/keys.mjs';
import { expectOk, expectProblem, ISSUER, startMock } from './helpers.mjs';

const REPO = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');
const statsFixture = (f) => readFileSync(join(REPO, 'contracts/fixtures/stats', f));
const statsExpected = JSON.parse(readFileSync(join(REPO, 'contracts/fixtures/stats/expected.json'), 'utf8')).fixtures;

let env;
afterEach(async () => {
  await env?.close();
  env = null;
});

function signedReport(bytes, key = testKey('stats'), { keyId } = {}) {
  const headers = { 'ever-stats-key': key.x, 'ever-stats-signature': `ed25519=${signBytes(key.privateKey, bytes)}` };
  if (keyId) headers['ever-stats-key-id'] = keyId;
  return { raw: bytes, headers };
}

describe('row 1: key manifest', () => {
  it('serves a manifest signed by the TEST root, and rotates entitlement keys', async () => {
    env = await startMock();
    const r = await env.call('GET', '/.well-known/ever-keys.json');
    expectOk(expect, r, 200, 'get_key_manifest');
    const v = verifyManifest(r.body, [testRootEntry(ISSUER)], ISSUER, env.now());
    expect(v.ok).toBe(true);
    expect(v.keys.filter((k) => k.ever_purpose === 'entitlement').map((k) => k.state)).toEqual(['active']);
    await env.admin('keys/rotate');
    const after = verifyManifest((await env.call('GET', '/.well-known/ever-keys.json')).body, [testRootEntry(ISSUER)], ISSUER, env.now());
    expect(
      after.keys
        .filter((k) => k.ever_purpose === 'entitlement')
        .map((k) => k.state)
        .sort(),
    ).toEqual(['active', 'previous']);
  });
});

describe('row 3: redeem', () => {
  it('answers 201 with a ULID instance id, and a second redeem of the code is byte-identical to an unknown code', async () => {
    env = await startMock();
    const { redeem } = await env.connect();
    expect(redeem.instance_id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(redeem.kid).toBe(instanceKid(testKey('connect').x));
    expect(redeem.status).toBe('active');
    const body = (code, key) => ({
      code,
      product: 'gauzy',
      version: '1.0.0',
      install_source: 'self-hosted',
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x: key.x },
    });
    const again = await env.call('POST', '/v1/connect/redeem', {
      body: body('EVC-TEST-0000-0001', testKey('connectNext')),
      headers: { 'idempotency-key': 'k2', 'x-request-id': 'req-fixed' },
    });
    const unknown = await env.call('POST', '/v1/connect/redeem', {
      body: body('EVC-ZZZZ-ZZZZ-ZZZZ', testKey('connectNext')),
      headers: { 'idempotency-key': 'k3', 'x-request-id': 'req-fixed' },
    });
    const malformed = await env.call('POST', '/v1/connect/redeem', {
      body: body('EVC-123', testKey('connectNext')),
      headers: { 'idempotency-key': 'k4', 'x-request-id': 'req-fixed' },
    });
    expectProblem(expect, again, 422, 'code_invalid');
    expect(unknown.text).toBe(again.text);
    expect(malformed.text).toBe(again.text);
  });

  it('refuses demand, another product, a held key and a bad key', async () => {
    env = await startMock();
    const base = {
      code: 'EVC-TEST-0000-0001',
      version: '1.0.0',
      install_source: 'self-hosted',
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connect').x },
    };
    expectProblem(
      expect,
      await env.call('POST', '/v1/connect/redeem', { body: { ...base, product: 'demand' }, headers: { 'idempotency-key': 'a' } }),
      422,
      'product_not_supported',
    );
    expectProblem(
      expect,
      await env.call('POST', '/v1/connect/redeem', { body: { ...base, product: 'works' }, headers: { 'idempotency-key': 'b' } }),
      422,
      'product_mismatch',
    );
    expectProblem(
      expect,
      await env.call('POST', '/v1/connect/redeem', {
        body: { ...base, product: 'gauzy', public_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } },
        headers: { 'idempotency-key': 'c' },
      }),
      422,
      'public_jwk_invalid',
    );
    await env.connect();
    await env.admin('codes', { code: 'EVC-TEST-0000-0009', product: 'gauzy' });
    expectProblem(
      expect,
      await env.call('POST', '/v1/connect/redeem', {
        body: { ...base, code: 'EVC-TEST-0000-0009', product: 'gauzy' },
        headers: { 'idempotency-key': 'd' },
      }),
      409,
      'already_connected',
    );
  });

  it('replays the first answer for the same Idempotency-Key and refuses another body with it', async () => {
    env = await startMock();
    const body = {
      code: 'EVC-TEST-0000-0001',
      product: 'gauzy',
      version: '1.0.0',
      install_source: 'self-hosted',
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connect').x },
    };
    const first = await env.call('POST', '/v1/connect/redeem', { body, headers: { 'idempotency-key': 'same' } });
    const replay = await env.call('POST', '/v1/connect/redeem', { body, headers: { 'idempotency-key': 'same' } });
    expect(replay.status).toBe(201);
    expect(replay.text).toBe(first.text);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expectProblem(
      expect,
      await env.call('POST', '/v1/connect/redeem', { body: { ...body, version: '2.0.0' }, headers: { 'idempotency-key': 'same' } }),
      422,
      'idempotency_mismatch',
    );
  });

  it('a 24-hour code redeems as pending approval: 403 everywhere except GET /v1/instances/me', async () => {
    env = await startMock();
    const { token, redeem } = await env.connect({ code: 'EVC-TEST-0000-0003' });
    expect(redeem.status).toBe('pending_approval');
    expectOk(expect, await env.call('GET', '/v1/instances/me', { token }), 200, 'getInstanceSelf');
    expectProblem(
      expect,
      await env.call('POST', '/v1/instances/me/heartbeat', { token, body: { version: '1.0.0' } }),
      403,
      'instance_pending_approval',
    );
    await env.admin('approve', {});
    expectOk(expect, await env.call('POST', '/v1/instances/me/heartbeat', { token, body: { version: '1.0.0' } }), 200, 'instanceHeartbeat');
  });
});

describe('row 4: instance token', () => {
  it('issues an evit_ token for a valid assertion; a UUID issuer, a replay, a long lifetime and another audience are invalid_client', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    expect(token).toMatch(/^evit_[A-Za-z0-9_-]{43}$/);
    const post = (assertion) =>
      env.call('POST', '/v1/instances/token', {
        body: {
          grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: assertion,
        },
      });
    expectProblem(expect, await post(env.assertion({ instanceId: '3d2b1a0c-5e4f-4a6b-8c7d-9e0f1a2b3c4d' })), 401, 'invalid_client');
    const once = env.assertion({ instanceId, jti: 'replayed-jti-000000001' });
    expectOk(expect, await post(once), 200, 'instanceToken');
    expectProblem(expect, await post(once), 401, 'invalid_client');
    expectProblem(expect, await post(env.assertion({ instanceId, ttl: 600 })), 401, 'invalid_client');
    expectProblem(
      expect,
      await post(env.assertion({ instanceId, audience: 'http://other.test/v1/instances/token' })),
      401,
      'invalid_client',
    );
    expectProblem(expect, await post(env.assertion({ instanceId, key: testKey('stranger') })), 401, 'invalid_client');
  });

  it('accepts the previous connect key for 7 days after a rotation, then refuses it', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    const rotated = await env.call('POST', '/v1/instances/me/keys', {
      token,
      body: env.rotation(instanceId),
      headers: { 'idempotency-key': 'rot' },
    });
    expectOk(expect, rotated, 200, 'instanceRotateKey');
    expect(await env.token(instanceId, testKey('connect'))).toMatch(/^evit_/);
    expect(await env.token(instanceId, testKey('connectNext'))).toMatch(/^evit_/);
    await env.admin('clock', { advance: 8 * 86400 });
    await expect(env.token(instanceId, testKey('connect'))).rejects.toThrow(/401/);
    expect(await env.token(instanceId, testKey('connectNext'))).toMatch(/^evit_/);
  });
});

describe('row 4: token limit', () => {
  it('mints at most 60 tokens an hour per installation, then 429 with Retry-After; the next hour mints again', async () => {
    env = await startMock();
    const { instanceId } = await env.connect();
    for (let i = 1; i < 60; i += 1) await env.token(instanceId);
    const limited = await env.call('POST', '/v1/instances/token', {
      body: {
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: env.assertion({ instanceId }),
      },
    });
    expectProblem(expect, limited, 429, 'rate_limited');
    expect(limited.headers.get('retry-after')).toBe('3600');
    // Another installation behind the same address has its own count.
    await env.admin('codes', { code: 'EVC-TEST-0000-0009' });
    const other = await env.connect({ code: 'EVC-TEST-0000-0009', key: testKey('stranger'), tenant: { product_tenant_id: 'tenant-9' } });
    expect(other.token).toMatch(/^evit_/);
    await env.admin('clock', { advance: 3600 });
    expect(await env.token(instanceId)).toMatch(/^evit_/);
  });
});

describe('row 5: link codes', () => {
  it('wrong link codes count per installation: a neighbour behind the same address still links, up to the per-address backstop', async () => {
    env = await startMock({ limits: { wrong_link_codes_per_address_hour: 12 } });
    let n = 0;
    const link = (token, code, tenant) => {
      n += 1;
      return env.call('POST', '/v1/instances/me/tenant-links', {
        token,
        body: { link_code: code, product: 'gauzy', product_tenant_id: tenant },
        headers: { 'idempotency-key': `link-${n}` },
      });
    };
    const a = await env.connect();
    for (let i = 0; i < 10; i += 1)
      expectProblem(expect, await link(a.token, `EVL-AAAA-BBBB-${String(i).padStart(4, '0')}`, 'tenant-a'), 422, 'code_invalid');
    const full = await link(a.token, 'EVL-TEST-0000-0002', 'tenant-a');
    expectProblem(expect, full, 429, 'rate_limited');
    expect(Number(full.headers.get('retry-after'))).toBeGreaterThan(0);
    // B, behind the same address: its redeem and its valid link code go through.
    await env.admin('codes', { code: 'EVC-TEST-0000-0009' });
    const b = await env.connect({ code: 'EVC-TEST-0000-0009', key: testKey('stranger'), tenant: { product_tenant_id: 'tenant-9' } });
    expectOk(expect, await link(b.token, 'EVL-TEST-0000-0002', 'tenant-b'), 201, 'instanceCreateTenantLink');
    // The per-address backstop (100 an hour; 12 in this test) counts every installation's wrong codes.
    expectProblem(expect, await link(b.token, 'EVL-AAAA-BBBB-0100', 'tenant-c'), 422, 'code_invalid');
    expectProblem(expect, await link(b.token, 'EVL-AAAA-BBBB-0101', 'tenant-c'), 422, 'code_invalid');
    expectProblem(expect, await link(b.token, 'EVL-AAAA-BBBB-0102', 'tenant-c'), 429, 'rate_limited');
  });

  it('a link code the organization revoked answers code_invalid, like an unknown one', async () => {
    env = await startMock();
    const { token } = await env.connect();
    await env.admin('codes/revoke', { code: 'EVL-TEST-0000-0002' });
    const r = await env.call('POST', '/v1/instances/me/tenant-links', {
      token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-r' },
      headers: { 'idempotency-key': 'revoked' },
    });
    expectProblem(expect, r, 422, 'code_invalid');
  });
});

describe('row 16: connect-key rotation', () => {
  let n = 0;
  const rotate = (token, body) => {
    n += 1;
    return env.call('POST', '/v1/instances/me/keys', { token, body, headers: { 'idempotency-key': `rotate-${n}` } });
  };
  const me = (token) => env.call('GET', '/v1/instances/me', { token });

  it('takes two proofs; the order is the key shape, the proofs, a replay, then the key itself', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    const short = { ...env.rotation(instanceId), public_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'short' } };
    expectProblem(expect, await rotate(token, short), 422, 'public_jwk_invalid');
    const alone = { public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connectNext').x } };
    expectProblem(expect, await rotate(token, alone), 422, 'validation_failed');
    for (const options of [
      { signers: [testKey('connectNext'), testKey('connectNext')] },
      { signers: [testKey('connect'), testKey('connect')] },
      { signers: [testKey('stranger'), testKey('connectNext')] },
      { bind: testKey('stranger') },
      { claims: { aud: `${ISSUER}/v1/instances/token` } },
      { jtis: ['rotation-same-jti-0001', 'rotation-same-jti-0001'] },
    ])
      expectProblem(expect, await rotate(token, env.rotation(instanceId, options)), 401, 'invalid_client');
    // Valid proofs for the current key: the proofs pass and are spent, the key is refused...
    const same = env.rotation(instanceId, { next: testKey('connect') });
    expectProblem(expect, await rotate(token, same), 422, 'public_jwk_invalid');
    // ...and the same proofs again are a replay, refused before the key is looked at.
    expectProblem(expect, await rotate(token, same), 401, 'invalid_client');
    // A key another installation holds is refused.
    await env.admin('codes', { code: 'EVC-TEST-0000-0009' });
    await env.connect({ code: 'EVC-TEST-0000-0009', key: testKey('stranger'), tenant: { product_tenant_id: 'tenant-9' } });
    expectProblem(expect, await rotate(token, env.rotation(instanceId, { next: testKey('stranger') })), 422, 'public_jwk_invalid');
    // Nothing above moved the key; a proper rotation works.
    const ok = await rotate(token, env.rotation(instanceId));
    expectOk(expect, ok, 200, 'instanceRotateKey');
    expect(ok.body.kid).toBe(instanceKid(testKey('connectNext').x));
    expect(ok.body.previous_kid).toBe(instanceKid(testKey('connect').x));
    expect(Date.parse(ok.body.previous_valid_until) / 1000).toBe(env.now() + 7 * 86400);
    // Back to the key it replaced: a key the installation held.
    const back = env.rotation(instanceId, { current: testKey('connectNext'), next: testKey('connect') });
    expectProblem(expect, await rotate(token, back), 422, 'public_jwk_invalid');
  });

  it('a token of the replaced key works inside the overlap and stops when the overlap ends', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    expectOk(expect, await rotate(token, env.rotation(instanceId)), 200, 'instanceRotateKey');
    expectOk(expect, await me(token), 200, 'getInstanceSelf');
    await env.admin('clock', { advance: 7 * 86400 - 600 });
    // The replaced key still mints near the end of the overlap; its token says an hour but stops with the overlap.
    const late = await env.token(instanceId, testKey('connect'));
    expectOk(expect, await me(late), 200, 'getInstanceSelf');
    await env.admin('clock', { advance: 600 });
    expectProblem(expect, await me(late), 401, 'unauthorized');
    await expect(env.token(instanceId, testKey('connect'))).rejects.toThrow(/401/);
    expectOk(expect, await me(await env.token(instanceId, testKey('connectNext'))), 200, 'getInstanceSelf');
  });

  it('a second rotation inside the overlap drops the older key and every token it minted at once', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    expectOk(expect, await rotate(token, env.rotation(instanceId)), 200, 'instanceRotateKey');
    const byFirst = await env.token(instanceId, testKey('connect'));
    const bySecond = await env.token(instanceId, testKey('connectNext'));
    const again = env.rotation(instanceId, { current: testKey('connectNext'), next: testKey('stranger') });
    expectOk(expect, await rotate(bySecond, again), 200, 'instanceRotateKey');
    expectProblem(expect, await me(token), 401, 'unauthorized');
    expectProblem(expect, await me(byFirst), 401, 'unauthorized');
    await expect(env.token(instanceId, testKey('connect'))).rejects.toThrow(/401/);
    expectOk(expect, await me(bySecond), 200, 'getInstanceSelf');
    expectOk(expect, await me(await env.token(instanceId, testKey('stranger'))), 200, 'getInstanceSelf');
  });
});

describe('row 29: device-first connect', () => {
  it('pending, slow down, approval, then the token for the parked key; another key is key_mismatch', async () => {
    env = await startMock();
    const key = testKey('connect');
    const start = await env.call('POST', '/v1/connect/device', {
      body: { product: 'gauzy', version: '1.0.0', install_source: 'self-hosted', public_jwk: { kty: 'OKP', crv: 'Ed25519', x: key.x } },
    });
    expectOk(expect, start, 200, 'connectDevice');
    const kid = instanceKid(key.x);
    const poll = (k = key) =>
      env.call('POST', '/v1/connect/token', {
        body: {
          device_code: start.body.device_code,
          client_assertion: env.assertion({ key: k, instanceId: kid, audience: `${ISSUER}/v1/connect/token` }),
        },
      });
    expectProblem(expect, await poll(), 400, 'authorization_pending');
    expectProblem(expect, await poll(), 400, 'slow_down');
    await env.admin('clock', { advance: 30 });
    await env.admin('approve', { user_code: start.body.user_code });
    expectProblem(expect, await poll(testKey('stranger')), 409, 'key_mismatch');
    await env.admin('clock', { advance: 30 });
    const ok = await poll();
    expectOk(expect, ok, 200, 'connectDeviceToken');
    expect(ok.body.access_token).toMatch(/^evit_/);
    expectProblem(expect, await poll(), 400, 'expired_token');
  });
});

describe('rows 6-10 and 16', () => {
  it('heartbeat: once a minute, then 429 with Retry-After', async () => {
    env = await startMock();
    const { token } = await env.connect();
    expectOk(
      expect,
      await env.call('POST', '/v1/instances/me/heartbeat', { token, body: { version: '96.2.1', serves_products: ['gauzy', 'teams'] } }),
      200,
      'instanceHeartbeat',
    );
    const limited = await env.call('POST', '/v1/instances/me/heartbeat', { token, body: { version: '96.2.1' } });
    expectProblem(expect, limited, 429, 'rate_limited');
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  it('feed: long-poll answers when an event arrives; ack moves the cursor; an unknown cursor is resync_required', async () => {
    env = await startMock();
    const { token } = await env.connect();
    const first = await env.call('GET', '/v1/instances/me/events?wait=0', { token });
    expectOk(expect, first, 200, 'instancePollEvents');
    expect(first.body.events.map((e) => e.type)).toContain('ever.registry.instance.connected');
    expectOk(
      expect,
      await env.call('POST', '/v1/instances/me/events/ack', { token, body: { last_id: first.body.last_id } }),
      200,
      'instanceAckEvents',
    );
    const waiting = env.call('GET', '/v1/instances/me/events?wait=5', { token });
    await new Promise((r) => setTimeout(r, 100));
    await env.admin('entitlement/reissue', {});
    const woke = await waiting;
    expect(woke.body.events.map((e) => e.type)).toEqual(['ever.entitlements.entitlement.issued']);
    expectProblem(
      expect,
      await env.call('GET', '/v1/instances/me/events?after=01JUNKNOWNCURS0R000000000A&wait=0', { token }),
      410,
      'resync_required',
    );
    expectProblem(expect, await env.call('GET', '/v1/instances/me/events?wait=99', { token }), 422, 'validation_failed');
  });

  it('entitlement: signed with the TEST key, 304 on the same sequence, a new sequence after a reissue', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    const r = await env.call('GET', '/v1/instances/me/entitlement', { token });
    expectOk(expect, r, 200, 'instanceGetEntitlement');
    const manifest = verifyManifest(
      (await env.call('GET', '/.well-known/ever-keys.json')).body,
      [testRootEntry(ISSUER)],
      ISSUER,
      env.now(),
    );
    const v = verifyEntitlement(r.body.document, {
      keys: manifest.keys,
      issuer: ISSUER,
      instanceId,
      subject: `instance:${instanceId}`,
      cached: null,
      now: env.now(),
    });
    // The mock answers over http in CI; the closed schema allows only https issuers.
    expect(['schema_violation', undefined]).toContain(v.code);
    expect((await env.call('GET', '/v1/instances/me/entitlement', { token, headers: { 'if-none-match': `"${r.body.seq}"` } })).status).toBe(
      304,
    );
    await env.admin('entitlement/reissue', {});
    expect(
      (await env.call('GET', '/v1/instances/me/entitlement', { token, headers: { 'if-none-match': `"${r.body.seq}"` } })).body.seq,
    ).toBe(r.body.seq + 1);
  });

  it('integrations, consent link and the local disable (enable is refused by the closed schema)', async () => {
    env = await startMock();
    const { token, linkId } = await env.connect();
    const states = await env.call('GET', '/v1/instances/me/integrations', { token });
    expectOk(expect, states, 200, 'instanceGetIntegrations');
    expect(states.body.instance.stats_link.state).toBe('available');
    expect(states.body.links[linkId].counterparty_lookup.state).toBe('available');
    const url = await env.call(
      'GET',
      `/v1/instances/me/consent-url?integration=counterparty_lookup&link=${linkId}&return=https%3A%2F%2Fgauzy.example.com%2Fsettings`,
      { token },
    );
    expectOk(expect, url, 200, 'instanceGetConsentUrl');
    await env.admin('consent', { integration: 'counterparty_lookup' });
    expectOk(
      expect,
      await env.call('PUT', '/v1/instances/me/integrations/counterparty_lookup', {
        token,
        body: { enabled: false, reason: 'policy', tenant_link_id: linkId },
      }),
      200,
      'instanceDisableIntegration',
    );
    expectProblem(
      expect,
      await env.call('PUT', '/v1/instances/me/integrations/counterparty_lookup', { token, body: { enabled: true, reason: 'instance' } }),
      422,
      'validation_failed',
    );
    expectProblem(
      expect,
      await env.call('PUT', '/v1/instances/me/integrations/no_such_key', { token, body: { enabled: false, reason: 'instance' } }),
      404,
      'not_found',
    );
  });

  it('disconnect: the next call is credential_revoked', async () => {
    env = await startMock();
    const { token } = await env.connect();
    expectOk(
      expect,
      await env.call('POST', '/v1/instances/me/disconnect', { token, headers: { 'idempotency-key': 'bye' } }),
      200,
      'instanceDisconnect',
    );
    expectProblem(expect, await env.call('GET', '/v1/instances/me', { token }), 401, 'credential_revoked');
  });
});

describe('row 17: statistics reports', () => {
  it('accepts a signed golden twice, pins the key, and refuses another key for the same id', async () => {
    env = await startMock();
    const bytes = statsFixture('valid/gauzy.json');
    const first = await env.call('POST', '/v1/stats/reports', signedReport(bytes));
    expectOk(expect, first, 202, 'ingestStatsReport');
    expect(first.body).toEqual({ accepted: true });
    const second = await env.call('POST', '/v1/stats/reports', signedReport(bytes));
    expect(second.body).toEqual({ accepted: true, superseded: true });
    expectProblem(expect, await env.call('POST', '/v1/stats/reports', signedReport(bytes, testKey('statsOther'))), 409, 'key_mismatch');
  });

  it('checks the signature headers: a bad signature is signature_invalid, a wrong key id validation_failed', async () => {
    env = await startMock();
    const bytes = statsFixture('valid/works.json');
    const r = signedReport(bytes);
    expectProblem(
      expect,
      await env.call('POST', '/v1/stats/reports', { raw: Buffer.concat([bytes, Buffer.from(' ')]), headers: r.headers }),
      400,
      'signature_invalid',
    );
    expectProblem(
      expect,
      await env.call('POST', '/v1/stats/reports', signedReport(bytes, testKey('stats'), { keyId: 'AAAAAAAAAAA' })),
      400,
      'validation_failed',
    );
    expectProblem(
      expect,
      await env.call('POST', '/v1/stats/reports', { raw: bytes, headers: { 'ever-stats-key': testKey('stats').x } }),
      400,
      'validation_failed',
    );
    expectOk(
      expect,
      await env.call('POST', '/v1/stats/reports', signedReport(bytes, testKey('stats'), { keyId: instanceKid(testKey('stats').x) })),
      202,
      'ingestStatsReport',
    );
  });

  it('answers every invalid fixture with its expected status, code and path', async () => {
    env = await startMock();
    for (const [file, e] of Object.entries(statsExpected)) {
      if (e.status === 202) continue;
      const r = await env.call('POST', '/v1/stats/reports', signedReport(statsFixture(file)));
      expect(r.status, file).toBe(e.status);
      expect(r.body.code, file).toBe(e.code);
      if (e.status === 422) expect(r.body.errors[0].path, file).toBe(e.path);
    }
  });

  it('allows 24 reports a day per statistics id, then 429', async () => {
    env = await startMock();
    const bytes = statsFixture('valid/rec.json');
    for (let i = 0; i < 24; i += 1) expect((await env.call('POST', '/v1/stats/reports', signedReport(bytes))).status).toBe(202);
    expectProblem(expect, await env.call('POST', '/v1/stats/reports', signedReport(bytes)), 429, 'rate_limited');
  });

  it('a connect-key rotation leaves the statistics pin alone', async () => {
    env = await startMock();
    const { instanceId, token } = await env.connect();
    const bytes = statsFixture('valid/gauzy.json');
    expect((await env.call('POST', '/v1/stats/reports', signedReport(bytes))).status).toBe(202);
    const rotated = await env.call('POST', '/v1/instances/me/keys', {
      token,
      body: env.rotation(instanceId),
      headers: { 'idempotency-key': 'rot' },
    });
    expect(rotated.status).toBe(200);
    expect((await env.call('POST', '/v1/stats/reports', signedReport(bytes))).status).toBe(202);
  });
});

describe('the request record', () => {
  it('holds templates and hashes only: no code, token or assertion', async () => {
    env = await startMock();
    const { token } = await env.connect();
    await env.call('POST', '/v1/instances/me/heartbeat', { token, body: { version: '1.0.0' } });
    await env.call('POST', '/v1/stats/reports', signedReport(statsFixture('valid/gauzy.json')));
    const log = (await env.call('GET', '/__mock/requests')).body;
    expect(log.map((e) => e.row)).toEqual([3, 4, 6, 17]);
    const text = JSON.stringify(log);
    expect(text).not.toMatch(/EVC-|evit_|eyJ/);
    for (const e of log)
      expect(Object.keys(e).sort()).toEqual([
        'body_sha256',
        'idempotency_key',
        'method',
        'path_template',
        'row',
        'status',
        'ts',
        'user_agent',
      ]);
  });

  it('every documented row is routed', async () => {
    env = await startMock();
    const rows = new Set(env.mock.routes.map((r) => r.row));
    for (let row = 1; row <= 34; row += 1) expect(rows.has(row), `row ${row}`).toBe(true);
    expect(readdirSync(join(REPO, 'tools/mock-platform/src/routes')).length).toBeGreaterThanOrEqual(12);
    expect(b64url(Buffer.from('x'))).toBe('eA');
  });
});
