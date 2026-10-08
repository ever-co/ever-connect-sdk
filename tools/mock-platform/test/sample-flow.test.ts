// The sample client flow against the mock with plain fetch and the generated contract types:
// redeem -> token -> entitlement -> integrations -> link -> heartbeat -> events -> lookup ->
// disconnect. The SDK client runs the same flow in packages/ts/connect-sdk/test/mock-flow/.
import { createHash } from 'node:crypto';
import type {
  components,
  EventEnvelope,
  FeedResponse,
  HeartbeatBody,
  RedeemRequest,
  RedeemResponse,
  TenantLinkCreate,
  TokenRequest,
  TokenResponse,
} from '@ever-co/connect-contracts';
import { CONSTANTS } from '@ever-co/connect-contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { verifyEntitlement, verifyManifest } from '../../test/lib/reference-verify.mjs';
import { fromB64url } from '../src/crypto.mjs';
import { signClientAssertion, testKey, testRootEntry } from '../src/keys.mjs';
import { ISSUER, startMock } from './helpers.mjs';

type Env = Awaited<ReturnType<typeof startMock>>;
let env: Env | null = null;
afterEach(async () => {
  await env?.close();
  env = null;
});

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

describe('sample flow', () => {
  it('connects, verifies its entitlement, links, heartbeats, reads events, looks up and disconnects', async () => {
    env = await startMock();
    const e = env;
    const connectKey = testKey('connect');
    const ua = { 'user-agent': 'ever-connect-sdk/0.0.0-sample (gauzy/96.2.1)' };

    const manifestBody = (await e.call('GET', CONSTANTS.key_manifest_path)).body as components['schemas']['KeyManifestBody'];
    const manifest = verifyManifest(manifestBody, [testRootEntry(ISSUER)], ISSUER, e.now());
    expect(manifest.ok).toBe(true);

    const redeem: RedeemRequest = {
      code: 'EVC-TEST-0000-0001',
      product: 'gauzy',
      version: '96.2.1',
      install_source: 'self-hosted',
      kind: 'self_hosted',
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x: connectKey.x },
      tenant: { product_tenant_id: 'tenant-1', product_org_id: 'org-1' },
    };
    const redeemed = await e.call('POST', '/v1/connect/redeem', {
      body: redeem,
      headers: { ...ua, 'idempotency-key': sha256(`instance|${redeem.code}`) },
    });
    expect(redeemed.status).toBe(201);
    const r = redeemed.body as RedeemResponse;
    expect(new RegExp(CONSTANTS.connect_code_pattern).test(redeem.code)).toBe(true);

    const tokenRequest: TokenRequest = {
      grant_type: 'client_credentials',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: signClientAssertion({ key: connectKey, instanceId: r.instance_id, audience: r.token_endpoint, iat: e.now() }),
    };
    const tokenAnswer = await e.call('POST', '/v1/instances/token', { body: tokenRequest, headers: ua });
    const token = (tokenAnswer.body as TokenResponse).access_token;
    expect(token.startsWith(CONSTANTS.instance_token_prefix)).toBe(true);

    const ent = (await e.call('GET', '/v1/instances/me/entitlement', { token, headers: ua }))
      .body as components['schemas']['EntitlementDocument'];
    const verified = verifyEntitlement(ent.document, {
      keys: manifest.keys!,
      issuer: ISSUER,
      instanceId: r.instance_id,
      subject: `instance:${r.instance_id}`,
      cached: null,
      now: e.now(),
    });
    // Every rule passes, the closed schema included: the mock's issuer is https (served over plain HTTP).
    expect(verified.code ?? 'ok').toBe('ok');

    const states = (await e.call('GET', '/v1/instances/me/integrations', { token, headers: ua }))
      .body as components['schemas']['InstanceIntegrations'];
    expect(states.instance.stats_link?.state).toBe('available');

    const link: TenantLinkCreate = { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-2' };
    const linked = await e.call('POST', '/v1/instances/me/tenant-links', {
      token,
      body: link,
      headers: { ...ua, 'idempotency-key': sha256('link-2') },
    });
    expect(linked.status).toBe(201);

    const heartbeat: HeartbeatBody = { version: '96.2.1', serves_products: ['gauzy', 'teams'] };
    expect((await e.call('POST', '/v1/instances/me/heartbeat', { token, body: heartbeat, headers: ua })).status).toBe(200);

    const page = (await e.call('GET', '/v1/instances/me/events?wait=0', { token, headers: ua })).body as FeedResponse;
    const types = page.events.map((ev: EventEnvelope) => ev.type);
    expect(types).toEqual(['ever.registry.instance.connected', 'ever.registry.tenant_link.created', 'ever.registry.instance.seen']);
    expect((await e.call('POST', '/v1/instances/me/events/ack', { token, body: { last_id: page.last_id }, headers: ua })).status).toBe(200);

    await e.admin('consent', { integration: 'counterparty_lookup' });
    const salt = (await e.call('GET', '/v1/lookup/salt', { headers: ua })).body as components['schemas']['SaltSet'];
    const active = salt.active[0]!;
    const hash = createHash('sha256')
      .update(Buffer.concat([fromB64url(active.salt), Buffer.from(':vat:BG123456789')]))
      .digest('hex');
    const linkId = (redeemed.body as RedeemResponse).link!.id;
    const found = await e.call('POST', '/v1/lookup', {
      token,
      body: { salt_version: active.version, hashes: [hash] },
      headers: { ...ua, 'ever-link-id': linkId },
    });
    expect((found.body as components['schemas']['LookupResponse']).matches.map((m) => m.handle)).toEqual(['acme']);

    expect(
      (await e.call('POST', '/v1/instances/me/disconnect', { token, headers: { ...ua, 'idempotency-key': sha256('bye') } })).status,
    ).toBe(200);
    expect((await e.call('GET', '/v1/instances/me', { token, headers: ua })).body.code).toBe('credential_revoked');

    // Exactly the documented calls, in order, each with its row.
    const log = (await e.call('GET', '/__mock/requests')).body as Array<{ row: number; user_agent: string }>;
    expect(log.map((x) => x.row)).toEqual([1, 3, 4, 8, 9, 5, 6, 7, 7, 13, 13, 16, 6]);
    expect(log.every((x) => x.user_agent.startsWith('ever-connect-sdk/'))).toBe(true);
  });
});
