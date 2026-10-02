// One scenario per operation (the good path) and per documented (row, status, code) pair. Each
// scenario gets a fresh mock and answers the response to check. rows.test.mjs runs them against
// contracts/generated/row-coverage.json and fails on any pair without a scenario.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromB64url, instanceKid, sha256Hex, signBytes } from '../src/crypto.mjs';
import { signStatsLinkStatement, testKey } from '../src/keys.mjs';
import { ISSUER } from './helpers.mjs';

const REPO = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');
const fixture = (p) => readFileSync(join(REPO, 'contracts/fixtures', p));
const GOLDEN = fixture('stats/valid/gauzy.json');
const GOLDEN_ID = JSON.parse(GOLDEN.toString('utf8')).instance_id;
const jwk = (key) => ({ kty: 'OKP', crv: 'Ed25519', x: key.x });
const idem = (label) => ({ 'idempotency-key': sha256Hex(label) });
const redeemBody = (code, key = testKey('connectNext'), product = 'gauzy') => ({
  code,
  product,
  version: '1.0.0',
  install_source: 'self-hosted',
  public_jwk: jwk(key),
});

function report(bytes = GOLDEN, key = testKey('stats'), extra = {}) {
  return {
    raw: bytes,
    headers: { 'ever-stats-key': key.x, 'ever-stats-signature': `ed25519=${signBytes(key.privateKey, bytes)}`, ...extra },
  };
}

/** Connected installation with the named integrations consented (per-link keys on the first link). */
async function connected(env, { enable = [], code } = {}) {
  const c = await env.connect(code ? { code } : {});
  for (const integration of enable) await env.admin('consent', { integration });
  return c;
}

async function revoked(env, integration) {
  const c = await connected(env, { enable: [integration] });
  await env.admin('revoke', { integration });
  return c;
}

const lookupSalt = (env) => env.state.config.lookup.salt_versions[0];
const lookupHash = (salt, kind, normalized) => sha256Hex(Buffer.concat([fromB64url(salt), Buffer.from(`:${kind}:${normalized}`)]));

async function webhook(env) {
  const c = await connected(env, { enable: ['webhooks'] });
  const created = await env.call('POST', '/v1/instances/me/webhooks', {
    token: c.token,
    body: { url: 'https://gauzy.example.com/api/ever-connect/webhooks', event_filter: ['ever.consent.*'] },
    headers: idem('wh'),
  });
  return { ...c, webhookId: created.body.id };
}

async function personToken(env, body = {}) {
  return (await env.admin('person-token', body)).token;
}

const managedRequest = async (env, extra = {}) => {
  const c = await connected(env, { enable: ['managed_operations'] });
  const op = await env.admin('managed/request', { kind: 'backup', params: {}, ...extra });
  return { ...c, operationId: op.operation_id };
};

const putState = (env, c, key, token, body) =>
  env.call(
    'PUT',
    `/v1/orgs/${c.redeem.instance_id ? env.state.instance(c.instanceId).org.id : ''}/instances/${c.instanceId}/integrations/${key}`,
    {
      token,
      body,
      headers: idem(`put-${key}-${Math.random()}`),
    },
  );

const grant = (body = {}) => ({
  enabled: true,
  consent: { scope_version: 1, dpa_version: '2026-10', accepted: true, screen_version: '1', ui_locale: 'en' },
  ...body,
});

// ------------------------------------------------------------------------------------ good paths
export const OK = {
  get_key_manifest: (env) => env.call('GET', '/.well-known/ever-keys.json'),
  getConnectLegal: (env) => env.call('GET', '/v1/connect/legal'),
  connectRedeem: (env) =>
    env.call('POST', '/v1/connect/redeem', {
      body: { ...redeemBody('EVC-TEST-0000-0001', testKey('connect')), tenant: { product_tenant_id: 't-1' } },
      headers: idem('r'),
    }),
  instanceToken: async (env) => {
    const c = await env.connect();
    return env.call('POST', '/v1/instances/token', {
      body: {
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: env.assertion({ instanceId: c.instanceId }),
      },
    });
  },
  instanceCreateTenantLink: async (env) => {
    const c = await connected(env);
    return env.call('POST', '/v1/instances/me/tenant-links', {
      token: c.token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-2' },
      headers: idem('l'),
    });
  },
  instanceUnlinkTenantLink: async (env) => {
    const c = await connected(env);
    return env.call('DELETE', `/v1/instances/me/tenant-links/${c.linkId}`, { token: c.token });
  },
  instanceRekeyTenantLink: async (env) => {
    const c = await connected(env);
    return env.call('PATCH', `/v1/instances/me/tenant-links/${c.linkId}`, { token: c.token, body: { product_tenant_id: 'org-default' } });
  },
  instanceHeartbeat: async (env) =>
    env.call('POST', '/v1/instances/me/heartbeat', {
      token: (await connected(env)).token,
      body: { version: '96.2.1', serves_products: ['gauzy'] },
    }),
  getInstanceSelf: async (env) => env.call('GET', '/v1/instances/me', { token: (await connected(env)).token }),
  instancePollEvents: async (env) => env.call('GET', '/v1/instances/me/events?wait=0&limit=10', { token: (await connected(env)).token }),
  instanceAckEvents: async (env) => {
    const c = await connected(env);
    const page = await env.call('GET', '/v1/instances/me/events?wait=0', { token: c.token });
    return env.call('POST', '/v1/instances/me/events/ack', { token: c.token, body: { last_id: page.body.last_id } });
  },
  instanceGetEntitlement: async (env) => env.call('GET', '/v1/instances/me/entitlement', { token: (await connected(env)).token }),
  instanceGetLinkEntitlement: async (env) => {
    const c = await connected(env);
    return env.call('GET', `/v1/instances/me/tenant-links/${c.linkId}/entitlement`, { token: c.token });
  },
  instanceGetIntegrations: async (env) => env.call('GET', '/v1/instances/me/integrations', { token: (await connected(env)).token }),
  instanceGetConsentUrl: async (env) =>
    env.call('GET', '/v1/instances/me/consent-url?integration=stats_link&return=https%3A%2F%2Fgauzy.example.com%2Fback', {
      token: (await connected(env)).token,
    }),
  instanceDisableIntegration: async (env) => {
    const c = await connected(env, { enable: ['stats_link'] });
    return env.call('PUT', '/v1/instances/me/integrations/stats_link', { token: c.token, body: { enabled: false, reason: 'instance' } });
  },
  instanceLinkStats: async (env) => {
    const c = await connected(env, { enable: ['stats_link'] });
    await env.call('POST', '/v1/stats/reports', report());
    return env.call('POST', '/v1/instances/me/stats-link', {
      token: c.token,
      body: signStatsLinkStatement({ statsInstanceId: GOLDEN_ID, iat: env.now() }),
      headers: idem('sl'),
    });
  },
  instancePutLinkIdentifiers: async (env) => {
    const c = await connected(env, { enable: ['counterparty_discoverable'] });
    return env.call('PUT', `/v1/instances/me/tenant-links/${c.linkId}/identifiers`, {
      token: c.token,
      body: { hashes: [{ kind: 'vat', salt_version: 1, hash: 'a'.repeat(64) }] },
    });
  },
  instanceDeleteLinkIdentifiers: async (env) => {
    const c = await connected(env, { enable: ['counterparty_discoverable'] });
    return env.call('DELETE', `/v1/instances/me/tenant-links/${c.linkId}/identifiers`, { token: c.token });
  },
  getLookupSalt: (env) => env.call('GET', '/v1/lookup/salt'),
  getLookupTestVectors: (env) => env.call('GET', '/v1/lookup/test-vectors'),
  lookupCounterparties: async (env) => {
    const c = await connected(env, { enable: ['counterparty_lookup'] });
    const salt = lookupSalt(env);
    const hit = lookupHash(salt.salt, 'vat', 'BG123456789');
    const r = await env.call('POST', '/v1/lookup', {
      token: c.token,
      body: { salt_version: salt.version, hashes: [hit, 'b'.repeat(64)] },
      headers: { 'ever-link-id': c.linkId },
    });
    if (r.body?.matches?.[0]?.handle !== 'acme') throw new Error(`the opt-in was not found: ${r.text}`);
    return r;
  },
  instanceRequestOidcClient: async (env) => {
    const c = await connected(env, { enable: ['ever_id_login'] });
    return env.call('POST', '/v1/instances/me/oidc-client', {
      token: c.token,
      body: { redirect_uri: 'https://gauzy.example.com/cb', logout_uri: 'https://gauzy.example.com/logout' },
      headers: idem('oidc'),
    });
  },
  instanceGetOidcClient: async (env) => {
    const c = await connected(env, { enable: ['ever_id_login'] });
    await env.call('POST', '/v1/instances/me/oidc-client', {
      token: c.token,
      body: { redirect_uri: 'https://gauzy.example.com/cb', logout_uri: 'https://gauzy.example.com/l' },
      headers: idem('o'),
    });
    const ready = await env.call('GET', '/v1/instances/me/oidc-client', { token: c.token });
    const again = await env.call('GET', '/v1/instances/me/oidc-client', { token: c.token });
    if (!ready.body.client_secret || again.body.client_secret) throw new Error('the secret must be answered once');
    return ready;
  },
  instanceMirrorApps: async (env) => {
    const c = await connected(env, { enable: ['app_sync'] });
    return env.call('POST', '/v1/instances/me/mirror/apps', {
      token: c.token,
      body: { ops: [{ op: 'upsert', kind: 'app', external_id: 'w-1', external_version: 1, occurred_at: '2026-11-02T10:00:00Z' }] },
    });
  },
  instanceListMirroredApps: async (env) => {
    const c = await connected(env, { enable: ['app_sync'] });
    return env.call('GET', '/v1/instances/me/mirror/apps?limit=10', { token: c.token });
  },
  instanceDisconnect: async (env) =>
    env.call('POST', '/v1/instances/me/disconnect', { token: (await connected(env)).token, headers: idem('d') }),
  instanceRotateKey: async (env) => {
    const c = await connected(env);
    return env.call('POST', '/v1/instances/me/keys', { token: c.token, body: env.rotation(c.instanceId), headers: idem('k') });
  },
  ingestStatsReport: (env) => env.call('POST', '/v1/stats/reports', report()),
  instancePutPublicUrl: async (env) => {
    const c = await connected(env, { enable: ['instance_url'] });
    return env.call('PUT', '/v1/instances/me/public-url', { token: c.token, body: { base_url: 'https://gauzy.example.com' } });
  },
  instanceDeletePublicUrl: async (env) =>
    env.call('DELETE', '/v1/instances/me/public-url', { token: (await connected(env, { enable: ['instance_url'] })).token }),
  instanceCreatePersonLink: async (env) => {
    const c = await connected(env, { enable: ['ever_id_login'] });
    return env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: {
        product_user_ref: 'user-1',
        identity_issuer: 'https://auth.ever.co',
        identity_subject: '275396402232829475',
        link_method: 'explicit',
      },
      headers: idem('pl'),
    });
  },
  instanceDeletePersonLink: async (env) => {
    const c = await connected(env, { enable: ['ever_id_login'] });
    await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: {
        product_user_ref: 'user-1',
        identity_issuer: 'https://auth.ever.co',
        identity_subject: '275396402232829475',
        link_method: 'explicit',
      },
      headers: idem('pl2'),
    });
    return env.call('DELETE', '/v1/instances/me/person-links/user-1', { token: c.token });
  },
  instanceAckRequest: async (env) => {
    const c = await connected(env);
    const job = await env.admin('person-request', { kind: 'deletion' });
    return env.call('POST', '/v1/instances/me/ack', { token: c.token, body: { job_id: job.job_id, result: 'no_account' } });
  },
  instancePushOrgProfile: async (env) => {
    const c = await connected(env, { enable: ['profile_import'] });
    return env.call('POST', '/v1/instances/me/org-profile', {
      token: c.token,
      body: {
        tenant_link_id: c.linkId,
        consent_id: env.state.instance(c.instanceId).integrations[`profile_import@${c.linkId}`].consent_id,
        fields: { name: 'Acme' },
      },
      headers: idem('op'),
    });
  },
  resolveIdentity: async (env) => {
    const c = await connected(env, { enable: ['ever_id_login'] });
    return env.call('POST', '/v1/identity/resolve', {
      token: c.token,
      body: { issuer: 'https://auth.ever.co', subject: '275396402232829475' },
    });
  },
  getMyContext: async (env) => {
    await connected(env);
    return env.call('GET', '/v1/me/context', { token: await personToken(env) });
  },
  listMyMemberships: async (env) => {
    await connected(env);
    return env.call('GET', '/v1/me/memberships', { token: await personToken(env) });
  },
  discoverSso: (env) => env.call('GET', '/v1/sso/discover?email_domain=acme.example'),
  instanceCreateBillingLink: async (env) => {
    const c = await connected(env, { enable: ['billing_link'] });
    return env.call('POST', '/v1/instances/me/billing-links', {
      token: c.token,
      body: { product_tenant_id: 'tenant-1', customer_ref: 'cus_test_1' },
      headers: { ...idem('bl'), 'ever-link-id': c.linkId },
    });
  },
  completeProvisionIntent: async (env) => {
    const c = await connected(env);
    const { jti } = await env.admin('provision-intent', {});
    return env.call('POST', `/v1/provision-intents/${jti}/complete`, {
      token: c.token,
      body: { instance_id: c.instanceId, product_tenant_id: 'tenant-9', result: 'created' },
    });
  },
  instanceReportUsage: async (env) => {
    const c = await connected(env, { enable: ['usage_reporting'] });
    return env.call('POST', '/v1/instances/me/usage', {
      token: c.token,
      body: { items: [{ meter_key: 'employees.reported', quantity: 3, period: '2026-11' }] },
      headers: { ...idem('u'), 'ever-link-id': c.linkId },
    });
  },
  instanceReportUsageReadings: async (env) => {
    const c = await connected(env, { enable: ['usage_reporting'] });
    return env.call('POST', '/v1/instances/me/usage-readings', {
      token: c.token,
      body: { readings: [{ unit: 'cpu_hour', quantity: 2, observed_at: '2026-11-02T10:00:00Z' }] },
      headers: { ...idem('ur'), 'ever-link-id': c.linkId },
    });
  },
  instanceReportInstallStatus: async (env) => {
    const c = await connected(env, { enable: ['marketplace_installs'] });
    const { install_id } = await env.admin('install', {});
    return env.call('POST', `/v1/installs/${install_id}/status`, { token: c.token, body: { state: 'installing' }, headers: idem('is') });
  },
  connectDevice: (env) =>
    env.call('POST', '/v1/connect/device', {
      body: { product: 'gauzy', version: '1.0.0', install_source: 'self-hosted', public_jwk: jwk(testKey('connect')) },
    }),
  connectDeviceToken: async (env) => {
    const start = await OK.connectDevice(env);
    await env.admin('approve', { user_code: start.body.user_code });
    const kid = instanceKid(testKey('connect').x);
    return env.call('POST', '/v1/connect/token', {
      body: {
        device_code: start.body.device_code,
        client_assertion: env.assertion({ instanceId: kid, audience: `${ISSUER}/v1/connect/token` }),
      },
    });
  },
  instanceCreateWebhook: async (env) => {
    const c = await connected(env, { enable: ['webhooks'] });
    return env.call('POST', '/v1/instances/me/webhooks', {
      token: c.token,
      body: { url: 'https://gauzy.example.com/wh', event_filter: ['ever.consent.*'] },
      headers: idem('w'),
    });
  },
  updateWebhook: async (env) => {
    const w = await webhook(env);
    return env.call('PATCH', `/v1/webhooks/${w.webhookId}`, { token: w.token, body: { event_filter: ['ever.entitlements.*'] } });
  },
  deleteWebhook: async (env) => {
    const w = await webhook(env);
    return env.call('DELETE', `/v1/webhooks/${w.webhookId}`, { token: w.token });
  },
  rotateWebhookSecret: async (env) => {
    const w = await webhook(env);
    return env.call('POST', `/v1/webhooks/${w.webhookId}/rotate-secret`, { token: w.token, headers: idem('rs') });
  },
  testWebhook: async (env) => {
    const w = await webhook(env);
    return env.call('POST', `/v1/webhooks/${w.webhookId}/test`, {
      token: w.token,
      body: { event_type: 'ever.system.webhook.test' },
      headers: idem('t'),
    });
  },
  listWebhookDeliveries: async (env) => {
    const w = await webhook(env);
    return env.call('GET', `/v1/webhooks/${w.webhookId}/deliveries`, { token: w.token });
  },
  redeliverWebhook: async (env) => {
    const w = await webhook(env);
    const { delivery_id } = await env.admin('webhook-delivery', { webhook_id: w.webhookId, state: 'failed' });
    return env.call('POST', `/v1/deliveries/${delivery_id}/redeliver`, { token: w.token, headers: idem('rd') });
  },
  instanceAcceptIntegration: async (env) => {
    const c = await connected(env);
    const { consent_id } = await env.admin('consent', { integration: 'stats_link', operator_accept: 'pending' });
    return env.call('POST', '/v1/instances/me/integrations/stats_link/accept', { token: c.token, body: { consent_id, accepted: true } });
  },
  instanceGetProviderGrant: async (env) => {
    const c = await connected(env, { enable: ['provider_access'] });
    const { grant_id } = await env.admin('provider-grant', {});
    return env.call('GET', `/v1/instances/me/provider-grants/${grant_id}`, { token: c.token });
  },
  instanceReportProviderGrantStatus: async (env) => {
    const c = await connected(env, { enable: ['provider_access'] });
    const { grant_id } = await env.admin('provider-grant', {});
    return env.call('POST', `/v1/instances/me/provider-grants/${grant_id}/status`, {
      token: c.token,
      body: { grant_id, status: 'accepted', product_user_ref: 'user-2' },
    });
  },
  putIntegrationState: async (env) => {
    const c = await connected(env);
    const r = await putState(
      env,
      c,
      'counterparty_lookup',
      await personToken(env, { auth_age_s: 300 }),
      grant({ tenant_link_id: c.linkId }),
    );
    if (r.body?.consent_source !== 'product_ui') throw new Error(`not a product_ui consent: ${r.text}`);
    return r;
  },
  instanceReportManagedOperationResult: async (env) => {
    const m = await managedRequest(env);
    return env.call('POST', `/v1/instances/me/managed-operations/${m.operationId}/result`, {
      token: m.token,
      body: { status: 'succeeded', size_bytes: 1024 },
    });
  },
};

// ---------------------------------------------------------------------------------------- errors
const disabledFor = (call) => async (env) => call(env, await connected(env));
const revokedFor = (integration, call) => async (env) => call(env, await revoked(env, integration));

const calls = {
  statsLink: (env, c) =>
    env.call('POST', '/v1/instances/me/stats-link', {
      token: c.token,
      body: signStatsLinkStatement({ statsInstanceId: GOLDEN_ID, iat: env.now() }),
      headers: idem('x'),
    }),
  identifiers: (env, c) =>
    env.call('PUT', `/v1/instances/me/tenant-links/${c.linkId}/identifiers`, { token: c.token, body: { hashes: [] } }),
  lookup: (env, c) =>
    env.call('POST', '/v1/lookup', {
      token: c.token,
      body: { salt_version: 1, hashes: ['c'.repeat(64)] },
      headers: { 'ever-link-id': c.linkId },
    }),
  oidc: (env, c) =>
    env.call('POST', '/v1/instances/me/oidc-client', {
      token: c.token,
      body: { redirect_uri: 'https://g.example.com/cb', logout_uri: 'https://g.example.com/l' },
      headers: idem('o'),
    }),
  mirror: (env, c) =>
    env.call('POST', '/v1/instances/me/mirror/apps', {
      token: c.token,
      body: { ops: [{ op: 'upsert', kind: 'app', external_id: 'w', external_version: 1, occurred_at: '2026-11-02T10:00:00Z' }] },
    }),
  publicUrl: (env, c) => env.call('PUT', '/v1/instances/me/public-url', { token: c.token, body: { base_url: 'https://g.example.com' } }),
  personLink: (env, c) =>
    env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { product_user_ref: 'u', identity_issuer: 'https://auth.ever.co', identity_subject: '1', link_method: 'explicit' },
      headers: idem('p'),
    }),
  orgProfile: (env, c) =>
    env.call('POST', '/v1/instances/me/org-profile', {
      token: c.token,
      body: { tenant_link_id: c.linkId, consent_id: '01JMQCK0RG000000000000000C', fields: {} },
      headers: idem('op'),
    }),
  resolve: (env, c) =>
    env.call('POST', '/v1/identity/resolve', { token: c.token, body: { issuer: 'https://auth.ever.co', subject: '275396402232829475' } }),
  billing: (env, c) =>
    env.call('POST', '/v1/instances/me/billing-links', {
      token: c.token,
      body: { product_tenant_id: 't', customer_ref: 'cus_1' },
      headers: { ...idem('b'), 'ever-link-id': c.linkId },
    }),
  usage: (env, c) =>
    env.call('POST', '/v1/instances/me/usage', {
      token: c.token,
      body: { items: [{ meter_key: 'members', quantity: 1, period: '2026-11' }] },
      headers: { ...idem('u'), 'ever-link-id': c.linkId },
    }),
  install: async (env, c) => {
    const { install_id } = await env.admin('install', {});
    return env.call('POST', `/v1/installs/${install_id}/status`, { token: c.token, body: { state: 'installing' }, headers: idem('i') });
  },
  webhookCreate: (env, c) =>
    env.call('POST', '/v1/instances/me/webhooks', {
      token: c.token,
      body: { url: 'https://g.example.com/wh', event_filter: ['ever.consent.*'] },
      headers: idem('w'),
    }),
  grant: async (env, c) => {
    const { grant_id } = await env.admin('provider-grant', {});
    return env.call('GET', `/v1/instances/me/provider-grants/${grant_id}`, { token: c.token });
  },
  managed: async (env, c) =>
    env.call('POST', '/v1/instances/me/managed-operations/01JMQCK0RG000000000000000D/result', {
      token: c.token,
      body: { status: 'running' },
    }),
};

const integrationPairs = (row, integration, call) => ({
  [`${row}:403:integration_disabled`]: disabledFor(call),
  [`${row}:403:integration_revoked`]: revokedFor(integration, call),
});

export const ERRORS = {
  '1:503:keys_unavailable': async (env) => {
    await env.admin('faults', { keys_unavailable: true });
    return env.call('GET', '/.well-known/ever-keys.json');
  },
  '3:404:not_found': async (env) => {
    // A deployment with issuance off answers a well-formed redeem 404 (a malformed one stays 422).
    await env.admin('faults', { connect_issuance_off: true });
    return env.call('POST', '/v1/connect/redeem', { body: redeemBody('EVC-TEST-0000-0001'), headers: idem('off') });
  },
  '3:409:already_connected': async (env) => {
    await env.connect();
    await env.admin('codes', { code: 'EVC-TEST-0000-0007', product: 'gauzy' });
    return env.call('POST', '/v1/connect/redeem', { body: redeemBody('EVC-TEST-0000-0007', testKey('connect')), headers: idem('ac') });
  },
  '3:422:validation_failed': (env) =>
    env.call('POST', '/v1/connect/redeem', {
      body: { ...redeemBody('EVC-TEST-0000-0001'), public_url: 'https://g.example.com' },
      headers: idem('v'),
    }),
  '3:422:code_invalid': (env) => env.call('POST', '/v1/connect/redeem', { body: redeemBody('EVC-AAAA-BBBB-CCCC'), headers: idem('ci') }),
  '3:422:product_mismatch': (env) =>
    env.call('POST', '/v1/connect/redeem', {
      body: redeemBody('EVC-TEST-0000-0001', testKey('connectNext'), 'works'),
      headers: idem('pm'),
    }),
  '3:422:product_not_supported': (env) =>
    env.call('POST', '/v1/connect/redeem', {
      body: redeemBody('EVC-TEST-0000-0001', testKey('connectNext'), 'demand'),
      headers: idem('pn'),
    }),
  '3:422:public_jwk_invalid': (env) =>
    env.call('POST', '/v1/connect/redeem', {
      body: { ...redeemBody('EVC-TEST-0000-0001'), public_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'short' } },
      headers: idem('pj'),
    }),
  '3:429:rate_limited': async (env) => {
    let r;
    for (let i = 0; i < 11; i += 1)
      r = await env.call('POST', '/v1/connect/redeem', {
        body: redeemBody(`EVC-AAAA-BBBB-${String(i).padStart(4, '0')}`),
        headers: idem(`rl${i}`),
      });
    return r;
  },
  '4:401:invalid_client': async (env) => {
    await env.connect();
    return env.call('POST', '/v1/instances/token', {
      body: {
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: env.assertion({ instanceId: GOLDEN_ID }),
      },
    });
  },
  '4:401:credential_revoked': async (env) => {
    const c = await env.connect();
    await env.admin('revoke-instance', {});
    return env.call('POST', '/v1/instances/token', {
      body: {
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: env.assertion({ instanceId: c.instanceId }),
      },
    });
  },
  '4:429:rate_limited': async (env) => {
    // The redeem's token is the first of the hour; the 61st answers 429 with Retry-After.
    const c = await env.connect();
    let r;
    for (let i = 0; i < 60; i += 1)
      r = await env.call('POST', '/v1/instances/token', {
        body: {
          grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: env.assertion({ instanceId: c.instanceId }),
        },
      });
    return r;
  },
  '4:422:validation_failed': (env) =>
    env.call('POST', '/v1/instances/token', {
      body: {
        grant_type: 'password',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: 'not.a.jws',
      },
    }),
  '5:401:credential_revoked': async (env) => {
    const c = await connected(env);
    await env.admin('revoke-instance', {});
    return env.call('POST', '/v1/instances/me/tenant-links', {
      token: c.token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 't2' },
      headers: idem('cr'),
    });
  },
  '5:403:instance_pending_approval': async (env) => {
    const c = await connected(env, { code: 'EVC-TEST-0000-0003' });
    return env.call('POST', '/v1/instances/me/tenant-links', {
      token: c.token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 't2' },
      headers: idem('pa'),
    });
  },
  '5:404:not_found': async (env) =>
    env.call('DELETE', '/v1/instances/me/tenant-links/01JMQCK0RG000000000000000E', { token: (await connected(env)).token }),
  '5:409:already_linked': async (env) => {
    const c = await connected(env);
    return env.call('POST', '/v1/instances/me/tenant-links', {
      token: c.token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-1', product_org_id: 'org-1' },
      headers: idem('al'),
    });
  },
  '5:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/tenant-links', {
      token: (await connected(env)).token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy' },
      headers: idem('lv'),
    }),
  '5:422:code_invalid': async (env) =>
    env.call('POST', '/v1/instances/me/tenant-links', {
      token: (await connected(env)).token,
      body: { link_code: 'EVL-ZZZZ-ZZZZ-ZZZZ', product: 'gauzy', product_tenant_id: 't' },
      headers: idem('lc'),
    }),
  '5:422:product_mismatch': async (env) =>
    env.call('POST', '/v1/instances/me/tenant-links', {
      token: (await connected(env)).token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'works', product_tenant_id: 't' },
      headers: idem('lpm'),
    }),
  '5:429:rate_limited': async (env) => {
    const { token } = await connected(env);
    let r;
    for (let i = 0; i < 11; i += 1)
      r = await env.call('POST', '/v1/instances/me/tenant-links', {
        token,
        body: { link_code: `EVL-AAAA-BBBB-${String(i).padStart(4, '0')}`, product: 'gauzy', product_tenant_id: 't' },
        headers: idem(`lrl${i}`),
      });
    return r;
  },
  '6:401:credential_revoked': async (env) => {
    const c = await connected(env);
    await env.call('POST', '/v1/instances/me/disconnect', { token: c.token, headers: idem('dc') });
    return env.call('GET', '/v1/instances/me', { token: c.token });
  },
  '6:403:instance_pending_approval': async (env) =>
    env.call('POST', '/v1/instances/me/heartbeat', {
      token: (await connected(env, { code: 'EVC-TEST-0000-0003' })).token,
      body: { version: '1.0.0' },
    }),
  '6:403:instance_disconnected': async (env) => {
    const c = await connected(env);
    await env.admin('disconnect', {});
    return env.call('POST', '/v1/instances/me/heartbeat', { token: c.token, body: { version: '1.0.0' } });
  },
  '6:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/heartbeat', { token: (await connected(env)).token, body: { version: '1.0.0', hostname: 'h' } }),
  '6:429:rate_limited': async (env) => {
    const c = await connected(env);
    await env.call('POST', '/v1/instances/me/heartbeat', { token: c.token, body: { version: '1.0.0' } });
    return env.call('POST', '/v1/instances/me/heartbeat', { token: c.token, body: { version: '1.0.0' } });
  },
  '7:410:resync_required': async (env) =>
    env.call('GET', '/v1/instances/me/events?after=01JMQCK0RG000000000000000F&wait=0', { token: (await connected(env)).token }),
  '7:422:validation_failed': async (env) => env.call('GET', '/v1/instances/me/events?wait=60', { token: (await connected(env)).token }),
  '8:404:not_found': async (env) =>
    env.call('GET', '/v1/instances/me/tenant-links/01JMQCK0RG000000000000000G/entitlement', { token: (await connected(env)).token }),
  '8:429:rate_limited': async (env) => {
    const c = await connected(env);
    let r;
    for (let i = 0; i < 7; i += 1) r = await env.call('GET', '/v1/instances/me/entitlement', { token: c.token });
    return r;
  },
  '9:422:validation_failed': async (env) =>
    env.call('GET', '/v1/instances/me/consent-url?integration=stats_link', { token: (await connected(env)).token }),
  '10:404:not_found': async (env) =>
    env.call('PUT', '/v1/instances/me/integrations/unknown_key', {
      token: (await connected(env)).token,
      body: { enabled: false, reason: 'instance' },
    }),
  '10:422:validation_failed': async (env) =>
    env.call('PUT', '/v1/instances/me/integrations/stats_link', {
      token: (await connected(env)).token,
      body: { enabled: true, reason: 'instance' },
    }),
  ...integrationPairs(11, 'stats_link', calls.statsLink),
  '11:409:key_mismatch': async (env) => calls.statsLink(env, await connected(env, { enable: ['stats_link'] })),
  '11:409:already_linked': async (env) => {
    const first = await connected(env, { enable: ['stats_link'] });
    await env.call('POST', '/v1/stats/reports', report());
    await calls.statsLink(env, first);
    const second = await env.connect({ code: 'EVC-TEST-0000-0004', product: 'works', key: testKey('connectNext') });
    await env.admin('consent', { integration: 'stats_link' });
    return env.call('POST', '/v1/instances/me/stats-link', {
      token: second.token,
      body: signStatsLinkStatement({ statsInstanceId: GOLDEN_ID, iat: env.now() }),
      headers: idem('second'),
    });
  },
  '11:422:validation_failed': async (env) => {
    const c = await connected(env, { enable: ['stats_link'] });
    await env.call('POST', '/v1/stats/reports', report());
    return env.call('POST', '/v1/instances/me/stats-link', {
      token: c.token,
      body: signStatsLinkStatement({ statsInstanceId: GOLDEN_ID, iat: env.now() - 3600 }),
      headers: idem('old'),
    });
  },
  ...integrationPairs(12, 'counterparty_discoverable', calls.identifiers),
  '12:409:identifier_claimed': async (env) => {
    env.state.config.lookup.claimed_hashes = ['d'.repeat(64)];
    const c = await connected(env, { enable: ['counterparty_discoverable'] });
    return env.call('PUT', `/v1/instances/me/tenant-links/${c.linkId}/identifiers`, {
      token: c.token,
      body: { hashes: [{ kind: 'vat', salt_version: 1, hash: 'd'.repeat(64) }] },
    });
  },
  '13:401:credential_revoked': async (env) => {
    const c = await connected(env, { enable: ['counterparty_lookup'] });
    await env.admin('revoke-instance', {});
    return calls.lookup(env, c);
  },
  ...integrationPairs(13, 'counterparty_lookup', calls.lookup),
  '13:403:entitlement_required': async (env) => {
    env.state.config.entitlement.features.lookup = false;
    return calls.lookup(env, await connected(env, { enable: ['counterparty_lookup'] }));
  },
  '13:422:salt_version_unknown': async (env) => {
    const c = await connected(env, { enable: ['counterparty_lookup'] });
    return env.call('POST', '/v1/lookup', {
      token: c.token,
      body: { salt_version: 9, hashes: ['c'.repeat(64)] },
      headers: { 'ever-link-id': c.linkId },
    });
  },
  '13:422:salt_version_retired': async (env) => {
    env.state.config.lookup.retired_versions = [2];
    const c = await connected(env, { enable: ['counterparty_lookup'] });
    return env.call('POST', '/v1/lookup', {
      token: c.token,
      body: { salt_version: 2, hashes: ['c'.repeat(64)] },
      headers: { 'ever-link-id': c.linkId },
    });
  },
  '13:422:hashes_invalid': async (env) => {
    const c = await connected(env, { enable: ['counterparty_lookup'] });
    return env.call('POST', '/v1/lookup', {
      token: c.token,
      body: { salt_version: 1, hashes: ['c'.repeat(64), 'c'.repeat(64)] },
      headers: { 'ever-link-id': c.linkId },
    });
  },
  '13:429:rate_limited': async (env) => {
    const c = await connected(env, { enable: ['counterparty_lookup'] });
    let r;
    for (let i = 0; i < 61; i += 1) r = await calls.lookup(env, c);
    return r;
  },
  ...integrationPairs(14, 'ever_id_login', calls.oidc),
  '14:404:not_found': async (env) =>
    env.call('GET', '/v1/instances/me/oidc-client', { token: (await connected(env, { enable: ['ever_id_login'] })).token }),
  '14:409:already_exists': async (env) => {
    const c = await connected(env, { enable: ['ever_id_login'] });
    await calls.oidc(env, c);
    return env.call('POST', '/v1/instances/me/oidc-client', {
      token: c.token,
      body: { redirect_uri: 'https://g.example.com/cb', logout_uri: 'https://g.example.com/l' },
      headers: idem('o2'),
    });
  },
  ...integrationPairs(15, 'app_sync', calls.mirror),
  '15:413:payload_too_large': async (env) => {
    const c = await connected(env, { enable: ['app_sync'] });
    return env.call('POST', '/v1/instances/me/mirror/apps', { token: c.token, raw: `{"ops":[${'"x",'.repeat(1100000)}"x"]}` });
  },
  '16:401:credential_revoked': async (env) => {
    const c = await connected(env);
    await env.call('POST', '/v1/instances/me/disconnect', { token: c.token, headers: idem('d1') });
    return env.call('POST', '/v1/instances/me/disconnect', { token: c.token, headers: idem('d2') });
  },
  '16:403:instance_pending_approval': async (env) =>
    env.call('POST', '/v1/instances/me/disconnect', {
      token: (await connected(env, { code: 'EVC-TEST-0000-0003' })).token,
      headers: idem('dp'),
    }),
  '16:401:invalid_client': async (env) => {
    // An instance token alone never rotates a key: the current key's proof signed with the new key.
    const c = await connected(env);
    return env.call('POST', '/v1/instances/me/keys', {
      token: c.token,
      body: env.rotation(c.instanceId, { signers: [testKey('connectNext'), testKey('connectNext')] }),
      headers: idem('ki'),
    });
  },
  '16:422:public_jwk_invalid': async (env) => {
    // Two valid proofs for the current key itself: a rotation needs a key no installation holds.
    const c = await connected(env);
    return env.call('POST', '/v1/instances/me/keys', {
      token: c.token,
      body: env.rotation(c.instanceId, { next: testKey('connect') }),
      headers: idem('kj'),
    });
  },
  '16:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/keys', {
      token: (await connected(env)).token,
      body: { public_jwk: jwk(testKey('connectNext')) },
      headers: idem('kv'),
    }),
  // No statistics key: the key is checked first (a missing signature is signature_invalid).
  '17:400:validation_failed': (env) =>
    env.call('POST', '/v1/stats/reports', { raw: GOLDEN, headers: { 'ever-stats-signature': report().headers['ever-stats-signature'] } }),
  '17:400:signature_invalid': (env) => env.call('POST', '/v1/stats/reports', { raw: GOLDEN, headers: report(Buffer.from('{}')).headers }),
  '17:409:key_mismatch': async (env) => {
    await env.call('POST', '/v1/stats/reports', report());
    return env.call('POST', '/v1/stats/reports', report(GOLDEN, testKey('statsOther')));
  },
  '17:413:validation_failed': (env) => env.call('POST', '/v1/stats/reports', report(fixture('stats/invalid/07-oversize.json'))),
  '17:415:unsupported_media_type': (env) => env.call('POST', '/v1/stats/reports', { ...report(), contentType: 'text/plain' }),
  '17:422:schema_violation': (env) => env.call('POST', '/v1/stats/reports', report(fixture('stats/invalid/01-extra-field.json'))),
  '17:429:rate_limited': async (env) => {
    let r;
    for (let i = 0; i < 25; i += 1) r = await env.call('POST', '/v1/stats/reports', report());
    return r;
  },
  ...integrationPairs(18, 'instance_url', calls.publicUrl),
  '18:422:validation_failed': async (env) =>
    env.call('PUT', '/v1/instances/me/public-url', {
      token: (await connected(env, { enable: ['instance_url'] })).token,
      body: { base_url: 'http://g.example.com' },
    }),
  ...integrationPairs(19, 'ever_id_login', calls.personLink),
  '19:404:not_found': async (env) =>
    env.call('DELETE', '/v1/instances/me/person-links/nobody', { token: (await connected(env, { enable: ['ever_id_login'] })).token }),
  '19:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/person-links', {
      token: (await connected(env, { enable: ['ever_id_login'] })).token,
      body: {
        product_user_ref: 'u',
        identity_issuer: 'https://auth.ever.co',
        identity_subject: '1',
        link_method: 'explicit',
        email: 'jane@example.com',
      },
      headers: idem('pe'),
    }),
  '20:404:not_found': async (env) =>
    env.call('POST', '/v1/instances/me/ack', {
      token: (await connected(env)).token,
      body: { job_id: '01JMQCK0RG000000000000000H', result: 'deleted' },
    }),
  '20:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/ack', {
      token: (await connected(env)).token,
      body: { job_id: '01JMQCK0RG000000000000000H', result: 'ignored' },
    }),
  ...integrationPairs(21, 'profile_import', calls.orgProfile),
  '21:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/org-profile', {
      token: (await connected(env, { enable: ['profile_import'] })).token,
      body: { fields: { email: 'x@example.com' } },
      headers: idem('ov'),
    }),
  ...integrationPairs(22, 'ever_id_login', calls.resolve),
  '22:404:not_found': async (env) =>
    env.call('POST', '/v1/identity/resolve', {
      token: (await connected(env, { enable: ['ever_id_login'] })).token,
      body: { issuer: 'https://auth.ever.co', subject: 'nobody' },
    }),
  '23:401:unauthorized': (env) => env.call('GET', '/v1/me/context'),
  '24:422:validation_failed': (env) => env.call('GET', '/v1/sso/discover?email_domain=jane%40acme.example'),
  '24:429:rate_limited': async (env) => {
    let r;
    for (let i = 0; i < 61; i += 1) r = await env.call('GET', '/v1/sso/discover?email_domain=acme.example');
    return r;
  },
  ...integrationPairs(25, 'billing_link', calls.billing),
  '25:422:validation_failed': async (env) => {
    const c = await connected(env, { enable: ['billing_link'] });
    return env.call('POST', '/v1/instances/me/billing-links', {
      token: c.token,
      body: { product_tenant_id: 't' },
      headers: { ...idem('bv'), 'ever-link-id': c.linkId },
    });
  },
  '26:404:not_found': async (env) =>
    env.call('POST', '/v1/provision-intents/01JMQCK0RG000000000000000J/complete', {
      token: (await connected(env)).token,
      body: { instance_id: '01JMQCK0RG000000000000000K', product_tenant_id: 't', result: 'created' },
    }),
  '26:409:illegal_transition': async (env) => {
    const c = await connected(env);
    const { jti } = await env.admin('provision-intent', {});
    await env.call('POST', `/v1/provision-intents/${jti}/complete`, {
      token: c.token,
      body: { instance_id: c.instanceId, product_tenant_id: 't', result: 'created' },
    });
    return env.call('POST', `/v1/provision-intents/${jti}/complete`, {
      token: c.token,
      body: { instance_id: c.instanceId, product_tenant_id: 't', result: 'refused' },
    });
  },
  '26:410:gone': async (env) => {
    const c = await connected(env);
    const { jti } = await env.admin('provision-intent', { expires_in_s: 60 });
    await env.admin('clock', { advance: 120 });
    return env.call('POST', `/v1/provision-intents/${jti}/complete`, {
      token: c.token,
      body: { instance_id: c.instanceId, product_tenant_id: 't', result: 'created' },
    });
  },
  '26:422:validation_failed': async (env) => {
    const c = await connected(env);
    const { jti } = await env.admin('provision-intent', {});
    return env.call('POST', `/v1/provision-intents/${jti}/complete`, {
      token: c.token,
      body: { instance_id: c.instanceId, result: 'created' },
    });
  },
  ...integrationPairs(27, 'usage_reporting', calls.usage),
  '27:422:validation_failed': async (env) => {
    const c = await connected(env, { enable: ['usage_reporting'] });
    return env.call('POST', '/v1/instances/me/usage', {
      token: c.token,
      body: { items: [] },
      headers: { ...idem('uv'), 'ever-link-id': c.linkId },
    });
  },
  ...integrationPairs(28, 'marketplace_installs', calls.install),
  '28:404:not_found': async (env) =>
    env.call('POST', '/v1/installs/01JMQCK0RG000000000000000M/status', {
      token: (await connected(env, { enable: ['marketplace_installs'] })).token,
      body: { state: 'installing' },
      headers: idem('in'),
    }),
  '28:409:illegal_transition': async (env) => {
    const c = await connected(env, { enable: ['marketplace_installs'] });
    const { install_id } = await env.admin('install', { state: 'removed' });
    return env.call('POST', `/v1/installs/${install_id}/status`, { token: c.token, body: { state: 'installing' }, headers: idem('it') });
  },
  '29:400:authorization_pending': async (env) => {
    const start = await OK.connectDevice(env);
    return env.call('POST', '/v1/connect/token', { body: { device_code: start.body.device_code, client_assertion: 'a.b.c' } });
  },
  '29:400:slow_down': async (env) => {
    const start = await OK.connectDevice(env);
    await env.call('POST', '/v1/connect/token', { body: { device_code: start.body.device_code, client_assertion: 'a.b.c' } });
    return env.call('POST', '/v1/connect/token', { body: { device_code: start.body.device_code, client_assertion: 'a.b.c' } });
  },
  '29:400:expired_token': (env) =>
    env.call('POST', '/v1/connect/token', { body: { device_code: 'unknown-device-code', client_assertion: 'a.b.c' } }),
  '29:409:key_mismatch': async (env) => {
    const start = await OK.connectDevice(env);
    await env.admin('approve', { user_code: start.body.user_code });
    const kid = instanceKid(testKey('connect').x);
    return env.call('POST', '/v1/connect/token', {
      body: {
        device_code: start.body.device_code,
        client_assertion: env.assertion({ key: testKey('stranger'), instanceId: kid, audience: `${ISSUER}/v1/connect/token` }),
      },
    });
  },
  '29:422:validation_failed': (env) =>
    env.call('POST', '/v1/connect/device', { body: { product: 'gauzy', version: '1.0.0', public_jwk: jwk(testKey('connect')) } }),
  '29:422:product_not_supported': (env) =>
    env.call('POST', '/v1/connect/device', {
      body: { product: 'demand', version: '1.0.0', install_source: 'self-hosted', public_jwk: jwk(testKey('connect')) },
    }),
  '29:429:rate_limited': async (env) => {
    let r;
    for (let i = 0; i < 11; i += 1) r = await OK.connectDevice(env);
    return r;
  },
  ...integrationPairs(30, 'webhooks', calls.webhookCreate),
  '30:404:module_disabled': async (env) => {
    const c = await connected(env, { enable: ['webhooks'] });
    await env.admin('faults', { webhooks_module_disabled: true });
    return calls.webhookCreate(env, c);
  },
  '30:409:illegal_transition': async (env) => {
    const w = await webhook(env);
    const { delivery_id } = await env.admin('webhook-delivery', { webhook_id: w.webhookId, state: 'delivered' });
    return env.call('POST', `/v1/deliveries/${delivery_id}/redeliver`, { token: w.token, headers: idem('r') });
  },
  '30:422:validation_failed': async (env) =>
    env.call('POST', '/v1/instances/me/webhooks', {
      token: (await connected(env, { enable: ['webhooks'] })).token,
      body: { url: 'http://g.example.com/wh', event_filter: ['ever.consent.*'] },
      headers: idem('wv'),
    }),
  '30:422:limit_exceeded': async (env) => {
    const c = await connected(env, { enable: ['webhooks'] });
    let r;
    for (let i = 0; i < 6; i += 1)
      r = await env.call('POST', '/v1/instances/me/webhooks', {
        token: c.token,
        body: { url: `https://g.example.com/wh${i}`, event_filter: ['ever.consent.*'] },
        headers: idem(`wl${i}`),
      });
    return r;
  },
  '31:404:not_found': async (env) =>
    env.call('POST', '/v1/instances/me/integrations/no_such_key/accept', {
      token: (await connected(env)).token,
      body: { consent_id: '01JMQCK0RG000000000000000N', accepted: true },
    }),
  '31:409:illegal_transition': async (env) =>
    env.call('POST', '/v1/instances/me/integrations/stats_link/accept', {
      token: (await connected(env)).token,
      body: { consent_id: '01JMQCK0RG000000000000000N', accepted: true },
    }),
  ...integrationPairs(32, 'provider_access', calls.grant),
  '32:409:illegal_transition': async (env) => {
    const c = await connected(env, { enable: ['provider_access'] });
    const { grant_id } = await env.admin('provider-grant', { status: 'invited' });
    return env.call('GET', `/v1/instances/me/provider-grants/${grant_id}`, { token: c.token });
  },
  '33:403:step_up_required': async (env) => {
    const c = await connected(env);
    return putState(env, c, 'counterparty_lookup', await personToken(env, { auth_age_s: 301 }), grant({ tenant_link_id: c.linkId }));
  },
  '33:403:session_required': async (env) => {
    const c = await connected(env);
    return putState(env, c, 'instance_url', await personToken(env, {}), grant());
  },
  '33:403:forbidden_role': async (env) => {
    const c = await connected(env);
    return putState(env, c, 'counterparty_lookup', await personToken(env, { role: 'member' }), grant({ tenant_link_id: c.linkId }));
  },
  '33:403:not_connection_owner': async (env) => {
    const c = await connected(env);
    const link = await env.call('POST', '/v1/instances/me/tenant-links', {
      token: c.token,
      body: { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-2' },
      headers: idem('nl'),
    });
    const token = await personToken(env, {});
    return env.call('PUT', `/v1/orgs/${link.body.org_id}/instances/${c.instanceId}/integrations/stats_link`, {
      token,
      body: grant(),
      headers: idem('nco'),
    });
  },
  '33:404:not_found': async (env) => {
    const c = await connected(env);
    return env.call(
      'PUT',
      `/v1/orgs/${env.state.instance(c.instanceId).org.id}/instances/01JMQCK0RG000000000000000P/integrations/stats_link`,
      { token: await personToken(env, {}), body: grant(), headers: idem('nf') },
    );
  },
  '33:422:validation_failed': async (env) => {
    const c = await connected(env);
    return putState(env, c, 'counterparty_lookup', await personToken(env, {}), {
      enabled: true,
      consent: { scope_version: 1, dpa_version: '2026-10', accepted: false },
    });
  },
  '33:422:scope_version_outdated': async (env) => {
    const c = await connected(env);
    return putState(
      env,
      c,
      'counterparty_lookup',
      await personToken(env, {}),
      grant({ tenant_link_id: c.linkId, consent: { scope_version: 0, dpa_version: '2026-10', accepted: true } }),
    );
  },
  ...integrationPairs(34, 'managed_operations', calls.managed),
  '34:404:not_found': async (env) => calls.managed(env, await connected(env, { enable: ['managed_operations'] })),
  '34:409:illegal_transition': async (env) => {
    const m = await managedRequest(env, { expires_in_s: 60 });
    await env.admin('clock', { advance: 120 });
    return env.call('POST', `/v1/instances/me/managed-operations/${m.operationId}/result`, {
      token: m.token,
      body: { status: 'succeeded' },
    });
  },
  '34:422:validation_failed': async (env) => {
    const m = await managedRequest(env);
    return env.call('POST', `/v1/instances/me/managed-operations/${m.operationId}/result`, {
      token: m.token,
      body: { status: 'succeeded', file_name: 'backup.tar' },
    });
  },
};
