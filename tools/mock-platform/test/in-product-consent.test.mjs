// Scenario in-product-consent: the consent write a product sends from its own dialog after a
// fresh Ever ID sign-in through its own client. 300 s is fresh, 301 s is not; the two keys that
// are enabled in app.ever.co only refuse it; an installation-wide key waits for the operator.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { validateSchema } from '../src/validate.mjs';
import { expectOk, expectProblem, startMock } from './helpers.mjs';

const REPO = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');
const grantFixture = JSON.parse(readFileSync(join(REPO, 'contracts/fixtures/requests/integration-put.product-ui.json'), 'utf8'));

let env;
afterEach(async () => {
  await env?.close();
  env = null;
});

async function setup() {
  env = await startMock();
  const c = await env.connect();
  const org = env.state.instance(c.instanceId).org.id;
  const put = async (key, tokenBody, body) => {
    const { token } = await env.admin('person-token', tokenBody);
    return env.call('PUT', `/v1/orgs/${org}/instances/${c.instanceId}/integrations/${key}`, {
      token,
      body,
      headers: { 'idempotency-key': `${key}-${Math.random()}` },
    });
  };
  return { ...c, org, put };
}

const body = (linkId) => ({ ...grantFixture, tenant_link_id: linkId });
// An installation-wide key takes no tenant link.
const wide = () => Object.fromEntries(Object.entries(grantFixture).filter(([k]) => k !== 'tenant_link_id'));

describe('scenario in-product-consent', () => {
  it('a sign-in 300 s old records a product_ui consent and enables the integration', async () => {
    const s = await setup();
    const r = await s.put('usage_reporting', { auth_age_s: 300 }, body(s.linkId));
    expectOk(expect, r, 200, 'putIntegrationState');
    expect(r.body.consent_source).toBe('product_ui');
    expect(r.body.state).toBe('enabled');
    const states = await env.call('GET', '/v1/instances/me/integrations', { token: s.token });
    expect(states.body.links[s.linkId].usage_reporting.state).toBe('enabled');
    const feed = await env.call('GET', '/v1/instances/me/events?wait=0', { token: s.token });
    expect(feed.body.events.map((e) => e.type)).toEqual(
      expect.arrayContaining(['ever.consent.consent.granted', 'ever.consent.integration.enabled']),
    );
    const granted = feed.body.events.find((e) => e.type === 'ever.consent.consent.granted');
    expect(granted.data.consent_source).toBe('product_ui');
  });

  it('a sign-in 301 s old is step_up_required', async () => {
    const s = await setup();
    expectProblem(expect, await s.put('usage_reporting', { auth_age_s: 301 }, body(s.linkId)), 403, 'step_up_required');
  });

  it('counterparty_discoverable and instance_url refuse the in-product consent', async () => {
    const s = await setup();
    expectProblem(expect, await s.put('counterparty_discoverable', { auth_age_s: 10 }, body(s.linkId)), 403, 'session_required');
    expectProblem(expect, await s.put('instance_url', { auth_age_s: 10 }, wide()), 403, 'session_required');
  });

  it('a token of another client, or a member, is refused', async () => {
    const s = await setup();
    expectProblem(
      expect,
      await s.put('usage_reporting', { auth_age_s: 10, azp: 'inst-01JMQCK0RG000000000000000Q' }, body(s.linkId)),
      403,
      'session_required',
    );
    expectProblem(expect, await s.put('usage_reporting', { auth_age_s: 10, role: 'member' }, body(s.linkId)), 403, 'forbidden_role');
  });

  it('an installation-wide key waits for the operator, who accepts it locally', async () => {
    const s = await setup();
    const r = await s.put('stats_link', { auth_age_s: 5 }, wide());
    expect(r.status).toBe(200);
    expect(r.body.enabled).toBe(false);
    const consentId = env.state.instance(s.instanceId).integrations.stats_link.consent_id;
    const accepted = await env.call('POST', '/v1/instances/me/integrations/stats_link/accept', {
      token: s.token,
      body: { consent_id: consentId, accepted: true },
      headers: { 'idempotency-key': 'accept-1' },
    });
    expect(accepted.status).toBe(200);
    expect(accepted.body.state).toBe('enabled');
  });

  it('options, a coming-soon integration, missing terms and the operator deny are refused', async () => {
    const s = await setup();
    const withConfig = { ...body(s.linkId), consent: { ...grantFixture.consent, config: { scope: 'all' } } };
    const options = await s.put('usage_reporting', { auth_age_s: 5 }, withConfig);
    expectProblem(expect, options, 422, 'validation_failed');
    expect(options.body.errors[0].path).toBe('/consent/config');
    expectProblem(expect, await s.put('counterparty_lookup', { auth_age_s: 5 }, body(s.linkId)), 422, 'integration_not_available');
    const missingLink = await s.put('usage_reporting', { auth_age_s: 5 }, wide());
    expect(missingLink.body.errors[0]).toMatchObject({ path: '/tenant_link_id', code: 'required' });
    await env.admin('faults', { legal_unavailable: true });
    expectProblem(expect, await s.put('usage_reporting', { auth_age_s: 5 }, body(s.linkId)), 503, 'unavailable');
    await env.admin('faults', { legal_unavailable: false });
    const beat = await env.call('POST', '/v1/instances/me/heartbeat', {
      token: s.token,
      body: { version: '96.2.1', integrations_denied: ['usage_reporting'] },
    });
    expect(beat.status).toBe(200);
    expectProblem(expect, await s.put('usage_reporting', { auth_age_s: 5 }, body(s.linkId)), 403, 'denied_by_policy');
  });

  it('the consent schema accepts the product_ui record the platform keeps', () => {
    const record = JSON.parse(readFileSync(join(REPO, 'contracts/fixtures/consent/valid/product-ui.json'), 'utf8'));
    expect(validateSchema('consent', record).ok).toBe(true);
    expect(validateSchema('consent', { ...record, integration_key: 'instance_url' }).ok).toBe(false);
  });
});
