// Rows 18, 20, 21, 24-28 and 30-32: the installation address, deletion and export receipts, the
// profile import, company sign-in discovery, billing links, provisioning hand-offs, usage reports,
// install status, the webhook endpoint, the operator's accept and provider access grants.
import { randomBytes } from 'node:crypto';
import { b64url } from '../crypto.mjs';
import { fail } from '../problem.mjs';

const INSTALL_TRANSITIONS = {
  requested: ['installing', 'failed', 'removed'],
  installing: ['installed', 'failed'],
  installed: ['removed', 'installing'],
  failed: ['installing', 'removed'],
  removed: [],
};

function endpointView(state, instance, e) {
  return {
    id: e.id,
    owner: { kind: 'instance', id: instance.id },
    url: e.url,
    event_filter: e.event_filter,
    api_version: e.api_version,
    status: e.status,
    failure_streak: 0,
    secret_prefix: e.secret.slice(0, 10),
    created_at: state.iso(e.created_at),
    last_success_at: null,
    last_failure_at: null,
  };
}

function ownEndpoint(instance, id) {
  const e = instance.webhooks[id];
  if (!e || e.deleted) fail(404, 'not_found', 'no such webhook endpoint of this installation');
  return e;
}

function delivery(state, e, { event_type = 'ever.system.webhook.test', state: s = 'delivered' } = {}) {
  const d = {
    id: state.ulid('delivery'),
    endpoint_id: e.id,
    event_id: state.ulid('event'),
    event_type,
    attempt: 1,
    state: s,
    created_at: state.iso(),
    delivered_at: s === 'delivered' ? state.iso() : null,
    response_status: s === 'delivered' ? 200 : null,
    error: null,
    next_attempt_at: null,
  };
  e.deliveries.push(d);
  return d;
}

const webhookCheck = (state) => {
  if (state.faults.webhooks_module_disabled) fail(404, 'module_disabled', 'webhooks are off on this deployment');
};

function validateWebhookInput(body) {
  const errors = [];
  if (body.url !== undefined && body.url !== null) {
    let u = null;
    try {
      u = new URL(body.url);
    } catch {
      /* not a URL */
    }
    if (!u || u.protocol !== 'https:' || !['', '443', '8443'].includes(u.port) || body.url.length > 2048)
      errors.push({ path: '/url', code: 'invalid', message: 'https on port 443 or 8443' });
  }
  if (body.event_filter !== undefined && body.event_filter !== null) {
    if (body.event_filter.length < 1 || body.event_filter.length > 50)
      errors.push({ path: '/event_filter', code: 'out_of_range', message: '1 to 50 types' });
    for (const [i, t] of body.event_filter.entries())
      if (!/^ever\.[a-z_.]+(\.\*)?$|^ever\.\*$/.test(t))
        errors.push({ path: `/event_filter/${i}`, code: 'invalid', message: 'a type or a prefix ending in .*' });
  }
  if (errors.length > 0) fail(422, 'validation_failed', undefined, { errors });
}

/** The longest public address accepted. */
const PUBLIC_URL_MAX = 2048;

/**
 * The installation's public address as Ever Platform stores it: an absolute https URL with a host,
 * no credentials, no query and no fragment, at most 2 048 characters, normalised by the URL
 * Standard (lower-case host, no default port); anything else is 422 at /base_url, never echoed.
 */
export function normalisedPublicUrl(raw) {
  const refuse = (message) => fail(422, 'validation_failed', undefined, { errors: [{ path: '/base_url', code: 'invalid', message }] });
  if (typeof raw !== 'string' || raw === '' || raw.length > PUBLIC_URL_MAX || raw.trim() !== raw)
    refuse('an absolute https URL of at most 2048 characters');
  let u;
  try {
    u = new URL(raw);
  } catch {
    refuse('an absolute https URL');
  }
  if (u.protocol !== 'https:') refuse('an https URL');
  if (!u.hostname) refuse('an https URL with a host');
  if (u.username || u.password) refuse('an https URL without credentials');
  if (u.href.includes('?') || u.href.includes('#')) refuse('an https URL without a query or a fragment');
  if (u.href.length > PUBLIC_URL_MAX) refuse('an absolute https URL of at most 2048 characters');
  return u.href;
}

export const miscHandlers = {
  instancePutPublicUrl({ instance, body }) {
    const base_url = normalisedPublicUrl(body.base_url);
    instance.public_url = base_url;
    return { status: 200, body: { base_url } };
  },

  instanceDeletePublicUrl({ instance }) {
    instance.public_url = null;
    return { status: 204 };
  },

  instanceAckRequest({ instance, body }) {
    const job = instance.jobs[body.job_id];
    if (!job) fail(404, 'not_found', 'no deletion or export request with this job id');
    job.result = body.result;
    return { status: 204 };
  },

  instancePushOrgProfile({ instance, body }) {
    if (!instance.links[body.tenant_link_id])
      fail(422, 'validation_failed', 'unknown tenant link', {
        errors: [{ path: '/tenant_link_id', code: 'invalid', message: 'not a link of this installation' }],
      });
    return { status: 200, body: {} };
  },

  discoverSso({ state, query, req }) {
    const domain = query.get('email_domain');
    if (!domain || domain.includes('@') || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain))
      fail(422, 'validation_failed', 'a domain, never an address', {
        errors: [{ path: '?email_domain', code: domain ? 'invalid' : 'required', message: 'a domain' }],
      });
    const wait = state.hit(`sso|${req.socket.remoteAddress}`, state.config.limits.sso_discover_per_min, 60);
    if (wait > 0) fail(429, 'rate_limited', undefined, { retry_after_s: wait });
    return { status: 200, body: { sso: false } };
  },

  instanceCreateBillingLink({ state, instance, headers, body }) {
    const link = instance.links[headers['ever-link-id']] ?? Object.values(instance.links)[0];
    return {
      status: 201,
      body: {
        id: state.ulid('billing-link'),
        instance_id: instance.id,
        product_tenant_id: body.product_tenant_id,
        org_id: link?.org_id ?? null,
        created_at: state.iso(),
      },
    };
  },

  completeProvisionIntent({ state, instance, params, body }) {
    const intent = state.intents.get(params.jti);
    if (!intent || intent.instance_id !== instance.id) fail(404, 'not_found', 'no provisioning intent with this id');
    if (intent.expires_at <= state.now() && !intent.completed) fail(410, 'gone', 'the intent expired');
    if (intent.completed) {
      if (intent.result !== body.result) fail(409, 'illegal_transition', 'the intent was completed with another result');
      return { status: 200, body: { status: 'already_completed', tenant_link_id: intent.tenant_link_id, job_id: intent.job_id } };
    }
    Object.assign(intent, {
      completed: true,
      result: body.result,
      tenant_link_id: body.result === 'refused' ? null : state.ulid('link'),
      job_id: state.ulid('job'),
    });
    return { status: 200, body: { status: 'completed', tenant_link_id: intent.tenant_link_id, job_id: intent.job_id } };
  },

  instanceReportUsage() {
    return { status: 202, body: {} };
  },

  instanceReportUsageReadings() {
    return { status: 202, body: {} };
  },

  instanceReportInstallStatus({ state, instance, params, body }) {
    const install = state.installs.get(params.install);
    if (!install || install.instance_id !== instance.id) fail(404, 'not_found', 'no install request with this id');
    if (install.state !== body.state && !INSTALL_TRANSITIONS[install.state]?.includes(body.state))
      fail(409, 'illegal_transition', `${install.state} cannot become ${body.state}`);
    install.state = body.state;
    return {
      status: 200,
      body: {
        id: install.id,
        listing_id: install.listing_id,
        org_id: install.org_id,
        instance_id: instance.id,
        tenant_link_id: null,
        mechanism: 'instance_plugin',
        state: install.state,
        external_ref: body.external_ref ?? null,
        created_at: state.iso(install.created_at),
      },
    };
  },

  instanceCreateWebhook({ state, instance, body }) {
    webhookCheck(state);
    validateWebhookInput(body);
    const live = Object.values(instance.webhooks).filter((e) => !e.deleted);
    if (live.length >= state.config.limits.webhook_endpoints) fail(422, 'limit_exceeded', 'the endpoint limit is reached');
    const e = {
      id: state.ulid('webhook'),
      url: body.url,
      event_filter: body.event_filter,
      api_version: body.api_version ?? 'v1',
      status: 'active',
      secret: `whsec_${b64url(randomBytes(24))}`,
      created_at: state.now(),
      deliveries: [],
      deleted: false,
    };
    instance.webhooks[e.id] = e;
    return { status: 201, body: { ...endpointView(state, instance, e), secret: e.secret } };
  },

  updateWebhook({ state, instance, params, body }) {
    webhookCheck(state);
    const e = ownEndpoint(instance, params.webhook);
    validateWebhookInput(body);
    if (body.url) e.url = body.url;
    if (body.event_filter) e.event_filter = body.event_filter;
    if (body.status) e.status = body.status;
    return { status: 200, body: endpointView(state, instance, e) };
  },

  deleteWebhook({ state, instance, params }) {
    webhookCheck(state);
    ownEndpoint(instance, params.webhook).deleted = true;
    return { status: 204 };
  },

  rotateWebhookSecret({ state, instance, params }) {
    webhookCheck(state);
    const e = ownEndpoint(instance, params.webhook);
    e.secret = `whsec_${b64url(randomBytes(24))}`;
    return { status: 200, body: { secret: e.secret, previous_valid_until: state.iso(state.now() + 86400) } };
  },

  testWebhook({ state, instance, params }) {
    webhookCheck(state);
    const e = ownEndpoint(instance, params.webhook);
    return { status: 202, body: delivery(state, e) };
  },

  listWebhookDeliveries({ state, instance, params }) {
    webhookCheck(state);
    const e = ownEndpoint(instance, params.webhook);
    return { status: 200, body: { items: [...e.deliveries].reverse(), next_cursor: null } };
  },

  redeliverWebhook({ state, instance, params }) {
    webhookCheck(state);
    for (const e of Object.values(instance.webhooks)) {
      const d = e.deliveries.find((x) => x.id === params.delivery);
      if (!d) continue;
      if (d.state === 'delivered') fail(409, 'illegal_transition', 'the delivery was delivered already');
      return { status: 202, body: delivery(state, e, { event_type: d.event_type }) };
    }
    fail(404, 'not_found', 'no such delivery of this installation');
  },

  instanceGetProviderGrant({ state, instance, params }) {
    const g = state.grants.get(params.grant);
    if (!g || g.instance_id !== instance.id) fail(404, 'not_found', 'no such grant');
    if (g.status !== 'person_accepted' && g.status !== 'accepted')
      fail(409, 'illegal_transition', 'the provider person has not accepted the grant yet');
    return { status: 200, body: { grant_id: g.id, status: g.status, role: g.role, email: g.email, name: g.name } };
  },

  instanceReportProviderGrantStatus({ state, instance, params, body }) {
    const g = state.grants.get(params.grant);
    if (!g || g.instance_id !== instance.id || body.grant_id !== g.id) fail(404, 'not_found', 'no such grant');
    if (['revoked', 'expired', 'declined'].includes(g.status)) fail(409, 'illegal_transition', `the grant is ${g.status}`);
    g.status = body.status;
    return { status: 200, body: { grant_id: g.id, status: g.status } };
  },
};
