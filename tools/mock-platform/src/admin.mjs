// Controls of the mock (/__mock/*): the record, the clock, keys, approvals, events, consent and
// faults. They stand in for what an organization does in app.ever.co or what Ever operates, so a
// product's tests can drive every state. Never recorded as product calls.
import { createHash } from 'node:crypto';
import { contract } from './contract.mjs';
import { signJws } from './crypto.mjs';
import { INTENT_TYP, testKey } from './keys.mjs';
import { consentEventData, integrationEventData, isInstanceWide } from './model.mjs';
import { fail } from './problem.mjs';
import { expireOperations, stateChangedData } from './routes/managed.mjs';
import { validateEventData } from './validate.mjs';

const need = (instance) => {
  if (!instance) fail(404, 'not_found', 'no installation yet: redeem a code first');
  return instance;
};

function slotFor(instance, key, link) {
  if (isInstanceWide(key)) return key;
  const linkId = link ?? Object.values(instance.links).find((l) => l.state !== 'unlinked')?.id;
  if (!linkId) fail(404, 'not_found', `${key} is per tenant link and the installation has no link`);
  return `${key}@${linkId}`;
}

function stateDump(state) {
  return {
    now: state.now(),
    instances: [...state.instances.values()].map((i) => ({
      id: i.id,
      product: i.product,
      status: i.status,
      kid: i.current_key.kid,
      links: Object.values(i.links).map((l) => ({ id: l.id, org_id: l.org_id, state: l.state, product_tenant_id: l.product_tenant_id })),
      integrations: Object.fromEntries(Object.entries(i.integrations).map(([k, v]) => [k, v.state])),
      feed_length: i.feed.length,
      acked: i.acked,
      last_seen_at: i.last_seen_at,
      stats_linked: i.stats_linked,
      public_url: i.public_url,
    })),
    stats: {
      pinned_ids: state.statsPins.size,
      reports: state.statsReports.map((r) => ({ instance_id: r.instance_id, period: r.period, product: r.product, day: r.day })),
    },
    operations: [...state.operations.values()].map((o) => ({ id: o.id, kind: o.kind, state: o.state, results: o.results.length })),
    tokens: { active: [...state.tokens.values()].filter((t) => !t.revoked && t.expires_at > state.now()).length },
  };
}

export const adminRoutes = {
  'GET /__mock/healthz': () => ({ body: { ok: true } }),

  'GET /__mock/requests': ({ recorder }) => ({ body: recorder.entries }),

  'POST /__mock/reset': ({ state, recorder }) => {
    state.reset();
    recorder.clear();
    return { body: { ok: true } };
  },

  'GET /__mock/state': ({ state }) => ({ body: stateDump(state) }),

  'POST /__mock/clock': ({ state, body }) => {
    if (Number.isInteger(body?.set)) state.offset = body.set - state.config.clock.start;
    if (Number.isInteger(body?.advance)) state.offset += body.advance;
    expireOperations(state);
    return { body: { now: state.now(), iso: state.iso() } };
  },

  'POST /__mock/keys/rotate': ({ state }) => {
    state.keyGeneration += 1;
    state.keysRotatedAt = state.now();
    return { body: { generation: state.keyGeneration } };
  },

  'POST /__mock/codes': ({ state, body }) => {
    state.addCode({ kind: 'connect', expires_in_s: 900, pending_approval: false, org: state.config.codes[0].org, ...body });
    return { status: 201, body: { code: body.code.toUpperCase() } };
  },

  'POST /__mock/approve': ({ state, body }) => {
    if (body?.user_code || body?.device_code) {
      const device = [...state.devices.entries()].find(([dc, d]) => dc === body.device_code || d.user_code === body.user_code)?.[1];
      if (!device) fail(404, 'not_found', 'no such device code');
      device.approved = true;
      device.org = body.org ?? state.config.codes[0].org;
      return { body: { approved: true } };
    }
    const instance = need(state.instance(body?.instance_id));
    if (instance.status !== 'pending_approval') fail(409, 'illegal_transition', 'the installation is not waiting for approval');
    instance.status = 'active';
    state.emit(instance, 'ever.registry.instance.approved', {
      instance_id: instance.id,
      org_id: instance.org.id,
      product: instance.product,
      serves_products: instance.serves_products,
      install_source: instance.install_source,
      kind: instance.kind,
      status: instance.status,
      last_seen_bucket: 'now',
      kid: instance.current_key.kid,
    });
    return { body: { approved: true, instance_id: instance.id } };
  },

  'POST /__mock/emit': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    if (!contract().constants.feed_event_types.includes(body?.type))
      fail(422, 'validation_failed', 'not an instance-audience event type', {
        errors: [{ path: '/type', code: 'invalid', message: 'not a feed event type' }],
      });
    const v = validateEventData(body.type, body.data);
    if (!v.ok) fail(422, 'validation_failed', 'the data does not match the event schema', { errors: v.errors });
    if (
      (body.type === 'ever.registry.person.deletion_requested' || body.type === 'ever.registry.person.export_requested') &&
      body.data.job_id
    )
      instance.jobs[body.data.job_id] = { type: body.type, result: null };
    const event = state.emit(instance, body.type, body.data, body.subject ? { subject: body.subject } : {});
    return { status: 201, body: { id: event.id } };
  },

  'POST /__mock/entitlement/reissue': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const subjectKey = body?.link ?? 'instance';
    if (!(subjectKey in instance.entitlement_seq)) fail(404, 'not_found', 'no such link');
    instance.entitlement_seq[subjectKey] += 1;
    const subject = subjectKey === 'instance' ? { kind: 'instance', id: instance.id } : { kind: 'link', id: subjectKey };
    state.emit(instance, 'ever.entitlements.entitlement.issued', {
      subject,
      org_id: instance.org.id,
      instance_id: instance.id,
      seq: instance.entitlement_seq[subjectKey],
      expires_at: state.iso(state.now() + 604800),
      tier: state.config.entitlement.tier,
      features_changed: [],
      limits_changed: [],
    });
    return { body: { seq: instance.entitlement_seq[subjectKey] } };
  },

  // An organization owner consents (enabled: true) or disables (false) in app.ever.co.
  'POST /__mock/consent': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const key = body?.integration;
    if (!contract().constants.integration_keys.includes(key)) fail(422, 'validation_failed', 'unknown integration');
    const slot = slotFor(instance, key, body.link);
    const s = instance.integrations[slot];
    if (body.enabled === false) {
      Object.assign(s, { state: 'disabled', enabled: false });
      state.emit(instance, 'ever.consent.integration.disabled', integrationEventData(instance, key, s, 'consent'));
      return { body: { slot, state: s.state } };
    }
    Object.assign(s, {
      consent_id: state.ulid('consent'),
      consent_source: body.consent_source ?? 'app_ever_co',
      dpa_version: '2026-10',
      granted_at: state.now(),
    });
    if (body.operator_accept === 'pending') Object.assign(s, { state: 'pending_operator', enabled: false, operator_accept: 'pending' });
    else Object.assign(s, { state: 'enabled', enabled: true });
    state.emit(instance, 'ever.consent.consent.granted', consentEventData(instance, key, s));
    if (s.state === 'enabled') state.emit(instance, 'ever.consent.integration.enabled', integrationEventData(instance, key, s, 'consent'));
    return { body: { slot, state: s.state, consent_id: s.consent_id } };
  },

  'POST /__mock/revoke': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const key = body?.integration;
    const slot = slotFor(instance, key, body.link);
    const s = instance.integrations[slot];
    if (!s) fail(404, 'not_found', 'no such integration state');
    Object.assign(s, { state: 'revoked', enabled: false, revoked_at: state.now() });
    if (s.consent_id) state.emit(instance, 'ever.consent.consent.revoked', consentEventData(instance, key, s, { revoke_reason: 'owner' }));
    if (key === 'ever_id_login' && instance.oidc) instance.oidc.status = 'revoked';
    return { body: { slot, state: s.state } };
  },

  // The organization disconnects the installation in app.ever.co.
  'POST /__mock/disconnect': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    instance.status = 'disconnected';
    instance.disconnected_at = state.now();
    return { body: { status: instance.status } };
  },

  // Ever revokes the installation's credential for good.
  'POST /__mock/revoke-instance': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    instance.status = 'revoked';
    state.revokeTokens(instance.id);
    return { body: { status: instance.status } };
  },

  // A TEST Ever ID token, as a product's own client receives it after a sign-in.
  'POST /__mock/person-token': ({ state, body, issuer }) => {
    const instance = state.instance(body?.instance_id);
    const person = state.config.people[0];
    const now = state.now();
    const authAge = Number.isInteger(body?.auth_age_s) ? body.auth_age_s : null;
    const claims = {
      iss: `${issuer}/idp`,
      sub: body?.sub ?? person.subject,
      aud: ['ever-platform'],
      azp: body?.azp ?? (instance ? `inst-${instance.id}` : 'unknown-client'),
      auth_time: Number.isInteger(body?.auth_time) ? body.auth_time : now - (authAge ?? 0),
      iat: now,
      exp: now + (body?.ttl ?? 900),
      'urn:ever:person_id': person.person_id,
      role: body?.role ?? person.org_role,
    };
    return { body: { token: signJws(testKey('identity').privateKey, { kid: testKey('identity').kid, typ: 'JWT' }, claims), claims } };
  },

  'POST /__mock/provision-intent': ({ state, body, issuer }) => {
    const instance = need(state.instance(body?.instance_id));
    const now = state.now();
    const jti = state.ulid('intent');
    state.intents.set(jti, { jti, instance_id: instance.id, expires_at: now + (body?.expires_in_s ?? 900), completed: false });
    const intent = signJws(
      testKey('intent').privateKey,
      { kid: testKey('intent').kid, typ: INTENT_TYP },
      { iss: issuer, aud: `ever-connect:${instance.id}`, jti, iat: now, exp: now + 900, ever_purpose: 'intent' },
    );
    return { status: 201, body: { jti, intent } };
  },

  'POST /__mock/install': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const id = state.ulid('install');
    state.installs.set(id, {
      id,
      instance_id: instance.id,
      listing_id: state.ulid('listing'),
      org_id: instance.org.id,
      state: body?.state ?? 'requested',
      created_at: state.now(),
    });
    return { status: 201, body: { install_id: id } };
  },

  'POST /__mock/provider-grant': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const id = state.ulid('grant');
    state.grants.set(id, {
      id,
      instance_id: instance.id,
      status: body?.status ?? 'person_accepted',
      role: body?.role ?? 'accountant',
      email: 'provider@example.com',
      name: 'Provider Person',
    });
    return { status: 201, body: { grant_id: id } };
  },

  'POST /__mock/managed/request': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const s = instance.integrations.managed_operations;
    if (s?.state !== 'enabled') fail(403, 'integration_disabled', 'managed_operations is not enabled for this installation');
    const now = state.now();
    const op = {
      id: state.ulid('operation'),
      org_id: instance.org.id,
      instance_id: instance.id,
      kind: body?.kind,
      params: body?.params ?? {},
      state: 'requested',
      not_before: now,
      expires_at: now + (body?.expires_in_s ?? 86400),
      results: [],
    };
    const data = {
      operation_id: op.id,
      org_id: op.org_id,
      instance_id: op.instance_id,
      kind: op.kind,
      params: op.params,
      not_before: state.iso(op.not_before),
      expires_at: state.iso(op.expires_at),
    };
    const v = validateEventData('ever.registry.managed_operation.requested', data);
    if (!v.ok && !body?.allow_invalid)
      fail(422, 'validation_failed', 'the operation does not match the event schema', { errors: v.errors });
    state.operations.set(op.id, op);
    const event = state.emit(instance, 'ever.registry.managed_operation.requested', data, {
      subject: { kind: 'managed_operation', id: op.id },
    });
    return { status: 201, body: { operation_id: op.id, event_id: event.id } };
  },

  'GET /__mock/managed/operations': ({ state }) => ({
    body: [...state.operations.values()].map((o) => ({ ...stateChangedData(o), results: o.results })),
  }),

  // A delivery of a webhook endpoint in a given state (to redeliver a failed one).
  'POST /__mock/webhook-delivery': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const e = instance.webhooks[body?.webhook_id];
    if (!e) fail(404, 'not_found', 'no such webhook endpoint');
    const d = {
      id: state.ulid('delivery'),
      endpoint_id: e.id,
      event_id: state.ulid('event'),
      event_type: 'ever.consent.integration.enabled',
      attempt: 1,
      state: body?.state ?? 'failed',
      created_at: state.iso(),
      delivered_at: null,
      response_status: 500,
      error: 'upstream_5xx',
      next_attempt_at: null,
    };
    e.deliveries.push(d);
    return { status: 201, body: { delivery_id: d.id } };
  },

  'POST /__mock/faults': ({ state, body }) => {
    Object.assign(state.faults, body ?? {});
    return { body: state.faults };
  },

  // The deletion/export request a product answers on row 20, with its subject hash.
  'POST /__mock/person-request': ({ state, body }) => {
    const instance = need(state.instance(body?.instance_id));
    const type = body?.kind === 'export' ? 'ever.registry.person.export_requested' : 'ever.registry.person.deletion_requested';
    const job = state.ulid('job');
    const person = state.config.people[0];
    const data = { person_id: person.person_id, job_id: job, respond_by: state.iso(state.now() + 30 * 86400) };
    if (type.endsWith('deletion_requested'))
      data.subject_hash = createHash('sha256').update(`${person.issuer}\n${person.subject}`).digest('hex');
    instance.jobs[job] = { type, result: null };
    const event = state.emit(instance, type, data, { subject: { kind: 'person', id: person.person_id } });
    return { status: 201, body: { job_id: job, event_id: event.id } };
  },
};
