// Row 33: the consent write from a product's own dialog, with a fresh Ever ID sign-in (step-up).
// The token is a TEST person token from /__mock/person-token: its azp must be this installation's
// own client (inst-<instance id>), auth_time at most 300 s old, the person an owner or admin.
// instance_url and counterparty_discoverable are enabled in app.ever.co only.
import { contract } from '../contract.mjs';
import { consentEventData, integrationEventData, isInstanceWide, stateView } from '../model.mjs';
import { fail } from '../problem.mjs';
import { personClaims } from './person.mjs';

const APP_ONLY = ['instance_url', 'counterparty_discoverable'];

export const consentHandlers = {
  putIntegrationState(ctx) {
    const { state, params, body } = ctx;
    const claims = personClaims(ctx);
    const instance = state.instances.get(params.instance);
    if (!instance || (instance.org.id !== params.org && !Object.values(instance.links).some((l) => l.org_id === params.org)))
      fail(404, 'not_found', 'no such installation of this organization');
    const key = params.key;
    if (!contract().constants.integration_keys.includes(key)) fail(404, 'not_found', 'unknown integration');
    if (claims.azp !== `inst-${instance.id}` && !(state.config.product_clients ?? []).includes(claims.azp))
      fail(403, 'session_required', 'the token was not issued to this installation');
    if (APP_ONLY.includes(key)) fail(403, 'session_required', `${key} is enabled in app.ever.co only`);
    if (!Number.isInteger(claims.auth_time) || state.now() - claims.auth_time > 300) fail(403, 'step_up_required');
    if (!['owner', 'admin'].includes(claims.role ?? 'owner')) fail(403, 'forbidden_role');
    if (isInstanceWide(key) && params.org !== instance.org.id) fail(403, 'not_connection_owner');
    const def = contract().integrations[key];
    if (body.enabled && body.consent && body.consent.scope_version < def.scope_version) fail(422, 'scope_version_outdated');
    if (body.enabled && !body.consent)
      fail(422, 'validation_failed', 'enabling needs a consent', { errors: [{ path: '/consent', code: 'required', message: 'required' }] });
    const linkId = isInstanceWide(key)
      ? null
      : (body.tenant_link_id ?? Object.values(instance.links).find((l) => l.org_id === params.org)?.id ?? null);
    if (!isInstanceWide(key) && (!linkId || !instance.links[linkId]))
      fail(404, 'not_found', 'no tenant link of this organization on the installation');
    const slot = isInstanceWide(key) ? key : `${key}@${linkId}`;
    const s = instance.integrations[slot];
    if (body.enabled) {
      Object.assign(s, {
        consent_id: state.ulid('consent'),
        consent_source: 'product_ui',
        dpa_version: body.consent.dpa_version,
        granted_at: state.now(),
        granted_by_person_id: claims['urn:ever:person_id'] ?? null,
        scope_version: body.consent.scope_version,
        evidence: { ui: `product:${instance.product}`, screen_version: body.consent.screen_version, ui_locale: body.consent.ui_locale },
      });
      // An installation-wide key still waits for the operator's local accept.
      if (isInstanceWide(key)) Object.assign(s, { state: 'pending_operator', enabled: false, operator_accept: 'pending' });
      else Object.assign(s, { state: 'enabled', enabled: true });
      state.emit(instance, 'ever.consent.consent.granted', consentEventData(instance, key, s));
      if (s.state === 'enabled')
        state.emit(instance, 'ever.consent.integration.enabled', integrationEventData(instance, key, s, 'consent'));
    } else {
      Object.assign(s, { state: 'disabled', enabled: false });
      state.emit(instance, 'ever.consent.integration.disabled', integrationEventData(instance, key, s, 'consent'));
    }
    return { status: 200, body: stateView(state, instance, key, s) };
  },
};
