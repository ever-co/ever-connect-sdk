// Row 33: the consent write from a product's own dialog, with a fresh Ever ID sign-in (step-up).
// The token is a TEST person token from /__mock/person-token: its azp must be this installation's
// own client (inst-<instance id>), auth_time at most 300 s old, the person an owner or admin.
// instance_url and counterparty_discoverable are enabled in app.ever.co only. The product's
// credential on this call is pending upstream (pending-upstream.json `security_overrides`); every
// other check follows the platform's order and answers.
import { contract } from '../contract.mjs';
import { consentEventData, denies, integrationEventData, isInstanceWide, stateView } from '../model.mjs';
import { fail } from '../problem.mjs';
import { personClaims } from './person.mjs';

const APP_ONLY = ['instance_url', 'counterparty_discoverable'];

const invalid = (path, message, code = 'invalid') => fail(422, 'validation_failed', message, { errors: [{ path, code, message }] });
const notAvailable = (message) => fail(422, 'integration_not_available', message);

export const consentHandlers = {
  putIntegrationState(ctx) {
    const { state, params, body } = ctx;
    const claims = personClaims(ctx);
    const instance = state.instances.get(params.instance);
    const reaches =
      instance &&
      (instance.org.id === params.org || Object.values(instance.links).some((l) => l.org_id === params.org && l.state !== 'unlinked'));
    if (!reaches) fail(404, 'not_found', 'no such installation of this organization');
    const key = params.key;
    const def = contract().integrations[key];
    if (!def || def.status === 'hidden') fail(404, 'not_found', 'unknown integration');
    if (claims.azp !== `inst-${instance.id}` && !(state.config.product_clients ?? []).includes(claims.azp))
      fail(403, 'session_required', 'the token was not issued to this installation');
    if (APP_ONLY.includes(key)) fail(403, 'session_required', `${key} is enabled in app.ever.co only`);
    if (!Number.isInteger(claims.auth_time) || state.now() - claims.auth_time > 300) fail(403, 'step_up_required');
    if (!['owner', 'admin'].includes(claims.role ?? 'owner')) fail(403, 'forbidden_role');
    const enabling = body.enabled === true;
    let link = null;
    if (isInstanceWide(key)) {
      if (body.tenant_link_id) invalid('/tenant_link_id', 'an installation-wide integration takes no tenant link');
      if (instance.kind === 'cloud')
        fail(403, 'not_connection_owner', 'Ever sets the installation-wide integrations of an installation it operates');
      if (params.org !== instance.org.id) fail(403, 'not_connection_owner');
    } else {
      if (!body.tenant_link_id) invalid('/tenant_link_id', 'a per-link integration names its tenant link', 'required');
      link = instance.links[body.tenant_link_id];
      if (!link || link.org_id !== params.org) fail(404, 'not_found', 'no such tenant link of this organization on the installation');
      if (enabling && link.state !== 'active') invalid('/tenant_link_id', 'the tenant link is not active');
    }
    const product = link ? link.product : null;
    const offered = product ? def.products.includes(product) : instance.serves_products.some((p) => def.products.includes(p));
    const availability = instance.kind === 'cloud' ? def.availability.cloud : def.availability.self_hosted;
    if (enabling && (!offered || availability === 'not_applicable')) notAvailable('this integration is not offered for this installation');
    if (enabling && instance.status !== 'active')
      notAvailable('the installation is not connected: an integration is enabled on a connected one');
    const slot = link ? `${key}@${link.id}` : key;
    const s = instance.integrations[slot];
    if (enabling) {
      const consent = body.consent;
      if (!consent) invalid('/consent', 'enabling needs the consent', 'required');
      if (consent.accepted !== true) invalid('/consent/accepted', 'the consent must be accepted');
      if (def.status !== 'active') notAvailable('this integration is not available yet');
      if (consent.scope_version !== def.scope_version || consent.dpa_version !== contract().catalog.dpa_version)
        fail(
          422,
          'scope_version_outdated',
          'the scope or the data-processing agreement changed: show the current consent screen and ask again',
        );
      if (consent.config !== undefined && consent.config !== null && Object.keys(consent.config).length > 0)
        invalid('/consent/config', 'this integration takes no options: send none, or {}');
      if (state.faults.legal_unavailable)
        fail(503, 'unavailable', 'no terms are published on this deployment, so no consent can be recorded');
      if (denies(instance, key)) fail(403, 'denied_by_policy', "the installation's operator denies this integration");
      Object.assign(s, {
        consent_id: state.ulid('consent'),
        consent_source: 'product_ui',
        dpa_version: consent.dpa_version,
        granted_at: state.now(),
        granted_by_person_id: claims['urn:ever:person_id'] ?? null,
        scope_version: consent.scope_version,
        revoked_at: null,
        config: {},
        evidence: { ui: `product:${instance.product}`, screen_version: consent.screen_version, ui_locale: consent.ui_locale },
      });
      // An installation-wide key still waits for the operator's local accept.
      if (isInstanceWide(key)) Object.assign(s, { state: 'pending_operator', enabled: false, operator_accept: 'pending' });
      else Object.assign(s, { state: 'enabled', enabled: true, operator_accept: null });
      state.emit(instance, 'ever.consent.consent.granted', consentEventData(instance, key, s));
      if (s.state === 'enabled')
        state.emit(instance, 'ever.consent.integration.enabled', integrationEventData(instance, key, s, 'consent'));
    } else {
      const wasEnabled = s.state === 'enabled';
      if (s.consent_id && s.state !== 'revoked')
        state.emit(instance, 'ever.consent.consent.revoked', consentEventData(instance, key, s, { revoke_reason: 'owner' }));
      Object.assign(s, { state: 'disabled', enabled: false, revoked_at: state.now() });
      if (wasEnabled) state.emit(instance, 'ever.consent.integration.disabled', integrationEventData(instance, key, s, 'consent'));
      if (key === 'stats_link') instance.stats_linked = false;
    }
    return { status: 200, body: stateView(state, instance, key, s) };
  },
};
