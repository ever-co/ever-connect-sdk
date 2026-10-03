// Installations, tenant links and integration states, and their views in the platform's shapes.
import { contract } from './contract.mjs';
import { instanceKid } from './crypto.mjs';

// The platform acts installation-wide for instance_url, stats_link, ever_id_login and webhooks.
// managed_operations stays installation-wide here until its platform module is built (the
// platform's consent module lists it per link today).
export const INSTANCE_WIDE_KEYS = ['instance_url', 'stats_link', 'ever_id_login', 'webhooks', 'managed_operations'];

/** Whether integration states of `key` live on the instance (true) or on each tenant link. */
export const isInstanceWide = (key) => INSTANCE_WIDE_KEYS.includes(key);

function initialState(key, { cloud }) {
  const def = contract().integrations[key];
  const enabled = cloud && def.defaults.cloud === true && def.availability.cloud === 'enabled';
  return {
    state: enabled ? 'enabled' : 'available',
    enabled,
    consent_id: null,
    scope_version: def.scope_version,
    consent_source: enabled ? 'cloud_terms' : null,
    operator_accept: null,
  };
}

/** Integration states for a new installation or a new link (per-link keys only). */
export function addIntegrationStates(state, instance, linkId = null) {
  const cloud = instance.kind === 'cloud' && state.config.integrations.cloud_defaults;
  for (const key of contract().constants.integration_keys) {
    if (linkId === null && isInstanceWide(key)) instance.integrations[key] = initialState(key, { cloud });
    if (linkId !== null && !isInstanceWide(key))
      instance.integrations[`${key}@${linkId}`] = { ...initialState(key, { cloud }), tenant_link_id: linkId };
  }
  for (const key of state.config.integrations.enabled ?? []) {
    const slot = isInstanceWide(key) ? key : linkId ? `${key}@${linkId}` : null;
    if (slot && instance.integrations[slot])
      Object.assign(instance.integrations[slot], {
        state: 'enabled',
        enabled: true,
        consent_id: state.ulid('consent'),
        consent_source: 'app_ever_co',
      });
  }
}

export function createInstance(state, { product, version, install_source, kind, serves_products, public_jwk, org, status }) {
  const id = state.ulid('instance');
  state.heldKeys.add(public_jwk.x);
  const instance = {
    id,
    product,
    version,
    install_source: install_source ?? 'self-hosted',
    kind: kind ?? 'self_hosted',
    serves_products: serves_products ?? [product],
    org,
    status,
    current_key: { x: public_jwk.x, kid: instanceKid(public_jwk.x) },
    previous_key: null,
    rotated_at: null,
    connected_at: state.now(),
    last_seen_at: null,
    last_heartbeat: null,
    links: {},
    integrations: {},
    feed: [],
    acked: null,
    entitlement_seq: { instance: 1 },
    oidc: null,
    webhooks: {},
    stats_linked: false,
    identifiers: {},
    person_links: {},
    mirror: {},
    public_url: null,
    jobs: {},
    seen_once: false,
  };
  addIntegrationStates(state, instance, null);
  state.instances.set(id, instance);
  state.lastInstanceId = id;
  return instance;
}

export function createLink(state, instance, { org, product, product_tenant_id, product_org_id, display_name, link_method }) {
  const link = {
    id: state.ulid('link'),
    org_id: org.id,
    org_handle: org.handle,
    instance_id: instance.id,
    product,
    product_tenant_id,
    product_org_id: product_org_id ?? null,
    display_name: display_name ?? null,
    link_method,
    state: 'active',
    linked_at: state.now(),
    unlinked_at: null,
  };
  instance.links[link.id] = link;
  instance.entitlement_seq[link.id] = 1;
  addIntegrationStates(state, instance, link.id);
  return link;
}

/** A link as the connect routes answer it (the platform's LinkedTenant). */
export function linkedTenantView(state, link) {
  return {
    id: link.id,
    org_id: link.org_id,
    instance_id: link.instance_id,
    product: link.product,
    product_tenant_id: link.product_tenant_id,
    product_org_id: link.product_org_id,
    display_name: link.display_name,
    link_method: link.link_method,
    state: link.state,
    linked_at: state.iso(link.linked_at),
  };
}

export function tenantLinkView(state, link) {
  return {
    id: link.id,
    org_id: link.org_id,
    instance_id: link.instance_id,
    product: link.product,
    product_tenant_id: link.product_tenant_id,
    product_org_id: link.product_org_id,
    display_name: link.display_name,
    link_method: link.link_method,
    linked_at: state.iso(link.linked_at),
    linked_by_person_id: null,
    state: link.state,
    unlinked_at: link.unlinked_at === null ? null : state.iso(link.unlinked_at),
  };
}

const bucket = (state, at) => {
  if (at === null) return 'never';
  const age = state.now() - at;
  if (age < 300) return 'now';
  if (age < 3600) return 'lt_1h';
  if (age < 86400) return 'lt_24h';
  if (age < 7 * 86400) return 'lt_7d';
  if (age < 30 * 86400) return 'lt_30d';
  return 'gt_30d';
};

/** The installation as it sees itself (the platform's Instance shape). */
export function instanceView(state, instance) {
  return {
    id: instance.id,
    product: instance.product,
    serves_products: instance.serves_products,
    operator: 'customer',
    kind: instance.kind,
    install_source: instance.install_source,
    status: instance.status,
    stats_linked: instance.stats_linked,
    key: { kid: instance.current_key.kid, rotated_at: instance.rotated_at === null ? null : state.iso(instance.rotated_at) },
    last_seen_bucket: bucket(state, instance.last_seen_at),
    last_seen_at: instance.last_seen_at === null ? null : state.iso(instance.last_seen_at),
    connected_at: state.iso(instance.connected_at),
    disconnected_at: instance.status === 'disconnected' ? state.iso(instance.disconnected_at ?? state.now()) : null,
    display_name: null,
    owner_org_id: instance.org.id,
    version: instance.version,
    version_row: 1,
  };
}

export function activeLinks(instance) {
  return Object.values(instance.links).filter((l) => l.state !== 'unlinked');
}

/** Whether the installation's local deny list (heartbeat `integrations_denied`, or a policy switch-off) names `key`. */
export function denies(instance, key) {
  const list = instance.denied ?? [];
  return list.includes('*') || list.includes(key);
}

/**
 * The state label the platform answers: denied_by_policy while the installation denies the key,
 * the stored state once anything was written, coming_soon for an untouched integration that is not
 * available yet, else available. (The platform never enables a coming-soon integration; the mock
 * still lets /__mock/consent enable one, so products can test what comes next.)
 */
export function stateLabel(instance, key, s) {
  if (instance && denies(instance, key)) return 'denied_by_policy';
  if (s && s.state !== 'available') return s.state;
  if (contract().integrations[key]?.status === 'coming_soon') return 'coming_soon';
  return 'available';
}

/** The platform's IntegrationStateBrief of one state. */
export function brief(s, instance = null, key = null) {
  const state = key ? stateLabel(instance, key, s) : s.state;
  return {
    enabled: state === 'enabled' && s.enabled !== false,
    state,
    consent_id: s.consent_id ?? null,
    scope_version: s.scope_version ?? null,
    config: s.config ?? {},
  };
}

/** The platform's IntegrationState view of one state. */
export function stateView(state, instance, key, s) {
  return {
    ...brief(s, instance, key),
    operator_accept: s.operator_accept ?? null,
    instance_id: instance.id,
    tenant_link_id: s.tenant_link_id ?? null,
    integration_key: key,
    dpa_version: s.dpa_version ?? null,
    consent_source: s.consent_source ?? null,
    granted_by_person_id: s.granted_by_person_id ?? null,
    granted_at: s.granted_at ? state.iso(s.granted_at) : null,
    revoked_at: s.revoked_at ? state.iso(s.revoked_at) : null,
    updated_at: state.iso(),
  };
}

/** The data of ever.consent.integration.enabled / .disabled for one state. */
export function integrationEventData(instance, key, s, reason) {
  const data = { org_id: instance.org.id, instance_id: instance.id, integration_key: key, enabled: s.state === 'enabled', reason };
  if (s.tenant_link_id) data.tenant_link_id = s.tenant_link_id;
  if (s.consent_id) data.consent_id = s.consent_id;
  if (s.operator_accept) data.operator_accept = s.operator_accept;
  return data;
}

/** The data of ever.consent.consent.granted / .revoked for one state. */
export function consentEventData(instance, key, s, extra = {}) {
  const data = {
    consent_id: s.consent_id,
    org_id: instance.org.id,
    instance_id: instance.id,
    integration_key: key,
    scope_version: s.scope_version,
    dpa_version: s.dpa_version ?? '2026-10',
    consent_source: s.consent_source ?? 'app_ever_co',
    ...extra,
  };
  if (s.tenant_link_id) data.tenant_link_id = s.tenant_link_id;
  return data;
}
