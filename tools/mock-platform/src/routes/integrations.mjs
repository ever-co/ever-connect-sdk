// Rows 9, 10 and 31: an installation reads its integration states, asks for a consent link, switches
// an integration off (for itself, or for every organization by its local deny list), and accepts
// or declines an installation-wide integration an organization consented to. The checks run in the
// platform's order, with its answers.
import { createHmac } from 'node:crypto';
import { contract } from '../contract.mjs';
import { b64url } from '../crypto.mjs';
import { brief, consentEventData, denies, integrationEventData, isInstanceWide } from '../model.mjs';
import { fail } from '../problem.mjs';

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const MAX_DENIED = 32;
// The consent-link signature of the mock (a public seed: it signs nothing anyone trusts).
const LINK_KEY = 'ever-connect-sdk/mock/consent-link';

const invalid = (path, message, code = 'invalid') => fail(422, 'validation_failed', message, { errors: [{ path, code, message }] });

const visible = (key) => {
  const def = contract().integrations[key];
  return def && def.status !== 'hidden' ? def : null;
};

/**
 * A return origin as the platform normalises a declared one (`scheme://host[:port]`, lower case, a
 * default port dropped): https, or plain http on localhost, 127.0.0.1 or [::1] only; no credentials,
 * path, query or fragment. Throws a sentence for the 422.
 */
export function returnOrigin(raw) {
  const text = String(raw).trim();
  const at = text.indexOf('://');
  if (at < 0) throw new Error('a return origin is an absolute https URL with no path');
  const scheme = text.slice(0, at).toLowerCase();
  let authority = text.slice(at + 3);
  if (authority.endsWith('/')) authority = authority.slice(0, -1);
  if (authority === '' || /[/?#@\\]/.test(authority) || /[^\x21-\x7e]/.test(authority))
    throw new Error('a return origin has a host only: no credentials, path, query or fragment');
  authority = authority.toLowerCase();
  let host;
  let port = null;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) throw new Error('a return origin names one host');
    host = authority.slice(0, close + 1);
    const after = authority.slice(close + 1);
    if (after !== '') {
      if (!after.startsWith(':')) throw new Error('a return origin names one host');
      port = after.slice(1);
    }
  } else {
    const colon = authority.lastIndexOf(':');
    if (colon >= 0) {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    } else host = authority;
  }
  let portNumber = null;
  if (port !== null) {
    portNumber = /^\d{1,5}$/.test(port) ? Number(port) : 0;
    if (portNumber < 1 || portNumber > 65535) throw new Error("a return origin's port is a number from 1 to 65535");
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(host);
  let defaultPort;
  if (scheme === 'https') defaultPort = 443;
  else if (scheme === 'http' && loopback) defaultPort = 80;
  else throw new Error('a return origin is https (plain http only on localhost)');
  const label = (l) => l.length >= 1 && l.length <= 63 && /^[a-z0-9-]+$/.test(l) && !l.startsWith('-') && !l.endsWith('-');
  if (!(loopback || (host.length <= 253 && host.split('.').every(label))))
    throw new Error('a return origin names a DNS host (punycode for a non-ASCII name)');
  return portNumber !== null && portNumber !== defaultPort ? `${scheme}://${host}:${portNumber}` : `${scheme}://${host}`;
}

/**
 * A consent link's return address: https without credentials (plain http on localhost when
 * allowed). A fragment is accepted (a product that routes in the browser returns to a page named
 * there): the origin rules apply to the part before `#`, and the link carries the whole address
 * encoded inside `return` (no raw `#`), signed like the rest.
 */
function checkedReturn(raw, allowLocal) {
  if (raw.length > 2048) throw new Error('return must be an absolute URL of at most 2048 characters');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('return must be an absolute URL');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (!(url.protocol === 'https:' || (url.protocol === 'http:' && local && allowLocal)))
    throw new Error('return must be an https URL (plain http only on localhost, on a development deployment)');
  if (!url.hostname) throw new Error('return must name a host');
  if (url.username || url.password) throw new Error('return must not carry credentials');
  return url;
}

/** The live tenant link of this installation a call names, or a 422 at `path`. */
function ownLink(instance, raw, path) {
  if (!ULID.test(String(raw))) invalid(path, 'a tenant link id');
  const link = instance.links[raw];
  if (!link || link.state === 'unlinked') invalid(path, 'not a live tenant link of this installation');
  return link;
}

/** The link a per-link call names, after the platform's checks on the key's scope. */
function linkFor(key, instance, raw, path) {
  const wide = isInstanceWide(key);
  if (wide && raw) invalid(path, 'an installation-wide integration takes no tenant link');
  if (wide) return null;
  if (!raw) invalid(path, 'a per-link integration names its tenant link', 'required');
  return ownLink(instance, raw, path);
}

const slotOf = (key, link) => (link ? `${key}@${link.id}` : key);

/** Whether a stored state carries a consent or a change (an untouched state is "no state"). */
const written = (s) => Boolean(s && (s.consent_id || s.state !== 'available'));

/**
 * The installation's local deny of `key`: every state of the key goes off on every link (its
 * consents revoked, reason `policy`), and no organization enables it until the deny is lifted.
 */
export function denyKey(state, instance, key) {
  for (const [slot, s] of Object.entries(instance.integrations)) {
    if (slot !== key && !slot.startsWith(`${key}@`)) continue;
    const wasEnabled = s.state === 'enabled';
    const hadConsent = s.consent_id && s.state !== 'revoked';
    if (hadConsent) state.emit(instance, 'ever.consent.consent.revoked', consentEventData(instance, key, s, { revoke_reason: 'policy' }));
    Object.assign(s, { state: 'disabled', enabled: false });
    if (wasEnabled) state.emit(instance, 'ever.consent.integration.disabled', integrationEventData(instance, key, s, 'policy'));
  }
}

/** The local deny list a heartbeat reports (at most 32 keys, or `*`); null when it sends none. */
export function checkedDenyList(raw) {
  if (raw === undefined || raw === null) return null;
  const grammar = (k) => typeof k === 'string' && (k === '*' || /^[a-z0-9_:-]{2,64}$/.test(k));
  if (!Array.isArray(raw) || raw.length > MAX_DENIED || !raw.every(grammar))
    invalid('/integrations_denied', 'at most 32 integration keys, or `*`');
  return [...raw];
}

/** Replaces the deny list; keys it newly names go off (a key it no longer names is lifted). */
export function reportDenyList(state, instance, list) {
  const before = instance.denied ?? [];
  instance.denied = list;
  const keys = contract().constants.integration_keys;
  for (const key of keys) if (denies(instance, key) && !(before.includes('*') || before.includes(key))) denyKey(state, instance, key);
}

export const integrationsHandlers = {
  instanceGetIntegrations({ instance }) {
    const out = { instance: {}, links: {}, catalog_version: String(contract().catalog.version) };
    for (const [slot, s] of Object.entries(instance.integrations)) {
      const [key, linkId] = slot.split('@');
      if (!visible(key)) continue;
      if (!linkId) out.instance[key] = brief(s, instance, key);
      else if (instance.links[linkId] && instance.links[linkId].state !== 'unlinked') {
        out.links[linkId] ??= {};
        out.links[linkId][key] = brief(s, instance, key);
      }
    }
    return { status: 200, body: out, headers: { 'cache-control': 'private, no-store' } };
  },

  instanceGetConsentUrl({ state, config, instance, query }) {
    const key = query.get('integration');
    if (!key) invalid('?integration', 'an integration key', 'required');
    const def = visible(key);
    if (!def) invalid('?integration', 'an integration key');
    if (def.status !== 'active') fail(422, 'integration_not_available', 'this integration is not available yet');
    const link = linkFor(key, instance, query.get('link'), '?link');
    const raw = query.get('return');
    let ret = null;
    if (raw) {
      let checked;
      try {
        checked = checkedReturn(raw, config.consent.allow_local_return);
      } catch (error) {
        invalid('?return', error.message);
      }
      let origin;
      try {
        origin = returnOrigin(checked.origin);
      } catch {
        origin = null;
      }
      if (!origin || !(instance.return_origins ?? []).includes(origin))
        invalid('?return', 'not an origin this installation declared when it connected (return_origins of the redeem)');
      ret = checked.href;
    }
    if (state.faults.consent_links_unavailable) fail(503, 'unavailable', 'consent links are not configured on this deployment');
    const exp = state.now() + 900;
    const params = new URLSearchParams({ instance: instance.id, integration: key });
    if (link) params.append('link', link.id);
    if (ret) params.append('return', ret);
    params.append('exp', String(exp));
    const sig = b64url(createHmac('sha256', LINK_KEY).update(`ever-consent-url:v1\n${params}`).digest());
    params.append('sig', sig);
    return {
      status: 200,
      body: { url: `${config.consent.web_url.replace(/\/$/, '')}/connect/consent?${params}`, expires_at: state.iso(exp) },
    };
  },

  instanceDisableIntegration({ state, instance, params, body }) {
    const key = params.key;
    if (!visible(key)) fail(404, 'not_found', 'unknown integration');
    if (body.enabled !== false)
      invalid('/enabled', 'an installation may only switch an integration off; an owner or admin of the organization enables it');
    if (!['instance', 'policy'].includes(body.reason)) invalid('/reason', '`instance` or `policy`');
    const link = linkFor(key, instance, body.tenant_link_id, '/tenant_link_id');
    const s = instance.integrations[slotOf(key, link)];
    if (body.reason === 'policy') {
      // The key is denied for every organization, on every link, until a heartbeat lifts it.
      if (!denies(instance, key)) {
        instance.denied = [...(instance.denied ?? []), key];
        denyKey(state, instance, key);
      }
      return { status: 200, body: brief(s ?? { state: 'available' }, instance, key) };
    }
    if (!written(s)) fail(404, 'not_found', 'no state for this integration (already off)');
    const wasEnabled = s.state === 'enabled';
    if (s.consent_id && s.state !== 'revoked')
      state.emit(instance, 'ever.consent.consent.revoked', consentEventData(instance, key, s, { revoke_reason: 'instance' }));
    Object.assign(s, { state: 'disabled', enabled: false, revoked_at: state.now() });
    if (wasEnabled) state.emit(instance, 'ever.consent.integration.disabled', integrationEventData(instance, key, s, 'instance'));
    if (key === 'stats_link') instance.stats_linked = false;
    return { status: 200, body: brief(s, instance, key) };
  },

  instanceAcceptIntegration({ state, instance, params, body }) {
    const key = params.key;
    if (!visible(key) || !isInstanceWide(key)) fail(404, 'not_found', 'no installation-wide integration with this key');
    if (!ULID.test(String(body.consent_id))) invalid('/consent_id', 'a consent id');
    const s = instance.integrations[key];
    if (!written(s)) fail(404, 'not_found', 'nothing waits for the operator for this key');
    if (s.operator_accept !== 'pending' || s.consent_id !== body.consent_id)
      fail(409, 'illegal_transition', 'the integration does not wait for this consent');
    if (body.accepted) {
      Object.assign(s, { state: 'enabled', enabled: true, operator_accept: 'accepted' });
      state.emit(instance, 'ever.consent.integration.enabled', integrationEventData(instance, key, s, 'consent'));
    } else {
      Object.assign(s, { state: 'revoked', enabled: false, operator_accept: 'declined', revoked_at: state.now() });
      state.emit(instance, 'ever.consent.consent.revoked', consentEventData(instance, key, s, { revoke_reason: 'operator' }));
    }
    return { status: 200, body: brief(s, instance, key) };
  },
};
