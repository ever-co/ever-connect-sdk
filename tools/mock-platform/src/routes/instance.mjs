// Rows 6-10 and 16: heartbeat and status, the event feed, entitlement documents, integration
// states and consent links, the local disable, disconnect and connect-key rotation.

import { verifyRotation } from '../assertion.mjs';
import { instanceKid, publicKeyFromX, thumbprint } from '../crypto.mjs';
import { signEntitlement } from '../keys.mjs';
import { activeLinks, instanceView, tenantLinkView } from '../model.mjs';
import { fail } from '../problem.mjs';
import { activeEntitlementKey, instanceEventData, KEY_OVERLAP_S } from './connect.mjs';
import { checkedDenyList, reportDenyList } from './integrations.mjs';

const FEATURES = [
  'handle',
  'discoverability',
  'lookup',
  'profile.public',
  'profile.badges',
  'listings',
  'marketplace.buy',
  'instances.multi',
  'ever_id_login',
  'app_sync',
  'usage_reporting',
  'provider_access',
];
const LIMITS = {
  'instances.connected': 5,
  'listings.published': 0,
  'api.rpm': 600,
  members: 25,
  'webhooks.endpoints': 5,
  'lookup.hashes_per_day': 6000,
  'lookup.queries_per_min': 60,
};

/** Entitlement claims for the installation (`instance:`) or one of its links (`link:`). */
export function entitlementClaims(state, instance, link = null) {
  const e = state.config.entitlement;
  const seq = instance.entitlement_seq[link ? link.id : 'instance'];
  const iat = state.now();
  const ever = {
    schema: 'ever.entitlement.v1',
    seq,
    org_id: link ? link.org_id : instance.org.id,
    handle: link ? link.org_handle : instance.org.handle,
    tenant_id: instance.org.id,
    instance_id: instance.id,
    tier: e.tier,
    plan: e.plan,
    products: instance.serves_products.filter((p) => p !== 'demand'),
    features: Object.fromEntries(FEATURES.map((f) => [f, Boolean(e.features[f])])),
    limits: { ...LIMITS },
    meters: { 'instances.connected': { used: 1, period: null } },
    managed: e.managed,
    grace_s: 2592000,
    refresh_after_s: 21600,
  };
  if (link) {
    ever.tenant_link_id = link.id;
    ever.tenant = {
      product: link.product,
      product_tenant_id: link.product_tenant_id,
      ...(link.product_org_id ? { product_org_id: link.product_org_id } : {}),
    };
  }
  return {
    iss: state.config.issuer,
    aud: 'ever-connect',
    sub: link ? `link:${link.id}` : `instance:${instance.id}`,
    jti: state.ulid('entitlement'),
    iat,
    nbf: iat - 60,
    exp: iat + 604800,
    ever,
  };
}

function entitlementAnswer(ctx, link) {
  const { state, instance, headers } = ctx;
  // As on the platform: per installation and path, a bucket of six refilled one every 10 minutes.
  const wait = state.bucket(`entitlement|${instance.id}|${link?.id ?? 'instance'}`, state.config.limits.entitlement_reads_per_hour, 3600);
  if (wait > 0) fail(429, 'rate_limited', undefined, { retry_after_s: wait });
  const seq = instance.entitlement_seq[link ? link.id : 'instance'];
  const inm = headers['if-none-match'];
  if (inm && inm.replace(/"/g, '') === String(seq)) return { status: 304, headers: { etag: `"${seq}"` } };
  const claims = entitlementClaims(state, instance, link);
  return {
    status: 200,
    headers: { etag: `"${seq}"` },
    body: {
      document: signEntitlement(claims, activeEntitlementKey(state)),
      seq,
      issued_at: state.iso(claims.iat),
      expires_at: state.iso(claims.exp),
      refresh_after_s: 21600,
    },
  };
}

function eventsAfter(instance, after) {
  if (after === null || after === undefined) {
    const start = instance.acked === null ? 0 : instance.feed.findIndex((e) => e.id === instance.acked) + 1;
    return instance.feed.slice(start);
  }
  const i = instance.feed.findIndex((e) => e.id === after);
  if (i < 0) return null;
  return instance.feed.slice(i + 1);
}

export const instanceHandlers = {
  getInstanceSelf({ state, instance }) {
    return {
      status: 200,
      body: { instance: instanceView(state, instance), tenant_links: activeLinks(instance).map((l) => tenantLinkView(state, l)) },
    };
  },

  instanceHeartbeat({ state, instance, body }) {
    const now = state.now();
    if (instance.last_heartbeat !== null && now - instance.last_heartbeat < state.config.limits.heartbeat_min_interval_s) {
      const wait = instance.last_heartbeat + state.config.limits.heartbeat_min_interval_s - now;
      fail(429, 'rate_limited', 'more than one heartbeat a minute', { retry_after_s: wait });
    }
    // The operator's local deny list: the whole list each time (a key it no longer names is lifted).
    const denied = checkedDenyList(body.integrations_denied);
    instance.last_heartbeat = now;
    instance.last_seen_at = now;
    instance.version = body.version;
    if (Array.isArray(body.serves_products)) instance.serves_products = body.serves_products;
    if (denied !== null) reportDenyList(state, instance, denied);
    if (!instance.seen_once) {
      instance.seen_once = true;
      state.emit(instance, 'ever.registry.instance.seen', instanceEventData(instance));
    }
    return { status: 200, body: { server_time: state.iso(now), recorded: true, notices: [] } };
  },

  async instancePollEvents(ctx) {
    const { state, instance, query } = ctx;
    const errors = [];
    const after = query.get('after');
    const wait = query.has('wait') ? Number(query.get('wait')) : 25;
    const limit = query.has('limit') ? Number(query.get('limit')) : 50;
    if (after !== null && after.length > 64) errors.push({ path: '?after', code: 'too_long', message: 'at most 64 characters' });
    if (!Number.isInteger(wait) || wait < 0 || wait > 25) errors.push({ path: '?wait', code: 'out_of_range', message: '0..25' });
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) errors.push({ path: '?limit', code: 'out_of_range', message: '1..100' });
    if (errors.length > 0) fail(422, 'validation_failed', undefined, { errors });
    let events = eventsAfter(instance, after);
    if (events === null) fail(410, 'resync_required', undefined, { last_id: instance.feed.at(-1)?.id ?? '' });
    if (events.length === 0 && wait > 0) {
      // Long-poll: answer as soon as an event arrives, or after `wait` seconds.
      await new Promise((resolve) => {
        const timer = setTimeout(done, wait * 1000);
        function done() {
          clearTimeout(timer);
          state.waiters.delete(listener);
          resolve();
        }
        function listener(id) {
          if (id === instance.id) done();
        }
        state.waiters.add(listener);
        ctx.req.on('close', done);
      });
      events = eventsAfter(instance, after) ?? [];
    }
    const page = events.slice(0, limit);
    const last = page.at(-1)?.id ?? after ?? instance.acked ?? '';
    return { status: 200, body: { events: page, last_id: last, has_more: events.length > page.length } };
  },

  instanceAckEvents({ instance, body }) {
    const i = instance.feed.findIndex((e) => e.id === body.last_id);
    if (i < 0)
      fail(422, 'validation_failed', 'unknown cursor', {
        errors: [{ path: '/last_id', code: 'invalid', message: 'not a cursor of this feed' }],
      });
    const current = instance.acked === null ? -1 : instance.feed.findIndex((e) => e.id === instance.acked);
    if (i > current) instance.acked = body.last_id;
    return { status: 200, body: { acknowledged: instance.acked } };
  },

  instanceGetEntitlement(ctx) {
    return entitlementAnswer(ctx, null);
  },

  instanceGetLinkEntitlement(ctx) {
    const link = ctx.instance.links[ctx.params.link];
    if (!link || link.state === 'unlinked') fail(404, 'not_found', 'no such link on this installation');
    return entitlementAnswer(ctx, link);
  },

  instanceDisconnect({ state, instance }) {
    instance.status = 'disconnected';
    instance.disconnected_at = state.now();
    state.revokeTokens(instance.id);
    for (const l of activeLinks(instance)) l.state = 'suspended';
    // The statistics link ends with the connection.
    instance.stats_linked = false;
    instance.stats_instance_id = null;
    state.emit(instance, 'ever.registry.instance.disconnected', instanceEventData(instance));
    return {
      status: 200,
      body: { instance: instanceView(state, instance), tenant_links: activeLinks(instance).map((l) => tenantLinkView(state, l)) },
    };
  },

  // The platform's rotation: an instance token alone never rotates a key. Order: the new key's
  // shape (422), the two proofs (401 invalid_client: signed with the current key and with the new
  // key, for the rotation endpoint, binding the new key, each jti once), then the key itself (422
  // for the current key or any key an installation holds or held).
  instanceRotateKey({ state, instance, body, issuer }) {
    const jwk = body.public_jwk;
    if (jwk?.kty !== 'OKP' || jwk.crv !== 'Ed25519' || 'd' in jwk) fail(422, 'public_jwk_invalid', 'not an Ed25519 public key');
    try {
      publicKeyFromX(jwk.x);
    } catch {
      fail(422, 'public_jwk_invalid', 'not an Ed25519 public key');
    }
    const now = state.now();
    const proofs = verifyRotation(body.current_key_proof, body.new_key_proof, {
      now,
      audience: `${issuer}/v1/instances/me/keys`,
      instanceId: instance.id,
      currentKey: instance.current_key,
      newKey: { x: jwk.x, kid: instanceKid(jwk.x) },
      thumbprint: thumbprint(jwk.x),
    });
    if (!proofs.ok) fail(401, 'invalid_client', `the rotation's proofs were not accepted (${proofs.reason})`);
    // Each proof is single use, recorded one after the other: a captured rotation is never replayed.
    for (const [i, jti] of proofs.jtis.entries()) {
      if (state.jti.has(jti)) fail(401, 'invalid_client', "the rotation's proofs were not accepted (replay)");
      state.jti.set(jti, proofs.exp[i]);
    }
    if (jwk.x === instance.current_key.x || state.heldKeys.has(jwk.x))
      fail(422, 'public_jwk_invalid', 'the current key, or a key an installation holds or held');
    // One replaced key is kept: rotating again inside the overlap drops the older key at once, and
    // every token it minted stops (keyAccepted); a token of the replaced key stops when its overlap ends.
    instance.previous_key = instance.current_key;
    instance.current_key = { x: jwk.x, kid: instanceKid(jwk.x) };
    instance.rotated_at = now;
    state.heldKeys.add(jwk.x);
    state.emit(instance, 'ever.registry.instance.key_rotated', instanceEventData(instance));
    return {
      status: 200,
      body: {
        kid: instance.current_key.kid,
        previous_kid: instance.previous_key.kid,
        previous_valid_until: state.iso(now + KEY_OVERLAP_S),
      },
    };
  },
};
