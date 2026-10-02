// Rows 1-4 and 29: the key manifest, the legal texts, redeeming a connect code, the instance token
// and the device-first connect.
import { randomBytes } from 'node:crypto';
import { verifyAssertion } from '../assertion.mjs';
import { b64url, decodeJws, instanceKid, publicKeyFromX, verifyBytes } from '../crypto.mjs';
import { manifestEntry, signManifest, testKey } from '../keys.mjs';
import { createInstance, createLink } from '../model.mjs';
import { fail } from '../problem.mjs';

export const LEGAL = {
  terms_url: 'https://ever.co/legal/terms',
  terms_version: '2026-10',
  dpa_url: 'https://ever.co/legal/dpa',
  dpa_version: '2026-10',
  subprocessors_url: 'https://ever.co/legal/subprocessors',
};

/** The keys the manifest serves: the active entitlement key rotates with /__mock/keys/rotate. */
export function manifestEntries(state) {
  const start = state.config.clock.start - 86400;
  const names = ['entitlement', 'entitlementNext'];
  const active = names[(state.keyGeneration - 1) % 2];
  const previous = state.keyGeneration > 1 ? names[state.keyGeneration % 2] : null;
  const entries = [
    manifestEntry(testKey('assertion'), { notBefore: start }),
    manifestEntry(testKey(active), { notBefore: state.keysRotatedAt ?? start }),
  ];
  if (previous)
    entries.push(manifestEntry(testKey(previous), { state: 'previous', notBefore: start, notAfter: state.keysRotatedAt + 30 * 86400 }));
  entries.push(manifestEntry(testKey('intent'), { notBefore: start }));
  return entries;
}

export const activeEntitlementKey = (state) => testKey(['entitlement', 'entitlementNext'][(state.keyGeneration - 1) % 2]);

const validJwk = (jwk) => {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return false;
  try {
    publicKeyFromX(jwk.x);
    return true;
  } catch {
    return false;
  }
};

function codeInvalid(state, code, ctx) {
  const entry = code ? state.codes.get(code) : null;
  if (entry && !entry.used) {
    entry.wrong_attempts += 1;
    if (entry.wrong_attempts >= state.config.limits.wrong_attempts_per_code) entry.revoked = true;
  }
  const wait = state.hit(`wrong-codes|${ctx.req.socket.remoteAddress}`, state.config.limits.wrong_codes_per_hour, 3600);
  if (wait > 0) fail(429, 'rate_limited', undefined, { retry_after_s: wait });
  fail(422, 'code_invalid');
}

function endpoints(issuer) {
  return {
    token_endpoint: `${issuer}/v1/instances/token`,
    entitlement_endpoint: `${issuer}/v1/instances/me/entitlement`,
    feed_endpoint: `${issuer}/v1/instances/me/events`,
  };
}

function connected(state, instance) {
  state.emit(instance, 'ever.registry.instance.connected', instanceEventData(instance));
}

export function instanceEventData(instance) {
  return {
    instance_id: instance.id,
    org_id: instance.org.id,
    product: instance.product,
    serves_products: instance.serves_products,
    install_source: instance.install_source,
    kind: instance.kind,
    status: instance.status,
    last_seen_bucket: 'now',
    kid: instance.current_key.kid,
  };
}

export const connectHandlers = {
  get_key_manifest({ state, issuer }) {
    if (state.faults.keys_unavailable) fail(503, 'keys_unavailable');
    const iat = state.keysRotatedAt ?? state.config.clock.start;
    return {
      status: 200,
      body: signManifest({ issuer, iat, keys: manifestEntries(state) }),
      headers: { 'cache-control': 'public, max-age=300' },
    };
  },

  getConnectLegal() {
    return { status: 200, body: { ...LEGAL } };
  },

  connectRedeem: Object.assign(
    (ctx) => {
      const { state, body, validation, issuer } = ctx;
      if (body?.product === 'demand') fail(422, 'product_not_supported');
      if (!validation.ok) {
        // A code of the wrong shape answers exactly like an unknown one.
        if (validation.errors.every((e) => e.path === '/code')) codeInvalid(state, null, ctx);
        fail(422, 'validation_failed', undefined, { errors: validation.errors });
      }
      const code = body.code.toUpperCase();
      const entry = state.codes.get(code);
      if (!entry || entry.kind !== 'connect' || entry.used || entry.revoked || entry.expires_at <= state.now())
        codeInvalid(state, code, ctx);
      if (entry.product && entry.product !== body.product) {
        entry.wrong_attempts += 1;
        fail(422, 'product_mismatch');
      }
      if (!validJwk(body.public_jwk)) fail(422, 'public_jwk_invalid');
      const holder = [...state.instances.values()].find(
        (i) => i.current_key.x === body.public_jwk.x || i.previous_key?.x === body.public_jwk.x,
      );
      if (holder?.status === 'active' || holder?.status === 'pending_approval') fail(409, 'already_connected');
      if (holder?.status === 'revoked') fail(422, 'public_jwk_invalid', 'a revoked key is never reused');
      entry.used = true;
      let instance = holder;
      if (instance) {
        instance.status = entry.pending_approval ? 'pending_approval' : 'active';
        state.lastInstanceId = instance.id;
      } else {
        instance = createInstance(state, { ...body, org: entry.org, status: entry.pending_approval ? 'pending_approval' : 'active' });
      }
      let link;
      if (body.tenant?.product_tenant_id) {
        link = createLink(state, instance, { org: entry.org, product: body.product, ...body.tenant, link_method: 'link_code' });
      }
      connected(state, instance);
      const out = { instance_id: instance.id, kid: instance.current_key.kid, status: instance.status, ...endpoints(issuer) };
      if (link) out.link = viewLink(state, link);
      return { status: 201, body: out };
    },
    { ownValidation: true },
  ),

  instanceToken({ state, body, issuer }) {
    if (
      body?.grant_type !== 'client_credentials' ||
      body?.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    )
      fail(401, 'invalid_client');
    const decoded = decodeJws(body.client_assertion);
    const instance = decoded ? state.instances.get(decoded.payload.iss) : null;
    const r = verifyAssertion(body.client_assertion, {
      now: state.now(),
      audience: `${issuer}/v1/instances/token`,
      instanceFor: (iss) => {
        const i = state.instances.get(iss);
        return i ? { current_key: i.current_key, previous_key: i.previous_key, rotated_at: i.rotated_at } : null;
      },
      seenJti: (jti) => state.jti.has(jti),
    });
    if (!r.ok) fail(401, 'invalid_client', `the client assertion was not accepted (${r.reason})`);
    state.jti.set(r.jti, r.exp);
    if (!instance || instance.status === 'disconnected' || instance.status === 'revoked') fail(401, 'credential_revoked');
    return {
      status: 200,
      body: { access_token: state.newToken(instance.id), token_type: 'Bearer', expires_in: 3600 },
      headers: { 'cache-control': 'no-store' },
    };
  },

  connectDevice({ state, body, req }) {
    const wait = state.hit(`device-starts|${req.socket.remoteAddress}`, state.config.limits.device_starts_per_hour, 3600);
    if (wait > 0) fail(429, 'rate_limited', undefined, { retry_after_s: wait });
    if (body.product === 'demand') fail(422, 'product_not_supported');
    if (!validJwk(body.public_jwk)) fail(422, 'public_jwk_invalid');
    const deviceCode = b64url(randomBytes(32));
    const letters = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    const group = () => Array.from(randomBytes(4), (b) => letters[b % 32]).join('');
    const userCode = `EVC-${group()}-${group()}-${group()}`;
    state.devices.set(deviceCode, {
      user_code: userCode,
      request: body,
      approved: false,
      expires_at: state.now() + 900,
      interval: 5,
      last_poll: null,
      done: false,
    });
    return {
      status: 200,
      body: {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: 'https://app.ever.co/connect',
        verification_uri_complete: `https://app.ever.co/connect?code=${userCode}`,
        expires_in: 900,
        interval: 5,
      },
    };
  },

  connectDeviceToken({ state, body, issuer }) {
    const device = state.devices.get(body.device_code);
    if (!device || device.done || device.expires_at <= state.now()) fail(400, 'expired_token');
    const now = state.now();
    if (device.last_poll !== null && now - device.last_poll < device.interval) {
      device.interval += 5;
      device.last_poll = now;
      fail(400, 'slow_down');
    }
    device.last_poll = now;
    if (!device.approved) fail(400, 'authorization_pending');
    const parked = device.request.public_jwk;
    const decoded = decodeJws(body.client_assertion);
    if (!decoded || decoded.header.alg !== 'EdDSA') fail(401, 'invalid_client');
    if (!verifyBytes(parked.x, decoded.signingInput, decoded.signature)) fail(409, 'key_mismatch');
    const kid = instanceKid(parked.x);
    const p = decoded.payload;
    if (
      p.iss !== kid ||
      p.sub !== kid ||
      p.aud !== `${issuer}/v1/connect/token` ||
      !Number.isInteger(p.exp) ||
      p.exp <= now ||
      p.exp - p.iat > 300
    )
      fail(401, 'invalid_client');
    device.done = true;
    const instance = createInstance(state, { ...device.request, org: device.org, status: 'active' });
    connected(state, instance);
    return {
      status: 200,
      body: {
        access_token: state.newToken(instance.id),
        token_type: 'Bearer',
        expires_in: 3600,
        instance_id: instance.id,
        kid: instance.current_key.kid,
        status: instance.status,
        entitlement_endpoint: `${issuer}/v1/instances/me/entitlement`,
        feed_endpoint: `${issuer}/v1/instances/me/events`,
      },
    };
  },
};

function viewLink(state, link) {
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
    unlinked_at: null,
  };
}
