// Rows 12 and 13: discoverable identifiers of a link, the published salts and vectors, and the
// counterparty lookup (salted hashes only; answers only configured opt-ins).
import { contract } from '../contract.mjs';
import { fromB64url, sha256Hex } from '../crypto.mjs';
import { fail } from '../problem.mjs';

const hashOf = (salt, kind, normalized) => sha256Hex(Buffer.concat([fromB64url(salt), Buffer.from(`:${kind}:${normalized}`, 'utf8')]));

export const lookupHandlers = {
  instancePutLinkIdentifiers({ state, instance, params, body }) {
    const link = instance.links[params.link];
    if (!link || link.state === 'unlinked') fail(404, 'not_found', 'no such link on this installation');
    for (const h of body.hashes) if (state.config.lookup.claimed_hashes.includes(h.hash)) fail(409, 'identifier_claimed');
    instance.identifiers[link.id] = body.hashes;
    return {
      status: 200,
      body: {
        items: body.hashes.map((h, i) => ({
          id: `${link.id.slice(0, 20)}${String(i).padStart(6, '0')}`,
          kind: h.kind,
          discoverable: true,
          provenance: 'instance',
          created_at: state.iso(),
        })),
      },
    };
  },

  instanceDeleteLinkIdentifiers({ instance, params }) {
    const link = instance.links[params.link];
    if (!link || link.state === 'unlinked') fail(404, 'not_found', 'no such link on this installation');
    delete instance.identifiers[link.id];
    return { status: 204 };
  },

  getLookupSalt({ state, issuer }) {
    return {
      status: 200,
      headers: { 'cache-control': 'public, max-age=300' },
      body: {
        active: state.config.lookup.salt_versions.map((s) => ({
          version: s.version,
          salt: s.salt,
          active_from: s.active_from,
          retire_after: s.retire_after ?? null,
        })),
        normalization_version: 1,
        test_vectors_url: `${issuer}/v1/lookup/test-vectors`,
      },
    };
  },

  getLookupTestVectors() {
    const v = contract().lookupVectors;
    return {
      status: 200,
      headers: { 'cache-control': 'public, max-age=300' },
      body: { normalization_version: v.normalization_version, salt_version: v.salt_version, salt: v.salt, vectors: v.vectors },
    };
  },

  lookupCounterparties: Object.assign(
    (ctx) => {
      const { state, instance, headers, body, validation } = ctx;
      const linkId = headers['ever-link-id'];
      if (!linkId)
        fail(422, 'validation_failed', 'the Ever-Link-Id header is required', {
          errors: [{ path: '#Ever-Link-Id', code: 'required', message: 'required' }],
        });
      if (!validation.ok) {
        if (validation.errors.every((e) => e.path.startsWith('/hashes')))
          fail(422, 'hashes_invalid', undefined, { errors: validation.errors });
        fail(422, 'validation_failed', undefined, { errors: validation.errors });
      }
      const s = instance.integrations[`counterparty_lookup@${linkId}`];
      if (!s || !instance.links[linkId]) fail(403, 'integration_disabled', 'counterparty_lookup is not enabled for this link');
      if (s.state === 'revoked') fail(403, 'integration_revoked');
      if (s.state !== 'enabled') fail(403, 'integration_disabled', 'counterparty_lookup is not enabled for this link');
      if (!state.config.entitlement.features.lookup) fail(403, 'entitlement_required');
      if ((state.config.lookup.retired_versions ?? []).includes(body.salt_version)) fail(422, 'salt_version_retired');
      const salt = state.config.lookup.salt_versions.find((x) => x.version === body.salt_version);
      if (!salt) fail(422, 'salt_version_unknown');
      const wait = state.hit(`lookup|${instance.id}`, state.config.limits.lookup_queries_per_min, 60);
      if (wait > 0) fail(429, 'rate_limited', undefined, { retry_after_s: wait });
      const matches = [];
      for (const o of state.config.lookup.optins) {
        const h = hashOf(salt.salt, o.kind, o.normalized);
        if (body.hashes.includes(h)) matches.push({ hash: h, handle: o.handle, features: o.features });
      }
      return { status: 200, body: { salt_version: body.salt_version, matches } };
    },
    { ownValidation: true },
  ),
};
