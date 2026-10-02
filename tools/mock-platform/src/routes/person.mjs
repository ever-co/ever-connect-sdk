// Rows 19, 22 and 23: person links, identity resolution, and the two reads a product makes with
// the token of a person who signed in with Ever ID (TEST tokens from /__mock/person-token).
import { verifyJws } from '../crypto.mjs';
import { testKey } from '../keys.mjs';
import { activeLinks } from '../model.mjs';
import { fail } from '../problem.mjs';

/** The claims of a TEST person token in the Authorization header, or a 401. */
export function personClaims(ctx) {
  const h = ctx.headers.authorization;
  const token = typeof h === 'string' ? /^Bearer\s+(\S+)$/i.exec(h)?.[1] : null;
  const decoded = token ? verifyJws(token, testKey('identity').x, { typ: 'JWT' }) : null;
  if (!decoded || !Number.isInteger(decoded.payload.exp) || decoded.payload.exp <= ctx.state.now())
    fail(401, 'unauthorized', 'no valid Ever ID token');
  return decoded.payload;
}

function context(state, claims, instance) {
  const person = state.config.people.find((p) => p.subject === claims.sub) ?? {
    person_id: claims['urn:ever:person_id'],
    org_role: claims.role ?? 'owner',
  };
  const links = instance ? activeLinks(instance) : [];
  const orgs = [...new Map(links.map((l) => [l.org_id, l])).values()].map((l) => ({
    id: l.org_id,
    handle: l.org_handle,
    role: person.org_role,
    tenant_id: l.org_id,
    identity_tier: 'personal',
    enforce_for_members: false,
    links: [
      {
        instance_id: l.instance_id,
        product: l.product,
        product_tenant_id: l.product_tenant_id,
        product_org_id: l.product_org_id,
        tenant_link_id: l.id,
      },
    ],
  }));
  return {
    person: { id: person.person_id, display_name: 'Ever ID user', status: 'active' },
    identity: { issuer: claims.iss, subject: claims.sub, kind: 'personal', enterprise_org_id: null },
    identities: [
      {
        kind: 'personal',
        issuer: claims.iss,
        subject_hint: `…${String(claims.sub).slice(-4)}`,
        linked_at: state.iso(state.config.clock.start),
      },
    ],
    tenants: orgs.map((o) => ({ id: o.tenant_id, role: o.role })),
    orgs: orgs.map((o) => ({ ...o, links: o.links.map(({ tenant_link_id: _drop, ...rest }) => rest) })),
    orgs_filtered: [],
    computed_at: state.now(),
    raw_orgs: orgs,
  };
}

const contextBody = ({ raw_orgs: _raw, ...body }) => body;

const instanceOfAzp = (state, claims) => {
  const m = /^inst-([0-9A-HJKMNP-TV-Z]{26})$/.exec(claims.azp ?? '');
  return m ? state.instances.get(m[1]) : null;
};

export const personHandlers = {
  instanceCreatePersonLink({ state, instance, body }) {
    const id = state.ulid('person-link');
    const person = state.config.people.find((p) => p.issuer === body.identity_issuer && p.subject === body.identity_subject);
    const link = {
      id,
      person_id: person?.person_id ?? state.ulid('person'),
      instance_id: instance.id,
      tenant_link_id: body.tenant_link_id ?? null,
      product_user_ref: body.product_user_ref,
      product_tenant_id: body.product_tenant_id ?? null,
      product_org_id: body.product_org_id ?? null,
      display_name: body.display_name ?? null,
      link_method: body.link_method,
      linked_at: state.iso(),
      unlinked_at: null,
    };
    instance.person_links[body.product_user_ref] = link;
    return { status: 201, body: link };
  },

  instanceDeletePersonLink({ instance, params }) {
    if (!instance.person_links[params.ref]) fail(404, 'not_found', 'no person link with this reference');
    delete instance.person_links[params.ref];
    return { status: 204 };
  },

  resolveIdentity({ state, instance, body }) {
    const person = state.config.people.find((p) => p.issuer === body.issuer && p.subject === body.subject);
    if (!person) fail(404, 'not_found', 'no Ever ID with this issuer and subject');
    return { status: 200, body: contextBody(context(state, { iss: body.issuer, sub: body.subject }, instance)) };
  },

  getMyContext(ctx) {
    const claims = personClaims(ctx);
    return { status: 200, body: contextBody(context(ctx.state, claims, instanceOfAzp(ctx.state, claims))) };
  },

  listMyMemberships(ctx) {
    const claims = personClaims(ctx);
    const c = context(ctx.state, claims, instanceOfAzp(ctx.state, claims));
    return {
      status: 200,
      body: {
        items: c.raw_orgs.map((o) => ({
          org_id: o.id,
          handle: o.handle,
          display_name: o.handle,
          role: o.role,
          state: 'active',
          tenant_id: o.tenant_id,
          identity_tier: o.identity_tier,
          links: o.links.map((x) => ({
            instance_id: x.instance_id,
            tenant_link_id: x.tenant_link_id,
            product: x.product,
            product_tenant_id: x.product_tenant_id,
            product_org_id: x.product_org_id,
          })),
        })),
      },
    };
  },
};
