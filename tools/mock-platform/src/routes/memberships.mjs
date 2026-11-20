// Row 38: the current members of the organization a tenant link points at, named as the
// membership events of the instance feed name them (the Ever ID issuer and subject, the product
// user when a person link of this installation names one, the role; never a person id or an
// e-mail). A product reads every page after the feed answered `410 resync_required`. While the
// fault `memberships_module_disabled` stands (a deployment that sends no membership events) the
// route answers `404 module_disabled`, as the platform does.
import { b64url, fromB64url } from '../crypto.mjs';
import { fail } from '../problem.mjs';

const DEFAULT_LIMIT = 25;
const CURSOR_PREFIX = 'm1:';

/** Members in the order pages hand them out: by issuer, then subject (code units, not locale). */
const compare = (a, b) => {
  const x = [a.identity_issuer, a.identity_subject];
  const y = [b.identity_issuer, b.identity_subject];
  if (x[0] !== y[0]) return x[0] < y[0] ? -1 : 1;
  if (x[1] !== y[1]) return x[1] < y[1] ? -1 : 1;
  return 0;
};

/**
 * The members of an organization: what `POST /__mock/memberships` seeded for it, else every
 * configured person (`people`) with their `org_role`.
 */
export function orgMembers(state, orgId) {
  const seeded = state.memberships?.get(orgId);
  const members = seeded ?? state.config.people.map((p) => ({ identity_issuer: p.issuer, identity_subject: p.subject, role: p.org_role }));
  return [...members].sort(compare);
}

/** The product user a person link of this installation names for the identity on this tenant link. */
function productUserRef(instance, linkId, member) {
  const entry = Object.values(instance.person_links).find(
    (e) =>
      e.issuer === member.identity_issuer &&
      e.subject === member.identity_subject &&
      (e.link.tenant_link_id === null || e.link.tenant_link_id === linkId),
  );
  return entry?.link.product_user_ref;
}

/** An opaque cursor: the last member of the page. */
const encodeCursor = (m) => b64url(Buffer.from(CURSOR_PREFIX + JSON.stringify([m.identity_issuer, m.identity_subject]), 'utf8'));

/** The member a cursor names (`null` for no cursor, `undefined` for one this route never handed out). */
function decodeCursor(raw) {
  if (raw === null) return null;
  if (!/^[A-Za-z0-9_-]{1,2048}$/.test(raw)) return undefined;
  const text = fromB64url(raw).toString('utf8');
  if (!text.startsWith(CURSOR_PREFIX)) return undefined;
  try {
    const [issuer, subject] = JSON.parse(text.slice(CURSOR_PREFIX.length));
    if (typeof issuer !== 'string' || typeof subject !== 'string') return undefined;
    return { identity_issuer: issuer, identity_subject: subject };
  } catch {
    return undefined;
  }
}

export const membershipHandlers = {
  // The platform's order: the module switch, `?limit` and `?cursor`, then the link (an active link
  // of the calling installation, else 404).
  instanceListLinkMemberships({ state, instance, params, query }) {
    if (state.faults.memberships_module_disabled) fail(404, 'module_disabled', 'membership events are not sent on this deployment');
    const limit = query.has('limit') ? Number(query.get('limit')) : DEFAULT_LIMIT;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100)
      fail(422, 'validation_failed', undefined, { errors: [{ path: '?limit', code: 'out_of_range', message: '1..100' }] });
    const after = decodeCursor(query.get('cursor'));
    if (after === undefined)
      fail(422, 'validation_failed', 'not a cursor from a previous page', {
        errors: [{ path: '?cursor', code: 'invalid', message: 'not a cursor from a previous page' }],
      });
    const link = instance.links[params.link];
    if (link?.state !== 'active') fail(404, 'not_found', 'no active tenant link of this installation');
    const all = orgMembers(state, link.org_id);
    const rest = after === null ? all : all.filter((m) => compare(m, after) > 0);
    const page = rest.slice(0, limit);
    const items = page.map((m) => {
      const ref = productUserRef(instance, link.id, m);
      return {
        identity_issuer: m.identity_issuer,
        identity_subject: m.identity_subject,
        ...(ref ? { product_user_ref: ref } : {}),
        role: m.role,
      };
    });
    return {
      status: 200,
      body: { tenant_link_id: link.id, items, next_cursor: rest.length > page.length ? encodeCursor(page.at(-1)) : null },
    };
  },
};
