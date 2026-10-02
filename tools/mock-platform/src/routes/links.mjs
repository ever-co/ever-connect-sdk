// Row 5: tenant links (link codes), unlink and re-key.
import { activeLinks, createLink, tenantLinkView } from '../model.mjs';
import { fail } from '../problem.mjs';

const linkEventData = (link) => ({
  tenant_link_id: link.id,
  org_id: link.org_id,
  instance_id: link.instance_id,
  product: link.product,
  product_tenant_id: link.product_tenant_id,
  product_org_id: link.product_org_id,
  state: link.state,
  link_method: link.link_method,
});

export const linkHandlers = {
  instanceCreateTenantLink({ state, instance, body }) {
    const code = body.link_code.toUpperCase();
    const entry = state.codes.get(code);
    if (!entry || entry.kind !== 'link' || entry.used || entry.revoked || entry.expires_at <= state.now()) fail(422, 'code_invalid');
    if (entry.product && entry.product !== body.product) fail(422, 'product_mismatch');
    const dup = activeLinks(instance).find(
      (l) => l.product_tenant_id === body.product_tenant_id && (l.product_org_id ?? null) === (body.product_org_id ?? null),
    );
    if (dup) fail(409, 'already_linked');
    entry.used = true;
    const link = createLink(state, instance, { org: entry.org, ...body, link_method: 'link_code' });
    state.emit(instance, 'ever.registry.tenant_link.created', linkEventData(link), { subject: { kind: 'tenant_link', id: link.id } });
    return { status: 201, body: tenantLinkView(state, link) };
  },

  instanceUnlinkTenantLink({ state, instance, params }) {
    const link = instance.links[params.link];
    if (!link || link.state === 'unlinked') fail(404, 'not_found', 'no such link on this installation');
    link.state = 'unlinked';
    link.unlinked_at = state.now();
    for (const [slot, s] of Object.entries(instance.integrations))
      if (slot.endsWith(`@${link.id}`)) Object.assign(s, { state: 'disabled', enabled: false });
    state.emit(instance, 'ever.registry.tenant_link.unlinked', linkEventData(link), { subject: { kind: 'tenant_link', id: link.id } });
    return { status: 204 };
  },

  instanceRekeyTenantLink({ state, instance, params, body }) {
    const link = instance.links[params.link];
    if (!link || link.state === 'unlinked') fail(404, 'not_found', 'no such link on this installation');
    link.product_tenant_id = body.product_tenant_id;
    return { status: 200, body: tenantLinkView(state, link) };
  },
};
