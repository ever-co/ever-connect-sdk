// Row 15: the app mirror (Ever Works). Per-item idempotency on (external_id, external_version);
// bodies above 4 MiB answer 413 before this handler runs.
import { fail } from '../problem.mjs';

export const mirrorHandlers = {
  instanceMirrorApps({ instance, body }) {
    const results = body.ops.map((op) => {
      const current = instance.mirror[op.external_id];
      if (current && current.external_version >= op.external_version)
        return { external_id: op.external_id, outcome: 'ignored_stale', app_id: current.app_id };
      const app_id = current?.app_id ?? `${instance.id.slice(0, 16)}${String(Object.keys(instance.mirror).length).padStart(10, '0')}`;
      instance.mirror[op.external_id] = { external_version: op.external_version, kind: op.kind, deleted: op.op === 'delete', app_id };
      return { external_id: op.external_id, outcome: 'applied', app_id };
    });
    return { status: 200, body: { results } };
  },

  instanceListMirroredApps({ instance, query }) {
    const limit = Number(query.get('limit') ?? 25);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100)
      fail(422, 'validation_failed', undefined, { errors: [{ path: '?limit', code: 'out_of_range', message: '1..100' }] });
    const all = Object.entries(instance.mirror)
      .filter(([, v]) => !v.deleted)
      .map(([external_id, v]) => ({ external_id, external_version: v.external_version, kind: v.kind, org_link_id: null }))
      .sort((a, b) => a.external_id.localeCompare(b.external_id));
    const cursor = query.get('cursor');
    const start = cursor ? all.findIndex((x) => x.external_id > cursor) : 0;
    const items = start < 0 ? [] : all.slice(start, start + limit);
    const next = start >= 0 && start + limit < all.length ? items.at(-1).external_id : null;
    return { status: 200, body: { items, next_cursor: next } };
  },
};
