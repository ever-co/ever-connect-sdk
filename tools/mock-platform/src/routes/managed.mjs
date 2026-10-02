// Row 34: the result of a managed operation. Operations are requested through
// POST /__mock/managed/request, which puts ever.registry.managed_operation.requested on the feed;
// the result call moves the operation through accepted -> running -> succeeded | failed. An
// operation past its expires_at is expired and accepts no result.
import { fail } from '../problem.mjs';

const NEXT = {
  requested: ['accepted', 'running', 'succeeded', 'failed'],
  accepted: ['running', 'succeeded', 'failed'],
  running: ['succeeded', 'failed'],
  succeeded: [],
  failed: [],
  expired: [],
  cancelled: [],
};

export function expireOperations(state) {
  for (const op of state.operations.values()) {
    if (op.state === 'requested' || op.state === 'accepted') {
      if (state.now() >= op.expires_at) {
        op.state = 'expired';
        const instance = state.instances.get(op.instance_id);
        if (instance)
          state.emit(instance, 'ever.registry.managed_operation.state_changed', stateChangedData(op), {
            subject: { kind: 'managed_operation', id: op.id },
          });
      }
    }
  }
}

export function stateChangedData(op) {
  const data = { operation_id: op.id, org_id: op.org_id, instance_id: op.instance_id, kind: op.kind, state: op.state };
  if (op.version) data.version = op.version;
  if (op.artefact_ref) data.artefact_ref = op.artefact_ref;
  if (Number.isInteger(op.size_bytes)) data.size_bytes = op.size_bytes;
  return data;
}

export const managedHandlers = {
  instanceReportManagedOperationResult({ state, instance, params, body }) {
    expireOperations(state);
    const op = state.operations.get(params.operation);
    if (!op || op.instance_id !== instance.id) fail(404, 'not_found', 'no such operation of this installation');
    if (op.state === body.status) return { status: 200, body: {} };
    if (!NEXT[op.state].includes(body.status)) fail(409, 'illegal_transition', `${op.state} cannot become ${body.status}`);
    Object.assign(op, {
      state: body.status,
      version: body.version ?? op.version,
      artefact_ref: body.artefact_ref ?? op.artefact_ref,
      size_bytes: body.size_bytes ?? op.size_bytes,
    });
    op.results.push({ status: body.status, at: state.now() });
    state.emit(instance, 'ever.registry.managed_operation.state_changed', stateChangedData(op), {
      subject: { kind: 'managed_operation', id: op.id },
    });
    return { status: 200, body: {} };
  },
};
