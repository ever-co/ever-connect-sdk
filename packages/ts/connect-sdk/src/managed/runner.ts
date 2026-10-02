/**
 * The managed-operation runner: consumes `ever.registry.managed_operation.requested` events from
 * the installation's feed and runs each operation through the product's executor, outbound-only.
 *
 * Rules, in order:
 *   1. only `managed_operation.requested` events are handled; every other type is ignored;
 *   2. the event data is validated against the vendored event schema (closed per-kind params);
 *      an invalid operation, or a kind the executor does not run, gets one `failed` result and
 *      nothing runs;
 *   3. an operation past its `expires_at` never runs (the platform expires it); one before its
 *      `not_before` is deferred for the product's scheduler;
 *   4. the dry run always runs first; a failed dry run is a `failed` result;
 *   5. every `update` takes `backupBeforeUpdate` before it executes; a failed backup is a `failed`
 *      result and the update never executes; `dry_run_only` updates stop after the dry run;
 *   6. exactly one result is posted per operation (a repeated delivery is ignored), carrying
 *      status, version and sizes only.
 *
 * The runner opens no listener and makes no request itself: the result sink the product passes in
 * is the only way out.
 */
import { EVENT_SCHEMAS, type EventEnvelope, type ManagedOperationResult } from '@ever-co/connect-contracts';
import Ajv2020 from 'ajv/dist/2020';
import type { ManagedOperation, ManagedOperationExecutor, ManagedOperationOutcome, ManagedOperationResultSink } from './executor';

export const MANAGED_REQUESTED = 'ever.registry.managed_operation.requested';

export type RunOutcome =
  | 'ignored'
  | 'duplicate'
  | 'refused_invalid'
  | 'refused_kind'
  | 'expired'
  | 'deferred'
  | 'dry_run_failed'
  | 'dry_run_only'
  | 'backup_failed'
  | 'executed'
  | 'execute_failed';

export interface RunReport {
  readonly outcome: RunOutcome;
  readonly operationId?: string;
  /** The result posted, when one was. */
  readonly result?: ManagedOperationResult;
  /** The executor hooks called, in order (for audit and tests). */
  readonly calls: readonly ('dryRun' | 'backupBeforeUpdate' | 'execute')[];
}

export interface ManagedOperationRunnerOptions {
  readonly executor: ManagedOperationExecutor;
  readonly postResult: ManagedOperationResultSink;
  /** Seconds since the epoch; defaults to the system clock. */
  readonly now?: () => number;
}

const ARTEFACT_REF = /^[A-Za-z0-9._:-]{1,64}$/;
const SEMVER = /^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-[0-9A-Za-z.]{1,16})?$/;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

let compiled: ((data: unknown) => boolean) | null = null;

function validator(): (data: unknown) => boolean {
  if (compiled) return compiled;
  const ajv = new Ajv2020({ strict: true, strictTypes: false, allErrors: false });
  ajv.addSchema(EVENT_SCHEMAS.common as object);
  compiled = ajv.compile(EVENT_SCHEMAS.data[MANAGED_REQUESTED] as object) as (data: unknown) => boolean;
  return compiled;
}

/** Status, version and sizes only: anything else an executor returns is dropped. */
export function sanitizeResult(outcome: ManagedOperationOutcome): ManagedOperationResult {
  const result: { status: ManagedOperationOutcome['status']; version?: string; artefact_ref?: string; size_bytes?: number } = {
    status: outcome.status === 'succeeded' ? 'succeeded' : 'failed',
  };
  if (typeof outcome.version === 'string' && SEMVER.test(outcome.version)) result.version = outcome.version;
  if (typeof outcome.artefact_ref === 'string' && ARTEFACT_REF.test(outcome.artefact_ref)) result.artefact_ref = outcome.artefact_ref;
  if (Number.isSafeInteger(outcome.size_bytes) && (outcome.size_bytes as number) >= 0) result.size_bytes = outcome.size_bytes as number;
  return result as ManagedOperationResult;
}

const seconds = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

export function createManagedOperationRunner(options: ManagedOperationRunnerOptions) {
  const { executor, postResult } = options;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const handled = new Set<string>();

  async function post(operationId: string, outcome: ManagedOperationOutcome): Promise<ManagedOperationResult> {
    const result = sanitizeResult(outcome);
    handled.add(operationId);
    await postResult(operationId, result);
    return result;
  }

  return {
    /** Handles one feed event; answers what happened. Never throws for an executor failure. */
    async handle(event: Pick<EventEnvelope, 'type' | 'data'>): Promise<RunReport> {
      const calls: ('dryRun' | 'backupBeforeUpdate' | 'execute')[] = [];
      if (event.type !== MANAGED_REQUESTED) return { outcome: 'ignored', calls };
      const data = event.data as Record<string, unknown>;
      const operationId = typeof data?.operation_id === 'string' && ULID.test(data.operation_id) ? data.operation_id : undefined;
      if (operationId && handled.has(operationId)) return { outcome: 'duplicate', operationId, calls };
      if (!validator()(data)) {
        if (!operationId) return { outcome: 'refused_invalid', calls };
        return { outcome: 'refused_invalid', operationId, calls, result: await post(operationId, { status: 'failed' }) };
      }
      const op = data as unknown as ManagedOperation;
      const id = op.operation_id;
      if (!executor.kinds().includes(op.kind))
        return { outcome: 'refused_kind', operationId: id, calls, result: await post(id, { status: 'failed' }) };
      if (now() >= seconds(op.expires_at)) return { outcome: 'expired', operationId: id, calls };
      if (op.not_before && now() < seconds(op.not_before)) return { outcome: 'deferred', operationId: id, calls };
      try {
        calls.push('dryRun');
        const dry = await executor.dryRun(op);
        if (!dry.ok) return { outcome: 'dry_run_failed', operationId: id, calls, result: await post(id, { status: 'failed' }) };
        const params = op.params as { dry_run_only?: boolean };
        if (op.kind === 'update' && params.dry_run_only === true)
          return { outcome: 'dry_run_only', operationId: id, calls, result: await post(id, { status: 'succeeded' }) };
        if (op.kind === 'update') {
          calls.push('backupBeforeUpdate');
          const backup = await executor.backupBeforeUpdate(op);
          if (!backup.ok) return { outcome: 'backup_failed', operationId: id, calls, result: await post(id, { status: 'failed' }) };
        }
        calls.push('execute');
        const outcome = await executor.execute(op);
        return {
          outcome: outcome.status === 'succeeded' ? 'executed' : 'execute_failed',
          operationId: id,
          calls,
          result: await post(id, outcome),
        };
      } catch {
        if (handled.has(id)) return { outcome: 'execute_failed', operationId: id, calls };
        return { outcome: 'execute_failed', operationId: id, calls, result: await post(id, { status: 'failed' }) };
      }
    },
  };
}
