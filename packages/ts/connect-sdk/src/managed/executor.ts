/**
 * Managed operations: what a product implements to run an operation an owner or admin requested
 * from app.ever.co (an update, a backup, a restore check, a health report), on the installation's
 * own hardware, through its own outbound connection. The runner (runner.ts) decides whether an
 * operation runs at all; the executor only does the work.
 */
import type { EventDataByType, ManagedOperationResult } from '@ever-co/connect-contracts';

/** The data of an `ever.registry.managed_operation.requested` event. */
export type ManagedOperation = EventDataByType['ever.registry.managed_operation.requested'];

export type ManagedOperationKind = ManagedOperation['kind'];

export const MANAGED_OPERATION_KINDS = [
  'update',
  'backup',
  'restore_check',
  'health_report',
] as const satisfies readonly ManagedOperationKind[];

/** The answer of a dry run: `ok: false` stops the operation before anything changes. */
export interface DryRunResult {
  readonly ok: boolean;
  /** A short, non-identifying reason (no file name, path or customer data). */
  readonly reason?: string;
}

/** The backup taken before an update; the reference and size stay in the installation's storage. */
export interface BackupResult {
  readonly ok: boolean;
  readonly artefact_ref?: string;
  readonly size_bytes?: number;
}

/** What an executor reports back: status, version and sizes only. */
export interface ManagedOperationOutcome {
  readonly status: 'succeeded' | 'failed';
  /** The product version after an update. */
  readonly version?: string;
  /** An opaque reference of a backup in the customer's own storage. */
  readonly artefact_ref?: string;
  readonly size_bytes?: number;
}

/**
 * Implemented by a product. Every hook may throw; the runner turns a throw into a failed result.
 */
export interface ManagedOperationExecutor {
  /** The kinds this installation can run; any other kind is refused without running anything. */
  kinds(): readonly ManagedOperationKind[];
  /** Checks that the operation can run now; always called first. */
  dryRun(op: ManagedOperation): Promise<DryRunResult>;
  /** Takes a backup; called before every update, after a successful dry run. */
  backupBeforeUpdate(op: ManagedOperation): Promise<BackupResult>;
  /** Runs the operation. */
  execute(op: ManagedOperation): Promise<ManagedOperationOutcome>;
}

/**
 * Sends the result call (`POST /v1/instances/me/managed-operations/{operation}/result`); the
 * product wires it to its Ever Platform client. The runner calls it at most once per operation.
 */
export type ManagedOperationResultSink = (operationId: string, result: ManagedOperationResult) => Promise<void>;
