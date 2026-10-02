/**
 * @ever-co/connect-sdk (skeleton): the managed-operation runner products build their executor on.
 * The client, the entitlement verifier, the statistics signer and the lookup hashing are added to
 * this package next; every export here stays.
 */
export type {
  BackupResult,
  DryRunResult,
  ManagedOperation,
  ManagedOperationExecutor,
  ManagedOperationKind,
  ManagedOperationOutcome,
  ManagedOperationResultSink,
} from './managed/executor';
export { MANAGED_OPERATION_KINDS } from './managed/executor';
export type { ManagedOperationRunnerOptions, RunOutcome, RunReport } from './managed/runner';
export { createManagedOperationRunner, MANAGED_REQUESTED, sanitizeResult } from './managed/runner';
