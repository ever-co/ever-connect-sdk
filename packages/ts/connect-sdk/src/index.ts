/**
 * @ever-co/connect-sdk: the managed-operation runner products build their executor on, and the
 * anonymous statistics signer and sender. The client, the entitlement verifier and the lookup
 * hashing are added to this package next; every export here stays.
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
export type {
  SendStatsReportOptions,
  SignedStatsReport,
  StatsErrorCode,
  StatsFieldError,
  StatsSendOutcome,
  StatsSigner,
  StatsString,
  StatsValidation,
} from './stats';
export {
  classifyStatsAnswer,
  generateStatsKey,
  isCalendarDate,
  MAX_STATS_ERRORS,
  MAX_STATS_REPORT_BYTES,
  STATS_ERROR_CODES,
  STATS_HEADERS,
  STATS_REPORTS_PATH,
  STATS_RETRY_DELAYS_S,
  STATS_SIGNATURE_PREFIX,
  StatsValidationError,
  sendStatsReport,
  signStatsReport,
  signStatsReportBytes,
  statsKeyId,
  statsReportsUrl,
  statsSignerFromSeed,
  validateStatsReport,
  validateStatsReportBytes,
  walkStrings,
} from './stats';
