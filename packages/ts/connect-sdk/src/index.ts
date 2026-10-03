/**
 * @ever-co/connect-sdk: the Ever Platform client of an Ever product installation (every call made
 * over the generated operation table, behind the egress guard), the key manifest and entitlement
 * verifier, the client assertion, lookup normalisation and hashing, the usage reading validator,
 * the anonymous statistics signer and sender, and the managed-operation runner. Nothing runs at
 * import.
 */

export { CONSTANTS, FEED_EVENT_TYPES, INTEGRATIONS, SCHEMAS } from '@ever-co/connect-contracts';
export type { ClientAssertionOptions, KeyRotationOptions } from './assertion';
export { jwkThumbprint, signClientAssertion, signKeyRotation, subjectHash } from './assertion';
export type { CallInput, EverPlatformClient, EverPlatformClientOptions, NotModified, RequestBody, ResponseBody } from './client';
export { createEverPlatformClient, resolveRootKeys } from './client';
export { codes, scopeTable } from './codes';
export type { CachedEntitlement, EntitlementStatus, VerifiedEntitlement, VerifyEntitlementOptions } from './entitlement';
export { entitlementStatus, verifyEntitlement } from './entitlement';
export type { EntitlementErrorCode, KeyManifestErrorCode } from './errors';
export {
  AssertionError,
  EgressRefusedError,
  EntitlementError,
  KeyManifestError,
  LookupInputError,
  LookupVectorError,
  NotConnectedError,
  ProblemError,
  RequestRefusedError,
  ResponseTooLargeError,
  TimeoutError,
  UsageValidationError,
} from './errors';
export type { HeaderRule, OperationAuth, OperationId, OperationSpec } from './generated/operations';
export { OPERATIONS, SDK_VERSION } from './generated/operations';
export type { Ed25519PublicJwk, InstanceSigner } from './keys';
export { generateInstanceKeyPair, keyIdFromPublicJwk, makeNodeSigner, publicJwkOf } from './keys';
export type { KeySetUpdate, StoredKeySet } from './keyset';
export { KeySet } from './keyset';
export { isLocalHost } from './local';
export type { LookupHash, LookupKind, LookupSalt, LookupTestVectors } from './lookup';
export { checkTestVectors, hashIdentifier, LOOKUP_KINDS, lookupHash, NORMALIZATION_VERSION, normalizeIdentifier } from './lookup';
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
export type { KeyManifestDocument, ManifestKey, RootKey, VerifiedKeyManifest, VerifyKeyManifestOptions } from './manifest';
export { CLOCK_SKEW_S, isVerifiedKeyManifest, keysSha256, pinnedRootKeys, verifyKeyManifest } from './manifest';
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
export type { UsageMethod, UsageReading, UsageUnit } from './usage';
export { usageReadingErrors, validateUsageReading } from './usage';
