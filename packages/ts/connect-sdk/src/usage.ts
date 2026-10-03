/**
 * `ever.usage.v1`: the counts an installation reports for apps priced per unit (employees, seats,
 * users, projects, transactions). Counts and timestamps only, closed at every level. The SDK adds
 * no call of its own: the push goes through the client's `usage` operation, which needs the
 * `usage_reporting` integration (off by default on a self-hosted installation).
 */
import { SCHEMAS, type UsageReportV1 } from '@ever-co/connect-contracts';
import { UsageValidationError } from './errors';
import { schemaViolations } from './schema';

export type UsageReading = UsageReportV1;
export type UsageUnit = UsageReportV1['units'][number]['unit'];
export type UsageMethod = UsageReportV1['units'][number]['method'];

const USAGE_SCHEMA = SCHEMAS.usage as unknown as { readonly [key: string]: unknown };

/** The field errors of a usage reading (`[]` when it is valid); paths are JSON pointers. */
export function usageReadingErrors(body: unknown): { path: string; code: string }[] {
  return schemaViolations(USAGE_SCHEMA, body).map((v) => ({ path: v.path, code: v.kind }));
}

/** Throws {@link UsageValidationError} unless `body` is a valid `ever.usage.v1` reading. */
export function validateUsageReading(body: unknown): asserts body is UsageReading {
  const errors = usageReadingErrors(body);
  if (errors.length > 0) throw new UsageValidationError(errors);
}
