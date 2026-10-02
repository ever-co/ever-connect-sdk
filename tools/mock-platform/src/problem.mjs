// RFC 9457 problem documents exactly as the platform shapes them: type, title, status, code,
// detail, instance (the request id) and, for validation failures, errors[].
import { STATUS_CODES } from 'node:http';

export class HttpProblem extends Error {
  constructor(status, code, detail, extra = {}) {
    super(`${status} ${code}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.extra = extra;
  }
}

/** Throws the problem; handlers call it to answer an error. */
export const fail = (status, code, detail, extra) => {
  throw new HttpProblem(status, code, detail, extra);
};

const SENTENCES = {
  code_invalid: 'the code is not valid or has expired',
  product_mismatch: 'the code was made for another product',
  product_not_supported: 'this product accepts no connection',
  public_jwk_invalid: 'the public key is not an Ed25519 key, or it belongs to another installation',
  already_connected: 'this key already holds an active connection; disconnect first',
  invalid_client: 'the client assertion was not accepted',
  credential_revoked: 'the credential of this installation is revoked',
  instance_pending_approval: 'the organization has not approved this installation yet',
  instance_disconnected: 'this installation is disconnected',
  integration_disabled: 'the integration is not enabled for this installation',
  integration_revoked: 'the consent for this integration was revoked',
  validation_failed: 'the request does not validate',
  schema_violation: 'the report does not match the published schema',
  key_mismatch: 'the key does not match the pinned key',
  rate_limited: 'too many requests',
  not_found: 'no such resource',
  unauthorized: 'no valid credential',
  step_up_required: 'a fresh sign-in is required',
  session_required: 'this credential is not accepted on this operation',
  forbidden_role: 'the person lacks the required role',
  not_connection_owner: 'the organization does not own this installation',
  scope_version_outdated: 'the consent names an outdated scope version',
  already_linked: 'this tenant is already linked',
  already_exists: 'the resource already exists',
  illegal_transition: 'the state does not allow this change',
  resync_required: 'events after the cursor are past retention; re-read the state',
  keys_unavailable: 'no signed key manifest is available yet',
  signature_invalid: 'the signature does not verify over the received bytes',
  payload_too_large: 'the body is too large',
  module_disabled: 'the module serving this route is disabled',
  idempotency_mismatch: 'the idempotency key was used with another request',
  authorization_pending: 'the code has not been approved yet',
  slow_down: 'polling too fast',
  expired_token: 'the device code expired',
  salt_version_unknown: 'unknown salt version',
  salt_version_retired: 'the salt version is retired',
  hashes_invalid: 'the hashes are not valid',
  entitlement_required: 'the entitlement does not include this feature',
  identifier_claimed: 'the identifier is claimed by another organization',
  gone: 'the resource is gone',
  limit_exceeded: 'a limit is reached',
  method_not_allowed: 'method not allowed',
  unsupported_media_type: 'the body must be application/json',
};

/** The problem body; `instance` echoes the caller's x-request-id (null without one). */
export function problemBody(problem, requestId) {
  const body = {
    type: `https://api.ever.co/problems/${problem.code}`,
    title: STATUS_CODES[problem.status] ?? 'Error',
    status: problem.status,
    code: problem.code,
    detail: `${problem.code}: ${problem.detail ?? SENTENCES[problem.code] ?? 'the request failed'}`,
    instance: requestId ?? null,
  };
  if (problem.extra?.errors) body.errors = problem.extra.errors;
  if (problem.extra?.retry_after_s !== undefined) body.retry_after_s = problem.extra.retry_after_s;
  if (problem.extra?.last_id !== undefined) body.last_id = problem.extra.last_id;
  return body;
}
