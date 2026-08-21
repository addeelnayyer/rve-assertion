/**
 * rve-assertion — the public surface.
 *
 * Builds RVE-1.b request envelopes and validates the assertions the Identity
 * and Assertion Provider returns. It performs no network I/O, holds no cache,
 * manages no tenant configuration, and does not cryptographically verify
 * signatures. See README.md for the seams it exposes for each of those.
 */

export {
  SAML_ASSERTION_NAMESPACE,
  SAML_PROTOCOL_NAMESPACE,
  SOAP_ENVELOPE_NAMESPACE,
  WS_ADDRESSING_NAMESPACE,
  WS_SECURITY_SECEXT_NAMESPACE,
} from './namespaces.js';
export { validateAssertion } from './assertion.js';
export type {
  AssertionFailure,
  AssertionFailureCode,
  AssertionValidation,
  InvalidAssertion,
  ValidAssertion,
} from './assertion.js';
export { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
export type { RegionalErrorCode } from './regional-error-codes.js';
export { buildRve1bRequest } from './request-envelope.js';
export {
  deriveMessageId,
  deriveRequestId,
  rve1bRequest,
  RVE_1B_ACTION,
  TWO_FACTOR_AUTHENTICATION_LEVEL,
} from './request.js';
export type {
  AuthenticationLevel,
  Rve1bRequest,
  Rve1bRequestInput,
  Username,
} from './request.js';
export {
  audienceMatches,
  BASELINE_SERVICE_POLICY,
  servicePolicy,
} from './service-policy.js';
export type {
  AudienceMatching,
  ServicePolicy,
  ServicePolicyInput,
} from './service-policy.js';
export { RequestInputError, ServicePolicyError } from './types.js';
export {
  applicationIdShape,
  isRequestContext,
  REQUEST_CONTEXTS,
  RVE_1B_USER_CLIENT_AUTHENTICATION,
} from './request-vocabulary.js';
export type { ApplicationId, ApplicationIdShape, RequestContext } from './request-vocabulary.js';
