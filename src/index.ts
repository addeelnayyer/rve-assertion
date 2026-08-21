/**
 * rve-assertion — the public surface.
 *
 * Builds RVE-1.b request envelopes and validates the assertions the Identity
 * and Assertion Provider returns. It performs no network I/O, holds no cache,
 * manages no tenant configuration, and does not cryptographically verify
 * signatures. See README.md for the seams it exposes for each of those.
 */

export { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
export type { RegionalErrorCode } from './regional-error-codes.js';
export { deriveMessageId, deriveRequestId } from './request.js';
export { RequestInputError } from './types.js';
export {
  applicationIdShape,
  isRequestContext,
  REQUEST_CONTEXTS,
  RVE_1B_USER_CLIENT_AUTHENTICATION,
} from './vocabulary.js';
export type { ApplicationId, ApplicationIdShape, RequestContext } from './vocabulary.js';
