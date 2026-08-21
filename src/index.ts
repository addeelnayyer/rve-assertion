/**
 * rve-assertion — the public surface.
 *
 * Builds RVE-1.b request envelopes and validates the assertions the Identity
 * and Assertion Provider returns. It performs no network I/O, holds no cache,
 * manages no tenant configuration, and does not cryptographically verify
 * signatures. See README.md for the seams it exposes for each of those.
 */

export { deriveMessageId, deriveRequestId } from './request.js';
export { RequestInputError } from './types.js';
