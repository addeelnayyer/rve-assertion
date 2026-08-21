/**
 * Shared types.
 */

/**
 * Thrown when caller code hands the request side an input it cannot build from.
 *
 * Deliberately asymmetric with the assertion validator, which returns a
 * discriminated result rather than throwing: validator input is adversarial
 * third-party data, where failure is an expected control-flow outcome that the
 * caller must handle. Request input is the caller passing its own arguments, where a
 * bad value is a programming error with no runtime remedy — so it fails at the
 * call site rather than surfacing later as an opaque regional error code.
 */
export class RequestInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RequestInputError';
  }
}

/**
 * Thrown when caller code hands the validator a service policy it cannot build.
 *
 * The same asymmetry {@link RequestInputError} draws, on the other side of the
 * library. An assertion is third-party data and its refusal is a result; a
 * service policy is the caller's own description of the regional service it is
 * about to call, assembled from tenant configuration, and a bad one is a
 * misconfiguration with no runtime remedy. It fails where the policy is built —
 * at startup, for most callers — rather than one assertion at a time.
 *
 * A separate class rather than a shared one because the two are raised by
 * opposite halves of the library and a caller catching one is not asking to
 * catch the other.
 */
export class ServicePolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ServicePolicyError';
  }
}
