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
 * Thrown when caller code hands the assertion validator an argument of its own
 * that it cannot check an assertion against: a time model, or a service policy.
 *
 * The same asymmetry {@link RequestInputError} describes, applied one level in.
 * The assertion is third-party data and a bad one is returned as a refusal; the
 * time model and the service policy beside it are the caller passing its own
 * clock, its own margins and its own description of the service it is calling,
 * where a bad value is a programming error. It is thrown rather than returned
 * because the silent behaviour is the dangerous one: every comparison against
 * `NaN` is false, so a clock that is not a time would accept every assertion,
 * expired or not, and report no reason to doubt it.
 *
 * A service policy is refused where it is built rather than one assertion at a
 * time, which for most callers is at startup: `servicePolicy` is a smart
 * constructor, and the validator is handed a value that cannot exist unchecked.
 *
 * Two classes rather than one, because a caller catching around a request build
 * and a caller catching around a validation are handling different call sites,
 * and a single shared class would let a `catch` placed around the request
 * builder swallow a defect in the validator's arguments. Not three: a policy
 * and a clock are both the validator's arguments, and the call site that gets
 * them wrong is the same one.
 */
export class ValidationInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationInputError';
  }
}
