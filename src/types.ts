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
