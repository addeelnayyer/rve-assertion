/**
 * The one URI rule both halves of the library apply.
 *
 * §4.1.6.2.2 has an `Audience` name its service by a URL given in full, and
 * WS-Addressing types `wsa:To` as an absolute IRI. The request builder checks a
 * value it is about to send and the validator checks a value it is about to
 * compare against, so the same rule is asked twice; it lives here so that it
 * has one answer.
 *
 * A predicate rather than a checker that throws, because the two callers raise
 * different errors — `RequestInputError` on the request side,
 * `ValidationInputError` on the validation side — and the message each writes
 * names the field it was given, which this module does not know.
 */

/**
 * Whether `value` is an absolute URI.
 *
 * `URL` is the parser because it is already in the runtime and accepts every
 * scheme, including the `urn:` forms an anonymous WS-Addressing endpoint uses.
 * It rejects relative references, which is the mistake actually worth catching:
 * a path such as `/ws` is neither an absolute IRI nor a complete service URL,
 * and cannot be compared against one written in full.
 */
export function isAbsoluteUri(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
