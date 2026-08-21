/**
 * Request building — §4.2.5.2.
 *
 * Carries the MessageID-to-ID derivation. The smart constructor and the
 * envelope builder land alongside it.
 */

import { RequestInputError } from './types.js';

/**
 * Scheme prefix a `wsa:MessageID` carries when it names a UUID (RFC 4122 §3),
 * in the canonical lowercase form of RFC 8141 §5.1. Stripped on the way to the
 * request identifier because XML `ID` forbids a colon.
 */
const MESSAGE_ID_SCHEME = 'urn:uuid:';

/** Prefix the SAML `AuthnRequest/@ID` carries — §4.2.5.2. */
const REQUEST_ID_PREFIX = 'msgId_';

/**
 * The hexadecimal UUID form of RFC 4122 §3, case-insensitive.
 *
 * The version and variant nibbles are deliberately not constrained. The
 * specification asks for a UUID, not for a particular version of one, and
 * refusing to build an identifier the region would have accepted is a worse
 * failure than emitting a nil or non-conforming UUID the caller chose.
 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Returns the UUID `value` carries after `prefix`, rejecting anything else.
 *
 * `whyPrefixMatters` is appended to the missing-prefix message so that each
 * caller explains its own prefix rather than sharing a generic complaint.
 */
function uuidAfter(value: string, prefix: string, whyPrefixMatters: string): string {
  if (!value.startsWith(prefix)) {
    throw new RequestInputError(
      `${JSON.stringify(value)} does not start with ${JSON.stringify(prefix)}. ${whyPrefixMatters}`,
    );
  }

  const uuid = value.slice(prefix.length);
  if (!UUID_PATTERN.test(uuid)) {
    throw new RequestInputError(
      `${JSON.stringify(value)} does not name a UUID after its ${JSON.stringify(prefix)} prefix.`,
    );
  }

  return uuid;
}

/**
 * Derives the SAML `AuthnRequest/@ID` from the SOAP `wsa:MessageID` — §4.2.5.2.
 *
 * The two strings differ because the SAML attribute is of XML `ID` type, which
 * forbids the colon the URN scheme prefix carries. This is a schema constraint,
 * not a convention, which is why the rule exists at all.
 *
 * Three inputs the specification does not settle are decided here: an uppercase
 * UUID keeps its case, a message ID carrying no scheme prefix is rejected
 * rather than treated as already stripped, and the scheme prefix itself must be
 * in canonical lowercase. Each decision and its cost is argued in
 * `docs/spec-questions.md` (D-001, D-002, D-003).
 *
 * @throws {RequestInputError} if `messageId` is not a `urn:uuid:` URN naming a
 * well-formed UUID.
 */
export function deriveRequestId(messageId: string): string {
  const uuid = uuidAfter(
    messageId,
    MESSAGE_ID_SCHEME,
    '§4.2.5.2 derives the request identifier by stripping that scheme prefix, so a message ID without one cannot be derived from and would not be the absolute IRI WS-Addressing requires.',
  );

  return REQUEST_ID_PREFIX + uuid;
}

/**
 * Recovers the SOAP `wsa:MessageID` from a request identifier produced by
 * {@link deriveRequestId}.
 *
 * The derivation is reversible so that correlation survives in both directions:
 * a support engineer holding only a request or assertion identifier can recover
 * the message ID that the response's `wsa:RelatesTo` will carry, and vice versa.
 *
 * @throws {RequestInputError} if `requestId` was not produced by
 * {@link deriveRequestId}.
 */
export function deriveMessageId(requestId: string): string {
  const uuid = uuidAfter(
    requestId,
    REQUEST_ID_PREFIX,
    'It was therefore not derived from a message ID under §4.2.5.2.',
  );

  return MESSAGE_ID_SCHEME + uuid;
}
