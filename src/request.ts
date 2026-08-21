/**
 * The RVE-1.b request as a value — §4.2.5.2.
 *
 * Two things live here: the MessageID-to-ID derivation, and the smart
 * constructor that turns caller input into a request every invariant of which
 * has already been checked. Serialising that value to the wire is
 * `request-envelope.ts`; the split is what lets the builder be total, and lets
 * a caller find out that its window is inverted before any XML exists.
 */

import {
  isRequestContext,
  RVE_1B_USER_CLIENT_AUTHENTICATION,
  type ApplicationId,
  type RequestContext,
} from './request-vocabulary.js';
import { RequestInputError } from './types.js';
import { isAbsoluteUri } from './uri.js';

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

/**
 * The WS-Addressing action that names RVE-1.b — §4.2.5.2.
 *
 * The action is what tells the IAP which of the four assertion transactions the
 * body carries, so it is pinned rather than supplied: a caller able to choose
 * it would be able to declare a transaction this library does not build.
 */
export const RVE_1B_ACTION = 'urn:rve:AuthenticateAndGetAssertionRequest-b';

/**
 * The value the `authLevel` attribute carries when the operator authenticated
 * through a two-factor mechanism — §4.2.5.2.
 *
 * The specification names this one value and no other, and gives no code system
 * to draw further ones from, so {@link AuthenticationLevel} is a union of one.
 * Declaring a level at all is optional; declaring a different one is refused,
 * for the reasons in `docs/spec-questions.md` (D-007).
 */
export const TWO_FACTOR_AUTHENTICATION_LEVEL = 'urn:rve:authnL2';

/** How strongly the responsible party authenticated, on the regional scale. */
export type AuthenticationLevel = typeof TWO_FACTOR_AUTHENTICATION_LEVEL;

/**
 * The identifier of the responsible party, as the security header carries it.
 *
 * A union rather than a string with a flag beside it, because the two forms are
 * different values: one is a username the IAP looks up directly, the other is
 * ciphertext the IAP must decrypt first (§4.2.5.3). Modelling them apart is
 * also what makes the absence of a password structural — neither variant has a
 * field for one, so no input can produce a `wsse:Password` element.
 *
 * This library does not encrypt. A caller using the encrypted form has already
 * encrypted the username under whatever key its AULSS issued, and hands the
 * result over as opaque text.
 */
export type Username =
  | { readonly form: 'plaintext'; readonly value: string }
  | { readonly form: 'encrypted'; readonly ciphertext: string };

/**
 * What a caller supplies to build an RVE-1.b request — §4.2.5.2.
 *
 * Optional properties are declared `?: T | undefined` rather than `?: T` so
 * that a caller assembling this object from its own optional configuration can
 * pass `undefined` through instead of building the object conditionally.
 */
export interface Rve1bRequestInput {
  /** The SOAP `wsa:MessageID`: a `urn:uuid:` URN the caller generates. */
  readonly messageId: string;

  /**
   * The SOAP `wsa:To`: the absolute URI of the IAP endpoint.
   *
   * Named for what the specification calls it — the final recipient of the
   * message — rather than `destination`, which in SAML names a different
   * attribute that this library deliberately does not emit (Q-006).
   */
  readonly recipient: string;

  /** The responsible party's identifier, for the `wsse:UsernameToken`. */
  readonly username: Username;

  /** The registered installation making the request. Opaque — see Q-003. */
  readonly applicationId: ApplicationId;

  /** The declared purpose of the transaction, from Appendix A.2, Table 5. */
  readonly requestContext: RequestContext;

  /** The moment the request is created, for `AuthnRequest/@IssueInstant`. */
  readonly issueInstant: Date;

  /** The first moment the requested assertion should be valid. */
  readonly notBefore: Date;

  /** The moment the requested assertion should expire. */
  readonly notOnOrAfter: Date;

  /**
   * The complete URLs of the services the assertion is being requested for.
   *
   * Omitted or empty means an unrestricted assertion, and no
   * `AudienceRestriction` element is emitted. A confidential service may refuse
   * such an assertion — §3.1.1.
   */
  readonly audiences?: readonly string[] | undefined;

  /** The MPI of the patient the operator is acting in respect of. */
  readonly patientId?: string | undefined;

  /** The OTP code returned by the AMPS service, where the service needs one. */
  readonly otpCode?: string | undefined;

  /**
   * The FLS11 codes of the organisations that authorised document viewing or
   * retrieval — the `codAziendaAuth` attribute. Encoding of the list is a
   * question for the specification's authors (Q-007).
   */
  readonly authorisingOrganisations?: readonly string[] | undefined;

  /** Declares multi-factor authentication. See {@link AuthenticationLevel}. */
  readonly authenticationLevel?: AuthenticationLevel | undefined;
}

/**
 * Brand marking a request as having been through {@link rve1bRequest}.
 *
 * A real runtime symbol rather than a phantom type, and not exported, so the
 * only way to obtain an {@link Rve1bRequest} is to have had its invariants
 * checked. That is what lets {@link "./request-envelope.js".buildRve1bRequest}
 * declare no failure mode.
 */
const CHECKED = Symbol('rve1bRequest');

/**
 * A validated RVE-1.b request, ready to serialise.
 *
 * Timestamps are already in their wire form — see {@link Rve1bRequest.issueInstant}
 * — because truncating to whole seconds can change whether the validity window
 * is a window at all, and the check has to run on what will actually be
 * emitted rather than on what was passed in.
 */
export interface Rve1bRequest {
  readonly [CHECKED]: true;

  /** The `wsa:MessageID`, exactly as supplied. */
  readonly messageId: string;

  /** The `AuthnRequest/@ID`, derived from {@link Rve1bRequest.messageId}. */
  readonly requestId: string;

  /** The `wsa:To`. */
  readonly recipient: string;

  /** The `wsse:Username`, plaintext or ciphertext. */
  readonly username: Username;

  /** Pinned to {@link RVE_1B_USER_CLIENT_AUTHENTICATION} — see Q-002. */
  readonly userClientAuthentication: typeof RVE_1B_USER_CLIENT_AUTHENTICATION;

  /** The `ApplicationID` attribute value. */
  readonly applicationId: ApplicationId;

  /** The `RequestContext` attribute value. */
  readonly requestContext: RequestContext;

  /** `AuthnRequest/@IssueInstant`, UTC, whole seconds, `Z`-suffixed (D-004). */
  readonly issueInstant: string;

  /** `Conditions/@NotBefore`, in the same lexical form. */
  readonly notBefore: string;

  /** `Conditions/@NotOnOrAfter`, in the same lexical form. */
  readonly notOnOrAfter: string;

  /** The audiences, normalised to an array. Empty means unrestricted. */
  readonly audiences: readonly string[];

  /** The `PatientID` attribute value, or `undefined` if there is none. */
  readonly patientId: string | undefined;

  /** The `codOTP` attribute value, or `undefined` if there is none. */
  readonly otpCode: string | undefined;

  /** The `codAziendaAuth` values, normalised to an array. */
  readonly authorisingOrganisations: readonly string[];

  /** The `authLevel` attribute value, or `undefined` if none was declared. */
  readonly authenticationLevel: AuthenticationLevel | undefined;
}

/** Returns `value` if it carries something, and complains about it if not. */
function nonBlank(value: string, what: string): string {
  if (value.trim().length === 0) {
    throw new RequestInputError(`${what} is blank. It must carry a value or be omitted.`);
  }

  return value;
}

/**
 * Returns `value` if it is an absolute URI — the rule `src/uri.ts` states, with
 * the error this side of the library raises.
 */
function absoluteUri(value: string, what: string): string {
  nonBlank(value, what);

  if (!isAbsoluteUri(value)) {
    throw new RequestInputError(
      `${what} is ${JSON.stringify(value)}, which is not an absolute URI.`,
    );
  }

  return value;
}

/**
 * Truncates `date` to a whole second, which is the resolution §4.2.5.2's
 * examples write timestamps at (D-004).
 *
 * Truncates towards the past rather than rounding, so that a `NotBefore` never
 * moves later than the caller asked and a `NotOnOrAfter` never moves earlier —
 * an assertion is never made valid for an instant outside the window that was
 * requested.
 */
function wholeSecond(date: Date, what: string): Date {
  const milliseconds = date.getTime();
  if (Number.isNaN(milliseconds)) {
    throw new RequestInputError(`${what} is not a valid instant.`);
  }

  return new Date(Math.floor(milliseconds / 1000) * 1000);
}

/**
 * Renders a whole-second instant as `YYYY-MM-DDThh:mm:ssZ` — see D-004.
 *
 * The seconds are taken by position rather than by stripping a `.000`
 * suffix: `toISOString` is specified to produce exactly
 * `YYYY-MM-DDTHH:mm:ss.sssZ` for the years this library deals in, so the first
 * nineteen characters are the whole-second form and nothing has to be matched.
 */
function utcSecondsLexical(date: Date): string {
  return `${date.toISOString().slice(0, 19)}Z`;
}

/**
 * Builds a validated {@link Rve1bRequest}, or explains why it cannot.
 *
 * Every check here is one the caller can satisfy by fixing its own arguments.
 * Checks that belong to the IAP — whether the context is enabled for this
 * ApplicationID, whether the ApplicationID is banned, whether the patient is in
 * the declared relationship with the operator (§4.2.5.3.1) — are not attempted:
 * this library cannot see the boundary tables those read, and guessing at them
 * would refuse requests the region would have granted.
 *
 * @throws {RequestInputError} on any invariant the request cannot be built
 * without.
 */
export function rve1bRequest(input: Rve1bRequestInput): Rve1bRequest {
  const requestId = deriveRequestId(input.messageId);

  const username: Username =
    input.username.form === 'plaintext'
      ? { form: 'plaintext', value: nonBlank(input.username.value, 'The username') }
      : {
          form: 'encrypted',
          ciphertext: nonBlank(input.username.ciphertext, 'The encrypted username'),
        };

  if (!isRequestContext(input.requestContext)) {
    throw new RequestInputError(
      `${JSON.stringify(input.requestContext)} is not a request context defined by Appendix A.2, Table 5. See docs/spec-questions.md (Q-004).`,
    );
  }

  if (
    input.authenticationLevel !== undefined &&
    input.authenticationLevel !== TWO_FACTOR_AUTHENTICATION_LEVEL
  ) {
    throw new RequestInputError(
      `${JSON.stringify(input.authenticationLevel)} is not an authentication level §4.2.5.2 attests. The only value it names is ${JSON.stringify(TWO_FACTOR_AUTHENTICATION_LEVEL)}.`,
    );
  }

  const notBefore = wholeSecond(input.notBefore, 'The start of the validity window');
  const notOnOrAfter = wholeSecond(input.notOnOrAfter, 'The end of the validity window');
  if (notOnOrAfter.getTime() <= notBefore.getTime()) {
    throw new RequestInputError(
      `The validity window ${utcSecondsLexical(notBefore)}/${utcSecondsLexical(notOnOrAfter)} is empty: NotOnOrAfter excludes its own instant, so the assertion would never be valid.`,
    );
  }

  return {
    [CHECKED]: true,
    messageId: input.messageId,
    requestId,
    recipient: absoluteUri(input.recipient, 'The recipient'),
    username,
    userClientAuthentication: RVE_1B_USER_CLIENT_AUTHENTICATION,
    applicationId: nonBlank(input.applicationId, 'The ApplicationID'),
    requestContext: input.requestContext,
    issueInstant: utcSecondsLexical(wholeSecond(input.issueInstant, 'The issue instant')),
    notBefore: utcSecondsLexical(notBefore),
    notOnOrAfter: utcSecondsLexical(notOnOrAfter),
    audiences: (input.audiences ?? []).map((audience) => absoluteUri(audience, 'An audience')),
    patientId:
      input.patientId === undefined
        ? undefined
        : nonBlank(input.patientId, 'The patient identifier'),
    otpCode: input.otpCode === undefined ? undefined : nonBlank(input.otpCode, 'The OTP code'),
    authorisingOrganisations: (input.authorisingOrganisations ?? []).map((code) =>
      nonBlank(code, 'An authorising organisation code'),
    ),
    authenticationLevel: input.authenticationLevel,
  };
}
