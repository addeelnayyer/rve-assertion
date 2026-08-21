/**
 * The assertion validator — §4.1.6.2.2, which §4.2.6 makes RVE-1.b's response
 * structure by reference.
 *
 * **Status: the structural phase, and the part of the semantic phase that reads
 * identity and attributes.** The validity window, the audience match against
 * the service being called, and signature integrity are not here yet, so a
 * `valid: true` result from this build means *this document is shaped like an
 * assertion, it carries the attributes the policy asked for, and it says one
 * thing about who the operator is* — and nothing about whether it is in date,
 * scoped to the service, or signed. Until the remaining work lands, a caller
 * must not read the success branch as permission to spend the assertion. The
 * README says the same thing where a reader will meet it first.
 *
 * ## What it is handed
 *
 * Raw bytes, and a bare `saml:Assertion` element in them, together with the
 * policy of the service the caller is about to call. Unwrapping — reaching into
 * a SOAP response to find the assertion, or into a `wsse:Security` header to
 * find one being presented — is transport's job and transport is out of scope,
 * so a caller hands over the sub-document it already located.
 *
 * Bytes rather than a string, and never reserialised, because §4.6 requires the
 * assertion be spent exactly as the IAP returned it — no modification of any
 * kind. A round trip through a document model normalises whitespace, attribute
 * order and namespace declarations, all of which are inside what the region
 * signed. So the bytes the caller passes are the bytes the caller still holds
 * afterwards: this module reads them and hands back nothing derived from them
 * beyond the values the success branch reports.
 *
 * ## Two phases, and why the first one stops
 *
 * The structural phase asks whether there is an assertion here at all:
 * parseable, an assertion element at the root, the attributes §4.1.6.2.2 makes
 * mandatory, exactly one each of the elements it requires — the issuer, the
 * subject, and the conditions carrying the validity window — and one operator
 * identifier in the subject. It reports one failure and stops, in both
 * directions: it does not accumulate structural failures, and it does not let
 * the semantic phase run. Neither would be worth anything, since a document
 * that failed to parse has no audience to compare, no window to check and no
 * signature to bind, so every later check would report a missing thing that is
 * missing only because the document is.
 *
 * The signature is mandatory too and is deliberately not checked here: §4.1.6.2.2
 * makes it an element like the others, but its absence and its being malformed
 * map to different regional error codes, and this phase has one code to report.
 *
 * The semantic phase runs to completion and reports every failure it finds,
 * because the alternative is a caller fixing one problem, spending a round trip
 * against a third-party IAP, and discovering the next.
 */

import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Document, Element } from '@xmldom/xmldom';

import { ASSERTION_ATTRIBUTES, readAssertionAttributes } from './assertion-attributes.js';
import type { AssertionAttributes } from './assertion-attributes.js';
import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES, type RegionalErrorCode } from './regional-error-codes.js';
import type { AuthenticationLevel } from './request.js';
import { attribute, onlySamlChild, samlChildren, text } from './saml-dom.js';

/** The local name of the element an assertion is — §4.1.6.2.2. */
const ASSERTION_ELEMENT = 'Assertion';

/** The local name of the element carrying the validity window — §4.1.6.2.2. */
const CONDITIONS_ELEMENT = 'Conditions';

/** The element §4.1.6.2.2 puts the operator's identity in. */
const SUBJECT_ELEMENT = 'Subject';

/** The element inside the subject that carries the operator's tax code. */
const NAME_ID_ELEMENT = 'NameID';

/** The element scoping an assertion to services — §4.1.6.2.2, optional. */
const AUDIENCE_RESTRICTION_ELEMENT = 'AudienceRestriction';

/** One service an assertion is scoped to — §4.1.6.2.2. */
const AUDIENCE_ELEMENT = 'Audience';

/** SAML 2.0 protocol version, the only value §4.1.6.2.2 permits. */
const SAML_VERSION = '2.0';

/**
 * What the service about to be called requires of an assertion.
 *
 * The specification does not publish this, and could not: §4.2.5.3.1 makes the
 * checks an actor performs a matter of organisational policy, and §3.1.1
 * describes services that refuse an assertion another service would accept. So
 * the requirements travel with the call rather than being compiled in, and the
 * library holds none of them between calls — a policy is an argument, not
 * configuration this library owns (see README, *What it does not do*).
 *
 * A policy is passed even when it is empty, so that *this service asks for
 * nothing in particular* is something a caller said rather than a default
 * nobody chose.
 */
export interface ServicePolicy {
  /**
   * The attributes this service will not act without, by the name §4.1.6.2.2
   * gives each one — {@link ASSERTION_ATTRIBUTES} names the ones it defines.
   *
   * Open, not a closed vocabulary: §4.2.5.2 says regional projects may provide
   * for further request parameters and defers their definition to a transaction
   * this excerpt does not contain, so a policy may name an attribute this
   * library has never heard of and the check still means what it says.
   *
   * Presence, not value. Whether `R.1.1` is a role that may reach this service
   * is a decision the X-Service Provider makes against information the region
   * holds and this library does not — Table 11's codes are the region's answers
   * to that question, not this library's.
   *
   * The responsible party is required whether or not it is named here; see
   * `docs/spec-questions.md` (D-014).
   */
  readonly requiredAttributes?: readonly string[] | undefined;

  /**
   * The authentication level this service requires the operator to have reached
   * — §4.1.6.2.2's `authLevel`.
   *
   * Omit it for a service that accepts an operator authenticated in the
   * ordinary way. Typed as the level the specification attests rather than as a
   * string, for the reason `docs/spec-questions.md` (D-007) gives: a required
   * level is a value the caller chooses, and a URN no regional document backs
   * is a requirement no assertion could ever satisfy.
   */
  readonly requiredAuthenticationLevel?: AuthenticationLevel | undefined;
}

/**
 * Why a validation failed, in this library's vocabulary.
 *
 * This is what a caller switches on. The regional code travelling beside it is
 * an annotation for the support conversation, not the identity of the failure —
 * see {@link AssertionFailure}.
 *
 * `malformed` covers every way of not being an assertion at all, deliberately,
 * since the remedy for all of them is the same and it is not a remedy this
 * library can name. The rest are distinguished from each other because their
 * remedies differ: a missing attribute is a re-request, a missing authentication
 * level escalates out of the assertion layer to the session that has to acquire
 * a second factor, and an identity mismatch is not a remedy at all.
 */
export type AssertionFailureCode =
  | 'malformed'
  | 'attribute-missing'
  | 'authentication-level-not-attested'
  | 'identity-mismatch';

/**
 * One reason an assertion was refused.
 *
 * The regional error code is an **annotation**. It says *this is the reason the
 * region names*, not *this is what the region said* — the library is not an
 * X-Service Provider and cannot speak for one, and Appendix A.5's tables are
 * open-ended anyway (`docs/spec-questions.md`, Q-005). A caller branching on
 * the regional code rather than on {@link AssertionFailureCode} is branching on
 * a best match.
 *
 * **The detail never quotes the document.** It is one sentence about what was
 * expected, in constant text — or, for a missing attribute, in the caller's own
 * words, since the name of an attribute the caller asked for came from the
 * caller. An assertion carries the operator's tax code, and on some documents it
 * carries a patient identifier; a detail that echoed what it found would put
 * those into whatever logs the failure, including on the refusal paths where
 * nothing has been validated and the document may be hostile. Diagnosis of a
 * specific document is the caller's, against the bytes it still holds.
 */
export interface AssertionFailure {
  readonly code: AssertionFailureCode;
  readonly detail: string;
  readonly regionalErrorCode: RegionalErrorCode;

  /**
   * Whether asking the same question again is certain to produce the same
   * answer.
   *
   * `true` is a positive claim: no round trip to the IAP, no re-request and no
   * re-authentication can turn this assertion into a usable one, so a caller
   * that retries is looping against a third party. `false` is the absence of
   * that claim — *not established to be unrecoverable* — and not a promise that
   * a retry will succeed. What to actually do about a failure is the remedy's
   * to say, and the remedy is a later ticket's.
   */
  readonly unrecoverable: boolean;
}

/**
 * An assertion this library found no fault with.
 *
 * Reports the three things a caller needs from an assertion it did not build:
 * who the region says the operator is, what the assertion is scoped to, and how
 * strongly the operator authenticated.
 *
 * The usable-until deadline the caching layer needs is not here yet; it belongs
 * with the validity window, and that is a later ticket's. See the module
 * comment for what this build does not check.
 */
export interface ValidAssertion {
  readonly valid: true;

  /**
   * The operator's tax code, as the subject's `NameID` carries it — §4.1.6.2.2
   * makes that the unique identifier of the user the credentials belong to, and
   * the responsible-party attribute has been checked to agree with it.
   *
   * Not validated as a tax code, deliberately: `docs/spec-questions.md` (D-012).
   * Reported as written, beyond the whitespace an indented document put around
   * it.
   */
  readonly operatorTaxCode: string;

  /**
   * The services this assertion is scoped to, in document order — the
   * `Audience` elements of §4.1.6.2.2's optional audience restriction.
   *
   * Empty for an assertion scoped to nothing in particular, which §4.1.6.2.2
   * permits and §3.1.1 explains: a service that considers itself confidential
   * may refuse exactly that assertion. Whether these audiences are good enough
   * for the service about to be called is the audience match's question, and
   * that is a later ticket's.
   */
  readonly audiences: readonly string[];

  /**
   * The authentication level the assertion attests, or `undefined` when it
   * attests none.
   *
   * A string rather than {@link AuthenticationLevel}, and deliberately not
   * narrowed: the excerpt names one level and cannot say the region has not
   * added another since (`docs/spec-questions.md`, D-007). A received value is
   * the IAP's to state; refusing an unrecognised one would refuse an assertion
   * that is stronger than this library knows how to read.
   */
  readonly authenticationLevel: string | undefined;
}

/**
 * An assertion this library refused, and every reason it refused it.
 *
 * The failure list is typed non-empty, so `failures[0]` needs no guard and an
 * invalid result carrying no reason cannot be constructed. A refusal with
 * nothing to show for it would be the one shape a caller could not act on.
 */
export interface InvalidAssertion {
  readonly valid: false;
  readonly failures: readonly [AssertionFailure, ...AssertionFailure[]];
}

/**
 * The validator's answer: an assertion is either usable or refused with
 * reasons, and the type makes the caller say which case it is handling.
 *
 * A discriminated union rather than a boolean because the failures are the
 * point. A boolean forces the caller to guess between refreshing, re-scoping
 * and giving up, and guessing wrong against a third-party IAP produces either a
 * retry loop or a silently accepted assertion.
 */
export type AssertionValidation = ValidAssertion | InvalidAssertion;

/** A structural refusal: one failure, always, and always the same code. */
function malformed(detail: string): AssertionFailure {
  return {
    code: 'malformed',
    detail,
    // A document not recognisable as an assertion token is what ERR_00023
    // names — Appendix A.5, Table 9. One code for the whole phase, including
    // the case of a caller handing over a document that is not an assertion at
    // all: ERR_00022 is the neighbouring code, but it names an assertion token
    // *absent* from a message an X-Service Provider was checking, and this
    // library is not that party and has no message. What it can say is that the
    // bytes it was handed are not a recognisable token, which is ERR_00023.
    // The annotation is a best match either way — see {@link AssertionFailure}.
    regionalErrorCode: REGIONAL_ERROR_CODES.ASSERTION_TOKEN_UNRECOGNISABLE,
    // Not a claim that a retry would help — see {@link AssertionFailure}. A
    // caller that mis-sliced a SOAP response fixes its own code; an IAP that
    // returned nonsense might not the next time.
    unrecoverable: false,
  };
}

/**
 * Decodes `assertion` as UTF-8, refusing bytes that are not.
 *
 * The specification names no character encoding for the response, and this
 * library reads one anyway — `docs/spec-questions.md` (D-009) has the argument
 * and the cost. Strict rather than replacing: a replacement character silently
 * substituted inside a tax code would be compared, logged and spent as though
 * it were the operator's, and the substitution is invisible at every step.
 */
function decodeUtf8(assertion: Uint8Array): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(assertion);
  } catch {
    return undefined;
  }
}

/**
 * Parses `source`, refusing anything a conforming XML parser would complain
 * about rather than repairing it.
 *
 * `onErrorStopParsing` is the decision here: xmldom's default is to recover
 * from an error-level problem and carry on, which is the right behaviour for a
 * document a human wants to read and the wrong one for a signed credential. A
 * recovered document is a document whose element tree no longer corresponds to
 * the bytes the region signed, and every check downstream would then be run
 * against the parser's opinion of the assertion rather than the assertion.
 * Argued in `docs/spec-questions.md` (D-010).
 */
function parse(source: string): Document | undefined {
  try {
    return new DOMParser({ onError: onErrorStopParsing }).parseFromString(source, 'text/xml');
  } catch {
    return undefined;
  }
}

/**
 * The first of `names` that `element` does not carry, or `undefined` when it
 * carries all of them.
 */
function firstAbsent(element: Element, names: readonly string[]): string | undefined {
  return names.find((name) => attribute(element, name) === undefined);
}

/** The attributes §4.1.6.2.2 makes mandatory on the assertion, beside Version. */
const REQUIRED_ASSERTION_ATTRIBUTES = ['ID', 'IssueInstant'] as const;

/** The attributes §4.1.6.2.2 requires the Conditions element to carry. */
const REQUIRED_CONDITIONS_ATTRIBUTES = ['NotBefore', 'NotOnOrAfter'] as const;

/**
 * The elements §4.1.6.2.2 says an assertion MUST contain, that the structural
 * phase is the right place to insist on.
 *
 * `ds:Signature` is mandatory too and is deliberately not here: its absence and
 * its being malformed map to different regional error codes, so it is checked
 * where that distinction can be drawn rather than collapsed into `malformed`.
 *
 * Presence only. Whether the subject names the same operator as the
 * responsible-party attribute, and whether the issuer is one this caller
 * trusts, are semantic questions about a document that has to exist first.
 */
const REQUIRED_ASSERTION_ELEMENTS = ['Issuer', SUBJECT_ELEMENT, CONDITIONS_ELEMENT] as const;

/**
 * What the structural phase hands the semantic phase: the assertion element,
 * and the one identifier the subject carries.
 *
 * The subject identifier is read here rather than later because §4.1.6.2.2
 * makes the subject carry it and there is no second place to look — an
 * assertion without one is not an assertion that failed a check, it is a
 * document that cannot say who it is about.
 */
interface StructuralAssertion {
  readonly assertion: Element;
  readonly subjectIdentifier: string;
}

/**
 * Reads `assertion` as far as being an assertion at all, and stops at the first
 * thing it is not.
 *
 * The checks run in the order a reader would ask the questions — is it a
 * document, is it *this* document, does it carry what the document must carry —
 * and the first one that fails ends the phase. Ordering them is not a ranking
 * of severity: a later check cannot mean anything until the earlier ones hold.
 */
function structural(assertion: Uint8Array): StructuralAssertion | AssertionFailure {
  const source = decodeUtf8(assertion);
  if (source === undefined) {
    return malformed('the assertion bytes are not valid UTF-8.');
  }

  const document = parse(source);
  if (document === undefined) {
    return malformed('the assertion bytes are not well-formed XML.');
  }

  // A document type declaration is refused rather than ignored. No assertion
  // needs one, and an internal subset is where an entity that expands into
  // something else would be declared — so the cheapest place to be sure the
  // element tree says what the bytes say is before reading the element tree.
  // Argued in `docs/spec-questions.md` (D-011).
  if (document.doctype !== null) {
    return malformed('the assertion carries a document type declaration, which is refused.');
  }

  const element = document.documentElement;
  if (
    element === null ||
    element.namespaceURI !== SAML_ASSERTION_NAMESPACE ||
    element.localName !== ASSERTION_ELEMENT
  ) {
    // The input contract, restated where it is broken: this is the check a
    // caller that handed over a whole SOAP response fails, and the message has
    // to be the one that tells them so.
    return malformed(
      "the root element is not a SAML 2.0 Assertion. The validator is handed the bare assertion element; unwrapping a response or a security header is the caller's.",
    );
  }

  if (attribute(element, 'Version') !== SAML_VERSION) {
    return malformed(`the assertion does not declare Version "${SAML_VERSION}".`);
  }

  const absentAttribute = firstAbsent(element, REQUIRED_ASSERTION_ATTRIBUTES);
  if (absentAttribute !== undefined) {
    return malformed(`the assertion carries no ${absentAttribute} attribute.`);
  }

  // Exactly one of each, not at least one. A second Conditions element would
  // give the validity-window check two windows to choose between, and a choice
  // is exactly what a document that wants to be read two ways relies on.
  for (const name of REQUIRED_ASSERTION_ELEMENTS) {
    if (samlChildren(element, name).length !== 1) {
      return malformed(`the assertion does not carry exactly one ${name} element.`);
    }
  }

  const conditions = onlySamlChild(element, CONDITIONS_ELEMENT);
  const subject = onlySamlChild(element, SUBJECT_ELEMENT);
  if (conditions === undefined || subject === undefined) {
    // Unreachable: the loop above established there is exactly one of each.
    // Written as a return rather than an assertion so that the compiler's
    // narrowing and the runtime's behaviour agree without a cast.
    return malformed('the assertion does not carry exactly one Subject and Conditions element.');
  }

  const absentConditionsAttribute = firstAbsent(conditions, REQUIRED_CONDITIONS_ATTRIBUTES);
  if (absentConditionsAttribute !== undefined) {
    return malformed(
      `the assertion's ${CONDITIONS_ELEMENT} carries no ${absentConditionsAttribute} attribute.`,
    );
  }

  const nameId = onlySamlChild(subject, NAME_ID_ELEMENT);
  const subjectIdentifier = nameId === undefined ? undefined : text(nameId);
  if (subjectIdentifier === undefined) {
    // §4.1.6.2.2 makes this the operator's identifier, and it is the only place
    // the success branch can report one from — so a subject that carries no
    // identifier, or two, is a document that cannot say who it is about rather
    // than one that fails a check.
    return malformed(
      `the assertion's ${SUBJECT_ELEMENT} does not carry exactly one ${NAME_ID_ELEMENT} with a value.`,
    );
  }

  return { assertion: element, subjectIdentifier };
}

/**
 * The regional code that names a missing attribute best, per attribute.
 *
 * Table 11's codes say *the value of this attribute does not permit access to
 * the service*, which is the nearest the region comes to naming an attribute a
 * service needed and did not get; no table names an absent one. Attributes
 * Table 11 has no code of its own for fall back to ERR_00058, which names an
 * assertion whose parameters do not conform to the organisation's policies —
 * and a required-attribute list is exactly an organisation's policy. A best
 * match either way; see {@link AssertionFailure}.
 */
const ATTRIBUTE_ERROR_CODES: Readonly<Record<string, RegionalErrorCode>> = {
  [ASSERTION_ATTRIBUTES.REQUEST_CONTEXT]: REGIONAL_ERROR_CODES.REQUEST_CONTEXT_NOT_PERMITTED,
  [ASSERTION_ATTRIBUTES.ROLE]: REGIONAL_ERROR_CODES.ROLE_NOT_PERMITTED,
  [ASSERTION_ATTRIBUTES.USER_CLIENT_AUTHENTICATION]:
    REGIONAL_ERROR_CODES.USER_CLIENT_AUTHENTICATION_NOT_PERMITTED,
  [ASSERTION_ATTRIBUTES.APPLICATION_ID]: REGIONAL_ERROR_CODES.APPLICATION_ID_NOT_PERMITTED,
};

/**
 * The attribute names an assertion must carry for this call: the policy's, and
 * the responsible party whether the policy asked for it or not.
 *
 * De-duplicated, in the order they were asked for, with the responsible party
 * first — a policy naming it as well should not produce the failure twice.
 */
function requiredAttributes(policy: ServicePolicy): readonly string[] {
  return [
    ...new Set([ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, ...(policy.requiredAttributes ?? [])]),
  ];
}

/** One attribute the assertion had to carry and did not. */
function attributeMissing(name: string): AssertionFailure {
  return {
    code: 'attribute-missing',
    // The name came from the policy, which came from the caller — so naming it
    // quotes the caller and not the document. See {@link AssertionFailure}.
    detail: `the assertion carries no ${name} attribute with a value, and the service requires one.`,
    regionalErrorCode:
      ATTRIBUTE_ERROR_CODES[name] ?? REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY,
    unrecoverable: false,
  };
}

/** The authentication level the assertion does not attest. */
function authenticationLevelNotAttested(detail: string): AssertionFailure {
  return {
    code: 'authentication-level-not-attested',
    detail,
    // Table 12's ERR_00065 — access to the service requires two-factor
    // authentication — is the code the region raises for exactly this, and the
    // only level §4.1.6.2.2 attests is the two-factor one.
    regionalErrorCode: REGIONAL_ERROR_CODES.TWO_FACTOR_AUTHENTICATION_REQUIRED,
    // The operator can authenticate again with a second factor. That is the
    // session layer's work rather than a re-request, but it is work that exists.
    unrecoverable: false,
  };
}

/**
 * The two identities in an assertion, compared as one identity written twice.
 *
 * Compared with case folded away, and nothing else: the region writes a Codice
 * Fiscale in upper case, and folding case cannot make two different tax codes
 * equal — so it removes a way of refusing a correct assertion without weakening
 * the check. Argued in `docs/spec-questions.md` (D-013). Locale-independent
 * deliberately: `toUpperCase` rather than `toLocaleUpperCase`, so that the
 * machine's locale is not part of who the operator is.
 */
function sameIdentity(one: string, other: string): boolean {
  return one.toUpperCase() === other.toUpperCase();
}

/**
 * Checks the operator's identity against itself.
 *
 * §4.1.6.2.2 has RVE-1.b's IAP derive both the subject's `NameID` and the
 * `ResponsibleParty` attribute from one query for one operator, so the two
 * carry the same tax code by construction. Two different values means the IAP
 * resolved two different people for one request, and nothing downstream can
 * tell which of them the regional audit trail should name.
 *
 * *Every* value is held against the subject, not the first: an assertion naming
 * a second responsible party beside the right one is the shape this check
 * exists to catch, and a check that stopped at the first value is a check that
 * second value could hide behind.
 */
function identityFailure(
  subjectIdentifier: string,
  attributes: AssertionAttributes,
): AssertionFailure | undefined {
  const responsibleParties = attributes.get(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY);
  if (responsibleParties === undefined) {
    // Absent, which is the missing-attribute failure and not this one. A
    // mismatch reported beside it would name a disagreement nothing had.
    return undefined;
  }

  if (responsibleParties.every((party) => sameIdentity(party, subjectIdentifier))) {
    return undefined;
  }

  return {
    code: 'identity-mismatch',
    detail: `the assertion's ${SUBJECT_ELEMENT} and its ${ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY} attribute do not name one operator.`,
    // Table 12's ERR_00059 names the responsible party's tax code not matching
    // the one the ULSS holds. The region's version of the check compares
    // against its own directory and this one compares the assertion against
    // itself, but it is the same disagreement about the same value.
    regionalErrorCode: REGIONAL_ERROR_CODES.RESPONSIBLE_PARTY_FISCAL_CODE_MISMATCH,
    // Asking the same IAP the same question returns the same two answers, so a
    // retry is a loop against a third party. Someone has to fix the directory
    // the IAP is reading, and no round trip from here does that.
    unrecoverable: true,
  };
}

/** The services the assertion is scoped to, in document order. */
function audiences(assertion: Element): readonly string[] {
  const conditions = onlySamlChild(assertion, CONDITIONS_ELEMENT);
  if (conditions === undefined) {
    return [];
  }

  return samlChildren(conditions, AUDIENCE_RESTRICTION_ELEMENT)
    .flatMap((restriction) => samlChildren(restriction, AUDIENCE_ELEMENT))
    .map((audience) => text(audience))
    .filter((audience): audience is string => audience !== undefined);
}

/**
 * Validates the identity assertion in `assertion` against `policy`, as the
 * exact bytes the Identity and Assertion Provider returned.
 *
 * Returns rather than throws, deliberately asymmetric with the request side's
 * smart constructor: this input is third-party data that a caller must handle
 * being refused, whereas request input is the caller's own arguments and a bad
 * one there is a programming error. See `src/types.ts`.
 *
 * Never mutates `assertion` and never reserialises it. The caller keeps the
 * bytes it will spend.
 *
 * **Incomplete — see the module comment.** This does not yet establish that an
 * assertion is in date, scoped to the service being called, or signed at all.
 */
export function validateAssertion(
  assertion: Uint8Array,
  policy: ServicePolicy,
): AssertionValidation {
  const structure = structural(assertion);
  if ('code' in structure) {
    return { valid: false, failures: [structure] };
  }

  const attributes = readAssertionAttributes(structure.assertion);
  const failures: AssertionFailure[] = [];

  for (const name of requiredAttributes(policy)) {
    if (!attributes.has(name)) {
      failures.push(attributeMissing(name));
    }
  }

  const levels = attributes.get(ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL) ?? [];
  const authenticationLevel = levels.length === 1 ? levels[0] : undefined;
  if (levels.length > 1) {
    // Two answers to a question with one answer, whatever the policy asked for.
    failures.push(
      authenticationLevelNotAttested(
        'the assertion attests more than one authentication level, so it attests none.',
      ),
    );
  } else if (
    policy.requiredAuthenticationLevel !== undefined &&
    authenticationLevel !== policy.requiredAuthenticationLevel
  ) {
    failures.push(
      authenticationLevelNotAttested(
        "the service requires an authentication level the assertion does not attest. The operator must authenticate again with a second factor, which is the session's work and not a re-request.",
      ),
    );
  }

  const identity = identityFailure(structure.subjectIdentifier, attributes);
  if (identity !== undefined) {
    failures.push(identity);
  }

  const [first, ...rest] = failures;
  if (first !== undefined) {
    return { valid: false, failures: [first, ...rest] };
  }

  return {
    valid: true,
    operatorTaxCode: structure.subjectIdentifier,
    audiences: audiences(structure.assertion),
    authenticationLevel,
  };
}
