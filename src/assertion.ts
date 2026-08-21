/**
 * The assertion validator — §4.1.6.2.2, which §4.2.6 makes RVE-1.b's response
 * structure by reference.
 *
 * **Status: incomplete.** The structural phase, the structural signature
 * phase, the validity window, the audience, the attributes the calling service
 * requires, the identity cross-check and the remedy a refusal carries are here. So a `valid: true` result
 * from this build means *this document is shaped like an assertion, it carries
 * a signature that claims to cover it, the clock is inside its window, it is
 * scoped to the service it was checked against, it carries what that service
 * asked for, and it says one thing about who the operator is* — and nothing
 * more. It does **not** mean the signature was verified: nothing here verifies
 * one cryptographically unless the caller supplies a verifier, and the success
 * branch says so in a warning rather than leaving it to be assumed. Until the
 * remaining work lands, a caller must not read the success branch as permission
 * to spend the assertion. The README says the same thing where a reader will
 * meet it first.
 *
 * ## What it is handed
 *
 * Raw bytes, and a bare `saml:Assertion` element in them. Unwrapping — reaching
 * into a SOAP response to find the assertion, or into a `wsse:Security` header
 * to find one being presented — is transport's job and transport is out of
 * scope, so a caller hands over the sub-document it already located.
 *
 * Bytes rather than a string, and never reserialised, because §4.6 requires the
 * assertion be spent exactly as the IAP returned it — no modification of any
 * kind. A round trip through a document model normalises whitespace, attribute
 * order and namespace declarations, all of which are inside what the region
 * signed. So the bytes the caller passes are the bytes the caller still holds
 * afterwards: this module reads them and hands back nothing derived from them.
 *
 * ## Three phases, and why the first two stop
 *
 * The structural phase asks whether there is an assertion here at all:
 * parseable, an assertion element at the root, one assertion element in the
 * whole document, the attributes §4.1.6.2.2 makes
 * mandatory, exactly one each of the elements it requires — the issuer, the
 * subject, and the conditions carrying the validity window — and one operator
 * identifier in the subject. It reports one
 * failure and stops, in both directions — it does not accumulate structural
 * failures, and it does not let the later phases run. Neither would be worth
 * anything: a document that failed to parse has no audience to compare, no
 * window to check and no signature to bind, so every later check would report a
 * missing thing that is missing only because the document is.
 *
 * The signature is mandatory too and is deliberately not checked there:
 * §4.1.6.2.2 makes it an element like the others, but its absence and its being
 * malformed map to different regional error codes, and a phase with one code to
 * report would collapse them. It gets its own phase, in `signature.ts`, which
 * asks whether the signature covers *this* assertion: present, built of the
 * elements §4.1.6.2.2 names, and carrying exactly one reference naming the
 * assertion's own identifier. It reports one failure and stops too, for the
 * same kind of reason — an assertion whose signature does not bind to it has no
 * content worth an opinion, and reporting that its audience was also wrong
 * would invite a caller to fix the audience.
 *
 * The semantic phase runs to completion and reports every failure it finds,
 * because by then the failures are independent: an assertion can be out of
 * date *and* wrongly scoped, and a caller deciding between refreshing and
 * re-scoping needs both. Today it holds four: the validity window, the
 * audience, the attributes the service requires, and the operator's identity
 * held against itself.
 *
 * ## Every refusal carries the one thing to do about it
 *
 * Reporting several reasons is only half an answer — a caller acting on them
 * one at a time spends a round trip per reason. So a refusal from any of the
 * three phases carries a single {@link Remedy}, derived in `src/remedy.ts` from
 * the whole failure set, which resolves all of them at once.
 *
 * ## The service is an argument too
 *
 * The audience, the attributes an assertion must carry and the authentication
 * level it must attest are all checked against a policy the caller supplies,
 * because §3.1.1 and §4.2.5.3.1 between them make "does this service accept
 * this assertion" a property of the service and of the organisation's own
 * policies rather than of the RVE-1.b transaction.
 * `src/service-policy.ts` holds the type and the reasoning; here it is one more
 * required argument, for the same reason the clock is one: there is no
 * validating an assertion without saying when, and against what, it is about to
 * be spent.
 *
 * ## Time is an argument, not an ambient fact
 *
 * The current instant is a required input with no default, and the two margins
 * around it are separate required inputs rather than one combined fudge factor,
 * because they are two different quantities that happen to share a unit.
 *
 * Clock skew is how far this host's clock may be from the IAP's. It moves both
 * bounds earlier by the same amount, which is exactly the assumption that this
 * clock may be that far *behind* the issuer's — the direction in which being
 * wrong is dangerous, since a clock that is behind is one that thinks a closed
 * window is still open. Estimated flight time is how long a call carrying the
 * assertion takes to reach the X-Service Provider that will check it: a real
 * interval that elapses *after* this library answers, so it moves the far bound
 * earlier again and the near bound not at all.
 *
 * One combined margin cannot do both, and gets the near bound wrong in the
 * direction that refuses assertions the IAP has only just issued.
 *
 * {@link RECOMMENDED_CLOCK_SKEW_MS} and {@link RECOMMENDED_FLIGHT_TIME_MS} are
 * named rather than applied, so that a caller taking them has written down that
 * it did. See `docs/spec-questions.md` (D-014).
 */

import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Document, Element } from '@xmldom/xmldom';

import { ASSERTION_ATTRIBUTES, readAssertionAttributes } from './assertion-attributes.js';
import type { AssertionAttributes } from './assertion-attributes.js';
import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES, type RegionalErrorCode } from './regional-error-codes.js';
import { deriveRemedy, type Remedy } from './remedy.js';
import { audienceMatches, type ServicePolicy } from './service-policy.js';
import {
  cryptographicVerification,
  NO_SIGNATURE_VERIFICATION,
  signatureIntegrity,
  type SignatureVerifier,
} from './signature.js';
import { ValidationInputError } from './types.js';
import { attribute, onlySamlChild, samlChildren, text } from './saml-dom.js';

/** The local name of the element an assertion is — §4.1.6.2.2. */
const ASSERTION_ELEMENT = 'Assertion';

/** The local name of the element carrying the validity window — §4.1.6.2.2. */
const CONDITIONS_ELEMENT = 'Conditions';

/** The local name of the element scoping an assertion to services — §4.1.6.2.2. */
const AUDIENCE_RESTRICTION_ELEMENT = 'AudienceRestriction';

/** The local name of the element naming one such service — §4.1.6.2.2. */
const AUDIENCE_ELEMENT = 'Audience';

/** The element §4.1.6.2.2 puts the operator's identity in. */
const SUBJECT_ELEMENT = 'Subject';

/** The element inside the subject that carries the operator's tax code. */
const NAME_ID_ELEMENT = 'NameID';

/** SAML 2.0 protocol version, the only value §4.1.6.2.2 permits. */
const SAML_VERSION = '2.0';

/**
 * Why a validation failed, in this library's vocabulary.
 *
 * This is what a caller switches on. The regional code travelling beside it is
 * an annotation for the support conversation, not the identity of the failure —
 * see {@link AssertionFailure}.
 *
 * `malformed` covers every way of not being an assertion, deliberately, since
 * the remedy for all of them is the same and it is not a remedy this library
 * can name. The two window verdicts are kept apart from each other because
 * their remedies differ and both are things a caller can act on without help:
 * `expired` is answered by requesting a fresh assertion, and `not-yet-valid`
 * is answered by fixing a clock, since an IAP that issues assertions starting
 * in the future is not something a retry loop will outlast.
 *
 * The two audience verdicts are kept apart for the same kind of reason.
 * `audience-mismatch` says a scoped assertion was spent on a service it was not
 * scoped to — a caching bug, or a re-request that kept the previous call's
 * audience. `audience-absent` says the assertion is generic and this service
 * refuses generic assertions (§3.1.1) — the request never asked for a scope,
 * and the tenant's configuration for this service is what changes. Both are
 * resolved by one re-request, and a caller told only "audience" cannot tell
 * which of its two bugs it has.
 *
 * The next three are kept apart for the same reason again. A missing attribute
 * is answered by a re-request; a missing authentication level escalates out of
 * the assertion layer entirely, to the session that has to acquire a second
 * factor; and an identity mismatch is answered by nothing a caller can do.
 *
 * The four signature verdicts are kept apart from each other and from
 * `malformed` because they are four different conversations.
 * `signature-absent` says the IAP returned an unsigned assertion;
 * `signature-malformed` says it returned a signed one this library could not
 * read, which is a defect to report to the AULSS; `signature-not-bound` says
 * the signature covers something other than this assertion, which is the shape
 * of an attack and may deserve an alert rather than a log line; and
 * `signature-verification-failed` is the caller's own verifier speaking.
 */
export type AssertionFailureCode =
  | 'malformed'
  | 'signature-absent'
  | 'signature-malformed'
  | 'signature-not-bound'
  | 'signature-verification-failed'
  | 'not-yet-valid'
  | 'expired'
  | 'audience-mismatch'
  | 'audience-absent'
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
 * caller. An assertion carries the operator's tax code, and
 * on some documents it carries a patient identifier; a detail that echoed what
 * it found would put those into whatever logs the failure, including on the
 * refusal paths where nothing has been validated and the document may be
 * hostile. Diagnosis of a specific document is the caller's, against the bytes
 * it still holds.
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
   * a retry will succeed. What to actually *do* about a failure is not here at
   * all: it is {@link InvalidAssertion.remedy}'s to say, derived from the whole
   * failure set, and a remedy field beside each failure would be a second
   * source for one mapping.
   */
  readonly unrecoverable: boolean;
}

/**
 * Something the caller should know about an assertion this library accepted.
 *
 * Not a failure and not a soft one. A warning never contributes to a refusal
 * and carries no regional error code, because the region did not refuse
 * anything either — every warning here describes a document the specification
 * permits, or a check this library did not perform. It exists so that a caller
 * can decide, with its own policy, what to do about either.
 */
export type AssertionWarningCode =
  | 'deprecated-signature-algorithm'
  | 'deprecated-digest-algorithm'
  | 'signature-not-cryptographically-verified';

/** One thing worth knowing about an accepted assertion. */
export interface AssertionWarning {
  readonly code: AssertionWarningCode;
  readonly detail: string;
}

/**
 * What a caller can supply to the validator beyond the assertion, the clock and
 * the service policy.
 *
 * One seam so far. Cryptographic verification needs a key, a trust decision
 * about that key and a canonicalisation implementation, none of which this
 * library holds — see {@link SignatureVerifier}. Omitting it is supported and
 * is the default, and the result says plainly that it happened.
 */
export interface AssertionValidationOptions {
  readonly verifySignature?: SignatureVerifier;
}

/**
 * An assertion this library found no fault with.
 *
 * Reports what a caller needs from an assertion it did not build: who the
 * region says the operator is, what the assertion is scoped to, how strongly
 * the operator authenticated, and how long it is worth holding.
 */
export interface ValidAssertion {
  readonly valid: true;

  /**
   * What was accepted about this assertion that a caller may still want to act
   * on: a deprecated algorithm the region permits, and — in every build where
   * the caller supplied no verifier — the fact that no signature was
   * cryptographically verified.
   *
   * On the success branch rather than beside the failures, because none of it
   * is a reason to refuse the assertion and none of it should be reachable
   * where a caller is handling refusals.
   */
  readonly warnings: readonly AssertionWarning[];

  /**
   * The operator's tax code, as the subject's `NameID` carries it — §4.1.6.2.2
   * makes that the unique identifier of the user the credentials belong to, and
   * the responsible-party attribute has been checked to agree with it.
   *
   * Not validated as a tax code, deliberately: `docs/spec-questions.md` (D-019).
   * Reported as written, beyond the whitespace an indented document put around
   * it.
   */
  readonly operatorTaxCode: string;

  /**
   * The services this assertion is scoped to, in document order — the
   * `Audience` elements of §4.1.6.2.2's optional audience restriction, across
   * every restriction the assertion carries.
   *
   * Empty for §3.1.1's generic assertion, which §4.1.6.2.2 permits and which
   * the audience check has already decided this service accepts. Reported for
   * the caching layer, which keys on what an assertion is good for as well as
   * on how long it is good for.
   */
  readonly audiences: readonly string[];

  /**
   * The authentication level the assertion attests, or `undefined` when it
   * attests none.
   *
   * A string rather than the level the specification names, and deliberately
   * not narrowed: the excerpt names one level and cannot say the region has not
   * added another since (`docs/spec-questions.md`, D-007). A received value is
   * the IAP's to state; refusing an unrecognised one would refuse an assertion
   * that is stronger than this library knows how to read.
   */
  readonly authenticationLevel: string | undefined;

  /**
   * The instant at which this assertion stops being worth spending: its
   * `NotOnOrAfter`, less the clock skew and the estimated flight time the
   * caller supplied.
   *
   * Exclusive, like the `NotOnOrAfter` it is derived from — a caller holding
   * the assertion *at* this instant is holding it one instant too long, and
   * this validator would refuse it. It is a deadline for a cache to evict on,
   * and it is deliberately earlier than the assertion's own expiry, because an
   * assertion held until the instant the document expires is one that expires
   * in flight.
   *
   * An expiry, not a promise: a caller holding one before this instant may
   * still have it refused, for any of the reasons this build does not check.
   */
  readonly usableUntil: Date;
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

  /**
   * The one thing to do about all of them — see {@link Remedy}.
   *
   * Derived from the whole failure set rather than from the first failure or
   * from a severity written down somewhere, so that executing it resolves every
   * reason at once and the caller makes at most one further round trip. A
   * caller acting on `failures[0]` alone would fix one reason, spend a round
   * trip against a third-party IAP, and meet the next.
   *
   * Beside the failures rather than on each of them: `src/remedy.ts` holds one
   * mapping from failure code to remedy, and a per-failure field would be a
   * second copy of it to keep in step.
   */
  readonly remedy: Remedy;
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
function refused(detail: string): StructuralRefusal {
  const failure: AssertionFailure = {
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

  return { read: false, failure };
}

/**
 * A recommended allowance for the difference between this host's clock and the
 * clock the IAP timestamped the assertion with: one minute.
 *
 * This library's own recommendation, not the region's, and one a caller passes
 * explicitly or replaces with its own — `docs/spec-questions.md` (D-014).
 */
export const RECOMMENDED_CLOCK_SKEW_MS = 60_000;

/**
 * A **placeholder** for the time a call carrying the assertion takes to reach
 * the X-Service Provider that will check it: five seconds.
 *
 * **Replace this.** It is the one figure in this module a caller is expected to
 * supply for itself: its own measured high-percentile round trip to the
 * regional services it calls — a p99, not a mean, because the calls that expire
 * in flight are by definition the slow ones. Five seconds is not a measurement
 * of anything and nothing in the specification supports it; the consequences of
 * leaving it wrong in either direction are in `docs/spec-questions.md` (D-014).
 */
export const RECOMMENDED_FLIGHT_TIME_MS = 5_000;

/**
 * The clock, and the two allowances around it, that an assertion's validity
 * window is checked against.
 *
 * Every field is required. There is no default clock because a validator that
 * reaches for the ambient one cannot be tested at a chosen instant and cannot
 * be driven by a caller that has a better time source than this process; and
 * there are no default margins because a margin applied silently is a margin
 * nobody chose — see {@link RECOMMENDED_CLOCK_SKEW_MS}.
 */
export interface AssertionTimeModel {
  /** The instant to judge the assertion at, normally `new Date()`. */
  readonly now: Date;

  /**
   * How far, in milliseconds, this host's clock may be from the IAP's, in
   * either direction. Loosens both bounds. Zero declines the allowance.
   */
  readonly clockSkewMs: number;

  /**
   * How long, in milliseconds, a call carrying this assertion is expected to
   * take to reach the service that will check it. Tightens the far bound only.
   * Zero declines the allowance.
   */
  readonly flightTimeMs: number;
}

/** The validity window an assertion's Conditions element declares. */
interface ValidityWindow {
  readonly notBefore: Date;
  readonly notOnOrAfter: Date;
}

/**
 * `xs:dateTime` restricted to the forms that name an instant on their own.
 *
 * A time zone is required: `xs:dateTime` permits one to be omitted, and a value
 * with none names a wall-clock reading rather than a moment, so comparing it to
 * a clock would be comparing it to whichever zone the reader happened to be in.
 * §4.1.6.2.2 requires UTC and the excerpt's examples are all `Z`-suffixed, but
 * an explicit offset denotes the same instant and is accepted rather than
 * refused on a spelling. Fractional seconds are accepted for the same reason:
 * this library writes whole seconds (D-004) and does not require the IAP to.
 * Argued in `docs/spec-questions.md` (D-012).
 */
const UTC_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * `value` as an instant, or `undefined` when it is not one.
 *
 * The shape is checked before `Date.parse` rather than after, because
 * `Date.parse` is permitted to accept whatever else it likes and engines do:
 * a value this library must refuse would otherwise be turned into a date by one
 * runtime and rejected by another, and a validity check that depends on which
 * JavaScript engine is running is not a validity check. The parse still has to
 * be tested afterwards — the pattern admits impossible dates like a thirty-first
 * of February, which the parse is required to reject.
 */
function parseInstant(value: string): Date | undefined {
  if (!UTC_DATE_TIME.test(value)) {
    return undefined;
  }
  const milliseconds = Date.parse(value);
  return Number.isNaN(milliseconds) ? undefined : new Date(milliseconds);
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
const REQUIRED_ASSERTION_ELEMENTS = ['Issuer', 'Subject', CONDITIONS_ELEMENT] as const;

/**
 * What the structural phase hands the semantic phase, or the one reason it has
 * nothing to hand it.
 *
 * Tagged on `read` rather than discriminated by which field happens to be
 * present, so that a call site says which case it is handling in the same way
 * {@link AssertionValidation} makes its own caller say it.
 *
 * The success side carries the window, already parsed, and the `Conditions`
 * element the audience restrictions hang off. The element rather than the
 * audiences themselves: the window comes off the same element, and reading half
 * of `Conditions` here and half in the phase that uses it would put the
 * document's shape in two places. The assertion element joins it for the same
 * reason, since the attribute statement and the signature both hang off that
 * one, and the assertion's own identifier joins them because the signature
 * phase has to compare its reference against it.
 *
 * The subject identifier is read here rather than in the semantic phase because
 * §4.1.6.2.2 makes the subject carry it and there is no second place to look —
 * an assertion without one is not an assertion that failed a check, it is a
 * document that cannot say who it is about.
 */
interface StructuralRefusal {
  readonly read: false;
  readonly failure: AssertionFailure;
}

interface StructureRead {
  readonly read: true;
  readonly window: ValidityWindow;
  readonly assertion: Element;
  readonly conditions: Element;
  readonly subjectIdentifier: string;

  /**
   * The assertion's own `ID`, which the signature's reference has to name.
   *
   * Carried rather than re-read by the phase that compares against it: this
   * phase has already established that the attribute is present and non-blank,
   * and reading it a second time is a second chance to read it differently.
   */
  readonly id: string;
}

type StructuralRead = StructureRead | StructuralRefusal;

/**
 * The instant `name` names on `conditions`, or the refusal for its not naming
 * one.
 *
 * The attribute is known to be present and non-blank by the time this is
 * called, so the only thing left to fail is its lexical form.
 */
function conditionsInstant(
  conditions: Element,
  name: (typeof REQUIRED_CONDITIONS_ATTRIBUTES)[number],
): { readonly read: true; readonly instant: Date } | StructuralRefusal {
  const instant = parseInstant(attribute(conditions, name) ?? '');
  return instant === undefined
    ? refused(
        `the assertion's ${CONDITIONS_ELEMENT} carries a ${name} that is not a UTC dateTime with a time zone.`,
      )
    : { read: true, instant };
}

/**
 * Reads the structure of `assertion`, or names the first reason it is not an
 * assertion at all.
 *
 * The checks run in the order a reader would ask the questions — is it a
 * document, is it *this* document, does it carry what the document must carry —
 * and the first one that fails ends the phase. Ordering them is not a ranking
 * of severity: a later check cannot mean anything until the earlier ones hold.
 *
 * The window's timestamps are parsed here rather than in the semantic phase,
 * and that is a boundary worth stating: a `NotOnOrAfter` that is not a time is
 * a malformed document, not an expired one. Reporting it as expired would tell
 * a caller to refresh, and the refresh would return another assertion from the
 * same IAP with the same defect.
 */
function readStructure(assertion: Uint8Array): StructuralRead {
  const source = decodeUtf8(assertion);
  if (source === undefined) {
    return refused('the assertion bytes are not valid UTF-8.');
  }

  const document = parse(source);
  if (document === undefined) {
    return refused('the assertion bytes are not well-formed XML.');
  }

  // A document type declaration is refused rather than ignored. No assertion
  // needs one, and an internal subset is where an entity that expands into
  // something else would be declared — so the cheapest place to be sure the
  // element tree says what the bytes say is before reading the element tree.
  // Argued in `docs/spec-questions.md` (D-011).
  if (document.doctype !== null) {
    return refused('the assertion carries a document type declaration, which is refused.');
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
    return refused(
      "the root element is not a SAML 2.0 Assertion. The validator is handed the bare assertion element; unwrapping a response or a security header is the caller's.",
    );
  }

  // One assertion in the whole document, not merely one at the root. SAML
  // permits an assertion to carry others inside `saml:Advice`, and this library
  // refuses that: a second assertion anywhere in the tree is a second element a
  // signature reference could have been pointing at, and the binding check in
  // `signature.ts` is worth exactly as much as the assumption that there is one
  // thing the signature can be about. Refusing the whole document is cheaper
  // and more certain than reasoning about which nested assertions are harmless.
  // Argued in `docs/spec-questions.md` (D-024).
  if (document.getElementsByTagNameNS(SAML_ASSERTION_NAMESPACE, ASSERTION_ELEMENT).length !== 1) {
    return refused(
      'the document carries more than one Assertion element. Exactly one is accepted, so that there is exactly one element a signature reference can be about.',
    );
  }

  if (attribute(element, 'Version') !== SAML_VERSION) {
    return refused(`the assertion does not declare Version "${SAML_VERSION}".`);
  }

  const absentAttribute = firstAbsent(element, REQUIRED_ASSERTION_ATTRIBUTES);
  if (absentAttribute !== undefined) {
    return refused(`the assertion carries no ${absentAttribute} attribute.`);
  }

  // Exactly one of each, not at least one. A second Conditions element would
  // give the validity-window check two windows to choose between, and a choice
  // is exactly what a document that wants to be read two ways relies on.
  for (const name of REQUIRED_ASSERTION_ELEMENTS) {
    if (samlChildren(element, name).length !== 1) {
      return refused(`the assertion does not carry exactly one ${name} element.`);
    }
  }

  const conditions = onlySamlChild(element, CONDITIONS_ELEMENT);
  const subject = onlySamlChild(element, SUBJECT_ELEMENT);
  if (conditions === undefined || subject === undefined) {
    // Unreachable: the loop above established there is exactly one of each.
    // Written as a return rather than an assertion so that the compiler's
    // narrowing and the runtime's behaviour agree without a cast.
    return refused(
      `the assertion does not carry exactly one ${SUBJECT_ELEMENT} and ${CONDITIONS_ELEMENT} element.`,
    );
  }

  const absentConditionsAttribute = firstAbsent(conditions, REQUIRED_CONDITIONS_ATTRIBUTES);
  if (absentConditionsAttribute !== undefined) {
    return refused(
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
    return refused(
      `the assertion's ${SUBJECT_ELEMENT} does not carry exactly one ${NAME_ID_ELEMENT} with a value.`,
    );
  }

  const notBefore = conditionsInstant(conditions, 'NotBefore');
  if (!notBefore.read) {
    return notBefore;
  }
  const notOnOrAfter = conditionsInstant(conditions, 'NotOnOrAfter');
  if (!notOnOrAfter.read) {
    return notOnOrAfter;
  }

  // Deliberately not checked here: that NotOnOrAfter is after NotBefore. An
  // inverted or empty window gets no verdict of its own — the semantic phase
  // reports both bounds failing, which is the whole truth about it and needs
  // nothing invented. Refusing a window for its *length* is a different
  // question, and its answer belongs to the party holding the policy — D-013.
  const id = attribute(element, 'ID');
  if (id === undefined) {
    // Unreachable: ID is one of the required attributes checked above. Written
    // as a return rather than an assertion for the same reason the subject and
    // conditions case above is.
    return refused('the assertion carries no ID attribute.');
  }

  return {
    read: true,
    window: { notBefore: notBefore.instant, notOnOrAfter: notOnOrAfter.instant },
    assertion: element,
    conditions,
    subjectIdentifier,
    id,
  };
}

/**
 * Refuses a time model that would make every comparison meaningless.
 *
 * Thrown rather than returned, and checked before the document is touched, for
 * the reason {@link ValidationInputError} gives: a `NaN` anywhere in the model
 * makes every subsequent comparison false, so the validator would accept every
 * assertion put to it and report nothing wrong. A negative margin is refused
 * for the milder reason that it means the opposite of what its name says —
 * a negative skew tightens the near bound — and a caller that wants a bound
 * moved that way should move the clock it passes.
 */
function checkTimeModel({ now, clockSkewMs, flightTimeMs }: AssertionTimeModel): void {
  if (Number.isNaN(now.getTime())) {
    throw new ValidationInputError('the current time is not a valid instant.');
  }
  for (const [name, value] of [
    ['clockSkewMs', clockSkewMs],
    ['flightTimeMs', flightTimeMs],
  ] as const) {
    if (!Number.isFinite(value) || value < 0) {
      throw new ValidationInputError(
        `${name} must be a finite, non-negative number of milliseconds.`,
      );
    }
  }
}

/**
 * Every way the clock sits outside `window`, and the deadline it sits inside
 * when there is none.
 *
 * The two bounds are treated asymmetrically, and the asymmetry is the point.
 * Skew alone loosens the near bound: the only uncertainty about whether the
 * assertion has started is whose clock is right. Skew *and* flight time tighten
 * the far bound: the assertion has to still be inside its window not now but
 * when it arrives, and the caller may also be reading a clock that is behind.
 *
 * `NotBefore` is inclusive and `NotOnOrAfter` is exclusive, which is what their
 * SAML names say and all that settles it — Appendix A.5's Table 10 describes
 * ERR_00032 as `NotOnOrAfter` being *earlier than* the moment of use, which if
 * read as the whole rule would make the bound inclusive. The deadline is
 * therefore the first instant that is too late, and a caller holding the
 * assertion until exactly it is holding it one instant too long.
 */
function checkWindow(
  { notBefore, notOnOrAfter }: ValidityWindow,
  { now, clockSkewMs, flightTimeMs }: AssertionTimeModel,
): { readonly failures: readonly AssertionFailure[]; readonly usableUntil: Date } {
  const failures: AssertionFailure[] = [];
  const usableUntil = new Date(notOnOrAfter.getTime() - clockSkewMs - flightTimeMs);

  if (now.getTime() + clockSkewMs < notBefore.getTime()) {
    failures.push({
      code: 'not-yet-valid',
      detail:
        "the assertion's validity window has not opened yet, allowing for clock skew. Either this host's clock is behind the issuer's by more than the skew allowed, or the assertion was issued to start in the future.",
      // ERR_00031 — Appendix A.5, Table 10: NotBefore later than the moment of
      // use. An annotation, as everything here is — see {@link AssertionFailure}.
      regionalErrorCode: REGIONAL_ERROR_CODES.ASSERTION_NOT_YET_VALID,
      // A clock moves. So does the instant the window opens at.
      unrecoverable: false,
    });
  }

  if (now.getTime() >= usableUntil.getTime()) {
    failures.push({
      code: 'expired',
      detail:
        "the assertion's validity window has closed, or will close before a call carrying it could arrive, allowing for clock skew and estimated flight time. A fresh assertion is needed.",
      // ERR_00032 — Appendix A.5, Table 10: NotOnOrAfter earlier than the
      // moment of use. Reported for a window that has not closed yet but will
      // close in flight, which is the same refusal arriving earlier.
      regionalErrorCode: REGIONAL_ERROR_CODES.ASSERTION_EXPIRED,
      // A fresh assertion is exactly the round trip this does not rule out.
      unrecoverable: false,
    });
  }

  return { failures, usableUntil };
}

/**
 * One audience refusal. Both map to `ERR_00044`, which is the only code
 * Appendix A.5, Table 11 offers for an audience, and they are separate library
 * codes anyway — see {@link AssertionFailureCode}.
 *
 * The detail names no URL, not even the caller's own. Details are constant text
 * throughout this module, and the caller already holds the policy it passed.
 */
function audienceFailure(code: 'audience-mismatch' | 'audience-absent'): AssertionFailure {
  return {
    code,
    detail:
      code === 'audience-absent'
        ? 'the assertion names no audience, and this service was declared to refuse a generic assertion.'
        : 'the assertion is scoped to services that do not include the one it was validated against.',
    regionalErrorCode: REGIONAL_ERROR_CODES.AUDIENCE_NOT_PERMITTED,
    // A re-request scoped to this service is the remedy, and it exists.
    unrecoverable: false,
  };
}

/**
 * Whether `restriction` names the service `policy` describes.
 *
 * SAML 2.0 core makes the audiences within one restriction a disjunction, and
 * §4.1.6.2.2 agrees in substance: each sub-element names one X-Service Provider
 * that is entitled to accept the assertion, and there may be several. A
 * restriction naming none — which §4.1.6.2.2 permits, since it puts no lower
 * bound on how many sub-elements there are — restricts to nobody, so it is
 * satisfied by nobody.
 */
function restrictionNames(restriction: Element, policy: ServicePolicy): boolean {
  return audiencesOf(restriction).some((audience) => audienceMatches(policy, audience));
}

/**
 * The services `element` names, in document order.
 *
 * One reading of an `Audience` element, shared by the check and by what the
 * success branch reports, so that a caller cannot be told it is scoped to
 * something the match did not compare. `text` refuses an element whose content
 * is other elements, which is how `<Audience><x>http://</x>evil</Audience>`
 * stops being a URL.
 */
function audiencesOf(element: Element): readonly string[] {
  return samlChildren(element, AUDIENCE_ELEMENT)
    .map((audience) => text(audience))
    .filter((audience): audience is string => audience !== undefined);
}

/** Every service the assertion is scoped to, across every restriction. */
function audiences(conditions: Element): readonly string[] {
  return samlChildren(conditions, AUDIENCE_RESTRICTION_ELEMENT).flatMap((restriction) =>
    audiencesOf(restriction),
  );
}

/**
 * Every way `conditions` scopes the assertion somewhere other than the service
 * `policy` describes — at most one, since there is one thing to say about it.
 */
function checkAudience(conditions: Element, policy: ServicePolicy): readonly AssertionFailure[] {
  const restrictions = samlChildren(conditions, AUDIENCE_RESTRICTION_ELEMENT);

  // No restriction at all is §3.1.1's generic assertion, and it is conforming:
  // §4.1.6.2.2 makes the element optional. Whether this service accepts one is
  // the caller's to declare, and the baseline says it does — see
  // BASELINE_SERVICE_POLICY.
  if (restrictions.length === 0) {
    return policy.refusesGenericAssertions ? [audienceFailure('audience-absent')] : [];
  }

  // Conjoined, not flattened. SAML 2.0 core makes each AudienceRestriction a
  // condition in its own right, so an assertion carrying two is scoped to the
  // intersection. Argued in `docs/spec-questions.md` (D-018).
  return restrictions.every((restriction) => restrictionNames(restriction, policy))
    ? []
    : [audienceFailure('audience-mismatch')];
}


/**
 * The regional code that names a missing attribute best, per attribute.
 *
 * No code in Appendix A.5 names an attribute that is absent, so each of these
 * is the nearest neighbour to a question the region asks differently. The
 * choice is argued in `docs/spec-questions.md` (D-022); the annotation is a
 * best match either way, per {@link AssertionFailure}.
 */
const ATTRIBUTE_ERROR_CODES: Readonly<Record<string, RegionalErrorCode>> = {
  [ASSERTION_ATTRIBUTES.REQUEST_CONTEXT]: REGIONAL_ERROR_CODES.REQUEST_CONTEXT_NOT_PERMITTED,
  [ASSERTION_ATTRIBUTES.ROLE]: REGIONAL_ERROR_CODES.ROLE_MISSING_OR_INVALID_IN_DIRECTORY,
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
  return [...new Set([ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, ...policy.requiredAttributes])];
}

/**
 * Every attribute the service required that the assertion does not carry.
 *
 * Presence, not value. Whether `R.1.1` is a role that may reach this service is
 * a decision the X-Service Provider makes against boundary tables the region
 * holds and this library does not sync — the same reason the policy carries no
 * permitted contexts and no permitted roles (D-017).
 */
function checkAttributes(
  attributes: AssertionAttributes,
  policy: ServicePolicy,
): readonly AssertionFailure[] {
  return requiredAttributes(policy)
    .filter((name) => !attributes.has(name))
    .map((name) => ({
      code: 'attribute-missing' as const,
      // The name came from the policy, which came from the caller — so naming
      // it quotes the caller and not the document. See {@link AssertionFailure}.
      detail: `the assertion carries no ${name} attribute with a value, and the service requires one.`,
      regionalErrorCode:
        ATTRIBUTE_ERROR_CODES[name] ?? REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY,
      unrecoverable: false,
    }));
}

/**
 * The authentication level the assertion attests, and every way it does not
 * attest the one required.
 *
 * The regional code differs between the two ways of failing, because they are
 * not the same claim. A service demanding a level is what Appendix A.5, Table
 * 12's ERR_00065 is for; an assertion contradicting itself is not, and saying
 * it was would put a demand into the support conversation that nothing made.
 * See `docs/spec-questions.md` (D-022, D-023).
 */
function checkAuthenticationLevel(
  attributes: AssertionAttributes,
  policy: ServicePolicy,
): {
  readonly failures: readonly AssertionFailure[];
  readonly authenticationLevel: string | undefined;
} {
  const levels = attributes.get(ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL) ?? [];
  const authenticationLevel = levels.length === 1 ? levels[0] : undefined;

  if (levels.length > 1) {
    // Two answers to a question with one answer, whatever the policy asked for
    // — an assertion contradicting itself about how strongly the operator
    // authenticated attests nothing, and there is no service that is safe for.
    // Argued in `docs/spec-questions.md` (D-023).
    return {
      authenticationLevel,
      failures: [
        {
          code: 'authentication-level-not-attested',
          detail: 'the assertion attests more than one authentication level, so it attests none.',
          regionalErrorCode: REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY,
          unrecoverable: false,
        },
      ],
    };
  }

  if (
    policy.requiredAuthenticationLevel !== undefined &&
    authenticationLevel !== policy.requiredAuthenticationLevel
  ) {
    return {
      authenticationLevel,
      failures: [
        {
          code: 'authentication-level-not-attested',
          detail:
            "the service requires an authentication level the assertion does not attest. The operator must authenticate again with a second factor, which is the session's work and not a re-request.",
          regionalErrorCode: REGIONAL_ERROR_CODES.TWO_FACTOR_AUTHENTICATION_REQUIRED,
          // The operator can authenticate again with a second factor. That is
          // the session layer's work rather than a re-request, but it is work
          // that exists.
          unrecoverable: false,
        },
      ],
    };
  }

  return { authenticationLevel, failures: [] };
}

/**
 * The two identities in an assertion, compared as one identity written twice.
 *
 * Compared with case folded away, and nothing else: the region writes a Codice
 * Fiscale in upper case, and folding case cannot make two different tax codes
 * equal — so it removes a way of refusing a correct assertion without weakening
 * the check. Argued in `docs/spec-questions.md` (D-020). Locale-independent
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
function checkIdentity(
  subjectIdentifier: string,
  attributes: AssertionAttributes,
): readonly AssertionFailure[] {
  const responsibleParties = attributes.get(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY);

  // Absent is the missing-attribute failure and not this one. A mismatch
  // reported beside it would name a disagreement nothing had.
  if (responsibleParties === undefined) {
    return [];
  }

  if (responsibleParties.every((party) => sameIdentity(party, subjectIdentifier))) {
    return [];
  }

  return [
    {
      code: 'identity-mismatch',
      detail: `the assertion's ${SUBJECT_ELEMENT} and its ${ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY} attribute do not name one operator.`,
      // Appendix A.5, Table 12's ERR_00059 is the region's code for this
      // disagreement about this value, reached by comparing against the AULSS's
      // own directory rather than by comparing the assertion against itself.
      // See `docs/spec-questions.md` (D-022).
      regionalErrorCode: REGIONAL_ERROR_CODES.RESPONSIBLE_PARTY_FISCAL_CODE_MISMATCH,
      // Asking the same IAP the same question returns the same two answers, so
      // a retry is a loop against a third party. Someone has to fix the
      // directory the IAP is reading, and no round trip from here does that.
      unrecoverable: true,
    },
  ];
}

/**
 * A refusal, with the single remedy for everything in it.
 *
 * One place the remedy is attached, so that no refusal path can return a result
 * without one — including the two phases that short-circuit, whose failures a
 * caller has to act on just as much.
 */
function invalid(
  failures: readonly [AssertionFailure, ...AssertionFailure[]],
  policy: ServicePolicy,
): InvalidAssertion {
  return { valid: false, failures, remedy: deriveRemedy(failures, policy) };
}

/**
 * Validates the identity assertion in `assertion`, as the exact bytes the
 * Identity and Assertion Provider returned.
 *
 * Returns rather than throws, deliberately asymmetric with the request side's
 * smart constructor: this input is third-party data that a caller must handle
 * being refused, whereas request input is the caller's own arguments and a bad
 * one there is a programming error. See `src/types.ts`.
 *
 * Never mutates `assertion` and never reserialises it. The caller keeps the
 * bytes it will spend.
 *
 * Throws {@link ValidationInputError} — never for the assertion, only for
 * `time`. The document is data to be refused; the time model is the caller's
 * own arguments, and one that cannot be compared against is a defect in the
 * caller rather than in the IAP. `policy` cannot fail here at all: it was
 * checked where it was built, by `servicePolicy`.
 *
 * `policy` describes the one regional service this assertion is about to be
 * spent on, and is required for the same reason `time` is: §3.1.1's
 * confidential services make "is this assertion acceptable" a question that
 * cannot be asked without naming the service asking it.
 *
 * **Incomplete — see the module comment.** The structure, the signature's
 * structure and binding, the validity window, the audience, the attributes the
 * service requires and the operator's identity are checked. The signature is
 * verified only if `options.verifySignature` says so, and a valid result
 * carries a warning saying which of those happened.
 */
export function validateAssertion(
  assertion: Uint8Array,
  time: AssertionTimeModel,
  policy: ServicePolicy,
  options: AssertionValidationOptions = {},
): AssertionValidation {
  checkTimeModel(time);

  const structure = readStructure(assertion);
  if (!structure.read) {
    return invalid([structure.failure], policy);
  }

  // The signature phase, before the semantic one and short-circuiting like the
  // structural phase: an assertion whose signature does not cover it has an
  // audience and a window nobody vouched for.
  const integrity = signatureIntegrity(structure.assertion, structure.id);
  if (!integrity.ok) {
    return invalid([integrity.failure], policy);
  }

  const verification = cryptographicVerification(
    assertion,
    options.verifySignature ?? NO_SIGNATURE_VERIFICATION,
  );
  if (!verification.ok) {
    return invalid([verification.failure], policy);
  }

  // The semantic phase: every check runs, and every failure is reported.
  const attributes = readAssertionAttributes(structure.assertion);
  const { failures: windowFailures, usableUntil } = checkWindow(structure.window, time);
  const { failures: levelFailures, authenticationLevel } = checkAuthenticationLevel(
    attributes,
    policy,
  );

  const [first, ...rest] = [
    ...windowFailures,
    ...checkAudience(structure.conditions, policy),
    ...checkAttributes(attributes, policy),
    ...levelFailures,
    ...checkIdentity(structure.subjectIdentifier, attributes),
  ];
  if (first !== undefined) {
    return invalid([first, ...rest], policy);
  }

  return {
    valid: true,
    warnings: [...integrity.warnings, ...verification.warnings],
    operatorTaxCode: structure.subjectIdentifier,
    audiences: audiences(structure.conditions),
    authenticationLevel,
    usableUntil,
  };
}
