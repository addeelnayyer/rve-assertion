/**
 * The assertion validator — §4.1.6.2.2, which §4.2.6 makes RVE-1.b's response
 * structure by reference.
 *
 * **Status: incomplete.** The structural phase, the validity window and the
 * audience are here; required attributes, identity cross-check and signature
 * integrity are not. So a `valid: true` result from this build means *this
 * document is shaped like an assertion, the clock is inside its window, and it
 * is scoped to the service it was checked against*, and nothing more — it does
 * not mean it was signed by anyone at all. Until the remaining work lands, a
 * caller must not read the success branch as permission to spend the assertion.
 * The README says the same thing where a reader will meet it first.
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
 * ## Two phases, and why the first one stops
 *
 * The structural phase asks whether there is an assertion here at all:
 * parseable, an assertion element at the root, the attributes §4.1.6.2.2 makes
 * mandatory, and exactly one each of the elements it requires — the issuer, the
 * subject, and the conditions carrying the validity window. It reports one
 * failure and stops, in both directions — it does not accumulate structural
 * failures, and it does not let the semantic phase run. Neither would be worth
 * anything: a document that failed to parse has no audience to compare, no
 * window to check and no signature to bind, so every later check would report a
 * missing thing that is missing only because the document is.
 *
 * The signature is mandatory too and is deliberately not checked here: §4.1.6.2.2
 * makes it an element like the others, but its absence and its being malformed
 * map to different regional error codes, and this phase has one code to report.
 *
 * The semantic phase runs to completion and reports every failure it finds,
 * because by then the failures are independent: an assertion can be out of
 * date *and* wrongly scoped, and a caller deciding between refreshing and
 * re-scoping needs both. Today it holds two checks, the validity window and the
 * audience.
 *
 * ## The service is an argument too
 *
 * The audience is checked against a policy the caller supplies, because §3.1.1
 * makes "does this service accept this assertion" a property of the service and
 * of the organisation's own policies rather than of the RVE-1.b transaction.
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

import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES, type RegionalErrorCode } from './regional-error-codes.js';
import { audienceMatches, type ServicePolicy } from './service-policy.js';
import { ValidationInputError } from './types.js';

/** The local name of the element an assertion is — §4.1.6.2.2. */
const ASSERTION_ELEMENT = 'Assertion';

/** The local name of the element carrying the validity window — §4.1.6.2.2. */
const CONDITIONS_ELEMENT = 'Conditions';

/** The local name of the element scoping an assertion to services — §4.1.6.2.2. */
const AUDIENCE_RESTRICTION_ELEMENT = 'AudienceRestriction';

/** The local name of the element naming one such service — §4.1.6.2.2. */
const AUDIENCE_ELEMENT = 'Audience';

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
 */
export type AssertionFailureCode =
  | 'malformed'
  | 'not-yet-valid'
  | 'expired'
  | 'audience-mismatch'
  | 'audience-absent';

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
 * expected, in constant text. An assertion carries the operator's tax code, and
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
}

/**
 * An assertion this library found no fault with.
 *
 * The operator's tax code and the authentication level are the rest of the
 * semantic phase's to report, and it is not written yet — see the module
 * comment. The audiences are read, to check them, and reported by nothing: a
 * caller that wants to know which services an assertion is scoped to is a
 * caching layer, and that is the ticket that will add the field beside the
 * deadline it is actually keyed on.
 */
export interface ValidAssertion {
  readonly valid: true;

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

/** `Node.ELEMENT_NODE`, named rather than written as a bare 1. */
const ELEMENT_NODE = 1;

/** The direct children of `element` with this SAML local name. */
function samlChildren(element: Element, localName: string): readonly Element[] {
  const children: Element[] = [];
  for (const node of Array.from(element.childNodes)) {
    if (node.nodeType !== ELEMENT_NODE) {
      continue;
    }
    const child = node as Element;
    if (child.namespaceURI === SAML_ASSERTION_NAMESPACE && child.localName === localName) {
      children.push(child);
    }
  }
  return children;
}

/**
 * The value of `name` on `element`, or `undefined` when it is absent.
 *
 * A blank value counts as absent. An `ID=""` is not an identifier the signature
 * reference can be bound to, and an empty `NotOnOrAfter` is not a time — so
 * treating the two cases alike costs a caller nothing and saves every check
 * downstream from having to ask twice.
 */
function attribute(element: Element, name: string): string | undefined {
  const value = element.getAttribute(name);
  return value === null || value.trim().length === 0 ? undefined : value;
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
 * document's shape in two places. The attribute statement and the signature
 * join it as the checks that read them arrive; each is added by the ticket that
 * reads it, so the type never carries a field no test reaches.
 */
interface StructuralRefusal {
  readonly read: false;
  readonly failure: AssertionFailure;
}

interface StructureRead {
  readonly read: true;
  readonly window: ValidityWindow;
  readonly conditions: Element;
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

  const [conditions] = samlChildren(element, CONDITIONS_ELEMENT);
  if (conditions === undefined) {
    // Unreachable: the loop above established there is exactly one. Written as
    // a return rather than an assertion so that the compiler's narrowing and
    // the runtime's behaviour agree without a cast.
    return refused(`the assertion does not carry exactly one ${CONDITIONS_ELEMENT} element.`);
  }

  const absentConditionsAttribute = firstAbsent(conditions, REQUIRED_CONDITIONS_ATTRIBUTES);
  if (absentConditionsAttribute !== undefined) {
    return refused(
      `the assertion's ${CONDITIONS_ELEMENT} carries no ${absentConditionsAttribute} attribute.`,
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
  return {
    read: true,
    window: { notBefore: notBefore.instant, notOnOrAfter: notOnOrAfter.instant },
    conditions,
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
  return samlChildren(restriction, AUDIENCE_ELEMENT).some((audience) =>
    audienceMatches(policy, audience.textContent ?? ''),
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
 * **Incomplete — see the module comment.** The structure, the validity window
 * and the audience are checked; the required attributes, the identity
 * cross-check and the signature are not, so a valid result does not establish
 * that this assertion was signed by anyone.
 */
export function validateAssertion(
  assertion: Uint8Array,
  time: AssertionTimeModel,
  policy: ServicePolicy,
): AssertionValidation {
  checkTimeModel(time);

  const structure = readStructure(assertion);
  if (!structure.read) {
    return { valid: false, failures: [structure.failure] };
  }

  // The semantic phase: every check runs, and every failure is reported. The
  // remaining checks join the list here as they are written.
  const { failures: windowFailures, usableUntil } = checkWindow(structure.window, time);
  const [first, ...rest] = [...windowFailures, ...checkAudience(structure.conditions, policy)];
  if (first !== undefined) {
    return { valid: false, failures: [first, ...rest] };
  }

  return { valid: true, usableUntil };
}
