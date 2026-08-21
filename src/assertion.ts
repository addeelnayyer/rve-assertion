/**
 * The assertion validator — §4.1.6.2.2, which §4.2.6 makes RVE-1.b's response
 * structure by reference.
 *
 * **Status: incomplete.** The structural phase and the audience check are here.
 * The rest of the semantic phase — validity window, required attributes,
 * identity cross-check, signature integrity — is not, so a `valid: true` result
 * from this build means *this document is shaped like an assertion and is
 * scoped to the service it was checked against*, and nothing more. It does not
 * mean the assertion is in date, or signed at all. Until the remaining work
 * lands, a caller must not read the success branch as permission to spend the
 * assertion. The README says the same thing where a reader will meet it first.
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
 * The semantic phase runs to completion and reports every failure. Today the
 * only thing it has to check is the audience — whether the assertion is scoped
 * to the service the caller is about to call, against a policy the caller
 * supplies, since §3.1.1 makes that a property of the service rather than of
 * the transaction. The rest arrives with the tickets that give it something to
 * check.
 */

import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Document, Element } from '@xmldom/xmldom';

import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES, type RegionalErrorCode } from './regional-error-codes.js';
import { audienceMatches, type ServicePolicy } from './service-policy.js';

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
 * `malformed` is the structural phase's one verdict: a document either is an
 * assertion or is not one, and it covers every way of not being one
 * deliberately, since the remedy for all of them is the same and it is not a
 * remedy this library can name.
 *
 * The two audience members are separate because they are two different
 * corrections. `audience-mismatch` says a scoped assertion was spent on a
 * service it was not scoped to — a caching bug, or a re-request that kept the
 * previous call's audience. `audience-absent` says the assertion is generic and
 * this service refuses generic assertions (§3.1.1) — the request never asked
 * for a scope, and the tenant's configuration for this service is what changes.
 * Both are resolved by one re-request, and a caller told only "audience" cannot
 * tell which of its two bugs it has.
 */
export type AssertionFailureCode = 'malformed' | 'audience-mismatch' | 'audience-absent';

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
 * Carries no payload yet. The operator's tax code, the audiences, the
 * authentication level and the usable-until deadline are reported by the
 * semantic checks that read them, and those are not written yet — see the
 * module comment. The audience check reads the audiences and reports none of
 * them, deliberately: a caller that wants to know which services an assertion
 * is scoped to is a caching layer, and that is the ticket that will add the
 * field along with the deadline it is actually keyed on.
 */
export interface ValidAssertion {
  readonly valid: true;
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
function refusal(detail: string): StructuralOutcome {
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

  return { structured: false, failure };
}

/**
 * What the structural phase reached: a refusal, or the parts of the document
 * the semantic phase reads.
 *
 * A tagged union rather than `AssertionFailure | Element`, so that adding a
 * second part for a later phase to read does not turn the discriminant into a
 * question about which shape came back.
 */
type StructuralOutcome =
  | { readonly structured: false; readonly failure: AssertionFailure }
  | { readonly structured: true; readonly conditions: Element };

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
 * Names the first reason `assertion` is not an assertion, or `undefined` when
 * it is one.
 *
 * The checks run in the order a reader would ask the questions — is it a
 * document, is it *this* document, does it carry what the document must carry —
 * and the first one that fails ends the phase. Ordering them is not a ranking
 * of severity: a later check cannot mean anything until the earlier ones hold.
 *
 * On success it hands the semantic phase the `Conditions` element and nothing
 * else, because the audience is all that phase reads today. The element rather
 * than the audiences themselves: the validity window lives on the same element,
 * and extracting one thing here and another there would put half the reading of
 * `Conditions` in the phase that is not about to use it.
 */
function checkStructure(assertion: Uint8Array): StructuralOutcome {
  const source = decodeUtf8(assertion);
  if (source === undefined) {
    return refusal('the assertion bytes are not valid UTF-8.');
  }

  const document = parse(source);
  if (document === undefined) {
    return refusal('the assertion bytes are not well-formed XML.');
  }

  // A document type declaration is refused rather than ignored. No assertion
  // needs one, and an internal subset is where an entity that expands into
  // something else would be declared — so the cheapest place to be sure the
  // element tree says what the bytes say is before reading the element tree.
  // Argued in `docs/spec-questions.md` (D-011).
  if (document.doctype !== null) {
    return refusal('the assertion carries a document type declaration, which is refused.');
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
    return refusal(
      "the root element is not a SAML 2.0 Assertion. The validator is handed the bare assertion element; unwrapping a response or a security header is the caller's.",
    );
  }

  if (attribute(element, 'Version') !== SAML_VERSION) {
    return refusal(`the assertion does not declare Version "${SAML_VERSION}".`);
  }

  const absentAttribute = firstAbsent(element, REQUIRED_ASSERTION_ATTRIBUTES);
  if (absentAttribute !== undefined) {
    return refusal(`the assertion carries no ${absentAttribute} attribute.`);
  }

  // Exactly one of each, not at least one. A second Conditions element would
  // give the validity-window check two windows to choose between, and a choice
  // is exactly what a document that wants to be read two ways relies on.
  for (const name of REQUIRED_ASSERTION_ELEMENTS) {
    if (samlChildren(element, name).length !== 1) {
      return refusal(`the assertion does not carry exactly one ${name} element.`);
    }
  }

  const [conditions] = samlChildren(element, CONDITIONS_ELEMENT);
  if (conditions === undefined) {
    // Unreachable: the loop above established there is exactly one. Written as
    // a return rather than an assertion so that the compiler's narrowing and
    // the runtime's behaviour agree without a cast.
    return refusal(`the assertion does not carry exactly one ${CONDITIONS_ELEMENT} element.`);
  }

  const absentConditionsAttribute = firstAbsent(conditions, REQUIRED_CONDITIONS_ATTRIBUTES);
  if (absentConditionsAttribute !== undefined) {
    return refusal(
      `the assertion's ${CONDITIONS_ELEMENT} carries no ${absentConditionsAttribute} attribute.`,
    );
  }

  return { structured: true, conditions };
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
 * Every reason the assertion may not be spent on the service `policy`
 * describes.
 *
 * Runs to completion rather than stopping at the first, which is the semantic
 * phase's contract: a caller that fixes one problem, retries against a
 * third-party IAP and discovers a second has spent a round trip to learn what
 * this list could have told it. Today the list has at most one member, because
 * the audience is the only thing checked here yet.
 */
function semanticFailures(conditions: Element, policy: ServicePolicy): AssertionFailure[] {
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
  // intersection. Argued in `docs/spec-questions.md` (D-015).
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
 * `policy` describes the one regional service this assertion is about to be
 * spent on, and is required: §3.1.1's confidential services make "is this
 * assertion acceptable" a question that cannot be asked without naming the
 * service asking it.
 *
 * **Incomplete — see the module comment.** This does not yet establish that an
 * assertion is in date, carries the attributes a service requires, or is signed
 * at all.
 */
export function validateAssertion(
  assertion: Uint8Array,
  policy: ServicePolicy,
): AssertionValidation {
  const structural = checkStructure(assertion);
  if (!structural.structured) {
    return { valid: false, failures: [structural.failure] };
  }

  const [first, ...rest] = semanticFailures(structural.conditions, policy);

  return first === undefined ? { valid: true } : { valid: false, failures: [first, ...rest] };
}
