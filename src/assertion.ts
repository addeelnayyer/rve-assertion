/**
 * The assertion validator — §4.1.6.2.2, which §4.2.6 makes RVE-1.b's response
 * structure by reference.
 *
 * **Status: the structural phase only.** The semantic phase — validity window,
 * audience, required attributes, identity cross-check, signature integrity —
 * is not here yet, so a `valid: true` result from this build means *this
 * document is shaped like an assertion*, and nothing more. Until the remaining
 * work lands, a caller must not read the success branch as permission to spend
 * the assertion. The README says the same thing where a reader will meet it
 * first.
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
 * mandatory, and a conditions element carrying its window. It reports one
 * failure and stops, in both directions — it does not accumulate structural
 * failures, and it does not let the semantic phase run. Neither would be worth
 * anything: a document that failed to parse has no audience to compare, no
 * window to check and no signature to bind, so every later check would report a
 * missing thing that is missing only because the document is.
 *
 * The semantic phase — the one that runs to completion and reports every
 * failure — arrives with the tickets that give it something to check.
 */

import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Document, Element } from '@xmldom/xmldom';

import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES, type RegionalErrorCode } from './regional-error-codes.js';

/** The local name of the element an assertion is — §4.1.6.2.2. */
const ASSERTION_ELEMENT = 'Assertion';

/** The local name of the element carrying the validity window — §4.1.6.2.2. */
const CONDITIONS_ELEMENT = 'Conditions';

/** SAML 2.0 protocol version, the only value §4.1.6.2.2 permits. */
const SAML_VERSION = '2.0';

/**
 * Why a validation failed, in this library's vocabulary.
 *
 * This is what a caller switches on. The regional code travelling beside it is
 * an annotation for the support conversation, not the identity of the failure —
 * see {@link AssertionFailure}.
 *
 * One member today, because the structural phase has one verdict to reach: a
 * document either is an assertion or is not one. `malformed` covers every way
 * of not being one, deliberately, since the remedy for all of them is the same
 * and it is not a remedy this library can name.
 */
export type AssertionFailureCode = 'malformed';

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
 * authentication level and the usable-until deadline are the semantic phase's
 * to report, and it does not exist yet — see the module comment.
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
function malformed(detail: string): AssertionFailure {
  return {
    code: 'malformed',
    detail,
    // A document that is not recognisable as an assertion token is what
    // ERR_00023 names — Appendix A.5, Table 9.
    regionalErrorCode: REGIONAL_ERROR_CODES.ASSERTION_TOKEN_UNRECOGNISABLE,
  };
}

/**
 * What the structural phase leaves behind for the semantic phase: the parsed
 * document, the assertion element, and the attributes whose presence it just
 * established.
 *
 * Held as the lexical strings the document carries rather than as parsed
 * values. Whether `NotOnOrAfter` is a time at all, and what it means beside the
 * current instant, is the validity-window check's question, not this phase's;
 * turning a string into a `Date` here would be that check, performed early and
 * reported under the wrong code.
 */
interface AssertionStructure {
  readonly assertion: Element;
  readonly id: string;
  readonly issueInstant: string;
  readonly notBefore: string;
  readonly notOnOrAfter: string;
}

type StructuralPhase =
  | { readonly ok: true; readonly structure: AssertionStructure }
  | { readonly ok: false; readonly failure: AssertionFailure };

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

/** The direct children of `element` with this SAML local name. */
function samlChildren(element: Element, localName: string): readonly Element[] {
  return Array.from(element.childNodes).filter(
    (node): node is Element =>
      node.nodeType === 1 &&
      (node as Element).namespaceURI === SAML_ASSERTION_NAMESPACE &&
      (node as Element).localName === localName,
  );
}

/** The value of `name` on `element`, or `undefined` when it is absent or blank. */
function attribute(element: Element, name: string): string | undefined {
  const value = element.getAttribute(name);
  return value === null || value.trim().length === 0 ? undefined : value;
}

/**
 * Establishes that the bytes are an assertion at all, or names the first reason
 * they are not.
 *
 * The checks run in the order a reader would ask the questions — is it a
 * document, is it *this* document, does it carry what the document must carry —
 * and the first one that fails ends the phase. Ordering them is not a ranking
 * of severity: a later check cannot mean anything until the earlier ones hold.
 */
function readStructure(assertion: Uint8Array): StructuralPhase {
  const source = decodeUtf8(assertion);
  if (source === undefined) {
    return { ok: false, failure: malformed('the assertion bytes are not valid UTF-8.') };
  }

  const document = parse(source);
  if (document === undefined) {
    return { ok: false, failure: malformed('the assertion bytes are not well-formed XML.') };
  }

  // A document type declaration is refused rather than ignored. No assertion
  // needs one, and an internal subset is where an entity that expands into
  // something else would be declared — so the cheapest place to be sure the
  // element tree says what the bytes say is before reading the element tree.
  // Argued in `docs/spec-questions.md` (D-011).
  if (document.doctype !== null) {
    return {
      ok: false,
      failure: malformed('the assertion carries a document type declaration, which is refused.'),
    };
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
    return {
      ok: false,
      failure: malformed(
        'the root element is not a SAML 2.0 Assertion. The validator is handed the bare assertion element; unwrapping a response or a security header is the caller\'s.',
      ),
    };
  }

  const version = attribute(element, 'Version');
  if (version !== SAML_VERSION) {
    return { ok: false, failure: malformed(`the assertion does not declare Version "${SAML_VERSION}".`) };
  }

  const id = attribute(element, 'ID');
  if (id === undefined) {
    return { ok: false, failure: malformed('the assertion carries no ID attribute.') };
  }

  const issueInstant = attribute(element, 'IssueInstant');
  if (issueInstant === undefined) {
    return { ok: false, failure: malformed('the assertion carries no IssueInstant attribute.') };
  }

  // Exactly one, not at least one. A second Conditions element would give the
  // validity-window check two windows to choose between, and the choice is
  // exactly the ambiguity a document that wants to be read two ways relies on.
  const conditions = samlChildren(element, CONDITIONS_ELEMENT);
  const [window] = conditions;
  if (window === undefined || conditions.length > 1) {
    return {
      ok: false,
      failure: malformed('the assertion does not carry exactly one Conditions element.'),
    };
  }

  const notBefore = attribute(window, 'NotBefore');
  if (notBefore === undefined) {
    return { ok: false, failure: malformed('the assertion\'s Conditions carries no NotBefore attribute.') };
  }

  const notOnOrAfter = attribute(window, 'NotOnOrAfter');
  if (notOnOrAfter === undefined) {
    return {
      ok: false,
      failure: malformed('the assertion\'s Conditions carries no NotOnOrAfter attribute.'),
    };
  }

  return { ok: true, structure: { assertion: element, id, issueInstant, notBefore, notOnOrAfter } };
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
 * **Incomplete — see the module comment.** Only the structural phase runs, so
 * this does not yet establish that an assertion is in date, correctly scoped,
 * carries the attributes a service requires, or is signed at all.
 */
export function validateAssertion(assertion: Uint8Array): AssertionValidation {
  const structure = readStructure(assertion);
  if (!structure.ok) {
    return { valid: false, failures: [structure.failure] };
  }

  // The semantic phase runs here, over `structure.structure`, and reports every
  // failure rather than the first.
  return { valid: true };
}
