/**
 * The assertion validator — §4.1.6.2.2, which §4.2.6 makes RVE-1.b's response
 * structure by reference.
 *
 * **Status: the structural and signature phases.** The semantic phase —
 * validity window, audience, required attributes, identity cross-check — is not
 * here yet, so a `valid: true` result from this build means *this document is
 * shaped like an assertion and carries a signature that claims to cover it*,
 * and nothing more. Nothing here verifies that signature cryptographically
 * unless the caller supplies something that does. Until the remaining work
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
 * ## Three phases, and why the first two stop
 *
 * The **structural phase** asks whether there is an assertion here at all:
 * parseable, an assertion element at the root, one assertion element in the
 * whole document, the attributes §4.1.6.2.2 makes mandatory, and exactly one
 * each of the elements it requires — the issuer, the subject, and the
 * conditions carrying the validity window. It reports one failure and stops.
 *
 * The **signature phase** (`signature.ts`) asks whether the signature covers
 * this assertion: present, built of the elements §4.1.6.2.2 names, and carrying
 * exactly one reference naming the assertion's own identifier. It reports one
 * failure and stops too, and for the same reason the structural phase does — an
 * assertion whose signature does not bind to it has no content worth an
 * opinion. Reporting that its audience was also wrong would invite a caller to
 * fix the audience.
 *
 * The **semantic phase** — the one that runs to completion and reports every
 * failure — arrives with the tickets that give it something to check.
 *
 * A short-circuit is not a ranking of severity. It is the claim that a later
 * check cannot mean anything until an earlier one holds: a document that failed
 * to parse has no audience to compare and no window to check, and a document
 * whose signature covers something else has an audience nobody vouched for.
 */

import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Document, Element } from '@xmldom/xmldom';

import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES, type RegionalErrorCode } from './regional-error-codes.js';
import {
  cryptographicVerification,
  NO_SIGNATURE_VERIFICATION,
  signatureIntegrity,
  type SignatureVerifier,
} from './signature.js';
import { attribute, childElements } from './xml.js';

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
 * `malformed` covers every way of not being an assertion at all, deliberately,
 * since the remedy for all of them is the same and it is not a remedy this
 * library can name. The signature codes are separate from it and from each
 * other because their remedies differ: an unsigned assertion is an IAP that did
 * not sign, a malformed signature is an IAP defect worth reporting to the
 * AULSS, and a signature bound to something else is the shape of an attack and
 * may deserve an alert rather than a log line.
 */
export type AssertionFailureCode =
  | 'malformed'
  | 'signature-absent'
  | 'signature-malformed'
  | 'signature-not-bound'
  | 'signature-verification-failed';

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
 * Something the caller should know about an assertion this library accepted.
 *
 * Not a failure and not a soft one. A warning never contributes to a refusal
 * and carries no regional error code, because the region did not refuse
 * anything either — every warning here describes a document the specification
 * permits. It exists so that a caller can decide, with its own policy, whether
 * to keep accepting what the specification currently allows.
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
 * An assertion this library found no fault with.
 *
 * The operator's tax code, the audiences, the authentication level and the
 * usable-until deadline are the semantic phase's to report, and it does not
 * exist yet — see the module comment.
 *
 * `warnings` is where an accepted assertion says what was accepted about it. In
 * this build it is never empty unless the caller supplied a verifier that
 * verified, because the absence of cryptographic verification is itself
 * reported here rather than left as an omission a caller has to know about.
 */
export interface ValidAssertion {
  readonly valid: true;
  readonly warnings: readonly AssertionWarning[];
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

/**
 * What a caller can supply to the validator beyond the assertion itself.
 *
 * One seam so far. Cryptographic verification needs a key, a trust decision
 * about that key and a canonicalisation implementation, none of which this
 * library holds — see {@link SignatureVerifier}. Omitting it is supported and
 * is the default, and the result says plainly that it happened.
 */
export interface AssertionValidationOptions {
  readonly verifySignature?: SignatureVerifier;
}

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

/** The direct children of `element` with this SAML local name. */
function samlChildren(element: Element, localName: string): readonly Element[] {
  return childElements(element, SAML_ASSERTION_NAMESPACE, localName);
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
 * in `signature.ts`, where that distinction can be drawn rather than collapsed
 * into `malformed`.
 *
 * Presence only. Whether the subject names the same operator as the
 * responsible-party attribute, and whether the issuer is one this caller
 * trusts, are semantic questions about a document that has to exist first.
 */
const REQUIRED_ASSERTION_ELEMENTS = ['Issuer', 'Subject', CONDITIONS_ELEMENT] as const;

/**
 * What the structural phase hands the phases after it: a refusal, or the
 * assertion element and the identifier the signature has to be bound to.
 *
 * The identifier travels separately because the signature phase compares
 * against it and would otherwise have to re-read an attribute this phase has
 * already established is present and non-blank. Reading it twice is a second
 * chance to read it differently.
 */
type Structure =
  | { readonly failure: AssertionFailure }
  | { readonly assertion: Element; readonly id: string };

/**
 * Names the first reason `assertion` is not an assertion, or hands on the
 * element when it is one.
 *
 * The checks run in the order a reader would ask the questions — is it a
 * document, is it *this* document, does it carry what the document must carry —
 * and the first one that fails ends the phase.
 */
function structure(assertion: Uint8Array): Structure {
  const source = decodeUtf8(assertion);
  if (source === undefined) {
    return { failure: malformed('the assertion bytes are not valid UTF-8.') };
  }

  const document = parse(source);
  if (document === undefined) {
    return { failure: malformed('the assertion bytes are not well-formed XML.') };
  }

  // A document type declaration is refused rather than ignored. No assertion
  // needs one, and an internal subset is where an entity that expands into
  // something else would be declared — so the cheapest place to be sure the
  // element tree says what the bytes say is before reading the element tree.
  // Argued in `docs/spec-questions.md` (D-011).
  if (document.doctype !== null) {
    return {
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
      failure: malformed(
        "the root element is not a SAML 2.0 Assertion. The validator is handed the bare assertion element; unwrapping a response or a security header is the caller's.",
      ),
    };
  }

  // One assertion in the whole document, not merely one at the root. SAML
  // permits an assertion to carry others inside `saml:Advice`, and this library
  // refuses that — a second assertion anywhere in the tree is a second element
  // a signature reference could have been pointing at, and the point of the
  // reference check in `signature.ts` is that there is exactly one thing the
  // signature can be about. Refusing the whole document is cheaper and more
  // certain than reasoning about which nested assertions are harmless.
  // Argued in `docs/spec-questions.md` (D-012).
  if (document.getElementsByTagNameNS(SAML_ASSERTION_NAMESPACE, ASSERTION_ELEMENT).length !== 1) {
    return {
      failure: malformed(
        'the document carries more than one Assertion element. Exactly one is accepted, so that there is exactly one element a signature reference can be about.',
      ),
    };
  }

  if (attribute(element, 'Version') !== SAML_VERSION) {
    return { failure: malformed(`the assertion does not declare Version "${SAML_VERSION}".`) };
  }

  const absentAttribute = firstAbsent(element, REQUIRED_ASSERTION_ATTRIBUTES);
  if (absentAttribute !== undefined) {
    return { failure: malformed(`the assertion carries no ${absentAttribute} attribute.`) };
  }

  // Exactly one of each, not at least one. A second Conditions element would
  // give the validity-window check two windows to choose between, and a choice
  // is exactly what a document that wants to be read two ways relies on.
  for (const name of REQUIRED_ASSERTION_ELEMENTS) {
    if (samlChildren(element, name).length !== 1) {
      return { failure: malformed(`the assertion does not carry exactly one ${name} element.`) };
    }
  }

  const [conditions] = samlChildren(element, CONDITIONS_ELEMENT);
  if (conditions === undefined) {
    // Unreachable: the loop above established there is exactly one. Written as
    // a return rather than an assertion so that the compiler's narrowing and
    // the runtime's behaviour agree without a cast.
    return {
      failure: malformed(`the assertion does not carry exactly one ${CONDITIONS_ELEMENT} element.`),
    };
  }

  const absentConditionsAttribute = firstAbsent(conditions, REQUIRED_CONDITIONS_ATTRIBUTES);
  if (absentConditionsAttribute !== undefined) {
    return {
      failure: malformed(
        `the assertion's ${CONDITIONS_ELEMENT} carries no ${absentConditionsAttribute} attribute.`,
      ),
    };
  }

  const id = attribute(element, 'ID');
  if (id === undefined) {
    // Unreachable: ID is one of the required attributes checked above. Written
    // as a return for the same reason the Conditions case above is.
    return { failure: malformed('the assertion carries no ID attribute.') };
  }

  return { assertion: element, id };
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
 * **Incomplete — see the module comment.** The structural and signature phases
 * run, so this does not yet establish that an assertion is in date, correctly
 * scoped, or carries the attributes a service requires. It establishes that the
 * signature claims to cover this assertion; whether it actually does is the
 * caller's `verifySignature` to say, and the success branch carries a warning
 * whenever nothing said it.
 */
export function validateAssertion(
  assertion: Uint8Array,
  options: AssertionValidationOptions = {},
): AssertionValidation {
  const structural = structure(assertion);
  if ('failure' in structural) {
    return { valid: false, failures: [structural.failure] };
  }

  const integrity = signatureIntegrity(structural.assertion, structural.id);
  if (!integrity.ok) {
    return { valid: false, failures: [integrity.failure] };
  }

  const verification = cryptographicVerification(
    assertion,
    options.verifySignature ?? NO_SIGNATURE_VERIFICATION,
  );
  if (!verification.ok) {
    return { valid: false, failures: [verification.failure] };
  }

  // The semantic phase runs here, over the parsed document the structural phase
  // hands it, and reports every failure rather than the first.
  return { valid: true, warnings: [...integrity.warnings, ...verification.warnings] };
}
