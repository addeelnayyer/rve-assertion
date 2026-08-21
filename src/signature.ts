/**
 * Structural signature integrity — §4.1.6.2.2's `ds:Signature`, checked for
 * everything that can be checked without a key.
 *
 * ## Why the name says structural, and why it says more than presence
 *
 * "Signature present" would be a check worth almost nothing. §4.1.6.2.2 does
 * not merely require a signature; it requires a signature whose single
 * `ds:Reference` names *this* assertion's own `ID` attribute, prefixed with a
 * hash. That binding is the whole point. A signature element sitting inside an
 * assertion says only that some bytes somewhere were signed by someone — it is
 * the reference that says the bytes are these bytes, and a validator that
 * checked presence alone would accept a genuine, correctly-signed, entirely
 * unrelated signature pasted into a forged assertion.
 *
 * That is signature wrapping, and it is not a hypothetical: it is the standard
 * attack against XML signatures, and it works precisely on validators that
 * confirm a signature exists and then read the document as if the signature
 * covered it. Two checks defeat it here, and both are structural:
 *
 *   - the reference URI must be `#` followed by the assertion's own identifier,
 *     so a signature pointing at any other element is refused; and
 *   - the document must carry exactly one assertion element in total (that one
 *     lives in the structural phase, in `assertion.ts`), so there is no second
 *     element for a reference to have been pointing at legitimately.
 *
 * Neither needs a key, which is why this library performs them even though it
 * does not verify cryptographically. A caller that later verifies with a real
 * XML-DSig implementation gets a document these checks have already narrowed to
 * one shape; a caller that does not verify at all is at least not accepting a
 * signature that was never about this assertion.
 *
 * ## Absent and malformed are different failures
 *
 * The region separates them and so does this module. An assertion with no
 * signature is `ERR_00053` — not signed, a `wsse:FailedAuthentication` — while
 * a signature that is present and structured wrongly is `ERR_00012`, a
 * `wsse:FailedCheck`. Collapsing the two would tell a support engineer that the
 * IAP had returned an unsigned assertion when in fact it had returned a signed
 * one this library could not read, which are different conversations with
 * different people.
 *
 * ## What it does not do
 *
 * It computes no digest and verifies no signature value. Cryptographic
 * verification needs a key, a trust decision about that key, and a
 * canonicalisation implementation — three things that belong to the layer
 * holding the AULSS's trust material, not to a library that has never seen it.
 * The seam is {@link SignatureVerifier}, its default is
 * {@link NO_SIGNATURE_VERIFICATION}, and that default reports the limitation on
 * the success branch as a warning rather than staying quiet about it.
 */

import type { Element } from '@xmldom/xmldom';

import type { AssertionFailure, AssertionWarning } from './assertion.js';
import { XML_SIGNATURE_NAMESPACE } from './namespaces.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import { attribute, childElements, onlyChild, text } from './saml-dom.js';

/** The local name of the signature element — §4.1.6.2.2. */
const SIGNATURE_ELEMENT = 'Signature';

/**
 * The signature algorithms §4.1.6.2.2 attests, and what it says about each.
 *
 * The two are the whole list the section gives. An algorithm outside it is
 * refused rather than warned about — see {@link algorithmStanding} — and the
 * cost of that is argued in `docs/spec-questions.md` (Q-008).
 */
const SIGNATURE_ALGORITHMS: Readonly<Record<string, 'deprecated' | 'current'>> = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'deprecated',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'current',
};

/** The digest algorithms §4.1.6.2.2 attests, on the same terms. */
const DIGEST_ALGORITHMS: Readonly<Record<string, 'deprecated' | 'current'>> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': 'deprecated',
  'http://www.w3.org/2001/04/xmlenc#sha256': 'current',
};

/**
 * What a cryptographic verifier concluded.
 *
 * Three answers rather than two, because *not verified* and *not attempted* are
 * not the same claim and a boolean would make them indistinguishable. A caller
 * that has wired up no verifier has not learned that the signature is bad; it
 * has learned nothing, and the result says which of those happened.
 */
export type SignatureVerification = 'verified' | 'not-verified' | 'not-attempted';

/**
 * The seam behind which real cryptographic verification sits.
 *
 * Handed the assertion's original bytes — the same ones the caller passed to
 * `validateAssertion`, unmodified — because that is what a signature covers.
 * Deliberately not handed this library's parsed document: canonicalisation is
 * defined over the octets, and a verifier reasoning about someone else's
 * document model would be verifying that model rather than the assertion.
 *
 * Synchronous, which is a constraint on the implementer worth naming: a
 * verifier that needs to fetch a key must hold its trust material before it is
 * called, rather than reaching for the network inside the call. Assertion
 * validation happens on the request path of a clinician waiting for a record,
 * and a seam that permitted an unbounded fetch there would be a seam that
 * eventually blocks one.
 *
 * An implementation must decide the key and the trust question for itself. This
 * library has no opinion about which AULSS certificate should have signed what,
 * and it cannot acquire one: there is no single regional issuer, there is one
 * per AULSS.
 */
export type SignatureVerifier = (assertion: Uint8Array) => SignatureVerification;

/**
 * The default verifier: it verifies nothing and says so.
 *
 * Returning `not-attempted` rather than `verified` is the point. A default that
 * claimed success would make an unverified assertion indistinguishable from a
 * verified one at the call site, which is the single most dangerous thing this
 * module could do. Instead the omission travels with the result, as a warning
 * on the success branch, until a caller supplies something that does the work.
 */
export const NO_SIGNATURE_VERIFICATION: SignatureVerifier = () => 'not-attempted';

/**
 * The outcome of one signature check: a refusal, or a pass carrying whatever
 * this library wants the caller to know anyway.
 *
 * Warnings on the success branch rather than a second failure list, because a
 * warning is not a reason to refuse an assertion and must not be reachable
 * where a caller is handling refusals.
 */
export type SignatureOutcome =
  | { readonly ok: false; readonly failure: AssertionFailure }
  | { readonly ok: true; readonly warnings: readonly AssertionWarning[] };

/** An assertion carrying no signature at all — §4.1.6.2.2 makes it mandatory. */
function absent(detail: string): SignatureOutcome {
  return {
    ok: false,
    failure: {
      code: 'signature-absent',
      detail,
      // ERR_00053 names an assertion that is not signed — Appendix A.5,
      // Table 12. The neighbouring signature codes of Table 8 all describe a
      // signature that exists and does not check out, which is the other branch
      // of this module and not this one. An annotation, as everything here is —
      // see `docs/spec-questions.md` (D-022).
      regionalErrorCode: REGIONAL_ERROR_CODES.ASSERTION_NOT_SIGNED,
      // Not a claim that a retry would help — an IAP that returned an unsigned
      // assertion may sign the next one. Nor a claim that it would: what to do
      // about a failure is the remedy's to say.
      unrecoverable: false,
    },
  };
}

/** A signature that is present and not structured as §4.1.6.2.2 requires. */
function malformed(detail: string): SignatureOutcome {
  return {
    ok: false,
    failure: {
      code: 'signature-malformed',
      detail,
      // ERR_00012 — Appendix A.5, Table 8: the one code in the excerpt that
      // describes a structural problem with a signature rather than a
      // cryptographic one.
      regionalErrorCode: REGIONAL_ERROR_CODES.SIGNATURE_MALFORMED,
      // A defect in what this IAP returned this time, which says nothing about
      // what it returns next time.
      unrecoverable: false,
    },
  };
}

/**
 * A signature that does not cover the assertion it sits in.
 *
 * Its own library code rather than {@link malformed}, because the two call for
 * different reactions. A malformed signature is most likely an IAP defect worth
 * reporting to the AULSS; a signature bound to something else is the shape of
 * an attack, and a caller may reasonably want to alert on it rather than log it.
 *
 * The regional annotation is `ERR_00012` all the same. The region's vocabulary
 * has no code for signature wrapping, and structurally incorrect is the nearest
 * true statement available — an annotation is a best match by construction
 * (`docs/spec-questions.md`, D-022), and the library code beside it is what
 * carries the distinction.
 */
function notBound(detail: string): SignatureOutcome {
  return {
    ok: false,
    failure: {
      code: 'signature-not-bound',
      detail,
      regionalErrorCode: REGIONAL_ERROR_CODES.SIGNATURE_MALFORMED,
      // Deliberately not marked unrecoverable, though it is the most alarming
      // failure here. The claim would be about the transaction rather than
      // about this document: a fresh request may well return an assertion whose
      // signature binds. Whether to make one at all, having seen this, is a
      // decision above this library.
      unrecoverable: false,
    },
  };
}

/** A pass, carrying nothing or carrying what the caller should know. */
function passed(warnings: readonly AssertionWarning[] = []): SignatureOutcome {
  return { ok: true, warnings };
}

/**
 * Reads the `Algorithm` attribute of `element` and places it in `attested`.
 *
 * Answers either with the refusal, or with whether the algorithm named is the
 * deprecated member of the pair — which the caller turns into a warning, since
 * a deprecated algorithm is one §4.1.6.2.2 permits.
 *
 * An **unattested** algorithm is refused rather than warned about: §4.1.6.2.2
 * gives a closed list of two in each position, and a validator that accepted
 * anything at all in the algorithm slot would pass on an assertion signed with
 * something the region never blessed — to a verifier that may well implement it.
 * The cost of that strictness is argued in `docs/spec-questions.md` (Q-008).
 */
function algorithmStanding(
  element: Element,
  attested: Readonly<Record<string, 'deprecated' | 'current'>>,
  what: string,
): { readonly failure: SignatureOutcome } | { readonly deprecated: boolean } {
  const algorithm = attribute(element, 'Algorithm');
  if (algorithm === undefined) {
    return { failure: malformed(`the signature's ${what} carries no Algorithm attribute.`) };
  }

  const standing = attested[algorithm];
  if (standing === undefined) {
    return {
      failure: malformed(
        `the signature's ${what} names an algorithm §4.1.6.2.2 does not attest. The section names two, and this is neither.`,
      ),
    };
  }

  return { deprecated: standing === 'deprecated' };
}

/**
 * Checks the signature on `assertion`, whose `ID` attribute is `assertionId`.
 *
 * The identifier is passed rather than re-read, so that this module and the
 * binding check are certainly talking about the same value: the structural
 * phase already established that the attribute is present and non-blank, and
 * reading it a second time would be a second chance to read it differently.
 *
 * The checks run outside-in — is there a signature, is it built of the two
 * elements the section names, does its reference name this assertion — and the
 * first one that fails ends the check. Ordering is not severity: a reference
 * cannot be examined inside a `ds:SignedInfo` that is not there.
 */
export function signatureIntegrity(assertion: Element, assertionId: string): SignatureOutcome {
  const signatures = childElements(assertion, XML_SIGNATURE_NAMESPACE, SIGNATURE_ELEMENT);
  if (signatures.length === 0) {
    return absent('the assertion carries no ds:Signature element, which §4.1.6.2.2 makes mandatory.');
  }
  if (signatures.length > 1) {
    // Not "absent", and not a choice this library makes on the document's
    // behalf either: two signatures means two answers to which one binds the
    // assertion, and picking the first would let a document that wants to be
    // read two ways decide which reading it gets.
    return malformed('the assertion carries more than one ds:Signature element.');
  }

  const [signature] = signatures;
  if (signature === undefined) {
    // Unreachable: the length is exactly one. Written as a return rather than a
    // cast so the compiler's narrowing and the runtime's behaviour agree.
    return malformed('the assertion carries more than one ds:Signature element.');
  }

  const signedInfo = onlyChild(signature, XML_SIGNATURE_NAMESPACE, 'SignedInfo');
  if (signedInfo === undefined) {
    return malformed(
      "the signature does not carry exactly one ds:SignedInfo element, which §4.1.6.2.2 requires.",
    );
  }

  const signatureValue = onlyChild(signature, XML_SIGNATURE_NAMESPACE, 'SignatureValue');
  if (signatureValue === undefined || text(signatureValue) === undefined) {
    // Empty counts as absent. A ds:SignatureValue with no base64 in it carries
    // no signature, and accepting the element for its own sake would be exactly
    // the presence check this module exists not to be.
    return malformed(
      'the signature does not carry exactly one non-empty ds:SignatureValue element, which §4.1.6.2.2 requires.',
    );
  }

  // Mandatory by §4.1.6.2.2, and its value deliberately not judged: the section
  // says a conforming application *should* use exclusive canonicalisation,
  // which is a recommendation rather than a requirement. Refusing another
  // canonicalisation would refuse a document the specification permits, and
  // this library cannot canonicalise anyway — the verifier behind
  // {@link SignatureVerifier} is the party that has to implement whatever is
  // named here, and it is better placed to refuse one it does not support.
  const canonicalisation = onlyChild(signedInfo, XML_SIGNATURE_NAMESPACE, 'CanonicalizationMethod');
  if (canonicalisation === undefined || attribute(canonicalisation, 'Algorithm') === undefined) {
    return malformed(
      "the signature's ds:SignedInfo does not carry exactly one ds:CanonicalizationMethod element with an Algorithm attribute.",
    );
  }

  const warnings: AssertionWarning[] = [];

  const signatureMethod = onlyChild(signedInfo, XML_SIGNATURE_NAMESPACE, 'SignatureMethod');
  if (signatureMethod === undefined) {
    return malformed(
      "the signature's ds:SignedInfo does not carry exactly one ds:SignatureMethod element.",
    );
  }
  const signatureAlgorithm = algorithmStanding(
    signatureMethod,
    SIGNATURE_ALGORITHMS,
    'ds:SignatureMethod',
  );
  if ('failure' in signatureAlgorithm) {
    return signatureAlgorithm.failure;
  }
  if (signatureAlgorithm.deprecated) {
    warnings.push({
      code: 'deprecated-signature-algorithm',
      detail:
        'the assertion is signed with the SHA-1 signature algorithm, which §4.1.6.2.2 attests and deprecates. Accepted rather than refused — see docs/spec-questions.md (Q-008).',
    });
  }

  // "must be UNIQUE" — one reference, so that there is one answer to what the
  // signature covers. Several references would each cover something, and the
  // assertion would be covered by whichever one a reader happened to check.
  const reference = onlyChild(signedInfo, XML_SIGNATURE_NAMESPACE, 'Reference');
  if (reference === undefined) {
    return malformed(
      "the signature's ds:SignedInfo does not carry exactly one ds:Reference element, which §4.1.6.2.2 requires to be unique.",
    );
  }

  // The check the module exists for. §4.1.6.2.2 requires the URI to be the
  // assertion's own ID attribute preceded by "#" — so anything else is a
  // signature covering an element other than the one about to be read, which
  // is signature wrapping whether or not it was meant as one.
  if (attribute(reference, 'URI') !== `#${assertionId}`) {
    return notBound(
      "the signature's ds:Reference does not name the assertion's own ID attribute prefixed with a hash, so the signature does not cover this assertion.",
    );
  }

  const digestMethod = onlyChild(reference, XML_SIGNATURE_NAMESPACE, 'DigestMethod');
  if (digestMethod === undefined) {
    return malformed(
      "the signature's ds:Reference does not carry exactly one ds:DigestMethod element.",
    );
  }
  const digestAlgorithm = algorithmStanding(digestMethod, DIGEST_ALGORITHMS, 'ds:DigestMethod');
  if ('failure' in digestAlgorithm) {
    return digestAlgorithm.failure;
  }
  if (digestAlgorithm.deprecated) {
    warnings.push({
      code: 'deprecated-digest-algorithm',
      detail:
        'the signature digests the assertion with SHA-1, which §4.1.6.2.2 attests and deprecates. Accepted rather than refused — see docs/spec-questions.md (Q-008).',
    });
  }

  const digestValue = onlyChild(reference, XML_SIGNATURE_NAMESPACE, 'DigestValue');
  if (digestValue === undefined || text(digestValue) === undefined) {
    return malformed(
      "the signature's ds:Reference does not carry exactly one non-empty ds:DigestValue element.",
    );
  }

  return passed(warnings);
}

/**
 * Runs `verifier` over the original bytes and turns its answer into an outcome.
 *
 * Called only after {@link signatureIntegrity} has passed, so a verifier is
 * never handed a document whose signature does not even claim to cover it.
 */
export function cryptographicVerification(
  assertion: Uint8Array,
  verifier: SignatureVerifier,
): SignatureOutcome {
  switch (verifier(assertion)) {
    case 'verified':
      return passed();

    case 'not-verified':
      return {
        ok: false,
        failure: {
          code: 'signature-verification-failed',
          detail: "the caller's signature verifier rejected the assertion's signature.",
          // ERR_00011, mismatch between signature and public key — Appendix A.5,
          // Table 8. The verifier's own reason is not reported here: it belongs
          // to an implementation this library did not write, and paraphrasing it
          // would put words in its mouth.
          regionalErrorCode: REGIONAL_ERROR_CODES.SIGNATURE_PUBLIC_KEY_MISMATCH,
          // Not established to be unrecoverable: a key the caller does not
          // trust today may be one it trusts after a rotation, and this library
          // cannot see the trust store to know.
          unrecoverable: false,
        },
      };

    case 'not-attempted':
      // The stated limitation, travelling with the result rather than living
      // only in the README where a caller may never meet it.
      return passed([
        {
          code: 'signature-not-cryptographically-verified',
          detail:
            'the signature was checked for structure and binding only. No digest was computed and no signature value was verified, because no verifier was supplied.',
        },
      ]);
  }
}
