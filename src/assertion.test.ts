import { describe, expect, it, vi } from 'vitest';

import { validateAssertion } from './assertion.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import { NO_SIGNATURE_VERIFICATION, type SignatureVerifier } from './signature.js';

const SAML_ASSERTION_XMLNS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const XML_SIGNATURE_XMLNS = 'http://www.w3.org/2000/09/xmldsig#';

const ASSERTION_ID =
  'assertion_2.16.840.1.113883.2.9.2.50999_msgId_9376254e-da05-41f5-9af3-ac56d63d8ebd';

/**
 * A distinctive value planted in the fixture wherever the assertion would carry
 * an identity, so that a test can assert no failure detail echoes it.
 */
const PLANTED_IDENTITY = 'PLANTEDIDENTITY00X';

/** The algorithms §4.1.6.2.2 attests, deprecated and current, in both slots. */
const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const EXCLUSIVE_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

interface ReferenceParts {
  readonly uri?: string;
  readonly digestMethod?: string;
  readonly digestValue?: string;
}

/**
 * A `ds:Reference` bound to the fixture's own assertion, minus whatever the
 * caller overrides.
 */
function referenceXml({ uri, digestMethod, digestValue }: ReferenceParts = {}): string {
  return [
    `<ds:Reference URI="${uri ?? `#${ASSERTION_ID}`}">`,
    digestMethod ?? `<ds:DigestMethod Algorithm="${SHA256}"/>`,
    digestValue ?? '<ds:DigestValue>ZGlnZXN0</ds:DigestValue>',
    '</ds:Reference>',
  ].join('');
}

interface SignatureParts {
  readonly canonicalization?: string;
  readonly signatureMethod?: string;
  readonly reference?: string;
  readonly signedInfo?: string;
  readonly signatureValue?: string;
}

/**
 * A `ds:Signature` that binds to the fixture's assertion, minus whatever the
 * caller overrides.
 *
 * Structurally what §4.1.6.2.2 describes and cryptographically meaningless —
 * the digest and the signature value are short constants, because nothing in
 * this library computes or checks either. A fixture carrying a real signature
 * would suggest otherwise to the next reader.
 */
function signatureXml({
  canonicalization,
  signatureMethod,
  reference,
  signedInfo,
  signatureValue,
}: SignatureParts = {}): string {
  const info =
    signedInfo ??
    [
      '<ds:SignedInfo>',
      canonicalization ?? `<ds:CanonicalizationMethod Algorithm="${EXCLUSIVE_C14N}"/>`,
      signatureMethod ?? `<ds:SignatureMethod Algorithm="${RSA_SHA256}"/>`,
      reference ?? referenceXml(),
      '</ds:SignedInfo>',
    ].join('');

  return [
    `<ds:Signature xmlns:ds="${XML_SIGNATURE_XMLNS}">`,
    info,
    signatureValue ?? '<ds:SignatureValue>c2lnbmF0dXJl</ds:SignatureValue>',
    '</ds:Signature>',
  ].join('');
}

interface AssertionParts {
  readonly attributes?: string;
  readonly issuer?: string;
  readonly signature?: string;
  readonly subject?: string;
  readonly conditions?: string;
  readonly extra?: string;
}

const ISSUER = '<saml:Issuer>https://iap.ulssx.veneto.it</saml:Issuer>';
const SUBJECT = `<saml:Subject><saml:NameID>${PLANTED_IDENTITY}</saml:NameID></saml:Subject>`;
const CONDITIONS =
  '<saml:Conditions NotBefore="2026-08-21T09:00:00Z" NotOnOrAfter="2026-08-21T13:00:00Z"/>';

/**
 * A structurally complete bare assertion element, minus whatever the caller
 * overrides. Deliberately not built from the specification's worked example
 * verbatim: the values are this repository's own. The identifier's middle
 * segment is an organisation OID, as §4.1.6.2.2 structures an assertion
 * identifier — not the ApplicationID the request tests carry.
 */
function assertionXml({
  attributes,
  issuer,
  signature,
  subject,
  conditions,
  extra,
}: AssertionParts = {}): string {
  return [
    `<saml:Assertion xmlns:saml="${SAML_ASSERTION_XMLNS}" `,
    attributes ?? `Version="2.0" ID="${ASSERTION_ID}" IssueInstant="2026-08-21T09:00:00Z"`,
    '>',
    issuer ?? ISSUER,
    signature ?? signatureXml(),
    subject ?? SUBJECT,
    conditions ?? CONDITIONS,
    extra ?? '',
    '</saml:Assertion>',
  ].join('');
}

function bytes(xml: string): Uint8Array {
  return new TextEncoder().encode(xml);
}

/** The single failure a refusal carries, or a failing assertion. */
function onlyFailure(input: Uint8Array) {
  const result = validateAssertion(input);
  if (result.valid) {
    throw new Error('expected the assertion to be refused');
  }
  expect(result.failures).toHaveLength(1);
  return result.failures[0];
}

/** The warning codes an accepted assertion carries, or a failing assertion. */
function warningCodes(input: Uint8Array, verifySignature?: SignatureVerifier): readonly string[] {
  const result = validateAssertion(
    input,
    verifySignature === undefined ? {} : { verifySignature },
  );
  if (!result.valid) {
    throw new Error(`expected the assertion to be accepted: ${result.failures[0].detail}`);
  }
  return result.warnings.map((warning) => warning.code);
}

describe('validateAssertion — the structural phase', () => {
  it('accepts a structurally complete assertion', () => {
    expect(validateAssertion(bytes(assertionXml())).valid).toBe(true);
  });

  it('reports exactly one failure for bytes that are not XML at all', () => {
    // The short-circuit, stated as the ticket states it: nothing downstream of
    // the parse can have an opinion about a document that does not exist.
    const failure = onlyFailure(bytes('this is not a document'));

    expect(failure.code).toBe('malformed');
    expect(failure.detail).not.toHaveLength(0);
  });

  it('reports exactly one failure for empty input', () => {
    expect(onlyFailure(new Uint8Array()).code).toBe('malformed');
  });

  it('refuses bytes that are not valid UTF-8, rather than substituting through them', () => {
    // The undecodable byte sits inside an otherwise complete assertion, where a
    // lenient decoder would replace it and hand on a document that validates
    // with one character of an identity silently changed.
    const input = bytes(assertionXml());
    input[input.indexOf(PLANTED_IDENTITY.charCodeAt(0))] = 0x80;

    expect(onlyFailure(input).detail).toMatch(/UTF-8/);
  });

  it('reports exactly one failure for XML that is well-formed only in part', () => {
    expect(onlyFailure(bytes('<saml:Assertion><unclosed></saml:Assertion>')).code).toBe('malformed');
  });

  it('refuses a document whose root element is not an assertion', () => {
    const failure = onlyFailure(bytes(`<saml:Response xmlns:saml="${SAML_ASSERTION_XMLNS}"/>`));

    expect(failure.detail).toMatch(/root element/i);
  });

  it('refuses an Assertion element in some other namespace', () => {
    const failure = onlyFailure(bytes('<Assertion xmlns="urn:example:not-saml"/>'));

    expect(failure.detail).toMatch(/root element/i);
  });

  it('refuses a document carrying a document type declaration', () => {
    // Otherwise structurally complete, so that the refusal is the declaration
    // and not something else the fixture happens to be missing.
    const failure = onlyFailure(bytes(`<!DOCTYPE saml:Assertion>${assertionXml()}`));

    expect(failure.detail).toMatch(/document type/i);
  });

  it.each([
    ['ID', `Version="2.0" IssueInstant="2026-08-21T09:00:00Z"`, /\bID\b/],
    ['IssueInstant', `Version="2.0" ID="${ASSERTION_ID}"`, /IssueInstant/],
    ['Version', `ID="${ASSERTION_ID}" IssueInstant="2026-08-21T09:00:00Z"`, /Version/],
  ])('refuses an assertion with no %s attribute', (_name, attributes, expected) => {
    expect(onlyFailure(bytes(assertionXml({ attributes }))).detail).toMatch(expected);
  });

  it('refuses an assertion whose mandatory attribute is present but blank', () => {
    // An ID of no characters is not an identifier the signature reference can
    // be bound to, so a blank attribute is refused exactly as an absent one is.
    const attributes = `Version="2.0" ID="  " IssueInstant="2026-08-21T09:00:00Z"`;

    expect(onlyFailure(bytes(assertionXml({ attributes }))).detail).toMatch(/\bID\b/);
  });

  it('refuses an assertion declaring a SAML version other than 2.0', () => {
    const attributes = `Version="1.1" ID="${ASSERTION_ID}" IssueInstant="2026-08-21T09:00:00Z"`;

    expect(onlyFailure(bytes(assertionXml({ attributes }))).detail).toMatch(/Version/);
  });

  it.each([
    ['Issuer', { issuer: '' }],
    ['Subject', { subject: '' }],
    ['Conditions', { conditions: '' }],
  ])('refuses an assertion with no %s element', (name, parts) => {
    // §4.1.6.2.2 makes each of these mandatory. Presence only — whether the
    // subject names the operator the responsible-party attribute names is a
    // question about a document that has to exist first.
    expect(onlyFailure(bytes(assertionXml(parts))).detail).toMatch(new RegExp(name));
  });

  it.each([
    ['Issuer', { issuer: ISSUER + ISSUER }],
    ['Subject', { subject: SUBJECT + SUBJECT }],
    ['Conditions', { conditions: CONDITIONS + CONDITIONS }],
  ])('refuses an assertion carrying more than one %s element', (name, parts) => {
    // A second one of any of these gives a later check two answers to choose
    // between, and the choice is what a document meant to be read two ways
    // relies on.
    expect(onlyFailure(bytes(assertionXml(parts))).detail).toMatch(new RegExp(name));
  });

  it.each([
    ['NotBefore', '<saml:Conditions NotOnOrAfter="2026-08-21T13:00:00Z"/>'],
    ['NotOnOrAfter', '<saml:Conditions NotBefore="2026-08-21T09:00:00Z"/>'],
  ])('refuses an assertion whose Conditions carries no %s', (name, conditions) => {
    expect(onlyFailure(bytes(assertionXml({ conditions }))).detail).toMatch(new RegExp(name));
  });

  it('reports one failure for a document that fails several structural checks at once', () => {
    // Two things wrong — no ID and no Conditions — and still one failure, because
    // the phase stops at the first. A caller fixing a structurally broken
    // document has one problem to look at, not a list ordered by luck.
    const failure = onlyFailure(bytes(assertionXml({ attributes: 'Version="2.0"', conditions: '' })));

    expect(failure.code).toBe('malformed');
  });
});

describe('validateAssertion — one assertion to a document', () => {
  // The other half of the wrapping defence. The reference check below insists
  // the signature names this assertion; this one insists there is only one
  // assertion for a reference to have named.
  const nested = `<saml:Assertion Version="2.0" ID="${ASSERTION_ID}-inner" IssueInstant="2026-08-21T09:00:00Z">${ISSUER}${SUBJECT}${CONDITIONS}</saml:Assertion>`;

  it('refuses a document carrying a second assertion inside an Advice element', () => {
    const failure = onlyFailure(bytes(assertionXml({ extra: `<saml:Advice>${nested}</saml:Advice>` })));

    expect(failure.code).toBe('malformed');
    expect(failure.detail).toMatch(/more than one Assertion/i);
  });

  it('refuses a wrapped assertion even when the outer signature binds correctly', () => {
    // The wrapping shape: a signature that passes every check it is given,
    // beside a second assertion the caller might read instead. Refused before
    // the signature phase is reached, because the ambiguity is the problem.
    const input = bytes(
      assertionXml({ extra: `<saml:Advice>${nested}</saml:Advice>`, signature: signatureXml() }),
    );

    expect(onlyFailure(input).detail).toMatch(/more than one Assertion/i);
  });
});

describe('validateAssertion — structural signature integrity', () => {
  it('accepts a signature whose single reference names the assertion itself', () => {
    expect(validateAssertion(bytes(assertionXml())).valid).toBe(true);
  });

  it('reports an absent signature and a malformed one as distinct failures', () => {
    // The distinction the ticket asks for, asserted in one place so that
    // collapsing the two later breaks a test that says why they are separate.
    const absent = onlyFailure(bytes(assertionXml({ signature: '' })));
    const malformed = onlyFailure(
      bytes(assertionXml({ signature: signatureXml({ signedInfo: '' }) })),
    );

    expect(absent.code).toBe('signature-absent');
    expect(absent.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.ASSERTION_NOT_SIGNED);
    expect(malformed.code).toBe('signature-malformed');
    expect(malformed.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.SIGNATURE_MALFORMED);
    expect(absent.regionalErrorCode).not.toBe(malformed.regionalErrorCode);
  });

  it('refuses an assertion carrying more than one signature', () => {
    const failure = onlyFailure(
      bytes(assertionXml({ signature: signatureXml() + signatureXml() })),
    );

    expect(failure.code).toBe('signature-malformed');
  });

  it('ignores a signature that is not a direct child of the assertion', () => {
    // A signature buried in an element of the assertion is not the assertion's
    // signature. Reported as absent, because that is what the assertion is:
    // unsigned, whatever else the document contains.
    const buried = `<saml:Advice>${signatureXml()}</saml:Advice>`;

    expect(onlyFailure(bytes(assertionXml({ signature: '', extra: buried }))).code).toBe(
      'signature-absent',
    );
  });

  it.each([
    ['no SignedInfo', { signedInfo: '' }],
    ['no SignatureValue', { signatureValue: '' }],
    ['an empty SignatureValue', { signatureValue: '<ds:SignatureValue>   </ds:SignatureValue>' }],
    ['no CanonicalizationMethod', { canonicalization: '' }],
    ['a CanonicalizationMethod with no Algorithm', { canonicalization: '<ds:CanonicalizationMethod/>' }],
    ['no SignatureMethod', { signatureMethod: '' }],
    ['a SignatureMethod with no Algorithm', { signatureMethod: '<ds:SignatureMethod/>' }],
    ['no Reference', { reference: '' }],
    ['two References', { reference: referenceXml() + referenceXml() }],
  ])('refuses a signature with %s', (_what, parts: SignatureParts) => {
    expect(onlyFailure(bytes(assertionXml({ signature: signatureXml(parts) }))).code).toBe(
      'signature-malformed',
    );
  });

  it.each([
    ['no DigestMethod', { digestMethod: '' }],
    ['a DigestMethod with no Algorithm', { digestMethod: '<ds:DigestMethod/>' }],
    ['an unattested digest algorithm', { digestMethod: '<ds:DigestMethod Algorithm="urn:example:md5"/>' }],
    ['no DigestValue', { digestValue: '' }],
    ['an empty DigestValue', { digestValue: '<ds:DigestValue></ds:DigestValue>' }],
  ])('refuses a reference with %s', (_what, parts: ReferenceParts) => {
    const signature = signatureXml({ reference: referenceXml(parts) });

    expect(onlyFailure(bytes(assertionXml({ signature }))).code).toBe('signature-malformed');
  });

  it('refuses a signature algorithm the specification does not attest', () => {
    // §4.1.6.2.2 names two. Something outside the pair is refused rather than
    // warned about, and the cost of that is Q-008.
    const signature = signatureXml({
      signatureMethod: '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>',
    });

    expect(onlyFailure(bytes(assertionXml({ signature }))).code).toBe('signature-malformed');
  });

  it('does not judge which canonicalisation algorithm a signature names', () => {
    // §4.1.6.2.2 makes the element mandatory and its value a recommendation.
    // The verifier behind the seam is the party that has to implement it.
    const signature = signatureXml({
      canonicalization: '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>',
    });

    expect(validateAssertion(bytes(assertionXml({ signature }))).valid).toBe(true);
  });
});

describe('validateAssertion — the reference that defeats signature wrapping', () => {
  it.each([
    ['names another element entirely', '#assertion_2.16.840.1.113883.2.9.2.50999_msgId_other'],
    ['carries the identifier without the leading hash', ASSERTION_ID],
    ['names the whole document', ''],
    ['names a fragment of the identifier', `#${ASSERTION_ID.slice(0, 12)}`],
  ])('refuses a reference that %s', (_what, uri) => {
    const signature = signatureXml({ reference: referenceXml({ uri }) });
    const failure = onlyFailure(bytes(assertionXml({ signature })));

    expect(failure.code).toBe('signature-not-bound');
    expect(failure.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.SIGNATURE_MALFORMED);
  });

  it('refuses a reference with no URI attribute at all', () => {
    const reference = `<ds:Reference><ds:DigestMethod Algorithm="${SHA256}"/><ds:DigestValue>ZGlnZXN0</ds:DigestValue></ds:Reference>`;
    const signature = signatureXml({ reference });

    expect(onlyFailure(bytes(assertionXml({ signature }))).code).toBe('signature-not-bound');
  });

  it('distinguishes a reference bound elsewhere from a signature that is merely malformed', () => {
    // Both are refusals; a caller may want to alert on one and log the other,
    // so they must not arrive under the same code.
    const notBound = onlyFailure(
      bytes(assertionXml({ signature: signatureXml({ reference: referenceXml({ uri: '#other' }) }) })),
    );
    const malformed = onlyFailure(
      bytes(assertionXml({ signature: signatureXml({ reference: '' }) })),
    );

    expect(notBound.code).not.toBe(malformed.code);
  });
});

describe('validateAssertion — deprecated algorithms', () => {
  it('accepts the deprecated signature algorithm and warns rather than refusing', () => {
    // The specification attests it and its own worked assertion uses it, so
    // refusing would refuse a conforming document — Q-008.
    const signature = signatureXml({ signatureMethod: `<ds:SignatureMethod Algorithm="${RSA_SHA1}"/>` });

    expect(warningCodes(bytes(assertionXml({ signature })))).toContain(
      'deprecated-signature-algorithm',
    );
  });

  it('accepts the deprecated digest algorithm and warns rather than refusing', () => {
    const signature = signatureXml({
      reference: referenceXml({ digestMethod: `<ds:DigestMethod Algorithm="${SHA1}"/>` }),
    });

    expect(warningCodes(bytes(assertionXml({ signature })))).toContain(
      'deprecated-digest-algorithm',
    );
  });

  it('warns twice for the pair of deprecated algorithms the worked assertion carries', () => {
    const signature = signatureXml({
      signatureMethod: `<ds:SignatureMethod Algorithm="${RSA_SHA1}"/>`,
      reference: referenceXml({ digestMethod: `<ds:DigestMethod Algorithm="${SHA1}"/>` }),
    });

    expect(warningCodes(bytes(assertionXml({ signature })))).toEqual(
      expect.arrayContaining(['deprecated-signature-algorithm', 'deprecated-digest-algorithm']),
    );
  });

  it('warns about neither when the current algorithms are used', () => {
    const codes = warningCodes(bytes(assertionXml()));

    expect(codes).not.toContain('deprecated-signature-algorithm');
    expect(codes).not.toContain('deprecated-digest-algorithm');
  });

  it('never refuses on the strength of a deprecated algorithm alone', () => {
    const signature = signatureXml({
      signatureMethod: `<ds:SignatureMethod Algorithm="${RSA_SHA1}"/>`,
      reference: referenceXml({ digestMethod: `<ds:DigestMethod Algorithm="${SHA1}"/>` }),
    });

    expect(validateAssertion(bytes(assertionXml({ signature }))).valid).toBe(true);
  });
});

describe('validateAssertion — the cryptographic verification seam', () => {
  it('states on the success branch that nothing verified the signature', () => {
    // The limitation reported rather than omitted: a caller that wires up no
    // verifier is told, in the result it is holding, what it did not get.
    expect(warningCodes(bytes(assertionXml()))).toContain(
      'signature-not-cryptographically-verified',
    );
  });

  it('attempts nothing by default', () => {
    expect(NO_SIGNATURE_VERIFICATION(bytes(assertionXml()))).toBe('not-attempted');
  });

  it('drops the warning when a supplied verifier verifies', () => {
    expect(warningCodes(bytes(assertionXml()), () => 'verified')).not.toContain(
      'signature-not-cryptographically-verified',
    );
  });

  it('refuses the assertion when a supplied verifier rejects the signature', () => {
    const result = validateAssertion(bytes(assertionXml()), {
      verifySignature: () => 'not-verified',
    });

    if (result.valid) {
      throw new Error('expected the assertion to be refused');
    }
    expect(result.failures[0].code).toBe('signature-verification-failed');
    expect(result.failures[0].regionalErrorCode).toBe(
      REGIONAL_ERROR_CODES.SIGNATURE_PUBLIC_KEY_MISMATCH,
    );
  });

  it("hands the verifier the caller's exact bytes", () => {
    // What a signature covers is the octets, so the seam is handed the octets —
    // not a document model, and not a copy this library normalised on the way.
    const input = bytes(assertionXml());
    const verifier = vi.fn<SignatureVerifier>(() => 'verified');

    validateAssertion(input, { verifySignature: verifier });

    expect(verifier).toHaveBeenCalledTimes(1);
    expect(verifier.mock.calls[0]?.[0]).toBe(input);
  });

  it('does not reach the verifier when the structure or the binding already failed', () => {
    // Verification is the expensive check and the last one. A document whose
    // signature does not even claim to cover it is refused before a key is
    // touched.
    const verifier = vi.fn<SignatureVerifier>(() => 'verified');
    const notBound = signatureXml({ reference: referenceXml({ uri: '#other' }) });

    validateAssertion(bytes('not a document'), { verifySignature: verifier });
    validateAssertion(bytes(assertionXml({ signature: '' })), { verifySignature: verifier });
    validateAssertion(bytes(assertionXml({ signature: notBound })), { verifySignature: verifier });

    expect(verifier).not.toHaveBeenCalled();
  });
});

describe('validateAssertion — what a failure carries', () => {
  it('annotates the failure with the regional code, as an annotation and not as its identity', () => {
    const failure = onlyFailure(bytes('not a document'));

    expect(failure.code).toBe('malformed');
    expect(failure.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.ASSERTION_TOKEN_UNRECOGNISABLE);
  });

  it('never echoes the document into the detail', () => {
    // The library is handed an identity assertion. A detail quoting what it
    // found is a detail that puts a tax code into whatever logs the failure —
    // so details describe the expectation and never the document.
    const failure = onlyFailure(bytes(assertionXml({ conditions: '' })));

    expect(failure.detail).not.toContain(PLANTED_IDENTITY);
    expect(failure.detail).not.toContain(ASSERTION_ID);
  });

  it('never echoes the document into a signature failure either', () => {
    // The wrapping path is the one where the document is most likely hostile,
    // and the reference URI is attacker-chosen text. It does not reach the log.
    const signature = signatureXml({ reference: referenceXml({ uri: `#${PLANTED_IDENTITY}` }) });
    const failure = onlyFailure(bytes(assertionXml({ signature })));

    expect(failure.detail).not.toContain(PLANTED_IDENTITY);
    expect(failure.detail).not.toContain(ASSERTION_ID);
  });
});

describe('validateAssertion — the byte contract', () => {
  it("leaves the caller's bytes exactly as they were", () => {
    // The assertion has to be spent exactly as the IAP returned it (§4.6), so
    // the one thing the validator must never do to its input is touch it.
    const input = bytes(assertionXml());
    const before = Uint8Array.from(input);

    validateAssertion(input);

    expect(input).toEqual(before);
  });
});
