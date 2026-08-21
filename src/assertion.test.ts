import { describe, expect, it, vi } from 'vitest';

import {
  RECOMMENDED_CLOCK_SKEW_MS,
  RECOMMENDED_FLIGHT_TIME_MS,
  validateAssertion,
  type AssertionFailureCode,
  type AssertionTimeModel,
  type AssertionValidationOptions,
} from './assertion.js';
import { ASSERTION_ATTRIBUTES } from './assertion-attributes.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import type { Remedy } from './remedy.js';
import { TWO_FACTOR_AUTHENTICATION_LEVEL } from './request.js';
import { servicePolicy, type ServicePolicy } from './service-policy.js';
import { NO_SIGNATURE_VERIFICATION, type SignatureVerifier } from './signature.js';
import { ValidationInputError } from './types.js';

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
  readonly statement?: string;

  /** Anything else the fixture should carry, after the attribute statement. */
  readonly extra?: string;
}

const ISSUER = '<saml:Issuer>https://iap.ulssx.veneto.it</saml:Issuer>';
const SUBJECT = `<saml:Subject><saml:NameID>${PLANTED_IDENTITY}</saml:NameID></saml:Subject>`;
const NOT_BEFORE = '2026-08-21T09:00:00Z';
const NOT_ON_OR_AFTER = '2026-08-21T13:00:00Z';
const CONDITIONS = `<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}"/>`;

/** One `saml:Attribute`, as §4.1.6.2.2's worked assertion writes it. */
function attributeXml(name: string, ...values: readonly string[]): string {
  const valueXml = values.map((value) => `<saml:AttributeValue>${value}</saml:AttributeValue>`);
  return `<saml:Attribute Name="${name}">${valueXml.join('')}</saml:Attribute>`;
}

function statementXml(...attributes: readonly string[]): string {
  return `<saml:AttributeStatement>${attributes.join('')}</saml:AttributeStatement>`;
}

/**
 * The attribute statement of an assertion nobody has anything against: the
 * responsible party names the same operator the subject does, which every
 * assertion must carry whatever the policy asks for (D-021).
 */
const STATEMENT = statementXml(
  attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
);

/** The service every test validates against unless it says otherwise. */
const SERVICE = 'https://fser.regione.veneto.it/Registry';

/**
 * The fixture policies, each a factory rather than a value.
 *
 * Built inside the test that asks for one rather than once at module scope. A
 * fixture built while the file is being collected takes any throw out of
 * `servicePolicy` with it: the file reports no results at all, which a runner
 * that counts test outcomes reads as a suite with nothing wrong in it.
 */
const baselinePolicy = () => servicePolicy({ audience: SERVICE });

/** A service that will not accept an assertion scoped to nobody in particular. */
const confidentialPolicy = () =>
  servicePolicy({ audience: SERVICE, refusesGenericAssertions: true });

/** A service that asks the assertion for the operator's role. */
const policyAskingForARole = () =>
  servicePolicy({ audience: SERVICE, requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE] });

/** A service that will not be called without a second factor behind the operator. */
const policyRequiringTwoFactor = () =>
  servicePolicy({
    audience: SERVICE,
    requiredAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
  });

/**
 * A moment comfortably inside the fixture's window, so that a structural test
 * fails for the structural reason it is about and not for the time.
 */
const NOW = new Date('2026-08-21T10:00:00Z');

/** The time model the structural tests pass, accepting both recommendations. */
const TIME: AssertionTimeModel = {
  now: NOW,
  clockSkewMs: RECOMMENDED_CLOCK_SKEW_MS,
  flightTimeMs: RECOMMENDED_FLIGHT_TIME_MS,
};

/** The same model, with the margins taken out, for tests about the bounds themselves. */
const EXACT: AssertionTimeModel = { now: NOW, clockSkewMs: 0, flightTimeMs: 0 };

/** `time`, with the clock moved to `instant`. */
function at(time: AssertionTimeModel, instant: string | number): AssertionTimeModel {
  return { ...time, now: new Date(instant) };
}

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
  statement,
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
    statement ?? STATEMENT,
    extra ?? '',
    '</saml:Assertion>',
  ].join('');
}

function bytes(xml: string): Uint8Array {
  return new TextEncoder().encode(xml);
}

/**
 * The failures an assertion was refused for, or a failing assertion.
 *
 * Every refusal that passes through here is held to the invariant the failure
 * type promises and no single test would think to restate: a refusal a support
 * engineer can act on says something, in a sentence, about what was wrong. A
 * detail left empty is the failure code repeated back at a reader who already
 * had it.
 */
function failures(
  input: Uint8Array,
  time: AssertionTimeModel = TIME,
  policy: ServicePolicy = baselinePolicy(),
) {
  const result = validateAssertion(input, time, policy);
  if (result.valid) {
    throw new Error('expected the assertion to be refused');
  }
  for (const failure of result.failures) {
    expect(failure.detail.trim().length, `${failure.code} carries no detail`).toBeGreaterThan(0);
  }
  return result.failures;
}

/** The single failure a refusal carries, or a failing assertion. */
function onlyFailure(
  input: Uint8Array,
  time: AssertionTimeModel = TIME,
  policy: ServicePolicy = baselinePolicy(),
) {
  const refusals = failures(input, time, policy);
  expect(refusals).toHaveLength(1);
  return refusals[0];
}

/** The assertion's success branch, or a failing assertion. */
function accepted(
  input: Uint8Array,
  time: AssertionTimeModel = TIME,
  policy: ServicePolicy = baselinePolicy(),
) {
  const result = validateAssertion(input, time, policy);
  if (!result.valid) {
    throw new Error(
      `expected the assertion to be accepted; it was refused for ${result.failures
        .map((failure) => failure.code)
        .join(', ')}`,
    );
  }
  for (const warning of result.warnings) {
    expect(warning.detail.trim().length, `${warning.code} carries no detail`).toBeGreaterThan(0);
  }
  return result;
}

/** The warning codes an accepted assertion carries, or a failing assertion. */
function warningCodes(input: Uint8Array, verifySignature?: SignatureVerifier): readonly string[] {
  const options = verifySignature === undefined ? {} : { verifySignature };
  const result = validateAssertion(input, TIME, baselinePolicy(), options);
  if (!result.valid) {
    throw new Error(`expected the assertion to be accepted: ${result.failures[0].detail}`);
  }
  return result.warnings.map((warning) => warning.code);
}

describe('validateAssertion — the structural phase', () => {
  it('accepts a structurally complete assertion', () => {
    expect(validateAssertion(bytes(assertionXml()), TIME, baselinePolicy()).valid).toBe(true);
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
    expect(validateAssertion(bytes(assertionXml()), TIME, baselinePolicy()).valid).toBe(true);
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

    expect(validateAssertion(bytes(assertionXml({ signature })), TIME, baselinePolicy()).valid).toBe(true);
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

    expect(validateAssertion(bytes(assertionXml({ signature })), TIME, baselinePolicy()).valid).toBe(true);
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
    const result = validateAssertion(bytes(assertionXml()), TIME, baselinePolicy(), {
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

    validateAssertion(input, TIME, baselinePolicy(), { verifySignature: verifier });

    expect(verifier).toHaveBeenCalledTimes(1);
    expect(verifier.mock.calls[0]?.[0]).toBe(input);
  });

  it('does not reach the verifier when the structure or the binding already failed', () => {
    // Verification is the expensive check and the last one. A document whose
    // signature does not even claim to cover it is refused before a key is
    // touched.
    const verifier = vi.fn<SignatureVerifier>(() => 'verified');
    const notBound = signatureXml({ reference: referenceXml({ uri: '#other' }) });

    validateAssertion(bytes('not a document'), TIME, baselinePolicy(), { verifySignature: verifier });
    validateAssertion(bytes(assertionXml({ signature: '' })), TIME, baselinePolicy(), {
      verifySignature: verifier,
    });
    validateAssertion(bytes(assertionXml({ signature: notBound })), TIME, baselinePolicy(), {
      verifySignature: verifier,
    });

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

    validateAssertion(input, TIME, baselinePolicy());

    expect(input).toEqual(before);
  });
});

describe('validateAssertion — the shape of a validity window', () => {
  function withWindow(notBefore: string, notOnOrAfter: string): Uint8Array {
    return bytes(
      assertionXml({
        conditions: `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"/>`,
      }),
    );
  }

  it.each([
    ['NotBefore', 'the thirtieth of January', NOT_ON_OR_AFTER],
    ['NotOnOrAfter', NOT_BEFORE, '1706651736'],
  ])('refuses an assertion whose %s is not a timestamp at all', (name, notBefore, notOnOrAfter) => {
    // Structural, not semantic: a window with no instants in it is not a window
    // the semantic phase can have an opinion about, so the phase that reports
    // one failure and stops is the one that has to catch this.
    const failure = onlyFailure(withWindow(notBefore, notOnOrAfter));

    expect(failure.code).toBe('malformed');
    expect(failure.detail).toMatch(new RegExp(name));
  });

  it.each([
    ['NotBefore', '2026-08-21T09:00:00', NOT_ON_OR_AFTER],
    ['NotOnOrAfter', NOT_BEFORE, '2026-08-21T13:00:00'],
  ])('refuses a %s carrying no time zone', (name, notBefore, notOnOrAfter) => {
    // A local time names no instant, so comparing it to a clock would be
    // comparing to whichever zone the reader happened to be in — D-012.
    expect(onlyFailure(withWindow(notBefore, notOnOrAfter)).detail).toMatch(new RegExp(name));
  });

  it('accepts fractional seconds', () => {
    // The library writes whole seconds (D-004); it does not require the IAP to.
    const result = validateAssertion(withWindow('2026-08-21T09:00:00.500Z', NOT_ON_OR_AFTER), TIME, baselinePolicy());

    expect(result.valid).toBe(true);
  });

  it('accepts a time zone offset other than Z, and reads it as the offset it declares', () => {
    // 11:00 at +02:00 is 09:00Z — the same instant the fixture's window opens
    // at, so an assertion read correctly is valid and one read as local is not.
    const result = validateAssertion(withWindow('2026-08-21T11:00:00+02:00', NOT_ON_OR_AFTER), {
      ...EXACT,
      now: new Date('2026-08-21T09:00:00Z'),
    }, baselinePolicy());

    expect(result.valid).toBe(true);
  });
});

describe('validateAssertion — the validity window', () => {
  it('accepts an assertion the clock is inside the window of', () => {
    expect(validateAssertion(bytes(assertionXml()), TIME, baselinePolicy()).valid).toBe(true);
  });

  it('reports the assertion as not yet valid before its window opens', () => {
    const failure = onlyFailure(bytes(assertionXml()), at(TIME, '2026-08-21T08:00:00Z'));

    expect(failure.code).toBe('not-yet-valid');
    expect(failure.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.ASSERTION_NOT_YET_VALID);
  });

  it('reports the assertion as expired after its window closes', () => {
    const failure = onlyFailure(bytes(assertionXml()), at(TIME, '2026-08-21T14:00:00Z'));

    expect(failure.code).toBe('expired');
    expect(failure.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.ASSERTION_EXPIRED);
  });

  it('treats NotBefore as inclusive and NotOnOrAfter as exclusive, with no margins', () => {
    const document = bytes(assertionXml());

    expect(validateAssertion(document, at(EXACT, NOT_BEFORE), baselinePolicy()).valid).toBe(true);
    expect(validateAssertion(document, at(EXACT, Date.parse(NOT_BEFORE) - 1), baselinePolicy()).valid).toBe(false);
    expect(validateAssertion(document, at(EXACT, Date.parse(NOT_ON_OR_AFTER) - 1), baselinePolicy()).valid).toBe(true);
    expect(validateAssertion(document, at(EXACT, NOT_ON_OR_AFTER), baselinePolicy()).valid).toBe(false);
  });

  it('lets clock skew loosen the not-before bound', () => {
    // A clock a little fast would otherwise refuse an assertion that is in
    // fact open, so the skew is subtracted from the bound rather than added.
    const document = bytes(assertionXml());
    const skewed = at(
      { ...EXACT, clockSkewMs: RECOMMENDED_CLOCK_SKEW_MS },
      Date.parse(NOT_BEFORE) - RECOMMENDED_CLOCK_SKEW_MS,
    );

    expect(validateAssertion(document, skewed, baselinePolicy()).valid).toBe(true);
    expect(validateAssertion(document, { ...skewed, clockSkewMs: 0 }, baselinePolicy()).valid).toBe(false);
  });

  it('moves the not-on-or-after bound earlier by the skew alone, with no flight time', () => {
    // Skew moves both bounds earlier, which is the assumption that this clock
    // may be behind the issuer's — the direction in which being wrong spends an
    // assertion whose window has in fact closed.
    const document = bytes(assertionXml());
    const skewed = at(
      { ...EXACT, clockSkewMs: RECOMMENDED_CLOCK_SKEW_MS },
      Date.parse(NOT_ON_OR_AFTER) - RECOMMENDED_CLOCK_SKEW_MS,
    );

    expect(validateAssertion(document, skewed, baselinePolicy()).valid).toBe(false);
    expect(validateAssertion(document, { ...skewed, clockSkewMs: 0 }, baselinePolicy()).valid).toBe(true);
  });

  it('lets clock skew and flight time together tighten the not-on-or-after bound', () => {
    // The assertion is still inside its window on this clock, and would not be
    // by the time a call carrying it reached the X-Service Provider.
    const document = bytes(assertionXml());
    const margin = RECOMMENDED_CLOCK_SKEW_MS + RECOMMENDED_FLIGHT_TIME_MS;
    const late = at(TIME, Date.parse(NOT_ON_OR_AFTER) - margin);

    expect(validateAssertion(document, late, baselinePolicy()).valid).toBe(false);
    expect(validateAssertion(document, { ...late, clockSkewMs: 0, flightTimeMs: 0 }, baselinePolicy()).valid).toBe(
      true,
    );
  });

  it('returns a usable-until deadline that is the tightened bound itself', () => {
    // What a cache evicts on: the last instant at which spending the assertion
    // is still expected to arrive in time.
    const result = validateAssertion(bytes(assertionXml()), TIME, baselinePolicy());

    if (!result.valid) {
      throw new Error('expected the assertion to be accepted');
    }
    expect(result.usableUntil).toEqual(
      new Date(Date.parse(NOT_ON_OR_AFTER) - RECOMMENDED_CLOCK_SKEW_MS - RECOMMENDED_FLIGHT_TIME_MS),
    );
  });

  it('reports both bounds when a window is too short to reach a service through', () => {
    // The semantic phase runs to completion, so a window narrower than the
    // flight time reports that it has not opened and that it is already too
    // late — which is the whole truth about it, and one failure would not be.
    const conditions =
      '<saml:Conditions NotBefore="2026-08-21T10:00:30Z" NotOnOrAfter="2026-08-21T10:00:31Z"/>';
    const result = validateAssertion(bytes(assertionXml({ conditions })), {
      ...EXACT,
      now: new Date('2026-08-21T10:00:29Z'),
      flightTimeMs: RECOMMENDED_FLIGHT_TIME_MS,
    }, baselinePolicy());

    if (result.valid) {
      throw new Error('expected the assertion to be refused');
    }
    expect(result.failures.map((failure) => failure.code)).toEqual(['not-yet-valid', 'expired']);
  });

  it('never echoes the document into a window failure detail', () => {
    const failure = onlyFailure(bytes(assertionXml()), at(TIME, '2026-08-21T14:00:00Z'));

    expect(failure.detail).not.toContain(NOT_ON_OR_AFTER);
    expect(failure.detail).not.toContain(PLANTED_IDENTITY);
  });

  it('does not refuse a window for its length', () => {
    // Neither the four-hour figure nor the fifteen-minute one is a bound this
    // library holds the policy for — D-013. A window far outside both is
    // accepted, and the region is left to say otherwise.
    const conditions =
      '<saml:Conditions NotBefore="2026-08-21T09:00:00Z" NotOnOrAfter="2027-08-21T09:00:00Z"/>';

    expect(validateAssertion(bytes(assertionXml({ conditions })), TIME, baselinePolicy()).valid).toBe(true);
  });
});

describe('validateAssertion — the time model', () => {
  const document = bytes(assertionXml());

  it.each([
    ['a clock that is not a time', { now: new Date(Number.NaN) }],
    ['a negative clock skew', { clockSkewMs: -1 }],
    ['a clock skew that is not a number', { clockSkewMs: Number.NaN }],
    ['an infinite flight time', { flightTimeMs: Number.POSITIVE_INFINITY }],
    ['a negative flight time', { flightTimeMs: -1 }],
  ])('throws on %s rather than answering', (_name, overrides) => {
    // The caller's own arguments, not the third party's document: a bad one is
    // a programming error, and the alternative is silent — every comparison
    // against NaN is false, so the assertion would be accepted unconditionally.
    expect(() => validateAssertion(document, { ...TIME, ...overrides }, baselinePolicy())).toThrow(
      ValidationInputError,
    );
  });

  it('accepts a caller that declines both margins', () => {
    expect(validateAssertion(document, EXACT, baselinePolicy()).valid).toBe(true);
  });

  it('names recommended margins without applying them', () => {
    // Exported so that taking them is something a caller writes down.
    expect(RECOMMENDED_CLOCK_SKEW_MS).toBeGreaterThan(0);
    expect(RECOMMENDED_FLIGHT_TIME_MS).toBeGreaterThan(0);
  });
});

/** A `Conditions` element carrying `inner`, over the fixture's own window. */
function conditionsWith(inner: string): string {
  return [
    `<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">`,
    inner,
    '</saml:Conditions>',
  ].join('');
}

/** One `AudienceRestriction` naming `audiences`, of which there may be none. */
function restriction(...audiences: readonly string[]): string {
  return [
    '<saml:AudienceRestriction>',
    ...audiences.map((audience) => `<saml:Audience>${audience}</saml:Audience>`),
    '</saml:AudienceRestriction>',
  ].join('');
}

/** Whether the assertion carrying `conditions` validates against `policy`. */
function accepts(conditions: string, policy: ServicePolicy = baselinePolicy()): boolean {
  return validateAssertion(bytes(assertionXml({ conditions })), TIME, policy).valid;
}

const OTHER_SERVICE = 'https://sar.regione.veneto.it/demVisualizzaErogatoCUP';

describe('validateAssertion — the audience', () => {
  it('accepts an assertion scoped to the service about to be called', () => {
    expect(accepts(conditionsWith(restriction(SERVICE)))).toBe(true);
  });

  it('accepts an assertion naming several services, one of which is this one', () => {
    // §4.1.6.2.2 allows more than one Audience, and SAML 2.0 core makes them a
    // disjunction: the assertion is scoped to any of the services it names.
    expect(accepts(conditionsWith(restriction(OTHER_SERVICE, SERVICE)))).toBe(true);
  });

  it('accepts an audience an XML pretty-printer wrapped in whitespace', () => {
    expect(accepts(conditionsWith(restriction(`\n        ${SERVICE}\n      `)))).toBe(true);
  });

  it('refuses an assertion scoped to some other service', () => {
    const failure = onlyFailure(
      bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
    );

    expect(failure.code).toBe('audience-mismatch');
    expect(failure.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.AUDIENCE_NOT_PERMITTED);
  });

  it('refuses an AudienceRestriction that names no service at all', () => {
    // §4.1.6.2.2 puts no lower bound on the Audience sub-elements. A restriction
    // naming nobody restricts to nobody, so it is a mismatch rather than the
    // generic assertion of §3.1.1 — the document did declare a restriction.
    expect(
      onlyFailure(bytes(assertionXml({ conditions: conditionsWith(restriction()) }))).code,
    ).toBe('audience-mismatch');
  });

  it('requires every AudienceRestriction to name the service, not merely one of them', () => {
    // SAML 2.0 core conjoins restrictions: each is a separate condition and all
    // must hold. Fails closed on a document the region's own examples never
    // produce — see docs/spec-questions.md (D-018).
    const conditions = conditionsWith(restriction(SERVICE) + restriction(OTHER_SERVICE));

    expect(onlyFailure(bytes(assertionXml({ conditions }))).code).toBe('audience-mismatch');
  });

  it('accepts an assertion whose every restriction names the service', () => {
    expect(
      accepts(conditionsWith(restriction(SERVICE) + restriction(SERVICE, OTHER_SERVICE))),
    ).toBe(true);
  });

  it('compares exactly by default, refusing a host differing only in case', () => {
    const conditions = conditionsWith(restriction('https://FSER.regione.veneto.it/Registry'));

    expect(onlyFailure(bytes(assertionXml({ conditions }))).code).toBe('audience-mismatch');
  });

  it('accepts that same assertion once the caller asks for normalised matching', () => {
    const normalising = servicePolicy({ audience: SERVICE, audienceMatching: 'normalised' });
    const conditions = conditionsWith(restriction('https://FSER.regione.veneto.it/Registry'));

    expect(accepts(conditions, normalising)).toBe(true);
  });

  it('never echoes the audience it found into the detail', () => {
    const conditions = conditionsWith(restriction(`${OTHER_SERVICE}?patient=${PLANTED_IDENTITY}`));

    expect(onlyFailure(bytes(assertionXml({ conditions }))).detail).not.toContain(
      PLANTED_IDENTITY,
    );
  });
});

describe('validateAssertion — a generic assertion', () => {

  it('accepts one, on the baseline policy', () => {
    // The baseline is an inference from §4.1.8, Table 3, which marks the
    // audience optional — not a statement §4.2.6 makes. D-015.
    expect(accepts(conditionsWith(''))).toBe(true);
  });

  it('accepts one whose Conditions has no children at all', () => {
    expect(validateAssertion(bytes(assertionXml()), TIME, baselinePolicy()).valid).toBe(true);
  });

  it('refuses one when the caller says the service refuses them', () => {
    // §3.1.1's confidential service: the only assertion it honours is one
    // whose request named it.
    const failure = onlyFailure(
      bytes(assertionXml({ conditions: conditionsWith('') })),
      TIME,
      confidentialPolicy(),
    );

    expect(failure.code).toBe('audience-absent');
    expect(failure.regionalErrorCode).toBe(REGIONAL_ERROR_CODES.AUDIENCE_NOT_PERMITTED);
  });

  it('distinguishes it from an assertion scoped to the wrong service', () => {
    // Two different corrections. An absent audience says this service needs a
    // scoped request it never gets; a mismatch says a scoped assertion was
    // reused across services. Both re-request, and a caller told only
    // "audience" cannot tell which of its two bugs it has.
    const scopedElsewhere = onlyFailure(
      bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
      TIME,
      confidentialPolicy(),
    );

    expect(scopedElsewhere.code).toBe('audience-mismatch');
  });

  it('does not reach the audience at all when the document is malformed', () => {
    // The structural short-circuit: a document with no Conditions has no
    // audience to be missing, and reporting one would be reporting the same
    // failure twice.
    const failure = onlyFailure(bytes(assertionXml({ conditions: '' })), TIME, confidentialPolicy());

    expect(failure.code).toBe('malformed');
  });
});

describe('validateAssertion — the semantic phase reports every reason', () => {
  it('reports both an expired window and a wrong audience, not the first of them', () => {
    // The two checks are independent, and a caller that fixed the audience,
    // re-requested and then discovered the expiry has spent a round trip on
    // learning what this list could have told it.
    const conditions = conditionsWith(restriction(OTHER_SERVICE));
    const result = validateAssertion(
      bytes(assertionXml({ conditions })),
      at(EXACT, NOT_ON_OR_AFTER),
      baselinePolicy(),
    );

    if (result.valid) {
      throw new Error('expected the assertion to be refused');
    }
    expect(result.failures.map((failure) => failure.code).sort()).toEqual([
      'audience-mismatch',
      'expired',
    ]);
  });
});

describe('validateAssertion — the remedy', () => {

  /** A validation that refused, or a failing assertion. */
  function refusal(
    input: Uint8Array,
    time: AssertionTimeModel = TIME,
    policy: ServicePolicy = baselinePolicy(),
    options: AssertionValidationOptions = {},
  ) {
    const result = validateAssertion(input, time, policy, options);
    if (result.valid) {
      throw new Error('expected the assertion to be refused');
    }
    return result;
  }

  interface Refused {
    readonly input: Uint8Array;
    readonly time?: AssertionTimeModel;
    /** A thunk, so that a policy that will not build fails the row rather than the file. */
    readonly policy?: () => ServicePolicy;

    /**
     * Whether the code claims nothing further can be tried. Beside the remedy
     * because the two answer one question between them, and a row that said
     * *fail-hard* while claiming a retry would help would be saying both.
     */
    readonly unrecoverable: boolean;
    readonly options?: AssertionValidationOptions;
    readonly remedy: Remedy['action'];
  }

  /**
   * One assertion refused for each way of being refused, and the remedy each
   * one alone resolves to.
   *
   * A `Record` keyed by the failure-code union rather than a list, so that a
   * code added to the validator fails to compile here until someone has said
   * which remedy resolves it — the one question a new code must not leave open,
   * since `src/remedy.ts` answering *nothing* for it is `fail-hard`, which is a
   * claim rather than a default.
   */
  const REFUSALS: Readonly<Record<AssertionFailureCode, Refused>> = {
    // Nothing this library can name resolves these: a document that is not an
    // assertion, a signature that does not cover one, a clock that disagrees
    // with the issuer's, or an IAP that resolved two identities.
    malformed: { input: bytes('not a document'), remedy: 'fail-hard', unrecoverable: false },
    'signature-absent': {
      input: bytes(assertionXml({ signature: '' })),
      remedy: 'fail-hard',
      unrecoverable: false,
    },
    'signature-malformed': {
      input: bytes(assertionXml({ signature: signatureXml({ reference: referenceXml({ digestValue: '' }) }) })),
      remedy: 'fail-hard',
      unrecoverable: false,
    },
    'signature-not-bound': {
      input: bytes(
        assertionXml({ signature: signatureXml({ reference: referenceXml({ uri: '#elsewhere' }) }) }),
      ),
      remedy: 'fail-hard',
      unrecoverable: false,
    },
    'signature-verification-failed': {
      input: bytes(assertionXml()),
      options: { verifySignature: () => 'not-verified' },
      remedy: 'fail-hard',
      unrecoverable: false,
    },
    'not-yet-valid': {
      input: bytes(assertionXml()),
      time: at(TIME, '2026-08-21T08:00:00Z'),
      remedy: 'fail-hard',
      unrecoverable: false,
    },
    'identity-mismatch': {
      input: bytes(
        assertionXml({
          statement: statementXml(
            attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, 'RSSMRA80A01H501U'),
          ),
        }),
      ),
      remedy: 'fail-hard',
      // The only one. Two identities in one assertion is the AULSS directory
      // disagreeing with itself, and asking it again returns both again.
      unrecoverable: true,
    },

    // A fresh assertion is a round trip that exists, and age is the only thing
    // asking the same question again can change.
    expired: {
      input: bytes(assertionXml()),
      time: at(EXACT, NOT_ON_OR_AFTER),
      remedy: 'refresh',
      unrecoverable: false,
    },

    // §3.1.1's own recovery: ask again, naming this service.
    'audience-mismatch': {
      input: bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
      remedy: 'rerequest-scoped',
      unrecoverable: false,
    },
    'audience-absent': {
      input: bytes(assertionXml({ conditions: conditionsWith('') })),
      policy: confidentialPolicy,
      remedy: 'rerequest-scoped',
      unrecoverable: false,
    },
    'attribute-missing': {
      input: bytes(assertionXml()),
      policy: policyAskingForARole,
      remedy: 'rerequest-scoped',
      unrecoverable: false,
    },

    // Out of this layer, to the session that can acquire a second factor.
    'authentication-level-not-attested': {
      input: bytes(assertionXml()),
      policy: policyRequiringTwoFactor,
      remedy: 'step-up-auth',
      unrecoverable: false,
    },
  };

  it.each(Object.entries(REFUSALS))('resolves %s with the remedy that answers it', (code, refused) => {
    const result = refusal(refused.input, refused.time, refused.policy?.(), refused.options);

    // The fixture is held to producing this one failure and no other, so that
    // the remedy beside it is the remedy for the code the row names.
    expect(result.failures.map((failure) => failure.code)).toEqual([code]);
    expect(result.remedy.action).toBe(refused.remedy);
    // Fail-hard and unrecoverable are not the same claim, and the rows prove
    // it: seven codes resolve to fail-hard because this library knows no remedy
    // for them, and only one of the seven says a further attempt is pointless.
    expect(result.failures[0].unrecoverable).toBe(refused.unrecoverable);
  });

  it('answers an expired and wrongly scoped assertion with a scoped re-request, not a refresh', () => {
    // The case the derivation exists for. A refresh returns a fresh assertion
    // still scoped to the wrong service, which fails again — a loop. The scoped
    // re-request returns one that is both fresh and correctly scoped, so the
    // caller makes one further round trip and no more.
    const result = refusal(
      bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
      at(EXACT, NOT_ON_OR_AFTER),
    );

    expect(result.failures.map((failure) => failure.code).sort()).toEqual([
      'audience-mismatch',
      'expired',
    ]);
    expect(result.remedy).toEqual({
      action: 'rerequest-scoped',
      withAudience: SERVICE,
      withAuthenticationLevel: undefined,
    });
  });

  it('carries the audience forward on a step-up, so resumption re-enters scoped', () => {
    // The escalation leaves this layer: the operator authenticates again with a
    // second factor, which is the session's work. It comes back to a re-request
    // naming this service, and it can only do that because the remedy said
    // which service — otherwise re-authentication resumes into a generic
    // request and meets the audience refusal it had already got past.
    const result = refusal(
      bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
      TIME,
      policyRequiringTwoFactor(),
    );

    expect(result.failures.map((failure) => failure.code).sort()).toEqual([
      'audience-mismatch',
      'authentication-level-not-attested',
    ]);
    expect(result.remedy).toEqual({
      action: 'step-up-auth',
      withAudience: SERVICE,
      withAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
    });
  });

  it('lets one unresolvable failure absorb the remedy for the rest', () => {
    // An identity mismatch beside an expired window. The expiry has a remedy
    // and the mismatch has none, so there is no round trip that resolves both —
    // and offering the one that resolves the expiry would send the caller after
    // an assertion that fails the same way.
    const result = refusal(REFUSALS['identity-mismatch'].input, at(EXACT, NOT_ON_OR_AFTER));

    expect(result.failures.map((failure) => failure.code).sort()).toEqual([
      'expired',
      'identity-mismatch',
    ]);
    expect(result.remedy).toEqual({ action: 'fail-hard' });
  });

  it('threads the audience through every remedy that acts', () => {
    for (const refused of Object.values(REFUSALS)) {
      if (refused.remedy === 'fail-hard') {
        continue;
      }
      const { remedy } = refusal(refused.input, refused.time, refused.policy?.(), refused.options);

      expect(remedy).toHaveProperty('withAudience', SERVICE);
    }
  });

  it('asks a re-request for the level the service requires, and for none where it requires none', () => {
    expect(
      refusal(
        bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
        TIME,
        policyRequiringTwoFactor(),
      ).remedy,
    ).toHaveProperty('withAuthenticationLevel', TWO_FACTOR_AUTHENTICATION_LEVEL);

    expect(
      refusal(bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) }))).remedy,
    ).toHaveProperty('withAuthenticationLevel', undefined);
  });

  it('carries a remedy on a refusal from a phase that short-circuits', () => {
    // The structural and signature phases return before the semantic one runs.
    // A caller handling their refusals needs the same answer to the same
    // question.
    expect(refusal(bytes('not a document')).remedy).toEqual({ action: 'fail-hard' });
    expect(refusal(bytes(assertionXml({ signature: '' }))).remedy).toEqual({ action: 'fail-hard' });
  });

  it('keeps the remedy off the failures, so the mapping has one source', () => {
    for (const failure of refusal(bytes(assertionXml({ conditions: '' }))).failures) {
      expect(Object.keys(failure).sort()).toEqual([
        'code',
        'detail',
        'regionalErrorCode',
        'unrecoverable',
      ]);
    }
  });
});

describe('validateAssertion — required attributes', () => {
  /** The baseline service, asking for `names` beyond what every assertion owes. */
  function asking(...names: readonly string[]): ServicePolicy {
    return servicePolicy({ audience: SERVICE, requiredAttributes: names });
  }

  it('accepts an assertion carrying every attribute the policy asks for', () => {
    const assertion = assertionXml({
      statement: statementXml(
        attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
        attributeXml(ASSERTION_ATTRIBUTES.ROLE, 'R.1.1'),
        attributeXml(ASSERTION_ATTRIBUTES.REQUEST_CONTEXT, 'C.1.1'),
      ),
    });

    expect(
      accepted(
        bytes(assertion),
        TIME,
        asking(ASSERTION_ATTRIBUTES.ROLE, ASSERTION_ATTRIBUTES.REQUEST_CONTEXT),
      ).valid,
    ).toBe(true);
  });

  it('refuses an assertion missing an attribute the policy asks for', () => {
    const failure = onlyFailure(bytes(assertionXml()), TIME, asking(ASSERTION_ATTRIBUTES.ROLE));

    expect(failure.code).toBe('attribute-missing');
    expect(failure.detail).toMatch(/Role/);
  });

  it('lets the policy require an attribute this excerpt does not name', () => {
    // §4.2.5.2 says regional projects may provide for further parameters and
    // defers their definition to a transaction this excerpt does not contain,
    // so the vocabulary a policy draws from is open.
    const failure = onlyFailure(bytes(assertionXml()), TIME, asking('codProgettoRegionale'));

    expect(failure.code).toBe('attribute-missing');
    expect(failure.detail).toMatch(/codProgettoRegionale/);
  });

  it('reports one failure per missing attribute rather than stopping at the first', () => {
    // The semantic phase runs to completion: a caller that fixes one attribute,
    // retries against a third-party IAP and discovers a second has spent a
    // round trip to learn what this result already said.
    const refusals = failures(
      bytes(assertionXml()),
      TIME,
      asking(ASSERTION_ATTRIBUTES.ROLE, ASSERTION_ATTRIBUTES.APPLICATION_ID),
    );

    expect(refusals.map((failure) => failure.code)).toEqual([
      'attribute-missing',
      'attribute-missing',
    ]);
    expect(refusals.map((failure) => failure.regionalErrorCode)).toEqual([
      // Table 12's ERR_00060 names a role that is absent; Table 11's ERR_00042
      // names one whose value does not permit access, which is a judgement this
      // library does not make. See docs/spec-questions.md (D-022).
      REGIONAL_ERROR_CODES.ROLE_MISSING_OR_INVALID_IN_DIRECTORY,
      REGIONAL_ERROR_CODES.APPLICATION_ID_NOT_PERMITTED,
    ]);
  });

  it('annotates an attribute the region has no code of its own for with the general one', () => {
    expect(
      onlyFailure(bytes(assertionXml()), TIME, asking(ASSERTION_ATTRIBUTES.FACILITY_CODE))
        .regionalErrorCode,
    ).toBe(REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY);
  });

  it('does not treat a present-but-empty attribute as satisfying the policy', () => {
    const assertion = assertionXml({
      statement: statementXml(
        attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
        `<saml:Attribute Name="${ASSERTION_ATTRIBUTES.ROLE}"/>`,
      ),
    });

    expect(onlyFailure(bytes(assertion), TIME, asking(ASSERTION_ATTRIBUTES.ROLE)).code).toBe(
      'attribute-missing',
    );
  });

  it('requires the responsible party whatever the policy asks for', () => {
    // Not policy-driven: the identity cross-check reads this attribute, and an
    // assertion that omits it is an assertion the cross-check cannot be run
    // against. See docs/spec-questions.md (D-021).
    const failure = onlyFailure(bytes(assertionXml({ statement: '' })));

    expect(failure.code).toBe('attribute-missing');
    expect(failure.detail).toMatch(/ResponsibleParty/);
  });

  it('does not report the responsible party twice when the policy names it too', () => {
    expect(
      failures(bytes(assertionXml({ statement: '' })), TIME, asking(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY)),
    ).toHaveLength(1);
  });

  it('marks a missing attribute as something a further round trip could fix', () => {
    expect(
      onlyFailure(bytes(assertionXml()), TIME, asking(ASSERTION_ATTRIBUTES.ROLE)).unrecoverable,
    ).toBe(false);
  });
});

describe('validateAssertion — the authentication level', () => {

  function withLevel(level: string): Uint8Array {
    return bytes(
      assertionXml({
        statement: statementXml(
          attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
          attributeXml(ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL, level),
        ),
      }),
    );
  }

  /** An assertion attesting two levels at once, one of them the required one. */
  const TWO_LEVELS = bytes(
    assertionXml({
      statement: statementXml(
        attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
        attributeXml(
          ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL,
          TWO_FACTOR_AUTHENTICATION_LEVEL,
          'urn:rve:authnL1',
        ),
      ),
    }),
  );

  it('accepts an assertion attesting the level the policy requires', () => {
    expect(
      accepted(withLevel(TWO_FACTOR_AUTHENTICATION_LEVEL), TIME, policyRequiringTwoFactor()).valid,
    ).toBe(true);
  });

  it('accepts an assertion attesting no level when the policy requires none', () => {
    expect(accepted(bytes(assertionXml())).valid).toBe(true);
  });

  it('distinguishes a missing authentication level from every other failure', () => {
    // Its own code, because its remedy is unlike any other: the operator has to
    // authenticate again with a second factor, which is the session layer's
    // work and not a re-request this library's caller can make.
    const failure = onlyFailure(bytes(assertionXml()), TIME, policyRequiringTwoFactor());

    expect(failure.code).toBe('authentication-level-not-attested');
    expect(failure.regionalErrorCode).toBe(
      REGIONAL_ERROR_CODES.TWO_FACTOR_AUTHENTICATION_REQUIRED,
    );
    expect(failure.unrecoverable).toBe(false);
  });

  it('refuses an assertion attesting some level other than the one required', () => {
    expect(onlyFailure(withLevel('urn:rve:authnL1'), TIME, policyRequiringTwoFactor()).code).toBe(
      'authentication-level-not-attested',
    );
  });

  it('refuses an assertion attesting the required level twice over, differently', () => {
    // Two values under one name is two answers, and a check that took the first
    // would be a check a second value could be hidden behind.
    expect(onlyFailure(TWO_LEVELS, TIME, policyRequiringTwoFactor()).code).toBe(
      'authentication-level-not-attested',
    );
  });

  it('refuses an assertion attesting two levels even where no level was asked for', () => {
    // Not the policy's business: an assertion contradicting itself about how
    // strongly the operator authenticated attests nothing, and there is no
    // service that is safe for. See docs/spec-questions.md (D-023).
    const failure = onlyFailure(TWO_LEVELS);

    expect(failure.code).toBe('authentication-level-not-attested');
    // A contradiction the operator can resolve by authenticating again, so it
    // is not the unrecoverable kind — that is the identity mismatch alone.
    expect(failure.unrecoverable).toBe(false);
    // Not ERR_00065: no service demanded a second factor here, and saying one
    // did would put a claim into the support conversation that nothing made.
    expect(failure.regionalErrorCode).toBe(
      REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY,
    );
  });

  it('does not object to a level the policy did not ask for', () => {
    // The excerpt names one level and cannot say the region has not added
    // another since. An unrecognised level is reported, not refused.
    expect(accepted(withLevel('urn:rve:authnL3')).authenticationLevel).toBe('urn:rve:authnL3');
  });

  it('refuses to build a policy requiring a level the specification does not attest', () => {
    // The same refusal the request side makes, for the same reason (D-007): a
    // required level typically arrives from the tenant configuration the
    // audience does, where the compiler was never involved.
    expect(() =>
      servicePolicy({
        audience: SERVICE,
        requiredAuthenticationLevel: 'urn:rve:authnL9' as typeof TWO_FACTOR_AUTHENTICATION_LEVEL,
      }),
    ).toThrow(ValidationInputError);
  });
});

describe('validateAssertion — the identity cross-check', () => {
  function withResponsibleParty(...values: readonly string[]): Uint8Array {
    return bytes(
      assertionXml({
        statement: statementXml(
          ...values.map((value) => attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, value)),
        ),
      }),
    );
  }

  it('accepts an assertion whose two identities agree', () => {
    expect(accepted(withResponsibleParty(PLANTED_IDENTITY)).valid).toBe(true);
  });

  it('refuses an assertion whose responsible party is not its subject', () => {
    // The IAP resolved two different people for one request. Nothing downstream
    // can tell which of them the audit trail should name.
    const failure = onlyFailure(withResponsibleParty('SOMEONEELSE00X'));

    expect(failure.code).toBe('identity-mismatch');
    expect(failure.regionalErrorCode).toBe(
      REGIONAL_ERROR_CODES.RESPONSIBLE_PARTY_FISCAL_CODE_MISMATCH,
    );
  });

  it('marks the mismatch unrecoverable rather than retryable', () => {
    // A re-request asks the same IAP the same question and gets the same two
    // answers. Retrying it is a loop against a third party.
    expect(onlyFailure(withResponsibleParty('SOMEONEELSE00X')).unrecoverable).toBe(true);
  });

  it('refuses an assertion naming a second responsible party beside the right one', () => {
    expect(onlyFailure(withResponsibleParty(PLANTED_IDENTITY, 'SOMEONEELSE00X')).code).toBe(
      'identity-mismatch',
    );
  });

  it('holds two spellings of one tax code to be the same identity', () => {
    // The region writes a Codice Fiscale in upper case, and case folding cannot
    // make two different tax codes equal — so folding removes a way of refusing
    // a correct assertion without weakening the check. See D-020.
    expect(accepted(withResponsibleParty(PLANTED_IDENTITY.toLowerCase())).valid).toBe(true);
  });

  it('does not validate the tax code, on either side', () => {
    // Deliberate — D-019. The check is that the assertion says one thing about
    // who the operator is, not that this library believes the thing.
    const assertion = bytes(
      assertionXml({
        subject: '<saml:Subject><saml:NameID>not-a-tax-code</saml:NameID></saml:Subject>',
        statement: statementXml(
          attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, 'not-a-tax-code'),
        ),
      }),
    );

    expect(accepted(assertion).operatorTaxCode).toBe('not-a-tax-code');
  });

  it('does not report a mismatch it has no second identity to have found', () => {
    // The responsible party is absent, which is one failure and not two. A
    // mismatch reported beside it would name a disagreement nothing had.
    expect(
      failures(bytes(assertionXml({ statement: '' }))).map((failure) => failure.code),
    ).toEqual(['attribute-missing']);
  });
});

describe('validateAssertion — the subject identifier', () => {
  it.each([
    ['no NameID', '<saml:Subject/>'],
    ['a blank NameID', '<saml:Subject><saml:NameID>   </saml:NameID></saml:Subject>'],
    [
      'two NameIDs',
      `<saml:Subject><saml:NameID>${PLANTED_IDENTITY}</saml:NameID><saml:NameID>${PLANTED_IDENTITY}</saml:NameID></saml:Subject>`,
    ],
    [
      'a NameID whose content is an element',
      '<saml:Subject><saml:NameID><x>CF</x></saml:NameID></saml:Subject>',
    ],
  ])('refuses an assertion whose subject carries %s', (_case, subject) => {
    // §4.1.6.2.2 makes the subject carry the operator's identifier, and this is
    // the only place the success branch can report it from — so it is a
    // structural requirement rather than a semantic one, and it stops the phase.
    const failure = onlyFailure(bytes(assertionXml({ subject })));

    expect(failure.code).toBe('malformed');
    expect(failure.detail).toMatch(/NameID/);
  });
});

describe('validateAssertion — what the success branch reports', () => {
  it('reports the operator tax code the subject names', () => {
    expect(accepted(bytes(assertionXml())).operatorTaxCode).toBe(PLANTED_IDENTITY);
  });

  it('reports the authentication level as undefined when the assertion attests none', () => {
    expect(accepted(bytes(assertionXml())).authenticationLevel).toBeUndefined();
  });

  it('reports the audiences the assertion is scoped to, in document order', () => {
    const conditions = [
      `<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">`,
      '<saml:AudienceRestriction>',
      `<saml:Audience>${SERVICE}</saml:Audience>`,
      '<saml:Audience>https://fser.regione.veneto.it/Repository</saml:Audience>',
      '</saml:AudienceRestriction>',
      '</saml:Conditions>',
    ].join('');

    expect(accepted(bytes(assertionXml({ conditions }))).audiences).toEqual([
      SERVICE,
      'https://fser.regione.veneto.it/Repository',
    ]);
  });

  it('reports the audiences of every audience restriction the assertion carries', () => {
    // Two restrictions are conjoined (D-018), so both must name the service —
    // and both are reported, because a caching layer keys on the whole scope.
    const conditions = [
      `<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">`,
      `<saml:AudienceRestriction><saml:Audience>${SERVICE}</saml:Audience></saml:AudienceRestriction>`,
      `<saml:AudienceRestriction><saml:Audience>${SERVICE}</saml:Audience><saml:Audience>https://other.example</saml:Audience></saml:AudienceRestriction>`,
      '</saml:Conditions>',
    ].join('');

    expect(accepted(bytes(assertionXml({ conditions }))).audiences).toEqual([
      SERVICE,
      SERVICE,
      'https://other.example',
    ]);
  });

  it('reports no audiences for a generic assertion', () => {
    // §4.1.6.2.2 makes the audience restriction optional, and the baseline
    // policy accepts an assertion carrying none (D-015).
    expect(accepted(bytes(assertionXml())).audiences).toEqual([]);
  });

  it('reports the deadline beside them, so a caching layer needs one call', () => {
    expect(accepted(bytes(assertionXml())).usableUntil).toBeInstanceOf(Date);
  });
});

describe('validateAssertion — a remedy that answers two failures at once', () => {
  /** The refusal a validation produced, or a failing assertion. */
  function refused(input: Uint8Array, policy: ServicePolicy, time: AssertionTimeModel = TIME) {
    const result = validateAssertion(input, time, policy);
    if (result.valid) {
      throw new Error('expected the assertion to be refused');
    }
    return result;
  }

  const GENERIC = bytes(assertionXml());

  // Each row pairs the level failure with one other, because the step-up is the
  // remedy that has to resolve everything the scoped re-request does *and* the
  // level. A step-up that resolved only the level would send a caller back for
  // an assertion that is still expired, still wrongly scoped, or still missing
  // the attribute — one round trip per failure, which is the loop the whole
  // derivation exists to make impossible.
  it.each<[string, Uint8Array, () => ServicePolicy, AssertionTimeModel]>([
    [
      'an expired assertion',
      GENERIC,
      policyRequiringTwoFactor,
      at(EXACT, NOT_ON_OR_AFTER),
    ],
    [
      'an assertion scoped elsewhere',
      bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
      policyRequiringTwoFactor,
      TIME,
    ],
    [
      'an assertion scoped to nothing, against a service that refuses generic ones',
      GENERIC,
      () =>
        servicePolicy({
          audience: SERVICE,
          refusesGenericAssertions: true,
          requiredAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
        }),
      TIME,
    ],
    [
      'an assertion missing an attribute the service asks for',
      GENERIC,
      () =>
        servicePolicy({
          audience: SERVICE,
          requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE],
          requiredAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
        }),
      TIME,
    ],
  ])(
    'answers %s that also attests no level with one step-up, not a step-up and a re-request',
    (_case, input, policy, time) => {
      const result = refused(input, policy(), time);

      expect(result.failures).toHaveLength(2);
      expect(result.failures.map((failure) => failure.code)).toContain(
        'authentication-level-not-attested',
      );
      expect(result.remedy).toEqual({
        action: 'step-up-auth',
        withAudience: SERVICE,
        withAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
      });
    },
  );

  it('names the level the specification attests when the service required none', () => {
    // The fallback in the step-up: an assertion attesting two levels attests
    // none whatever the policy asked for, so this failure arises against a
    // service with no requirement of its own — and a step-up naming no level
    // is one the session layer cannot execute. See D-026.
    const twoLevels = bytes(
      assertionXml({
        statement: statementXml(
          attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
          attributeXml(
            ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL,
            TWO_FACTOR_AUTHENTICATION_LEVEL,
            'urn:rve:authnL1',
          ),
        ),
      }),
    );

    const result = refused(twoLevels, baselinePolicy());

    expect(result.remedy).toEqual({
      action: 'step-up-auth',
      withAudience: SERVICE,
      withAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
    });
  });
});

describe('validateAssertion — what a refusal tells a support engineer', () => {
  it('says which mandatory attribute is missing when one is blank rather than absent', () => {
    // A blank ID is not an identifier a signature reference can be bound to, so
    // it is absent — and the refusal has to say so, because a support engineer
    // reading "carries no ID attribute" against a document that visibly has one
    // is the only way to learn that blank counts as absent.
    const blankId = bytes(
      assertionXml({ attributes: 'Version="2.0" ID="   " IssueInstant="2026-08-21T09:00:00Z"' }),
    );

    expect(onlyFailure(blankId).detail).toMatch(/carries no ID attribute/);
  });

  it('distinguishes an assertion scoped to nobody from one scoped elsewhere, in words', () => {
    const confidential = servicePolicy({ audience: SERVICE, refusesGenericAssertions: true });
    const absent = onlyFailure(bytes(assertionXml()), TIME, confidential);
    const mismatch = onlyFailure(
      bytes(assertionXml({ conditions: conditionsWith(restriction(OTHER_SERVICE)) })),
    );

    expect(absent.detail).toMatch(/names no audience/);
    expect(mismatch.detail).toMatch(/scoped to services that do not include/);
  });

  it('says which element there is not exactly one of', () => {
    expect(onlyFailure(bytes(assertionXml({ subject: '' }))).detail).toMatch(
      /exactly one Subject element/,
    );
    expect(onlyFailure(bytes(assertionXml({ conditions: '' }))).detail).toMatch(
      /exactly one Conditions element/,
    );
  });
});

describe('validateAssertion — the text an element carries', () => {
  function withNameId(nameId: string): Uint8Array {
    return bytes(assertionXml({ subject: `<saml:Subject>${nameId}</saml:Subject>` }));
  }

  it('reads a CDATA section as the text it stands for', () => {
    const cdata = withNameId(`<saml:NameID><![CDATA[${PLANTED_IDENTITY}]]></saml:NameID>`);

    expect(accepted(cdata).operatorTaxCode).toBe(PLANTED_IDENTITY);
  });

  it('reads text a comment interrupts as the text alone', () => {
    // The comment is not content. Collecting it would put characters into the
    // operator's tax code that the region never signed into it, and the
    // identity cross-check would then refuse a document nothing is wrong with.
    const interrupted = withNameId(
      `<saml:NameID>${PLANTED_IDENTITY.slice(0, 6)}<!-- a comment -->${PLANTED_IDENTITY.slice(6)}</saml:NameID>`,
    );

    expect(accepted(interrupted).operatorTaxCode).toBe(PLANTED_IDENTITY);
  });

  it('refuses an element whose content is an element beside text', () => {
    // `<x>http://</x>evil` concatenated is a URL; read as this library reads
    // it, an element carrying an element carries no text at all.
    const wrapped = withNameId(
      `<saml:NameID><x>${PLANTED_IDENTITY.slice(0, 6)}</x>${PLANTED_IDENTITY.slice(6)}</saml:NameID>`,
    );

    expect(onlyFailure(wrapped).code).toBe('malformed');
  });

  it('reports only the audiences that are text, never an element that is not', () => {
    const audiences = bytes(
      assertionXml({
        conditions: conditionsWith(
          `<saml:AudienceRestriction><saml:Audience><x>${OTHER_SERVICE}</x></saml:Audience><saml:Audience>${SERVICE}</saml:Audience></saml:AudienceRestriction>`,
        ),
      }),
    );

    expect(accepted(audiences).audiences).toEqual([SERVICE]);
  });
});

describe('validateAssertion — the lexical form of a validity window', () => {
  it('refuses a NotBefore carrying anything before the timestamp', () => {
    expect(
      onlyFailure(
        bytes(
          assertionXml({
            conditions: `<saml:Conditions NotBefore="on ${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}"/>`,
          }),
        ),
      ).code,
    ).toBe('malformed');
  });

  it('refuses a NotOnOrAfter carrying anything after the timestamp', () => {
    expect(
      onlyFailure(
        bytes(
          assertionXml({
            conditions: `<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER} at the latest"/>`,
          }),
        ),
      ).code,
    ).toBe('malformed');
  });
});

describe('validateAssertion — a document a lenient parser would repair', () => {
  // D-010. xmldom recovers from an error-level problem by default and carries
  // on; this library refuses instead, because a recovered document is one whose
  // element tree no longer corresponds to the bytes the region signed, and
  // every check after it would run against the parser's opinion of the
  // assertion rather than against the assertion.
  it('refuses a document carrying an entity reference nothing defines', () => {
    const undefinedEntity = bytes(
      assertionXml({ issuer: '<saml:Issuer>https://iap.ulssx.veneto.it/&nope;</saml:Issuer>' }),
    );

    expect(onlyFailure(undefinedEntity).code).toBe('malformed');
  });

  it('refuses a document carrying content after its root element', () => {
    expect(onlyFailure(bytes(`${assertionXml()}<trailing/>`)).code).toBe('malformed');
  });
});

describe('validateAssertion — the signature, in words a support engineer can act on', () => {
  it('names the element whose Algorithm attribute is missing', () => {
    // "carries no Algorithm attribute" and "names an algorithm the section does
    // not attest" send a reader to different places: one is a malformed
    // document, the other is an IAP signing with something unblessed.
    const noSignatureAlgorithm = signatureXml({
      signatureMethod: '<ds:SignatureMethod/>',
    });
    const noDigestAlgorithm = signatureXml({
      reference: referenceXml({ digestMethod: '<ds:DigestMethod/>' }),
    });

    expect(onlyFailure(bytes(assertionXml({ signature: noSignatureAlgorithm }))).detail).toMatch(
      /ds:SignatureMethod carries no Algorithm attribute/,
    );
    expect(onlyFailure(bytes(assertionXml({ signature: noDigestAlgorithm }))).detail).toMatch(
      /ds:DigestMethod carries no Algorithm attribute/,
    );
  });

  it('says an unattested algorithm is unattested, and which element named it', () => {
    const unattested = signatureXml({
      signatureMethod: '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>',
    });

    expect(onlyFailure(bytes(assertionXml({ signature: unattested }))).detail).toMatch(
      /ds:SignatureMethod names an algorithm §4\.1\.6\.2\.2 does not attest/,
    );
  });

  it('says a deprecated algorithm was accepted, and which one', () => {
    const deprecated = signatureXml({
      signatureMethod: '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>',
      reference: referenceXml({
        digestMethod: '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>',
      }),
    });
    const result = accepted(bytes(assertionXml({ signature: deprecated })));
    const details = result.warnings.map((warning) => warning.detail).join(' ');

    expect(details).toMatch(/signed with the SHA-1 signature algorithm/);
    expect(details).toMatch(/digests the assertion with SHA-1/);
  });

  it('says the caller’s own verifier is what rejected the signature', () => {
    const result = validateAssertion(bytes(assertionXml()), TIME, baselinePolicy(), {
      verifySignature: () => 'not-verified',
    });

    if (result.valid) {
      throw new Error('expected the assertion to be refused');
    }
    expect(result.failures[0].detail).toMatch(/verifier rejected/);
  });

  it('carries no warning at all when the algorithms are current and a verifier verified', () => {
    // Exactly none, not merely none of the two deprecation warnings: a warning
    // a caller did not earn is one they learn to scroll past.
    const result = validateAssertion(bytes(assertionXml()), TIME, baselinePolicy(), {
      verifySignature: () => 'verified',
    });

    if (!result.valid) {
      throw new Error('expected the assertion to be accepted');
    }
    expect(result.warnings).toEqual([]);
  });
});

describe('validateAssertion — the arguments the caller supplies', () => {
  // Thrown rather than returned, so the message is the whole diagnosis: there
  // is no failure object beside it carrying a code.
  it('says the clock is not a clock', () => {
    expect(() => validateAssertion(bytes(assertionXml()), at(TIME, NaN), baselinePolicy())).toThrow(
      /the current time is not a valid instant/,
    );
  });

  it('names the margin that is not a number of milliseconds', () => {
    expect(() =>
      validateAssertion(bytes(assertionXml()), { ...TIME, clockSkewMs: -1 }, baselinePolicy()),
    ).toThrow(/clockSkewMs must be a finite, non-negative number of milliseconds/);
    expect(() =>
      validateAssertion(bytes(assertionXml()), { ...TIME, flightTimeMs: Number.NaN }, baselinePolicy()),
    ).toThrow(/flightTimeMs must be a finite, non-negative number of milliseconds/);
  });
});

describe('validateAssertion — a timestamp is the whole attribute, not part of it', () => {
  function withConditions(notBefore: string, notOnOrAfter: string): Uint8Array {
    return bytes(
      assertionXml({
        conditions: `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"/>`,
      }),
    );
  }

  // The pattern is anchored at both ends, and these are the inputs that prove
  // it: each carries a timestamp a search would find inside it, and each parses
  // once the surrounding characters are ignored. An unanchored check would
  // accept them and validate the window they only look like.
  it('refuses a NotBefore padded with whitespace', () => {
    expect(onlyFailure(withConditions(` ${NOT_BEFORE}`, NOT_ON_OR_AFTER)).detail).toMatch(
      /NotBefore that is not a UTC dateTime/,
    );
  });

  it('refuses a NotOnOrAfter padded with whitespace', () => {
    expect(onlyFailure(withConditions(NOT_BEFORE, `${NOT_ON_OR_AFTER} `)).detail).toMatch(
      /NotOnOrAfter that is not a UTC dateTime/,
    );
  });

  it('distinguishes an absent bound from one that is not a timestamp', () => {
    const absent = bytes(
      assertionXml({ conditions: `<saml:Conditions NotOnOrAfter="${NOT_ON_OR_AFTER}"/>` }),
    );

    expect(onlyFailure(absent).detail).toMatch(/carries no NotBefore attribute/);
  });
});
