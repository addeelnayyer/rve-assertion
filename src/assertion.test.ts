import { describe, expect, it } from 'vitest';

import { validateAssertion } from './assertion.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import { servicePolicy, type ServicePolicy } from './service-policy.js';

const SAML_ASSERTION_XMLNS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const ASSERTION_ID =
  'assertion_2.16.840.1.113883.2.9.2.50999_msgId_9376254e-da05-41f5-9af3-ac56d63d8ebd';

/**
 * A distinctive value planted in the fixture wherever the assertion would carry
 * an identity, so that a test can assert no failure detail echoes it.
 */
const PLANTED_IDENTITY = 'PLANTEDIDENTITY00X';

/** The service every test validates against unless it says otherwise. */
const SERVICE = 'https://fser.regione.veneto.it/Registry';

/** A policy on the baseline: exact matching, generic assertions accepted. */
const POLICY = servicePolicy({ audience: SERVICE });

interface AssertionParts {
  readonly attributes?: string;
  readonly issuer?: string;
  readonly subject?: string;
  readonly conditions?: string;
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
function assertionXml({ attributes, issuer, subject, conditions }: AssertionParts = {}): string {
  return [
    `<saml:Assertion xmlns:saml="${SAML_ASSERTION_XMLNS}" `,
    attributes ?? `Version="2.0" ID="${ASSERTION_ID}" IssueInstant="2026-08-21T09:00:00Z"`,
    '>',
    issuer ?? ISSUER,
    subject ?? SUBJECT,
    conditions ?? CONDITIONS,
    '</saml:Assertion>',
  ].join('');
}

function bytes(xml: string): Uint8Array {
  return new TextEncoder().encode(xml);
}

/** The single failure a refusal carries, or a failing assertion. */
function onlyFailure(input: Uint8Array, policy: ServicePolicy = POLICY) {
  const result = validateAssertion(input, policy);
  if (result.valid) {
    throw new Error('expected the assertion to be refused');
  }
  expect(result.failures).toHaveLength(1);
  return result.failures[0];
}

describe('validateAssertion — the structural phase', () => {
  it('accepts a structurally complete assertion', () => {
    expect(validateAssertion(bytes(assertionXml()), POLICY).valid).toBe(true);
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
    const failure = onlyFailure(
      bytes(`<saml:Response xmlns:saml="${SAML_ASSERTION_XMLNS}"/>`),
    );

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
    const failure = onlyFailure(
      bytes(assertionXml({ attributes: 'Version="2.0"', conditions: '' })),
    );

    expect(failure.code).toBe('malformed');
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
});

describe('validateAssertion — the byte contract', () => {
  it("leaves the caller's bytes exactly as they were", () => {
    // The assertion has to be spent exactly as the IAP returned it (§4.6), so
    // the one thing the validator must never do to its input is touch it.
    const input = bytes(assertionXml());
    const before = Uint8Array.from(input);

    validateAssertion(input, POLICY);

    expect(input).toEqual(before);
  });
});

/** A `Conditions` element carrying `inner`, and a window nothing here reads. */
function conditionsWith(inner: string): string {
  return [
    '<saml:Conditions NotBefore="2026-08-21T09:00:00Z" NotOnOrAfter="2026-08-21T13:00:00Z">',
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
function accepts(conditions: string, policy: ServicePolicy = POLICY): boolean {
  return validateAssertion(bytes(assertionXml({ conditions })), policy).valid;
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
    // §4.1.6.2.2 permits zero Audience sub-elements. A restriction naming
    // nobody restricts to nobody, so it is a mismatch rather than the generic
    // assertion of §3.1.1 — the document did declare a restriction.
    expect(onlyFailure(bytes(assertionXml({ conditions: conditionsWith(restriction()) }))).code).toBe(
      'audience-mismatch',
    );
  });

  it('requires every AudienceRestriction to name the service, not merely one of them', () => {
    // SAML 2.0 core conjoins restrictions: each is a separate condition and all
    // must hold. Fails closed on a document the region's own examples never
    // produce — see docs/spec-questions.md (D-015).
    const conditions = conditionsWith(restriction(SERVICE) + restriction(OTHER_SERVICE));

    expect(onlyFailure(bytes(assertionXml({ conditions }))).code).toBe('audience-mismatch');
  });

  it('accepts an assertion whose every restriction names the service', () => {
    expect(accepts(conditionsWith(restriction(SERVICE) + restriction(SERVICE, OTHER_SERVICE)))).toBe(
      true,
    );
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

    expect(onlyFailure(bytes(assertionXml({ conditions }))).detail).not.toContain(PLANTED_IDENTITY);
  });
});

describe('validateAssertion — a generic assertion', () => {
  const CONFIDENTIAL = servicePolicy({ audience: SERVICE, refusesGenericAssertions: true });

  it('accepts one, on the baseline policy', () => {
    // The baseline is an inference from §4.1.8, Table 3, which marks the
    // audience optional — not a statement §4.2.6 makes. D-012.
    expect(accepts(conditionsWith(''))).toBe(true);
  });

  it('accepts one whose Conditions has no children at all', () => {
    expect(validateAssertion(bytes(assertionXml()), POLICY).valid).toBe(true);
  });

  it('refuses one when the caller says the service refuses them', () => {
    // §3.1.1's confidential service: the only assertion it honours is one
    // whose request named it.
    const failure = onlyFailure(bytes(assertionXml({ conditions: conditionsWith('') })), CONFIDENTIAL);

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
      CONFIDENTIAL,
    );

    expect(scopedElsewhere.code).toBe('audience-mismatch');
  });

  it('does not reach the audience at all when the document is malformed', () => {
    // The structural short-circuit, restated now that there is a later phase to
    // short-circuit: a document with no Conditions has no audience to be
    // missing, and reporting one would be reporting the same failure twice.
    const failure = onlyFailure(bytes(assertionXml({ conditions: '' })), CONFIDENTIAL);

    expect(failure.code).toBe('malformed');
  });
});
