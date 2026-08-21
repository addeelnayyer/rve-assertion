import { describe, expect, it } from 'vitest';

import { validateAssertion } from './assertion.js';
import type { ServicePolicy } from './assertion.js';
import { ASSERTION_ATTRIBUTES } from './assertion-attributes.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import { TWO_FACTOR_AUTHENTICATION_LEVEL } from './request.js';

const SAML_ASSERTION_XMLNS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const ASSERTION_ID =
  'assertion_2.16.840.1.113883.2.9.2.50999_msgId_9376254e-da05-41f5-9af3-ac56d63d8ebd';

/**
 * A distinctive value planted in the fixture wherever the assertion would carry
 * an identity, so that a test can assert no failure detail echoes it.
 */
const PLANTED_IDENTITY = 'PLANTEDIDENTITY00X';

interface AssertionParts {
  readonly attributes?: string;
  readonly issuer?: string;
  readonly subject?: string;
  readonly conditions?: string;
  readonly statement?: string;
}

/**
 * A policy asking for nothing beyond what the library requires of every
 * assertion. The parameter is not optional, so that a caller states what the
 * service it is about to call needs rather than inheriting a default nobody
 * chose — and "nothing" is a thing to state.
 */
const NO_REQUIREMENTS: ServicePolicy = {};

const ISSUER = '<saml:Issuer>https://iap.ulssx.veneto.it</saml:Issuer>';
const SUBJECT = `<saml:Subject><saml:NameID>${PLANTED_IDENTITY}</saml:NameID></saml:Subject>`;
const CONDITIONS =
  '<saml:Conditions NotBefore="2026-08-21T09:00:00Z" NotOnOrAfter="2026-08-21T13:00:00Z"/>';

/** One `saml:Attribute`, as §4.1.6.2.2's worked assertion writes it. */
function attributeXml(name: string, value: string): string {
  return `<saml:Attribute Name="${name}"><saml:AttributeValue>${value}</saml:AttributeValue></saml:Attribute>`;
}

function statementXml(...attributes: readonly string[]): string {
  return `<saml:AttributeStatement>${attributes.join('')}</saml:AttributeStatement>`;
}

/**
 * The attribute statement of an assertion nobody has anything against: the
 * responsible party names the same operator the subject does.
 */
const STATEMENT = statementXml(
  attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
);

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
  subject,
  conditions,
  statement,
}: AssertionParts = {}): string {
  return [
    `<saml:Assertion xmlns:saml="${SAML_ASSERTION_XMLNS}" `,
    attributes ?? `Version="2.0" ID="${ASSERTION_ID}" IssueInstant="2026-08-21T09:00:00Z"`,
    '>',
    issuer ?? ISSUER,
    subject ?? SUBJECT,
    conditions ?? CONDITIONS,
    statement ?? STATEMENT,
    '</saml:Assertion>',
  ].join('');
}

function bytes(xml: string): Uint8Array {
  return new TextEncoder().encode(xml);
}

/** The failures an assertion was refused for, or a failing assertion. */
function failures(input: Uint8Array, policy: ServicePolicy = NO_REQUIREMENTS) {
  const result = validateAssertion(input, policy);
  if (result.valid) {
    throw new Error('expected the assertion to be refused');
  }
  return result.failures;
}

/** The single failure a structural refusal carries, or a failing assertion. */
function onlyFailure(input: Uint8Array, policy: ServicePolicy = NO_REQUIREMENTS) {
  const refused = failures(input, policy);
  expect(refused).toHaveLength(1);
  return refused[0];
}

/** The assertion's success branch, or a failing assertion. */
function accepted(input: Uint8Array, policy: ServicePolicy = NO_REQUIREMENTS) {
  const result = validateAssertion(input, policy);
  if (!result.valid) {
    throw new Error(
      `expected the assertion to be accepted; it was refused for ${result.failures
        .map((failure) => failure.code)
        .join(', ')}`,
    );
  }
  return result;
}

describe('validateAssertion — the structural phase', () => {
  it('accepts a structurally complete assertion', () => {
    expect(validateAssertion(bytes(assertionXml()), NO_REQUIREMENTS).valid).toBe(true);
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

    validateAssertion(input, NO_REQUIREMENTS);

    expect(input).toEqual(before);
  });
});

describe('validateAssertion — required attributes', () => {
  it('accepts an assertion carrying every attribute the policy asks for', () => {
    const assertion = assertionXml({
      statement: statementXml(
        attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
        attributeXml(ASSERTION_ATTRIBUTES.ROLE, 'R.1.1'),
        attributeXml(ASSERTION_ATTRIBUTES.REQUEST_CONTEXT, 'C.1.1'),
      ),
    });

    expect(
      accepted(bytes(assertion), {
        requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE, ASSERTION_ATTRIBUTES.REQUEST_CONTEXT],
      }).valid,
    ).toBe(true);
  });

  it('refuses an assertion missing an attribute the policy asks for', () => {
    const failure = onlyFailure(bytes(assertionXml()), {
      requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE],
    });

    expect(failure.code).toBe('attribute-missing');
    expect(failure.detail).toMatch(/Role/);
  });

  it('lets the policy require an attribute this excerpt does not name', () => {
    // §4.2.5.2 says regional projects may provide for further parameters and
    // defers their definition to a transaction this excerpt does not contain,
    // so the vocabulary a policy draws from is open.
    const failure = onlyFailure(bytes(assertionXml()), {
      requiredAttributes: ['codProgettoRegionale'],
    });

    expect(failure.code).toBe('attribute-missing');
    expect(failure.detail).toMatch(/codProgettoRegionale/);
  });

  it('reports one failure per missing attribute rather than stopping at the first', () => {
    // The semantic phase runs to completion: a caller that fixes one attribute,
    // retries against a third-party IAP and discovers a second has spent a
    // round trip to learn what this result already said.
    const refused = failures(bytes(assertionXml()), {
      requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE, ASSERTION_ATTRIBUTES.APPLICATION_ID],
    });

    expect(refused.map((failure) => failure.code)).toEqual([
      'attribute-missing',
      'attribute-missing',
    ]);
    expect(refused.map((failure) => failure.regionalErrorCode)).toEqual([
      REGIONAL_ERROR_CODES.ROLE_NOT_PERMITTED,
      REGIONAL_ERROR_CODES.APPLICATION_ID_NOT_PERMITTED,
    ]);
  });

  it('annotates an attribute the region has no code of its own for with the general one', () => {
    const failure = onlyFailure(bytes(assertionXml()), {
      requiredAttributes: [ASSERTION_ATTRIBUTES.FACILITY_CODE],
    });

    expect(failure.regionalErrorCode).toBe(
      REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY,
    );
  });

  it('does not treat a present-but-empty attribute as satisfying the policy', () => {
    const assertion = assertionXml({
      statement: statementXml(
        attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
        `<saml:Attribute Name="${ASSERTION_ATTRIBUTES.ROLE}"/>`,
      ),
    });

    expect(onlyFailure(bytes(assertion), { requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE] }).code).toBe(
      'attribute-missing',
    );
  });

  it('requires the responsible party whatever the policy asks for', () => {
    // Not policy-driven: the identity cross-check reads this attribute, and an
    // assertion that omits it is an assertion the cross-check cannot be run
    // against. See docs/spec-questions.md (D-014).
    const failure = onlyFailure(bytes(assertionXml({ statement: '' })));

    expect(failure.code).toBe('attribute-missing');
    expect(failure.detail).toMatch(/ResponsibleParty/);
  });

  it('marks a missing attribute as something a further round trip could fix', () => {
    const failure = onlyFailure(bytes(assertionXml()), {
      requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE],
    });

    expect(failure.unrecoverable).toBe(false);
  });
});

describe('validateAssertion — the authentication level', () => {
  const REQUIRES_TWO_FACTOR: ServicePolicy = {
    requiredAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
  };

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

  it('accepts an assertion attesting the level the policy requires', () => {
    expect(accepted(withLevel(TWO_FACTOR_AUTHENTICATION_LEVEL), REQUIRES_TWO_FACTOR).valid).toBe(
      true,
    );
  });

  it('accepts an assertion attesting no level when the policy requires none', () => {
    expect(accepted(bytes(assertionXml())).valid).toBe(true);
  });

  it('distinguishes a missing authentication level from every other failure', () => {
    // Its own code, because its remedy is unlike any other: the operator has to
    // authenticate again with a second factor, which is the session layer's
    // work and not a re-request this library's caller can make.
    const failure = onlyFailure(bytes(assertionXml()), REQUIRES_TWO_FACTOR);

    expect(failure.code).toBe('authentication-level-not-attested');
    expect(failure.regionalErrorCode).toBe(
      REGIONAL_ERROR_CODES.TWO_FACTOR_AUTHENTICATION_REQUIRED,
    );
    expect(failure.unrecoverable).toBe(false);
  });

  it('refuses an assertion attesting some level other than the one required', () => {
    expect(onlyFailure(withLevel('urn:rve:authnL1'), REQUIRES_TWO_FACTOR).code).toBe(
      'authentication-level-not-attested',
    );
  });

  it('refuses an assertion attesting the required level twice over, differently', () => {
    // Two values under one name is two answers, and a check that took the first
    // would be a check a second value could be hidden behind.
    const assertion = bytes(
      assertionXml({
        statement: statementXml(
          attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, PLANTED_IDENTITY),
          `<saml:Attribute Name="${ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL}"><saml:AttributeValue>${TWO_FACTOR_AUTHENTICATION_LEVEL}</saml:AttributeValue><saml:AttributeValue>urn:rve:authnL1</saml:AttributeValue></saml:Attribute>`,
        ),
      }),
    );

    expect(onlyFailure(assertion, REQUIRES_TWO_FACTOR).code).toBe(
      'authentication-level-not-attested',
    );
  });

  it('does not object to a level the policy did not ask for', () => {
    // The excerpt names one level and cannot say the region has not added
    // another since. An unrecognised level is reported, not refused.
    expect(accepted(withLevel('urn:rve:authnL3')).authenticationLevel).toBe('urn:rve:authnL3');
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
    // a correct assertion without weakening the check. See D-013.
    expect(accepted(withResponsibleParty(PLANTED_IDENTITY.toLowerCase())).valid).toBe(true);
  });

  it('does not validate the tax code, on either side', () => {
    // Deliberate — D-012. The check is that the assertion says one thing about
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
    expect(failures(bytes(assertionXml({ statement: '' }))).map((failure) => failure.code)).toEqual([
      'attribute-missing',
    ]);
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
      '<saml:Conditions NotBefore="2026-08-21T09:00:00Z" NotOnOrAfter="2026-08-21T13:00:00Z">',
      '<saml:AudienceRestriction>',
      '<saml:Audience>https://fser.regione.veneto.it/Registry</saml:Audience>',
      '<saml:Audience>https://fser.regione.veneto.it/Repository</saml:Audience>',
      '</saml:AudienceRestriction>',
      '</saml:Conditions>',
    ].join('');

    expect(accepted(bytes(assertionXml({ conditions }))).audiences).toEqual([
      'https://fser.regione.veneto.it/Registry',
      'https://fser.regione.veneto.it/Repository',
    ]);
  });

  it('reports the audiences of every audience restriction the assertion carries', () => {
    const conditions = [
      '<saml:Conditions NotBefore="2026-08-21T09:00:00Z" NotOnOrAfter="2026-08-21T13:00:00Z">',
      '<saml:AudienceRestriction><saml:Audience>https://a.example</saml:Audience></saml:AudienceRestriction>',
      '<saml:AudienceRestriction><saml:Audience>https://b.example</saml:Audience></saml:AudienceRestriction>',
      '</saml:Conditions>',
    ].join('');

    expect(accepted(bytes(assertionXml({ conditions }))).audiences).toEqual([
      'https://a.example',
      'https://b.example',
    ]);
  });

  it('reports no audiences for an assertion that names none', () => {
    // §4.1.6.2.2 makes the audience restriction optional, so an assertion
    // without one is scoped to nothing in particular rather than malformed.
    // Whether that is good enough for the service about to be called is the
    // audience match's question, not this one's.
    expect(accepted(bytes(assertionXml())).audiences).toEqual([]);
  });
});
