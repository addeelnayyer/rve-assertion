import { describe, expect, it } from 'vitest';

import {
  RECOMMENDED_CLOCK_SKEW_MS,
  RECOMMENDED_FLIGHT_TIME_MS,
  validateAssertion,
  type AssertionTimeModel,
} from './assertion.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import { ValidationInputError } from './types.js';

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
}

const ISSUER = '<saml:Issuer>https://iap.ulssx.veneto.it</saml:Issuer>';
const SUBJECT = `<saml:Subject><saml:NameID>${PLANTED_IDENTITY}</saml:NameID></saml:Subject>`;
const NOT_BEFORE = '2026-08-21T09:00:00Z';
const NOT_ON_OR_AFTER = '2026-08-21T13:00:00Z';
const CONDITIONS = `<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}"/>`;

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
function onlyFailure(input: Uint8Array, time: AssertionTimeModel = TIME) {
  const result = validateAssertion(input, time);
  if (result.valid) {
    throw new Error('expected the assertion to be refused');
  }
  expect(result.failures).toHaveLength(1);
  return result.failures[0];
}

describe('validateAssertion — the structural phase', () => {
  it('accepts a structurally complete assertion', () => {
    expect(validateAssertion(bytes(assertionXml()), TIME).valid).toBe(true);
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

    validateAssertion(input, TIME);

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
    const result = validateAssertion(withWindow('2026-08-21T09:00:00.500Z', NOT_ON_OR_AFTER), TIME);

    expect(result.valid).toBe(true);
  });

  it('accepts a time zone offset other than Z, and reads it as the offset it declares', () => {
    // 11:00 at +02:00 is 09:00Z — the same instant the fixture's window opens
    // at, so an assertion read correctly is valid and one read as local is not.
    const result = validateAssertion(withWindow('2026-08-21T11:00:00+02:00', NOT_ON_OR_AFTER), {
      ...EXACT,
      now: new Date('2026-08-21T09:00:00Z'),
    });

    expect(result.valid).toBe(true);
  });
});

describe('validateAssertion — the validity window', () => {
  it('accepts an assertion the clock is inside the window of', () => {
    expect(validateAssertion(bytes(assertionXml()), TIME).valid).toBe(true);
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

    expect(validateAssertion(document, at(EXACT, NOT_BEFORE)).valid).toBe(true);
    expect(validateAssertion(document, at(EXACT, Date.parse(NOT_BEFORE) - 1)).valid).toBe(false);
    expect(validateAssertion(document, at(EXACT, Date.parse(NOT_ON_OR_AFTER) - 1)).valid).toBe(true);
    expect(validateAssertion(document, at(EXACT, NOT_ON_OR_AFTER)).valid).toBe(false);
  });

  it('lets clock skew loosen the not-before bound', () => {
    // A clock a little fast would otherwise refuse an assertion that is in
    // fact open, so the skew is subtracted from the bound rather than added.
    const document = bytes(assertionXml());
    const skewed = at(
      { ...EXACT, clockSkewMs: RECOMMENDED_CLOCK_SKEW_MS },
      Date.parse(NOT_BEFORE) - RECOMMENDED_CLOCK_SKEW_MS,
    );

    expect(validateAssertion(document, skewed).valid).toBe(true);
    expect(validateAssertion(document, { ...skewed, clockSkewMs: 0 }).valid).toBe(false);
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

    expect(validateAssertion(document, skewed).valid).toBe(false);
    expect(validateAssertion(document, { ...skewed, clockSkewMs: 0 }).valid).toBe(true);
  });

  it('lets clock skew and flight time together tighten the not-on-or-after bound', () => {
    // The assertion is still inside its window on this clock, and would not be
    // by the time a call carrying it reached the X-Service Provider.
    const document = bytes(assertionXml());
    const margin = RECOMMENDED_CLOCK_SKEW_MS + RECOMMENDED_FLIGHT_TIME_MS;
    const late = at(TIME, Date.parse(NOT_ON_OR_AFTER) - margin);

    expect(validateAssertion(document, late).valid).toBe(false);
    expect(validateAssertion(document, { ...late, clockSkewMs: 0, flightTimeMs: 0 }).valid).toBe(
      true,
    );
  });

  it('returns a usable-until deadline that is the tightened bound itself', () => {
    // What a cache evicts on: the last instant at which spending the assertion
    // is still expected to arrive in time.
    const result = validateAssertion(bytes(assertionXml()), TIME);

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
    });

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

    expect(validateAssertion(bytes(assertionXml({ conditions })), TIME).valid).toBe(true);
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
    expect(() => validateAssertion(document, { ...TIME, ...overrides })).toThrow(
      ValidationInputError,
    );
  });

  it('accepts a caller that declines both margins', () => {
    expect(validateAssertion(document, EXACT).valid).toBe(true);
  });

  it('names recommended margins without applying them', () => {
    // Exported so that taking them is something a caller writes down.
    expect(RECOMMENDED_CLOCK_SKEW_MS).toBeGreaterThan(0);
    expect(RECOMMENDED_FLIGHT_TIME_MS).toBeGreaterThan(0);
  });
});
