import { DOMParser } from '@xmldom/xmldom';
import type { Element } from '@xmldom/xmldom';
import { describe, expect, it } from 'vitest';

import { ASSERTION_ATTRIBUTES, readAssertionAttributes } from './assertion-attributes.js';

const SAML_ASSERTION_XMLNS = 'urn:oasis:names:tc:SAML:2.0:assertion';

/** A bare assertion element carrying `content`, parsed. */
function assertionWith(content: string): Element {
  const xml = `<saml:Assertion xmlns:saml="${SAML_ASSERTION_XMLNS}">${content}</saml:Assertion>`;
  const element = new DOMParser().parseFromString(xml, 'text/xml').documentElement;
  if (element === null) {
    throw new Error('the fixture did not parse');
  }
  return element;
}

/** One `saml:Attribute` with one `saml:AttributeValue`, as §4.1.6.2.2 writes it. */
function attributeXml(name: string, ...values: readonly string[]): string {
  const valueXml = values.map((value) => `<saml:AttributeValue>${value}</saml:AttributeValue>`);
  return `<saml:Attribute Name="${name}">${valueXml.join('')}</saml:Attribute>`;
}

function statement(...attributes: readonly string[]): string {
  return `<saml:AttributeStatement>${attributes.join('')}</saml:AttributeStatement>`;
}

describe('readAssertionAttributes', () => {
  it('reads a single-valued attribute by the name the assertion gives it', () => {
    const attributes = readAssertionAttributes(
      assertionWith(statement(attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, 'CFOPERATORE1'))),
    );

    expect(attributes.get(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY)).toEqual(['CFOPERATORE1']);
  });

  it('reads an assertion carrying no attribute statement as carrying no attributes', () => {
    expect(readAssertionAttributes(assertionWith('')).size).toBe(0);
  });

  it('collects the values of an attribute repeated across two attribute statements', () => {
    // The wrapping case the cross-check exists to catch: one assertion naming
    // two responsible parties must not read as naming whichever comes first.
    const attributes = readAssertionAttributes(
      assertionWith(
        statement(attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, 'CFOPERATORE1')) +
          statement(attributeXml(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, 'CFOPERATORE2')),
      ),
    );

    expect(attributes.get(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY)).toEqual([
      'CFOPERATORE1',
      'CFOPERATORE2',
    ]);
  });

  it('collects every value of an attribute carrying more than one, in document order', () => {
    const attributes = readAssertionAttributes(
      assertionWith(statement(attributeXml('codAziendaAuth', '101', '102'))),
    );

    expect(attributes.get('codAziendaAuth')).toEqual(['101', '102']);
  });

  it('trims a value of the whitespace an indented document puts around it', () => {
    const attributes = readAssertionAttributes(
      assertionWith(
        statement(
          `<saml:Attribute Name="${ASSERTION_ATTRIBUTES.ROLE}">\n  <saml:AttributeValue>\n    R.1.1\n  </saml:AttributeValue>\n</saml:Attribute>`,
        ),
      ),
    );

    expect(attributes.get(ASSERTION_ATTRIBUTES.ROLE)).toEqual(['R.1.1']);
  });

  it('does not report an attribute whose only value is blank', () => {
    // Present-but-empty is not a value a service policy can be satisfied by,
    // and reporting it as present would satisfy one.
    const attributes = readAssertionAttributes(
      assertionWith(statement(attributeXml(ASSERTION_ATTRIBUTES.ROLE, '   '))),
    );

    expect(attributes.has(ASSERTION_ATTRIBUTES.ROLE)).toBe(false);
  });

  it('does not report an attribute carrying no value element at all', () => {
    const attributes = readAssertionAttributes(
      assertionWith(statement(`<saml:Attribute Name="${ASSERTION_ATTRIBUTES.ROLE}"/>`)),
    );

    expect(attributes.has(ASSERTION_ATTRIBUTES.ROLE)).toBe(false);
  });

  it('ignores an attribute that names nothing', () => {
    const attributes = readAssertionAttributes(
      assertionWith(statement('<saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute>')),
    );

    expect(attributes.size).toBe(0);
  });

  it('ignores an attribute statement in some other namespace', () => {
    // Matched by namespace rather than by tag name: a document is free to bind
    // the `saml:` prefix to something else, and this one does.
    const attributes = readAssertionAttributes(
      assertionWith(
        '<other:AttributeStatement xmlns:other="urn:example:not-saml"><other:Attribute Name="Role"><other:AttributeValue>R.1.1</other:AttributeValue></other:Attribute></other:AttributeStatement>',
      ),
    );

    expect(attributes.size).toBe(0);
  });

  it('ignores an attribute nested below the statement rather than in it', () => {
    // Direct children at every step. An attribute reached by descending through
    // an element §4.1.6.2.2 does not put there is an attribute of some other
    // document that happens to be inside this one.
    const attributes = readAssertionAttributes(
      assertionWith(
        `<saml:AttributeStatement><saml:Advice>${attributeXml(ASSERTION_ATTRIBUTES.ROLE, 'R.1.1')}</saml:Advice></saml:AttributeStatement>`,
      ),
    );

    expect(attributes.size).toBe(0);
  });

  it('ignores an attribute whose name is blank', () => {
    // Blank counts as absent here as it does everywhere else this library reads
    // an attribute, so a whitespace name cannot become something a policy is
    // asked to match.
    const attributes = readAssertionAttributes(
      assertionWith(statement(attributeXml('   ', 'R.1.1'))),
    );

    expect(attributes.size).toBe(0);
  });

  it('reads a name the document indented, by the name it means', () => {
    const attributes = readAssertionAttributes(
      assertionWith(statement(attributeXml(` ${ASSERTION_ATTRIBUTES.ROLE} `, 'R.1.1'))),
    );

    expect(attributes.get(ASSERTION_ATTRIBUTES.ROLE)).toEqual(['R.1.1']);
  });

  it('names the attributes §4.1.6.2.2 defines, so that a policy need not spell them', () => {
    expect(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY).toBe('ResponsibleParty');
    expect(ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL).toBe('authLevel');
    expect(ASSERTION_ATTRIBUTES.APPLICATION_ID).toBe('ApplicationID');
  });
});
