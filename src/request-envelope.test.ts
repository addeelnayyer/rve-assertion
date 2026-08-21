import { DOMParser } from '@xmldom/xmldom';
import * as xpath from 'xpath';
import { describe, expect, it } from 'vitest';

import {
  SAML_ASSERTION_NAMESPACE,
  SAML_PROTOCOL_NAMESPACE,
  SOAP_ENVELOPE_NAMESPACE,
  WS_ADDRESSING_NAMESPACE,
  WS_SECURITY_SECEXT_NAMESPACE,
} from './namespaces.js';
import { buildRve1bRequest } from './request-envelope.js';
import { deriveRequestId, rve1bRequest, TWO_FACTOR_AUTHENTICATION_LEVEL } from './request.js';
import type { Rve1bRequestInput } from './request.js';

const MESSAGE_ID = 'urn:uuid:9376254e-da05-41f5-9af3-ac56d63d8ebd';

const VALID: Rve1bRequestInput = {
  messageId: MESSAGE_ID,
  recipient: 'https://iap.ulssx.veneto.it/ws',
  username: { form: 'plaintext', value: 'a-directory-server-username' },
  applicationId: '2.16.840.1.113883.2.9.2.50.4.5.0999',
  requestContext: 'C.1.1',
  issueInstant: new Date('2026-08-21T09:00:00Z'),
  notBefore: new Date('2026-08-21T09:00:00Z'),
  notOnOrAfter: new Date('2026-08-21T13:00:00Z'),
};

const select = xpath.useNamespaces({
  soap: SOAP_ENVELOPE_NAMESPACE,
  wsa: WS_ADDRESSING_NAMESPACE,
  wsse: WS_SECURITY_SECEXT_NAMESPACE,
  samlp: SAML_PROTOCOL_NAMESPACE,
  saml: SAML_ASSERTION_NAMESPACE,
});

/** Builds an envelope from `overrides` and parses it back for querying. */
function envelope(overrides: Partial<Rve1bRequestInput> = {}): Document {
  const bytes = buildRve1bRequest(rve1bRequest({ ...VALID, ...overrides }));
  const xml = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document;
}

/** The text content of the single node `expression` selects, or `undefined`. */
function text(document: Document, expression: string): string | undefined {
  const nodes = select(expression, document) as Node[];
  expect(nodes.length).toBeLessThanOrEqual(1);
  return nodes[0]?.textContent ?? undefined;
}

/** How many nodes `expression` selects. */
function count(document: Document, expression: string): number {
  return (select(expression, document) as Node[]).length;
}

/** The value of the named attribute of the single `Attribute` element for `name`. */
function attributeValues(document: Document, name: string): string[] {
  const nodes = select(
    `//samlp:Extensions/saml:AttributeStatement/saml:Attribute[@Name="${name}"]/saml:AttributeValue`,
    document,
  ) as Node[];
  return nodes.map((node) => node.textContent ?? '');
}

describe('the envelope', () => {
  it('is bytes rather than a string', () => {
    const bytes = buildRve1bRequest(rve1bRequest(VALID));
    expect(bytes).toBeInstanceOf(Uint8Array);
  });

  it('is UTF-8 and declares itself so', () => {
    const bytes = buildRve1bRequest(rve1bRequest(VALID));
    const xml = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
  });

  it('encodes a non-ASCII username as UTF-8 rather than truncating it', () => {
    const bytes = buildRve1bRequest(
      rve1bRequest({ ...VALID, username: { form: 'plaintext', value: 'niccolò' } }),
    );
    const xml = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    expect(xml).toContain('niccolò');
  });

  it('is a SOAP 1.2 envelope', () => {
    expect(count(envelope(), '/soap:Envelope')).toBe(1);
  });
});

describe('the addressing header', () => {
  it('carries exactly the three WS-Addressing elements §4.2.5.2 names', () => {
    const document = envelope();
    expect(count(document, '/soap:Envelope/soap:Header/wsa:*')).toBe(3);
    expect(text(document, '//wsa:Action')).toBe('urn:rve:AuthenticateAndGetAssertionRequest-b');
    expect(text(document, '//wsa:MessageID')).toBe(MESSAGE_ID);
    expect(text(document, '//wsa:To')).toBe('https://iap.ulssx.veneto.it/ws');
  });

  it('emits no reply-to element, which §4.2.5.2 does not name', () => {
    // Q-006 in docs/spec-questions.md.
    expect(count(envelope(), '//wsa:ReplyTo')).toBe(0);
  });
});

describe('the security header', () => {
  it('carries a username element', () => {
    expect(text(envelope(), '//wsse:Security/wsse:UsernameToken/wsse:Username')).toBe(
      'a-directory-server-username',
    );
  });

  it.each([
    ['a plaintext username', { username: { form: 'plaintext', value: 'pippo' } } as const],
    ['an encrypted username', { username: { form: 'encrypted', ciphertext: 'q1w2e3==' } } as const],
  ])('emits no password element for %s', (_case, overrides) => {
    const document = envelope(overrides);
    expect(count(document, '//wsse:Password')).toBe(0);
    expect(count(document, '//*[local-name()="Password"]')).toBe(0);
  });

  it('carries only the username element inside the token', () => {
    expect(count(envelope(), '//wsse:UsernameToken/*')).toBe(1);
  });

  it('leaves a plaintext username unmarked', () => {
    expect(count(envelope(), '//wsse:Username/@type')).toBe(0);
  });

  it('signals an encrypted username with the attribute, carrying the ciphertext as its text', () => {
    const document = envelope({ username: { form: 'encrypted', ciphertext: 'q1w2e3==' } });
    expect(text(document, '//wsse:Username/@type')).toBe('encrypted');
    expect(text(document, '//wsse:Username')).toBe('q1w2e3==');
  });
});

describe('the AuthnRequest element', () => {
  it('carries the three mandatory attributes', () => {
    const document = envelope();
    expect(text(document, '//samlp:AuthnRequest/@ID')).toBe(
      'msgId_9376254e-da05-41f5-9af3-ac56d63d8ebd',
    );
    expect(text(document, '//samlp:AuthnRequest/@Version')).toBe('2.0');
    expect(text(document, '//samlp:AuthnRequest/@IssueInstant')).toBe('2026-08-21T09:00:00Z');
  });

  it('carries an identifier equal to the derivation applied to its own message ID', () => {
    const document = envelope();
    const messageId = text(document, '//wsa:MessageID');
    expect(messageId).toBeDefined();
    expect(text(document, '//samlp:AuthnRequest/@ID')).toBe(deriveRequestId(messageId as string));
  });

  it.each(['saml:Issuer', 'saml:Subject'])('emits no %s element', (element) => {
    // Q-006 in docs/spec-questions.md.
    expect(count(envelope(), `//samlp:AuthnRequest/${element}`)).toBe(0);
  });

  it('emits no Destination attribute', () => {
    // Q-006 in docs/spec-questions.md.
    expect(count(envelope(), '//samlp:AuthnRequest/@Destination')).toBe(0);
  });

  it('places the conditions element after the extensions element', () => {
    const children = select('//samlp:AuthnRequest/*', envelope()) as Element[];
    expect(children.map((child) => child.localName)).toEqual(['Extensions', 'Conditions']);
  });
});

describe('the request attributes', () => {
  it('sit in an attribute statement inside the extensions element', () => {
    const document = envelope();
    expect(count(document, '/soap:Envelope/soap:Body/samlp:AuthnRequest/samlp:Extensions')).toBe(1);
    expect(count(document, '//samlp:Extensions/saml:AttributeStatement')).toBe(1);
    expect(count(document, '//samlp:Extensions/*')).toBe(1);
  });

  it('carry bare-string names and no name-format attribute', () => {
    const document = envelope();
    const names = (select('//saml:AttributeStatement/saml:Attribute/@Name', document) as Attr[]).map(
      (attribute) => attribute.value,
    );
    expect(names).toEqual(['UserClientAuthentication', 'ApplicationID', 'RequestContext']);
    expect(names.every((name) => !name.includes(':'))).toBe(true);
    expect(count(document, '//saml:Attribute/@NameFormat')).toBe(0);
  });

  it('pin the user client authentication code RVE-1.b declares', () => {
    expect(attributeValues(envelope(), 'UserClientAuthentication')).toEqual(['A.1.1']);
  });

  it('carry the ApplicationID exactly as supplied', () => {
    expect(attributeValues(envelope({ applicationId: 'product^1.4^install-7' }), 'ApplicationID')) //
      .toEqual(['product^1.4^install-7']);
  });

  it('carry the request context', () => {
    expect(attributeValues(envelope({ requestContext: 'C.7.10' }), 'RequestContext')).toEqual([
      'C.7.10',
    ]);
  });

  it('omit the patient identifier entirely rather than emitting an empty element', () => {
    const document = envelope();
    expect(count(document, '//saml:Attribute[@Name="PatientID"]')).toBe(0);
    expect(count(document, '//saml:AttributeValue[not(text())]')).toBe(0);
  });

  it('carry the patient identifier when there is one', () => {
    expect(attributeValues(envelope({ patientId: '7254395' }), 'PatientID')).toEqual(['7254395']);
  });

  const optionalAttributes: [string, Partial<Rve1bRequestInput>, string[]][] = [
    ['codOTP', { otpCode: '482915' }, ['482915']],
    ['authLevel', { authenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL }, ['urn:rve:authnL2']],
    ['codAziendaAuth', { authorisingOrganisations: ['090', '102'] }, ['090', '102']],
  ];

  it.each(optionalAttributes)('carry %s when supplied and omit it otherwise', (name, overrides, expected) => {
    expect(attributeValues(envelope(overrides), name)).toEqual(expected);
    expect(count(envelope(), `//saml:Attribute[@Name="${name}"]`)).toBe(0);
  });

  it('gives each authorising organisation its own value element', () => {
    // Q-007 in docs/spec-questions.md: the list encoding is not specified.
    const document = envelope({ authorisingOrganisations: ['090', '102'] });
    expect(count(document, '//saml:Attribute[@Name="codAziendaAuth"]')).toBe(1);
    expect(count(document, '//saml:Attribute[@Name="codAziendaAuth"]/saml:AttributeValue')).toBe(2);
  });
});

describe('the conditions element', () => {
  it('carries the requested window', () => {
    const document = envelope();
    expect(text(document, '//saml:Conditions/@NotBefore')).toBe('2026-08-21T09:00:00Z');
    expect(text(document, '//saml:Conditions/@NotOnOrAfter')).toBe('2026-08-21T13:00:00Z');
  });

  it('omits the audience restriction entirely rather than emitting an empty one', () => {
    const document = envelope();
    expect(count(document, '//saml:AudienceRestriction')).toBe(0);
    expect(count(document, '//saml:Conditions/*')).toBe(0);
  });

  it('omits the audience restriction for an empty list too', () => {
    expect(count(envelope({ audiences: [] }), '//saml:AudienceRestriction')).toBe(0);
  });

  it('carries one audience element per audience, in one restriction', () => {
    const document = envelope({
      audiences: [
        'https://sar.regione.veneto.it/demVisualizzaErogatoCUP',
        'https://fser.regione.veneto.it/Registry',
      ],
    });
    expect(count(document, '//saml:Conditions/saml:AudienceRestriction')).toBe(1);
    expect(
      (select('//saml:AudienceRestriction/saml:Audience', document) as Node[]).map(
        (node) => node.textContent,
      ),
    ).toEqual([
      'https://sar.regione.veneto.it/demVisualizzaErogatoCUP',
      'https://fser.regione.veneto.it/Registry',
    ]);
  });
});

describe('the namespace layout', () => {
  it('emits the attribute statement and the conditions in the default SAML namespace, and prefixes the rest', () => {
    // Pinned because it is the one place §4.2.5.2's example departs from the
    // prefixing it uses everywhere else, and an IAP matching on qualified names
    // would not notice the difference while a reader diffing against the
    // published example would.
    const xml = new TextDecoder().decode(buildRve1bRequest(rve1bRequest(VALID)));
    expect(xml).toContain(`<AttributeStatement xmlns="${SAML_ASSERTION_NAMESPACE}">`);
    expect(xml).toContain(`<Conditions xmlns="${SAML_ASSERTION_NAMESPACE}"`);
    expect(xml).toContain('<samlp:AuthnRequest');
    expect(xml).toContain('<samlp:Extensions>');
    expect(xml).toContain('<soap:Envelope');
    expect(xml).toContain('<wsa:Action>');
    expect(xml).toContain('<wsse:Security>');
  });

  it('leaves the attributes and values unprefixed, inheriting the default namespace', () => {
    const xml = new TextDecoder().decode(buildRve1bRequest(rve1bRequest(VALID)));
    expect(xml).toContain('<Attribute Name="UserClientAuthentication">');
    expect(xml).toContain('<AttributeValue>A.1.1</AttributeValue>');
  });

  it('declares each prefix once, on the element §4.2.5.2 declares it on', () => {
    const xml = new TextDecoder().decode(buildRve1bRequest(rve1bRequest(VALID)));
    for (const declaration of [
      `xmlns:soap="${SOAP_ENVELOPE_NAMESPACE}"`,
      `xmlns:wsa="${WS_ADDRESSING_NAMESPACE}"`,
      `xmlns:wsse="${WS_SECURITY_SECEXT_NAMESPACE}"`,
      `xmlns:samlp="${SAML_PROTOCOL_NAMESPACE}"`,
    ]) {
      expect(xml.split(declaration).length - 1).toBe(1);
    }
  });
});

describe('the serialised form', () => {
  it('is indented, so a captured envelope can be read by the person diagnosing it', () => {
    // Not cosmetic. The envelope is what a support engineer is handed when the
    // IAP refuses one, and a single-line SOAP envelope is read by nobody.
    const xml = new TextDecoder().decode(buildRve1bRequest(rve1bRequest(VALID)));

    expect(xml).toMatch(/\n\s+<wsa:MessageID>/);
  });
});
