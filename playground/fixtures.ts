/**
 * The fixtures the playground feeds the library: a worked RVE-1.b request, and
 * an assertion XML builder with a knob for every way the page breaks one.
 *
 * The assertion is the one `src/assertion.test.ts` builds — issued at 09:00Z,
 * usable 09:00–13:00Z, scoped to the patient registry — and its signature is
 * structural only. No key signs it, so a success without a verifier always
 * carries `signature-not-cryptographically-verified`.
 */

import {
  ASSERTION_ATTRIBUTES,
  SAML_ASSERTION_NAMESPACE,
  TWO_FACTOR_AUTHENTICATION_LEVEL,
  XML_SIGNATURE_NAMESPACE,
  type Rve1bRequestInput,
} from '../src/index.js';

export const SERVICE = 'https://fser.regione.veneto.it/Registry';
export const OTHER_SERVICE = 'https://some-other-service.veneto.it/Prescriptions';
export const OPERATOR = 'RSSMRA80A01H501U';
export const OTHER_OPERATOR = 'VRDLGI75B02F205X';
export const MESSAGE_ID = 'urn:uuid:9376254e-da05-41f5-9af3-ac56d63d8ebd';
export const APPLICATION_ID = '2.16.840.1.113883.2.9.2.50999';
export const L1 = 'urn:rve:authnL1';
export const L2 = TWO_FACTOR_AUTHENTICATION_LEVEL;
export const L3 = 'urn:rve:authnL3';

/** The instant the page judges everything at unless a control moves it. */
export const NOW = new Date('2026-09-10T10:00:00Z');

const HOUR = 3_600_000;

const ASSERTION_ID = `assertion_${APPLICATION_ID}_msgId_9376254e-da05-41f5-9af3-ac56d63d8ebd`;

const ALGORITHM = {
  exclusiveC14n: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  rsaSha256: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  rsaSha1: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  dsaSha1: 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
  sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
} as const;

/** Every signature the page can put on an assertion. */
export type SignatureKind =
  | 'current'
  | 'deprecated'
  | 'rsa-sha1-only'
  | 'sha1-digest-only'
  | 'absent'
  | 'no-value'
  | 'unattested'
  | 'no-algorithm'
  | 'no-uri'
  | 'unbound'
  | 'double';

function signatureMethod(kind: SignatureKind): string {
  if (kind === 'no-algorithm') return '<ds:SignatureMethod/>';
  const algorithm =
    kind === 'deprecated' || kind === 'rsa-sha1-only'
      ? ALGORITHM.rsaSha1
      : kind === 'unattested'
        ? ALGORITHM.dsaSha1
        : ALGORITHM.rsaSha256;
  return `<ds:SignatureMethod Algorithm="${algorithm}"/>`;
}

function reference(kind: SignatureKind): string {
  const digest =
    kind === 'deprecated' || kind === 'sha1-digest-only' ? ALGORITHM.sha1 : ALGORITHM.sha256;
  const uri =
    kind === 'no-uri'
      ? ''
      : ` URI="#${kind === 'unbound' ? 'assertion_someone_elses_id' : ASSERTION_ID}"`;
  return (
    `<ds:Reference${uri}><ds:DigestMethod Algorithm="${digest}"/>` +
    '<ds:DigestValue>ZGlnZXN0</ds:DigestValue></ds:Reference>'
  );
}

export function signatureXml(kind: SignatureKind): string {
  if (kind === 'absent') return '';
  const value = kind === 'no-value' ? '' : '<ds:SignatureValue>c2lnbmF0dXJl</ds:SignatureValue>';
  const signature =
    `<ds:Signature xmlns:ds="${XML_SIGNATURE_NAMESPACE}"><ds:SignedInfo>` +
    `<ds:CanonicalizationMethod Algorithm="${ALGORITHM.exclusiveC14n}"/>` +
    signatureMethod(kind) +
    reference(kind) +
    `</ds:SignedInfo>${value}</ds:Signature>`;
  return kind === 'double' ? signature + signatureXml('current') : signature;
}

/** Everything about an assertion the page can change. */
export interface AssertionShape {
  /** Bytes to send instead of building an assertion at all. */
  readonly raw: string | null;
  readonly version: string;
  readonly doctype: boolean;
  readonly root: string;
  readonly notBefore: string;
  readonly notOnOrAfter: string;
  /** One inner list per `AudienceRestriction`. */
  readonly restrictions: readonly (readonly string[])[];
  /** One entry per `NameID` in the `Subject`. */
  readonly subject: readonly string[];
  /** `ResponsibleParty` values, or `null` to leave the attribute out. */
  readonly responsibleParty: readonly string[] | null;
  readonly role: string | null;
  readonly requestContext: string | null;
  /** `authLevel` values, or `null` to leave the attribute out. */
  readonly authLevel: readonly string[] | null;
  readonly signature: SignatureKind;
  /** Smuggle a second assertion into `Conditions/Advice`. */
  readonly advice: boolean;
}

export const ASSERTION_DEFAULTS: AssertionShape = {
  raw: null,
  version: '2.0',
  doctype: false,
  root: 'Assertion',
  notBefore: '2026-09-10T09:00:00Z',
  notOnOrAfter: '2026-09-10T13:00:00Z',
  restrictions: [[SERVICE]],
  subject: [OPERATOR],
  responsibleParty: [OPERATOR],
  role: 'R.1.1',
  requestContext: 'C.1.1',
  authLevel: [L2],
  signature: 'current',
  advice: false,
};

function attribute(name: string, values: readonly string[]): string {
  const inner = values.map((value) => `<saml:AttributeValue>${value}</saml:AttributeValue>`);
  return `<saml:Attribute Name="${name}">${inner.join('')}</saml:Attribute>`;
}

export function assertionXml(overrides: Partial<AssertionShape> = {}): string {
  const shape = { ...ASSERTION_DEFAULTS, ...overrides };
  if (shape.raw !== null) return shape.raw;

  const restrictions = shape.restrictions
    .map((audiences) => {
      const inner = audiences.map((audience) => `<saml:Audience>${audience}</saml:Audience>`);
      return `<saml:AudienceRestriction>${inner.join('')}</saml:AudienceRestriction>`;
    })
    .join('');
  const nameIds = shape.subject.map((nameId) => `<saml:NameID>${nameId}</saml:NameID>`).join('');
  const advice = shape.advice
    ? '<saml:Advice><saml:Assertion Version="2.0" ID="smuggled" IssueInstant="2026-09-10T09:00:00Z">' +
      '<saml:Issuer>https://attacker.example</saml:Issuer></saml:Assertion></saml:Advice>'
    : '';

  let attributes = '';
  if (shape.responsibleParty !== null) {
    attributes += attribute(ASSERTION_ATTRIBUTES.RESPONSIBLE_PARTY, shape.responsibleParty);
  }
  if (shape.role !== null) attributes += attribute(ASSERTION_ATTRIBUTES.ROLE, [shape.role]);
  if (shape.requestContext !== null) {
    attributes += attribute(ASSERTION_ATTRIBUTES.REQUEST_CONTEXT, [shape.requestContext]);
  }
  if (shape.authLevel !== null) {
    attributes += attribute(ASSERTION_ATTRIBUTES.AUTHENTICATION_LEVEL, shape.authLevel);
  }

  return (
    (shape.doctype ? '<!DOCTYPE saml:Assertion [<!ENTITY x "y">]>' : '') +
    `<saml:${shape.root} xmlns:saml="${SAML_ASSERTION_NAMESPACE}" Version="${shape.version}" ` +
    `ID="${ASSERTION_ID}" IssueInstant="2026-09-10T09:00:00Z">` +
    '<saml:Issuer>https://iap.ulssx.veneto.it</saml:Issuer>' +
    signatureXml(shape.signature) +
    `<saml:Subject>${nameIds}</saml:Subject>` +
    `<saml:Conditions NotBefore="${shape.notBefore}" NotOnOrAfter="${shape.notOnOrAfter}">` +
    `${restrictions}${advice}</saml:Conditions>` +
    `<saml:AttributeStatement>${attributes}</saml:AttributeStatement></saml:${shape.root}>`
  );
}

/** The worked RVE-1.b request: C.1.1, a four-hour window, one audience. */
export function requestInput(overrides: Partial<Rve1bRequestInput> = {}): Rve1bRequestInput {
  return {
    messageId: MESSAGE_ID,
    recipient: 'https://iap.example-aulss.veneto.it/ws',
    username: { form: 'plaintext', value: 'm.rossi' },
    applicationId: APPLICATION_ID,
    requestContext: 'C.1.1',
    issueInstant: NOW,
    notBefore: NOW,
    notOnOrAfter: new Date(NOW.getTime() + 4 * HOUR),
    audiences: [SERVICE],
    ...overrides,
  };
}

/**
 * Indents a one-line XML document for reading. Display only: the bytes the
 * library judged are the unindented ones.
 */
export function pretty(xml: string): string {
  if (xml === '' || xml.includes('\n') || !xml.startsWith('<')) return xml;

  const lines: string[] = [];
  let depth = 0;
  for (const line of xml.replace(/>\s*</g, '>\n<').split('\n')) {
    const closing = line.startsWith('</');
    const selfContained = /^<[^!?/][^>]*\/>$/.test(line) || /^<([\w:]+)[^>]*>.*<\/\1>$/.test(line);
    if (closing) depth = Math.max(0, depth - 1);
    lines.push('  '.repeat(depth) + line);
    if (!closing && !selfContained && !/^<[!?]/.test(line)) depth += 1;
  }
  return lines.join('\n');
}
