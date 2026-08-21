/**
 * The RVE-1.b request on the wire — §4.2.5.2.
 *
 * Serialisation only. Everything this module emits comes from an
 * {@link Rve1bRequest}, which cannot exist without having had its invariants
 * checked, so {@link buildRve1bRequest} has no failure mode and declares none.
 *
 * The output is deliberately close to §4.2.5.2's worked example — same
 * prefixes, same namespace declarations on the same elements, same element
 * order — so that the two can be read side by side. Where the example and the
 * prose disagree, or where the example shows something no rule requires, the
 * choice is argued in `docs/spec-questions.md` rather than left as a silent
 * resemblance.
 */

import { create } from 'xmlbuilder2';
import type { XMLBuilder } from 'xmlbuilder2/lib/interfaces.js';

import {
  SAML_ASSERTION_NAMESPACE,
  SAML_PROTOCOL_NAMESPACE,
  SOAP_ENVELOPE_NAMESPACE,
  WS_ADDRESSING_NAMESPACE,
  WS_SECURITY_SECEXT_NAMESPACE,
} from './namespaces.js';
import { RVE_1B_ACTION, type Rve1bRequest } from './request.js';

/** The namespace an `xmlns:`-prefixed declaration attribute itself lives in. */
const XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/';

/** SAML 2.0 protocol version, fixed for every message of this family. */
const SAML_VERSION = '2.0';

/**
 * Marks a `wsse:Username` as carrying ciphertext — §4.2.5.2.
 *
 * Unprefixed: the specification writes the rule in XPath as
 * `wsse:Username/@type`, which qualifies the element and leaves the attribute
 * in no namespace, and its worked handling in §4.2.5.3 reads it back the same
 * way. An unprefixed attribute is also the SAML and WS-Security norm.
 */
const ENCRYPTED_USERNAME_TYPE = 'encrypted';

/**
 * Appends one `Attribute` element, or nothing when there are no values.
 *
 * Taking the values as an array is what keeps the omission rule in one place:
 * an attribute the caller did not supply and an attribute whose list is empty
 * are the same thing on the wire, which is nothing at all rather than an
 * element with no content.
 */
function appendAttribute(statement: XMLBuilder, name: string, values: readonly string[]): void {
  if (values.length === 0) {
    return;
  }

  const attribute = statement.ele(SAML_ASSERTION_NAMESPACE, 'Attribute').att('Name', name);
  for (const value of values) {
    attribute.ele(SAML_ASSERTION_NAMESPACE, 'AttributeValue').txt(value);
  }
}

/** The values for an attribute that is either absent or carries exactly one. */
function optional(value: string | undefined): readonly string[] {
  return value === undefined ? [] : [value];
}

/**
 * Serialises `request` as the UTF-8 bytes of an RVE-1.b request envelope.
 *
 * Bytes rather than a string because the envelope declares its own encoding,
 * and a string does not carry one: handing the caller a string moves the
 * decision about how to encode it to whatever writes it to the socket, which is
 * exactly where a mismatch between the declaration and the octets gets
 * introduced. A non-ASCII username is the case that finds it.
 */
export function buildRve1bRequest(request: Rve1bRequest): Uint8Array {
  const envelope = create({ version: '1.0', encoding: 'UTF-8' }).ele(
    SOAP_ENVELOPE_NAMESPACE,
    'soap:Envelope',
  );

  // The prefix declarations are hoisted onto Header and Body so that the output
  // matches where §4.2.5.2's example declares them. Without this, xmlbuilder2
  // would repeat each declaration on every element that uses it — equivalent
  // XML, but not a document a reader can diff against the published one.
  const header = envelope
    .ele(SOAP_ENVELOPE_NAMESPACE, 'soap:Header')
    .att(XMLNS_NAMESPACE, 'xmlns:wsa', WS_ADDRESSING_NAMESPACE)
    .att(XMLNS_NAMESPACE, 'xmlns:wsse', WS_SECURITY_SECEXT_NAMESPACE);

  // Exactly the three elements §4.2.5.2 names, in the order its example gives
  // them. No wsa:ReplyTo and no wsa:From — see Q-006.
  header.ele(WS_ADDRESSING_NAMESPACE, 'wsa:Action').txt(RVE_1B_ACTION);
  header.ele(WS_ADDRESSING_NAMESPACE, 'wsa:MessageID').txt(request.messageId);
  header.ele(WS_ADDRESSING_NAMESPACE, 'wsa:To').txt(request.recipient);

  // "MUST contain only the <wsse:Username> element" — so no wsse:Password, no
  // wsu:Created, no nonce, whatever the username form.
  const username = header
    .ele(WS_SECURITY_SECEXT_NAMESPACE, 'wsse:Security')
    .ele(WS_SECURITY_SECEXT_NAMESPACE, 'wsse:UsernameToken')
    .ele(WS_SECURITY_SECEXT_NAMESPACE, 'wsse:Username');
  if (request.username.form === 'encrypted') {
    username.att('type', ENCRYPTED_USERNAME_TYPE).txt(request.username.ciphertext);
  } else {
    username.txt(request.username.value);
  }

  const authnRequest = envelope
    .ele(SOAP_ENVELOPE_NAMESPACE, 'soap:Body')
    .att(XMLNS_NAMESPACE, 'xmlns:samlp', SAML_PROTOCOL_NAMESPACE)
    .ele(SAML_PROTOCOL_NAMESPACE, 'samlp:AuthnRequest')
    .att('ID', request.requestId)
    .att('Version', SAML_VERSION)
    .att('IssueInstant', request.issueInstant);

  // The attribute statement and the conditions are emitted in the default SAML
  // namespace, unprefixed, because that is what §4.2.5.2's example does. It is
  // namespace-equivalent to prefixing them and pinned by a test anyway.
  const statement = authnRequest
    .ele(SAML_PROTOCOL_NAMESPACE, 'samlp:Extensions')
    .ele(SAML_ASSERTION_NAMESPACE, 'AttributeStatement');

  // Attribute order follows the worked example for the attributes it shows, and
  // §4.2.5.2's own listing order for the rest. Order carries no meaning in a
  // SAML AttributeStatement; matching the example is a reader's convenience.
  //
  // Names are bare strings with no NameFormat, again as the example has them.
  // SAML 2.0 defaults an absent NameFormat to `unspecified`, which is what a
  // bare regional name is, so adding one would assert more than is known.
  appendAttribute(statement, 'UserClientAuthentication', [request.userClientAuthentication]);
  appendAttribute(statement, 'ApplicationID', [request.applicationId]);
  appendAttribute(statement, 'PatientID', optional(request.patientId));
  appendAttribute(statement, 'RequestContext', [request.requestContext]);
  appendAttribute(statement, 'codOTP', optional(request.otpCode));
  appendAttribute(statement, 'codAziendaAuth', request.authorisingOrganisations);
  appendAttribute(statement, 'authLevel', optional(request.authenticationLevel));

  const conditions = authnRequest
    .ele(SAML_ASSERTION_NAMESPACE, 'Conditions')
    .att('NotBefore', request.notBefore)
    .att('NotOnOrAfter', request.notOnOrAfter);

  if (request.audiences.length > 0) {
    const restriction = conditions.ele(SAML_ASSERTION_NAMESPACE, 'AudienceRestriction');
    for (const audience of request.audiences) {
      restriction.ele(SAML_ASSERTION_NAMESPACE, 'Audience').txt(audience);
    }
  }

  return new TextEncoder().encode(envelope.end({ prettyPrint: true }));
}
