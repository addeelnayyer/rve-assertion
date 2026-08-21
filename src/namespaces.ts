/**
 * The XML namespaces an RVE-1.b exchange is written in.
 *
 * Exported rather than kept private because a caller that wants to inspect a
 * built envelope — a test, a diagnostic dump, an XPath in a support script —
 * needs the same URIs the builder used, and re-typing them is how a namespace
 * mismatch gets introduced.
 *
 * The prefixes below are the ones §4.2.5.2's worked example uses. Prefixes
 * carry no meaning in XML, but matching the example is what lets a reader hold
 * the document and the output side by side, so the builder pins them.
 */

/** SOAP 1.2 — §4.2.5.2 names the schema this URI identifies. */
export const SOAP_ENVELOPE_NAMESPACE = 'http://www.w3.org/2003/05/soap-envelope';

/** WS-Addressing 1.0 SOAP Binding — §4.2.5.2, prefix `wsa`. */
export const WS_ADDRESSING_NAMESPACE = 'http://www.w3.org/2005/08/addressing';

/**
 * WS-Security SOAP Message Security, the `secext` schema — prefix `wsse`.
 *
 * §4.2.5.2's prose cites version 1.1.1 of the standard while its example
 * declares the 2004/01 namespace. Those agree: 1.1 keeps this namespace for the
 * elements 1.0 defined — `Security`, `UsernameToken`, `Username` — and adds a
 * separate `wsse11` namespace only for what it introduced. This library emits
 * none of the latter, so the example's namespace is the correct one.
 */
export const WS_SECURITY_SECEXT_NAMESPACE =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

/** SAML 2.0 protocol — §4.2.5.2, prefix `samlp`. */
export const SAML_PROTOCOL_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:protocol';

/** SAML 2.0 assertion — §4.2.5.2, the default namespace in its example. */
export const SAML_ASSERTION_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

/**
 * XML Signature — §4.1.6.2.2, prefix `ds`.
 *
 * On the validation side rather than the request side: this library builds no
 * signature and this namespace never appears in an envelope it emits. It is
 * here because the assertion validator reads the signature by namespace, and
 * because a caller writing an XPath against a received assertion needs the same
 * URI the validator used.
 */
export const XML_SIGNATURE_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#';
