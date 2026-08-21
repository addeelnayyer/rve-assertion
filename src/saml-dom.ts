/**
 * The handful of DOM reads the assertion validator does, in one place.
 *
 * Nothing here is SAML-specific beyond the namespace it filters on: these are
 * the two questions every phase of the validator asks a parsed document —
 * *which children of this element are the element I mean*, and *what does this
 * attribute say* — and they are shared rather than duplicated because two
 * modules asking them differently is how a namespace check quietly stops being
 * a namespace check.
 *
 * The SAML-named pair are the common case and read as one call; the signature
 * phase reads `ds:` elements through the same walk with its own namespace,
 * rather than through a second walk written to a different standard of care.
 *
 * Reads only. Nothing here constructs, mutates or serialises a node: §4.6
 * requires the assertion be spent exactly as the Identity and Assertion
 * Provider returned it, and the parsed tree exists to be interrogated and
 * discarded.
 */

import type { Element } from '@xmldom/xmldom';

import { SAML_ASSERTION_NAMESPACE } from './namespaces.js';

/** `Node.ELEMENT_NODE`, named rather than written as a bare 1. */
const ELEMENT_NODE = 1;

/** `Node.TEXT_NODE`, named rather than written as a bare 3. */
const TEXT_NODE = 3;

/** `Node.CDATA_SECTION_NODE`, named rather than written as a bare 4. */
const CDATA_SECTION_NODE = 4;

/**
 * The direct children of `element` that are SAML elements with this local name.
 *
 * Direct children rather than descendants, everywhere, deliberately. A search
 * that reaches down the whole subtree will happily find an element belonging to
 * some other assertion nested inside this one, which is the shape a signature
 * wrapping attack takes; a step-by-step walk down the path §4.1.6.2.2 describes
 * cannot.
 *
 * Matched by namespace and local name, never by tag name. Prefixes carry no
 * meaning in XML, so a document is free to bind `saml:` to something else and
 * the real assertion namespace to a prefix of its choosing.
 */
export function childElements(
  element: Element,
  namespaceURI: string,
  localName: string,
): readonly Element[] {
  const children: Element[] = [];
  for (const node of Array.from(element.childNodes)) {
    if (node.nodeType !== ELEMENT_NODE) {
      continue;
    }
    const child = node as Element;
    if (child.namespaceURI === namespaceURI && child.localName === localName) {
      children.push(child);
    }
  }
  return children;
}

/** {@link childElements}, for the SAML assertion namespace. */
export function samlChildren(element: Element, localName: string): readonly Element[] {
  return childElements(element, SAML_ASSERTION_NAMESPACE, localName);
}

/**
 * The one direct child of `element` with this namespace and local name, or
 * `undefined` when there is not exactly one.
 */
export function onlyChild(
  element: Element,
  namespaceURI: string,
  localName: string,
): Element | undefined {
  const children = childElements(element, namespaceURI, localName);
  return children.length === 1 ? children[0] : undefined;
}

/**
 * The one direct SAML child of `element` with this local name, or `undefined`
 * when there is not exactly one.
 *
 * Exactly one, not the first of several. Where the specification says an
 * element is there, a second one is a second answer to a question that has one
 * answer — and a document offering two answers is a document relying on two
 * readers picking differently.
 */
export function onlySamlChild(element: Element, localName: string): Element | undefined {
  return onlyChild(element, SAML_ASSERTION_NAMESPACE, localName);
}

/**
 * The value of the `name` attribute on `element`, or `undefined` when it is
 * absent.
 *
 * A blank value counts as absent. An `ID=""` is not an identifier the signature
 * reference can be bound to, and an empty `NotOnOrAfter` is not a time — so
 * treating the two cases alike costs a caller nothing and saves every check
 * downstream from having to ask twice.
 *
 * The value is returned as written, not trimmed. Whitespace inside an
 * identifier is part of it as far as this library is concerned, because it is
 * part of what the region signed.
 */
export function attribute(element: Element, name: string): string | undefined {
  const value = element.getAttribute(name);
  return value === null || value.trim().length === 0 ? undefined : value;
}

/**
 * The text `element` contains, trimmed, or `undefined` when it contains none.
 *
 * An element carrying any child element has no text value at all here, rather
 * than the concatenation of the text around its children. Concatenating is how
 * `<saml:Audience><x>http://</x>evil</saml:Audience>` becomes a URL, and how a
 * document reads one way to a validator that walks it and another to a reader
 * that does not.
 *
 * Trimmed, because the surrounding whitespace in an indented document is the
 * serialiser's and not the value's. Comparing an identifier against one
 * carrying a stray newline would refuse an assertion for how it was formatted.
 */
export function text(element: Element): string | undefined {
  let collected = '';
  for (const node of Array.from(element.childNodes)) {
    if (node.nodeType === ELEMENT_NODE) {
      return undefined;
    }
    if (node.nodeType === TEXT_NODE || node.nodeType === CDATA_SECTION_NODE) {
      collected += node.nodeValue ?? '';
    }
  }
  const trimmed = collected.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}
