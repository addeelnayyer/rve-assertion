/**
 * The XML reading this library does against a received document.
 *
 * Two helpers, shared by the assertion's structural phase and by the signature
 * phase rather than written twice, because both phases have to read the same
 * way to be talking about the same document.
 *
 * Reading is by namespace and local name throughout, never by prefix. A prefix
 * is a local abbreviation the sender chose — an IAP is free to write
 * `<dsig:Signature>` or to make the signature namespace the default one — and a
 * check that matched on the prefix would refuse conforming documents and, worse,
 * could be steered by a document that declared a prefix to mean something else.
 */

import type { Element } from '@xmldom/xmldom';

/** `Node.ELEMENT_NODE`, named rather than written as a bare 1. */
const ELEMENT_NODE = 1;

/**
 * The direct children of `element` with this namespace and local name.
 *
 * Direct children only. Every cardinality this library insists on — one
 * `Conditions`, one `Signature`, one `Reference` — is a statement about what an
 * element carries itself, and a descendant search would let a nested document
 * satisfy a check about its container.
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

/**
 * The one child of `element` with this namespace and local name, or `undefined`
 * when it carries none or more than one.
 *
 * "More than one" collapsing into the same answer as "none" is deliberate. Both
 * leave the caller without a single element to read, and a check that picked
 * the first of several would be choosing on the document's behalf — which is
 * what a document written to be read two ways relies on.
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
 * The value of `name` on `element`, or `undefined` when it is absent.
 *
 * A blank value counts as absent. An `ID=""` is not an identifier the signature
 * reference can be bound to, and an empty `NotOnOrAfter` is not a time — so
 * treating the two cases alike costs a caller nothing and saves every check
 * downstream from having to ask twice.
 */
export function attribute(element: Element, name: string): string | undefined {
  const value = element.getAttribute(name);
  return value === null || value.trim().length === 0 ? undefined : value;
}

/** The text `element` carries directly, or `undefined` when it carries none. */
export function textContent(element: Element): string | undefined {
  const text = element.textContent;
  return text === null || text.trim().length === 0 ? undefined : text;
}
