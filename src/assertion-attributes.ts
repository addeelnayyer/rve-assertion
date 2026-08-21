/**
 * The assertion's attribute statement — §4.1.6.2.2.
 *
 * §4.1.6.2.2 puts the information an X-Service Provider weighs in a
 * `saml:AttributeStatement`: some attributes inherited from the request, some
 * added by the Identity and Assertion Provider from its own directory. This
 * module turns that statement into something a check can ask questions of, and
 * does nothing else — whether a given attribute had to be there is the calling
 * service's policy to say, and it is said in `src/assertion.ts`.
 *
 * ## Every value, not the first
 *
 * An attribute is read as the list of values carried under its name, across
 * every attribute statement the assertion carries. Nothing here collapses that
 * list, because collapsing is the vulnerability: an assertion naming two
 * responsible parties must not read as naming whichever one a reader happens to
 * reach first. The identity cross-check holds *every* value it is given against
 * the subject, so a second value is a mismatch rather than a value ignored.
 *
 * SAML permits more than one attribute statement, and permits an attribute to
 * carry more than one value, so both are collected rather than refused. The
 * specification's own `codAziendaAuth` is a list (`docs/spec-questions.md`,
 * Q-007), so a multi-valued attribute is not by itself suspicious.
 *
 * ## Present means carrying a value
 *
 * An attribute with no value element, or whose values are all whitespace, is
 * not reported at all. A policy asking for an attribute is asking for something
 * to be in it; an empty one that satisfied the ask would be the easiest way
 * past a presence check there is.
 */

import type { Element } from '@xmldom/xmldom';

import { samlChildren, text } from './saml-dom.js';

/** The element §4.1.6.2.2 puts the assertion's attributes in. */
const ATTRIBUTE_STATEMENT_ELEMENT = 'AttributeStatement';

/** The element naming one attribute — §4.1.6.2.2. */
const ATTRIBUTE_ELEMENT = 'Attribute';

/** The element carrying one value of an attribute — §4.1.6.2.2. */
const ATTRIBUTE_VALUE_ELEMENT = 'AttributeValue';

/** The attribute that names an attribute. Unprefixed, as §4.1.6.2.2 writes it. */
const NAME_ATTRIBUTE = 'Name';

/**
 * The attribute names §4.1.6.2.2 defines for the identity assertion.
 *
 * Named so a service policy can ask for an attribute without spelling it, since
 * these are wire names with an irregular casing the specification chose and a
 * misspelling would silently mean *this attribute is never present*. The
 * strings are the specification's, exactly — the Italian names and the mixed
 * casing included.
 *
 * **Not a closed vocabulary.** §4.2.5.2 says regional projects may provide for
 * further parameters and defers their definition to RVE-1.d, which this excerpt
 * does not contain. A policy is therefore free to name an attribute that is not
 * here, and this module reads whatever it finds; these are the names it did not
 * want a caller retyping.
 */
export const ASSERTION_ATTRIBUTES = {
  // Inherited from the request — §4.1.6.2.2.
  APPLICATION_ID: 'ApplicationID',
  PATIENT_ID: 'PatientID',
  WARD_CODE: 'codReparto',
  REQUEST_CONTEXT: 'RequestContext',
  USER_CLIENT_AUTHENTICATION: 'UserClientAuthentication',

  // Added by the Identity and Assertion Provider — §4.1.6.2.2.
  ROLE: 'Role',
  RESPONSIBLE_PARTY: 'ResponsibleParty',
  FACILITY_CODE: 'codStruttura',
  USER_GRANTS: 'UserGrants',
  OTP_CODE: 'codOTP',
  OTP_VERIFICATION_CODE: 'codVerifica',
  AUTHORISING_ORGANISATIONS: 'codAziendaAuth',
  EMAIL: 'email',
  AUTHENTICATION_LEVEL: 'authLevel',
} as const;

/**
 * The attributes an assertion carries, by the name it gives each one.
 *
 * A name is present only when at least one non-blank value was found under it,
 * so `has` answers the question a presence check is asking. Values keep
 * document order, and the list is never empty.
 */
export type AssertionAttributes = ReadonlyMap<string, readonly string[]>;

/**
 * Reads the attribute statement of `assertion`.
 *
 * Walks `Assertion > AttributeStatement > Attribute > AttributeValue` a direct
 * child at a time. An attribute reached by descending through an element
 * §4.1.6.2.2 does not put on that path belongs to some other document that
 * happens to be inside this one, and is not this assertion's to report.
 *
 * Reads only, and returns only strings: the caller's bytes and the parsed tree
 * are both left as they were.
 */
export function readAssertionAttributes(assertion: Element): AssertionAttributes {
  const attributes = new Map<string, string[]>();

  for (const statement of samlChildren(assertion, ATTRIBUTE_STATEMENT_ELEMENT)) {
    for (const attribute of samlChildren(statement, ATTRIBUTE_ELEMENT)) {
      // Blank counts as absent, as it does everywhere else this library reads
      // an attribute: a name of no characters names nothing, and a policy
      // cannot ask for it.
      const name = attribute.getAttribute(NAME_ATTRIBUTE)?.trim();
      if (name === undefined || name.length === 0) {
        continue;
      }

      const values = samlChildren(attribute, ATTRIBUTE_VALUE_ELEMENT)
        .map((value) => text(value))
        .filter((value): value is string => value !== undefined);
      if (values.length === 0) {
        continue;
      }

      const collected = attributes.get(name);
      if (collected === undefined) {
        attributes.set(name, values);
      } else {
        collected.push(...values);
      }
    }
  }

  return attributes;
}
