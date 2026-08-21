import { describe, expect, it } from 'vitest';

import * as publicSurface from './index.js';

/**
 * The published surface, pinned.
 *
 * Types are not observable at runtime, so this pins the values: the two
 * functions, the smart constructors, the constants a caller would otherwise
 * hardcode, the advisory predicates, and the two error classes. A name added
 * here is a name callers may depend on, and a name removed here breaks them —
 * so the set is asserted whole rather than one membership at a time, which
 * catches an accidental export as well as a missing one.
 */
const PUBLISHED = [
  'ASSERTION_ATTRIBUTES',
  'BASELINE_SERVICE_POLICY',
  'NO_SIGNATURE_VERIFICATION',
  'RECOMMENDED_CLOCK_SKEW_MS',
  'RECOMMENDED_FLIGHT_TIME_MS',
  'REGIONAL_ERROR_CODES',
  'REQUEST_CONTEXTS',
  'RVE_1B_ACTION',
  'RVE_1B_USER_CLIENT_AUTHENTICATION',
  'SAML_ASSERTION_NAMESPACE',
  'SAML_PROTOCOL_NAMESPACE',
  'SOAP_ENVELOPE_NAMESPACE',
  'TWO_FACTOR_AUTHENTICATION_LEVEL',
  'WS_ADDRESSING_NAMESPACE',
  'WS_SECURITY_SECEXT_NAMESPACE',
  'XML_SIGNATURE_NAMESPACE',
  'RequestInputError',
  'ValidationInputError',
  'applicationIdShape',
  'buildRve1bRequest',
  'deriveMessageId',
  'deriveRemedy',
  'deriveRequestId',
  'isRequestContext',
  'rve1bRequest',
  'servicePolicy',
  'validateAssertion',
] as const;

describe('the published surface', () => {
  it('exports exactly the names it means to, and no more', () => {
    expect(Object.keys(publicSurface).sort()).toEqual([...PUBLISHED].sort());
  });

  it('exports the two functions the library is', () => {
    expect(typeof publicSurface.buildRve1bRequest).toBe('function');
    expect(typeof publicSurface.validateAssertion).toBe('function');
  });

  it('exports the margins as recommendations a caller applies, not defaults it inherits', () => {
    expect(publicSurface.RECOMMENDED_CLOCK_SKEW_MS).toBeTypeOf('number');
    expect(publicSurface.RECOMMENDED_FLIGHT_TIME_MS).toBeTypeOf('number');
  });

  it('exports the advisory predicates, which report rather than refuse', () => {
    expect(publicSurface.isRequestContext('not a code')).toBe(false);
    expect(publicSurface.applicationIdShape('not an ApplicationID')).toBeTypeOf('string');
  });
});
