import { describe, expect, it } from 'vitest';

import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';

const codes = Object.values(REGIONAL_ERROR_CODES);

describe('REGIONAL_ERROR_CODES', () => {
  it('maps every name to a distinct code', () => {
    expect(new Set(codes).size).toBe(codes.length);
  });

  it.each(codes)('spells %s in the region’s ERR_ form', (code) => {
    expect(code).toMatch(/^ERR_\d{5}$/);
  });

  it('names every code the validator can annotate an assertion failure with', () => {
    // The checks the library performs locally, and the code the region would
    // report for each. Anything absent here is a failure the validator would
    // have to describe in its own words rather than the region's.
    expect({
      securityTokenAbsent: REGIONAL_ERROR_CODES.SECURITY_TOKEN_ABSENT,
      assertionTokenAbsent: REGIONAL_ERROR_CODES.ASSERTION_TOKEN_ABSENT,
      assertionTokenUnrecognisable: REGIONAL_ERROR_CODES.ASSERTION_TOKEN_UNRECOGNISABLE,
      assertionNotYetValid: REGIONAL_ERROR_CODES.ASSERTION_NOT_YET_VALID,
      assertionExpired: REGIONAL_ERROR_CODES.ASSERTION_EXPIRED,
      assertionValidityIntervalAgainstPolicy:
        REGIONAL_ERROR_CODES.ASSERTION_VALIDITY_INTERVAL_AGAINST_POLICY,
      requestContextNotPermitted: REGIONAL_ERROR_CODES.REQUEST_CONTEXT_NOT_PERMITTED,
      roleNotPermitted: REGIONAL_ERROR_CODES.ROLE_NOT_PERMITTED,
      userClientAuthenticationNotPermitted:
        REGIONAL_ERROR_CODES.USER_CLIENT_AUTHENTICATION_NOT_PERMITTED,
      audienceNotPermitted: REGIONAL_ERROR_CODES.AUDIENCE_NOT_PERMITTED,
      applicationIdNotPermitted: REGIONAL_ERROR_CODES.APPLICATION_ID_NOT_PERMITTED,
      assertionNotSigned: REGIONAL_ERROR_CODES.ASSERTION_NOT_SIGNED,
    }).toEqual({
      securityTokenAbsent: 'ERR_00021',
      assertionTokenAbsent: 'ERR_00022',
      assertionTokenUnrecognisable: 'ERR_00023',
      assertionNotYetValid: 'ERR_00031',
      assertionExpired: 'ERR_00032',
      assertionValidityIntervalAgainstPolicy: 'ERR_00033',
      requestContextNotPermitted: 'ERR_00041',
      roleNotPermitted: 'ERR_00042',
      userClientAuthenticationNotPermitted: 'ERR_00043',
      audienceNotPermitted: 'ERR_00044',
      applicationIdNotPermitted: 'ERR_00045',
      assertionNotSigned: 'ERR_00053',
    });
  });

  it('also names the codes that only ever arrive from the region', () => {
    // The library never raises these — they reach a caller on an inbound fault,
    // and naming them is what lets the caller branch on one without a literal.
    expect(REGIONAL_ERROR_CODES.SIGNATURE_PUBLIC_KEY_MISMATCH).toBe('ERR_00011');
    expect(REGIONAL_ERROR_CODES.PASSWORD_CHANGE_REQUIRED).toBe('ERR_00061');
    expect(REGIONAL_ERROR_CODES.TWO_FACTOR_AUTHENTICATION_REQUIRED).toBe('ERR_00065');
  });
});
