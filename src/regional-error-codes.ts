/**
 * The regional failure vocabulary — Appendix A.5, dialect `RVE:FSE`.
 *
 * These codes travel in two directions, and both matter.
 *
 * Inbound, a code arrives in the `wsrf-bf:ErrorCode` element of a SOAP fault
 * from an IAP or an X-Service Provider, and a caller that wants to branch on
 * one — retry, re-authenticate, prompt for an OTP — needs a name for it.
 *
 * Outbound, the assertion validator annotates its own local failures with the
 * code the region would have used, so that a support conversation about a
 * rejection this library made and one the region made can be conducted in the
 * same words. The library is not the X-Service Provider and cannot speak for
 * one; the annotation says *this is the reason the region names*, not *this is
 * what the region said*.
 *
 * The names below are this library's own. Appendix A.5's descriptions are not
 * reproduced, for the reason given in `src/vocabulary.ts`; the section and
 * table are cited instead.
 *
 * **Not a closed vocabulary.** Tables 9 and 10 end in an ellipsis in the
 * excerpt, so codes exist in those classes that the document in hand does not
 * list — and §4.2.5.3.1's worked fault and Figure 3 each carry a code
 * (`ERR_00010`, `ERR_00006`) that no table defines at all. An inbound code
 * absent from this module is therefore an unknown code, not an invalid one, and
 * must not be treated as evidence that a fault was malformed.
 */

/**
 * The codes of Appendix A.5, grouped by the WS-Security fault class the
 * specification files each under. The class is a property of the fault the code
 * travels in rather than of the code itself, so it is left in the grouping
 * rather than modelled — the validator can carry it when it has faults to
 * build.
 */
export const REGIONAL_ERROR_CODES = {
  // wsse:FailedCheck — Table 8. Cryptographic verification, which this library
  // does not perform, so these are inbound-only here.
  SIGNATURE_PUBLIC_KEY_MISMATCH: 'ERR_00011',
  SIGNATURE_MALFORMED: 'ERR_00012',
  PASSWORD_ENCRYPTED_WITH_WRONG_CERTIFICATE: 'ERR_00013',

  // wsse:SecurityTokenUnavailable — Table 9.
  SECURITY_TOKEN_ABSENT: 'ERR_00021',
  ASSERTION_TOKEN_ABSENT: 'ERR_00022',
  ASSERTION_TOKEN_UNRECOGNISABLE: 'ERR_00023',

  // wsse:MessageExpired — Table 10.
  ASSERTION_NOT_YET_VALID: 'ERR_00031',
  ASSERTION_EXPIRED: 'ERR_00032',
  ASSERTION_VALIDITY_INTERVAL_AGAINST_POLICY: 'ERR_00033',

  // wsse:InvalidSecurityToken — Table 11. One code per attribute an X-Service
  // Provider weighs, which is why the validator can annotate all five.
  REQUEST_CONTEXT_NOT_PERMITTED: 'ERR_00041',
  ROLE_NOT_PERMITTED: 'ERR_00042',
  USER_CLIENT_AUTHENTICATION_NOT_PERMITTED: 'ERR_00043',
  AUDIENCE_NOT_PERMITTED: 'ERR_00044',
  APPLICATION_ID_NOT_PERMITTED: 'ERR_00045',

  // wsse:FailedAuthentication — Table 12. Decided against the organisation's
  // directory, so inbound-only apart from the unsigned-assertion case, which is
  // structural and therefore checkable without a key.
  SIGNER_NOT_TRUSTED: 'ERR_00051',
  RESPONSIBLE_PARTY_OR_USER_NOT_PERMITTED: 'ERR_00052',
  ASSERTION_NOT_SIGNED: 'ERR_00053',
  PASSWORD_INCORRECT: 'ERR_00054',
  CLOCK_MISALIGNED: 'ERR_00055',
  PASSWORD_EXPIRED: 'ERR_00056',
  PASSWORD_AGAINST_POLICY: 'ERR_00057',
  REQUEST_PARAMETERS_AGAINST_POLICY: 'ERR_00058',
  RESPONSIBLE_PARTY_FISCAL_CODE_MISMATCH: 'ERR_00059',
  ROLE_MISSING_OR_INVALID_IN_DIRECTORY: 'ERR_00060',
  PASSWORD_CHANGE_REQUIRED: 'ERR_00061',
  OPERATOR_ACCOUNT_DISABLED: 'ERR_00062',
  USER_NOT_FOUND: 'ERR_00063',
  OTP_EXPIRED_OR_INVALID: 'ERR_00064',
  TWO_FACTOR_AUTHENTICATION_REQUIRED: 'ERR_00065',
} as const;

/**
 * A code from {@link REGIONAL_ERROR_CODES}.
 *
 * A union over the codes the excerpt names, not over the codes that exist — see
 * the module comment. Suitable for typing a code this library produces; not
 * suitable for parsing an inbound one.
 */
export type RegionalErrorCode = (typeof REGIONAL_ERROR_CODES)[keyof typeof REGIONAL_ERROR_CODES];
