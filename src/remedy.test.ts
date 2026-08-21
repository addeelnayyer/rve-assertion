import { describe, expect, it } from 'vitest';

import type { AssertionFailure, AssertionFailureCode } from './assertion.js';
import { REGIONAL_ERROR_CODES } from './regional-error-codes.js';
import { deriveRemedy, type Remedy } from './remedy.js';
import { TWO_FACTOR_AUTHENTICATION_LEVEL } from './request.js';
import { servicePolicy } from './service-policy.js';

const AUDIENCE = 'https://fser.regione.veneto.it/Registry';

/** A service that asks for nothing beyond being named. */
const OPEN_SERVICE = servicePolicy({ audience: AUDIENCE });

/** A service that requires the operator to have used a second factor. */
const TWO_FACTOR_SERVICE = servicePolicy({
  audience: AUDIENCE,
  requiredAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
});

/**
 * A failure carrying `code` and nothing the derivation is allowed to read.
 *
 * The regional code and the detail are constants: if changing either changed a
 * remedy, the mapping would have a second source.
 */
function failure(code: AssertionFailureCode, unrecoverable = false): AssertionFailure {
  return {
    code,
    detail: 'a detail.',
    regionalErrorCode: REGIONAL_ERROR_CODES.REQUEST_PARAMETERS_AGAINST_POLICY,
    unrecoverable,
  };
}

/** `deriveRemedy` over a set of codes, in the shape the validator hands it. */
function remedyFor(
  [first, ...rest]: readonly [AssertionFailureCode, ...AssertionFailureCode[]],
  policy = OPEN_SERVICE,
): Remedy {
  return deriveRemedy([failure(first), ...rest.map((code) => failure(code))], policy);
}

/**
 * What each failure resolves to on its own.
 *
 * A `Record` keyed by the union rather than a list, so that a failure code
 * added to the validator fails to compile here until someone has said which
 * remedy resolves it — the one question a new code cannot be allowed to leave
 * open.
 */
const ALONE: Readonly<Record<AssertionFailureCode, Remedy['action']>> = {
  // Nothing this library can name resolves any of these: a document that is
  // not an assertion, a signature that does not cover one, an IAP that
  // resolved two identities, or a clock that disagrees with the issuer's.
  malformed: 'fail-hard',
  'signature-absent': 'fail-hard',
  'signature-malformed': 'fail-hard',
  'signature-not-bound': 'fail-hard',
  'signature-verification-failed': 'fail-hard',
  'not-yet-valid': 'fail-hard',
  'identity-mismatch': 'fail-hard',

  expired: 'refresh',

  'audience-mismatch': 'rerequest-scoped',
  'audience-absent': 'rerequest-scoped',
  'attribute-missing': 'rerequest-scoped',

  'authentication-level-not-attested': 'step-up-auth',
};

/** The codes some remedy resolves — everything the order is derived over. */
const RESOLVABLE = (Object.keys(ALONE) as AssertionFailureCode[]).filter(
  (code) => ALONE[code] !== 'fail-hard',
);

describe('deriveRemedy — one failure at a time', () => {
  it.each(Object.entries(ALONE))('resolves %s with %s', (code, action) => {
    expect(remedyFor([code as AssertionFailureCode], TWO_FACTOR_SERVICE).action).toBe(action);
  });
});

describe('deriveRemedy — the aggregate is derived, not ranked', () => {
  // The two cases the design exists for. Both are stated as a loop that does
  // not happen rather than as an ordering that was written down.

  it('answers an expired and wrongly scoped assertion with a scoped re-request, not a refresh', () => {
    // A refresh would return a fresh assertion carrying the same wrong
    // audience, which fails again. A scoped re-request returns one that is
    // both fresh and correctly scoped.
    expect(remedyFor(['expired', 'audience-mismatch'])).toEqual({
      action: 'rerequest-scoped',
      withAudience: AUDIENCE,
      withAuthenticationLevel: undefined,
    });
  });

  it('answers a wrongly scoped assertion missing an authentication level with a step-up', () => {
    // A scoped re-request would return a correctly scoped assertion still
    // attesting no second factor. The step-up resolves both, and only because
    // it carries the audience forward.
    expect(remedyFor(['audience-mismatch', 'authentication-level-not-attested'])).toEqual({
      action: 'step-up-auth',
      withAudience: AUDIENCE,
      withAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
    });
  });

  it('reaches the same aggregate whichever order the failures arrive in', () => {
    expect(remedyFor(['audience-mismatch', 'expired'])).toEqual(
      remedyFor(['expired', 'audience-mismatch']),
    );
  });

  it('never invents an action neither failure asks for', () => {
    for (const one of RESOLVABLE) {
      for (const other of RESOLVABLE) {
        expect([ALONE[one], ALONE[other]]).toContain(remedyFor([one, other]).action);
      }
    }
  });

  it('resolves every resolvable failure at once with the greatest remedy', () => {
    const [first, ...rest] = RESOLVABLE as [AssertionFailureCode, ...AssertionFailureCode[]];

    expect(remedyFor([first, ...rest]).action).toBe('step-up-auth');
  });
});

describe('deriveRemedy — fail-hard absorbs', () => {
  it('answers a failure no remedy resolves with fail-hard, whatever is beside it', () => {
    for (const code of RESOLVABLE) {
      expect(remedyFor(['identity-mismatch', code]).action).toBe('fail-hard');
    }
  });

  it('carries nothing to execute it with', () => {
    expect(remedyFor(['malformed'])).toEqual({ action: 'fail-hard' });
  });
});

describe('deriveRemedy — the mapping is the only source', () => {
  it('reads the failure code and not the unrecoverable flag', () => {
    expect(remedyFor(['identity-mismatch']).action).toBe('fail-hard');
    expect(deriveRemedy([failure('identity-mismatch', true)], OPEN_SERVICE).action).toBe(
      'fail-hard',
    );
    expect(deriveRemedy([failure('expired', true)], OPEN_SERVICE).action).toBe('refresh');
  });

  it('answers one failure and the same failure reported twice identically', () => {
    expect(remedyFor(['expired', 'expired'])).toEqual(remedyFor(['expired']));
  });
});

describe('deriveRemedy — the audience threads through', () => {
  it('carries the service the assertion was validated against on every remedy that acts', () => {
    for (const code of RESOLVABLE) {
      const remedy = remedyFor([code]);

      expect(remedy.action).not.toBe('fail-hard');
      expect(remedy).toHaveProperty('withAudience', AUDIENCE);
    }
  });

  it('carries the audience the policy holds, not the one the assertion named', () => {
    const elsewhere = servicePolicy({ audience: 'https://fser.regione.veneto.it/Repository' });

    expect(remedyFor(['audience-mismatch'], elsewhere)).toHaveProperty(
      'withAudience',
      'https://fser.regione.veneto.it/Repository',
    );
  });
});

describe('deriveRemedy — the authentication level', () => {
  it('asks a re-request for the level the service requires, when it requires one', () => {
    expect(remedyFor(['audience-mismatch'], TWO_FACTOR_SERVICE)).toEqual({
      action: 'rerequest-scoped',
      withAudience: AUDIENCE,
      withAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
    });
  });

  it('asks a re-request for no level when the service requires none', () => {
    expect(remedyFor(['audience-mismatch'], OPEN_SERVICE)).toEqual({
      action: 'rerequest-scoped',
      withAudience: AUDIENCE,
      withAuthenticationLevel: undefined,
    });
  });

  it('names a level on a step-up even where the service required none', () => {
    // An assertion attesting two levels attests none, whatever the policy asked
    // for (D-023), so this failure reaches a step-up with nothing required. A
    // step-up naming no level is one a caller cannot execute — see D-026.
    expect(remedyFor(['authentication-level-not-attested'], OPEN_SERVICE)).toEqual({
      action: 'step-up-auth',
      withAudience: AUDIENCE,
      withAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
    });
  });
});
