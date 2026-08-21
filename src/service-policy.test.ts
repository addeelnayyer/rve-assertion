import { describe, expect, it } from 'vitest';

import {
  audienceMatches,
  BASELINE_SERVICE_POLICY,
  servicePolicy,
} from './service-policy.js';
import { ValidationInputError } from './types.js';

const AUDIENCE = 'https://fser.regione.veneto.it/Registry';

describe('servicePolicy — the baseline', () => {
  it('leaves a caller that names only a service on the baseline', () => {
    const policy = servicePolicy({ audience: AUDIENCE });

    expect(policy.audience).toBe(AUDIENCE);
    expect(policy.refusesGenericAssertions).toBe(BASELINE_SERVICE_POLICY.refusesGenericAssertions);
    expect(policy.audienceMatching).toBe(BASELINE_SERVICE_POLICY.audienceMatching);
  });

  it('accepts a generic assertion and compares exactly, on the baseline', () => {
    // Both values are inferences from the RVE-1.a information-content table,
    // which marks the audience optional in both directions — not statements
    // §4.2.6 makes about RVE-1.b. See docs/spec-questions.md (D-012).
    expect(BASELINE_SERVICE_POLICY.refusesGenericAssertions).toBe(false);
    expect(BASELINE_SERVICE_POLICY.audienceMatching).toBe('exact');
  });

  it('carries no permitted-contexts and no permitted-roles fields', () => {
    // A deliberate omission, not an oversight: the request context, the role
    // and the ApplicationID are checked by the IAP and by the X-Service
    // Provider against boundary tables this library cannot see, so a
    // client-side copy of them would be a second, staler answer. D-017.
    //
    // `requiredAttributes` is not that copy: it asks whether an attribute is
    // there, never which value would be acceptable, so a permitted-roles list
    // cannot be smuggled through it.
    expect(Object.keys(servicePolicy({ audience: AUDIENCE })).sort()).toEqual([
      'audience',
      'audienceMatching',
      'refusesGenericAssertions',
      'requiredAttributes',
      'requiredAuthenticationLevel',
    ]);
  });

  it('takes an override for each baseline value', () => {
    const policy = servicePolicy({
      audience: AUDIENCE,
      refusesGenericAssertions: true,
      audienceMatching: 'normalised',
    });

    expect(policy.refusesGenericAssertions).toBe(true);
    expect(policy.audienceMatching).toBe('normalised');
  });
});

describe('servicePolicy — what it refuses to build', () => {
  it.each([['', 'empty'], ['   ', 'whitespace-only']])(
    'refuses a %s audience',
    (audience) => {
      // A blank audience is the absence of a service to check against, and a
      // policy holding one would refuse every scoped assertion while accepting
      // every generic one — a fail-open shaped like a fail-closed.
      expect(() => servicePolicy({ audience })).toThrow(ValidationInputError);
    },
  );

  it('refuses an audience that is not an absolute URI', () => {
    // §4.1.6.2.2 asks an Audience to name its service by a URL given in full. A
    // path cannot be compared against one the IAP wrote in full.
    expect(() => servicePolicy({ audience: '/Registry' })).toThrow(ValidationInputError);
  });

  it('stores the audience without the whitespace around it', () => {
    // Trimmed once, where the policy is built, rather than at each comparison:
    // an indent that arrived from tenant configuration would otherwise be
    // compared away silently and then travel on into the scoped re-request the
    // failure calls for.
    expect(servicePolicy({ audience: `  ${AUDIENCE}\n` }).audience).toBe(AUDIENCE);
  });

  it('refuses a matching mode it does not implement', () => {
    const input = { audience: AUDIENCE, audienceMatching: 'loose' } as never;

    expect(() => servicePolicy(input)).toThrow(ValidationInputError);
  });

  it('names the failing value rather than reporting that something was wrong', () => {
    expect(() => servicePolicy({ audience: '/Registry' })).toThrow(/Registry/);
  });
});

describe('audienceMatches — exact, which is the default', () => {
  const policy = servicePolicy({ audience: AUDIENCE });

  it('matches the identical string', () => {
    expect(audienceMatches(policy, AUDIENCE)).toBe(true);
  });

  it('matches across the surrounding whitespace a pretty-printer adds', () => {
    // xs:anyURI collapses whitespace, so leading and trailing space is not part
    // of the value and stripping it is the schema's behaviour, not this
    // library's normalisation.
    expect(audienceMatches(policy, `\n      ${AUDIENCE}\n    `)).toBe(true);
  });

  it('does not match a host differing only in case', () => {
    expect(audienceMatches(policy, 'https://FSER.regione.veneto.it/Registry')).toBe(false);
  });

  it('does not match the same service with a trailing slash', () => {
    expect(audienceMatches(policy, `${AUDIENCE}/`)).toBe(false);
  });

  it('does not match a different service', () => {
    expect(audienceMatches(policy, 'https://sar.regione.veneto.it/Repository')).toBe(false);
  });
});

describe('audienceMatches — normalised, behind the explicit flag', () => {
  const policy = servicePolicy({ audience: AUDIENCE, audienceMatching: 'normalised' });

  it.each([
    ['a host differing in case', 'https://FSER.Regione.Veneto.IT/Registry'],
    ['a scheme differing in case', 'HTTPS://fser.regione.veneto.it/Registry'],
    ["the scheme's default port written out", 'https://fser.regione.veneto.it:443/Registry'],
  ])('matches %s', (_case, candidate) => {
    expect(audienceMatches(policy, candidate)).toBe(true);
  });

  it('treats an absent path and a bare slash as the same service', () => {
    const bare = servicePolicy({
      audience: 'https://fser.regione.veneto.it',
      audienceMatching: 'normalised',
    });

    expect(audienceMatches(bare, 'https://fser.regione.veneto.it/')).toBe(true);
  });

  it('keeps the path case-sensitive, because RFC 3986 does', () => {
    expect(audienceMatches(policy, 'https://fser.regione.veneto.it/registry')).toBe(false);
  });

  it('keeps a trailing slash on a non-empty path significant', () => {
    expect(audienceMatches(policy, `${AUDIENCE}/`)).toBe(false);
  });

  it('still refuses a different service', () => {
    expect(audienceMatches(policy, 'https://sar.regione.veneto.it/Registry')).toBe(false);
  });

  it('falls back to comparing the trimmed values when one side is not a URL', () => {
    // The policy's own audience is a URL — the smart constructor saw to that —
    // so this is the assertion carrying something that is not one. Comparing
    // the raw values keeps the answer false rather than throwing on a document
    // the caller cannot control.
    expect(audienceMatches(policy, 'not a url')).toBe(false);
  });
});
