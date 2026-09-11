import { describe, expect, it } from 'vitest';

import { deriveRequestId } from '../src/index.js';
import {
  ASSERTION_SECTIONS,
  INITIAL_STATE,
  PRESETS,
  REQUEST_CONTROLS,
  applyPreset,
  compose,
  setControl,
  type AssertionResult,
  type AssertionState,
  type ComposerState,
  type PolicyState,
  type RequestResult,
  type RequestState,
} from './composer.js';
import { L2, L3, MESSAGE_ID, OTHER_SERVICE, SERVICE } from './fixtures.js';

interface Patch {
  readonly request?: Partial<RequestState>;
  readonly assertion?: Partial<AssertionState>;
  readonly policy?: Partial<PolicyState>;
  readonly followRequest?: boolean;
}

function stateWith(patch: Patch): ComposerState {
  return {
    request: { ...INITIAL_STATE.request, ...patch.request },
    assertion: { ...INITIAL_STATE.assertion, ...patch.assertion },
    policy: { ...INITIAL_STATE.policy, ...patch.policy },
    followRequest: patch.followRequest ?? INITIAL_STATE.followRequest,
  };
}

/** What the catalogue compares: never the details, which are free prose. */
interface Summary {
  readonly outcome: string;
  readonly errorName?: string;
  readonly where?: string;
  readonly codes?: readonly string[];
  readonly remedy?: string;
  readonly warnings?: readonly string[];
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

function summariseRequest(result: RequestResult): Summary {
  return result.outcome === 'built'
    ? { outcome: 'built' }
    : { outcome: 'thrown', errorName: result.errorName, where: result.where };
}

function summariseAssertion(result: AssertionResult): Summary {
  switch (result.outcome) {
    case 'valid':
      return { outcome: 'valid', warnings: sorted(result.warnings.map((w) => w.code)) };
    case 'invalid':
      return {
        outcome: 'invalid',
        codes: sorted(result.failures.map((f) => f.code)),
        remedy: result.remedy.action,
      };
    case 'thrown':
      return { outcome: 'thrown', errorName: result.errorName, where: result.where };
  }
}

const NOT_VERIFIED = 'signature-not-cryptographically-verified';

const built = (): Summary => ({ outcome: 'built' });
const refusedRequest = (): Summary => ({
  outcome: 'thrown',
  errorName: 'RequestInputError',
  where: 'rve1bRequest',
});
const threw = (where: 'servicePolicy' | 'validateAssertion'): Summary => ({
  outcome: 'thrown',
  errorName: 'ValidationInputError',
  where,
});
const fails = (codes: readonly string[], remedy: string): Summary => ({
  outcome: 'invalid',
  codes: sorted(codes),
  remedy,
});
const accepted = (warnings: readonly string[] = [NOT_VERIFIED]): Summary => ({
  outcome: 'valid',
  warnings: sorted(warnings),
});

type Entry = readonly ['request' | 'assertion', Patch, Summary];

/**
 * The 64 scenarios of the prototype's catalogue, each reached from controls
 * alone. Where the catalogue used an input no control offers — `rem-scoped`'s
 * 04:00–08:00 window — the entry reaches the same failures another way.
 */
const CATALOGUE: Record<string, Entry> = {
  'req-plain': ['request', {}, built()],
  'req-encrypted': ['request', { request: { username: 'encrypted' } }, built()],
  'req-full': [
    'request',
    {
      request: {
        patientId: 'present',
        otpCode: 'present',
        authorisingOrganisations: 'two',
        authenticationLevel: 'L2',
        audiences: 'two',
      },
    },
    built(),
  ],
  'req-generic': ['request', { request: { audiences: 'none' } }, built()],

  'req-bare-uuid': ['request', { request: { messageId: 'bare' } }, refusedRequest()],
  'req-not-uuid': ['request', { request: { messageId: 'not-uuid' } }, refusedRequest()],
  'req-blank-user': ['request', { request: { username: 'blank-plaintext' } }, refusedRequest()],
  'req-blank-cipher': ['request', { request: { username: 'blank-ciphertext' } }, refusedRequest()],
  'req-relative-recipient': ['request', { request: { recipient: 'relative' } }, refusedRequest()],
  'req-blank-app': ['request', { request: { applicationId: 'blank' } }, refusedRequest()],
  'req-context': ['request', { request: { requestContext: 'C.1.6' } }, refusedRequest()],
  'req-level': ['request', { request: { authenticationLevel: 'L3' } }, refusedRequest()],
  'req-empty-window': ['request', { request: { window: 'empty' } }, refusedRequest()],
  'req-collapsed-window': ['request', { request: { window: 'same-second' } }, refusedRequest()],
  'req-invalid-instant': ['request', { request: { issueInstant: 'not-a-date' } }, refusedRequest()],
  'req-relative-audience': ['request', { request: { audiences: 'relative' } }, refusedRequest()],
  'req-blank-patient': ['request', { request: { patientId: 'blank' } }, refusedRequest()],
  'req-blank-otp': ['request', { request: { otpCode: 'blank' } }, refusedRequest()],
  'req-blank-org': [
    'request',
    { request: { authorisingOrganisations: 'one-blank' } },
    refusedRequest(),
  ],

  'pol-relative': ['assertion', { policy: { audience: 'relative' } }, threw('servicePolicy')],
  'pol-matching': ['assertion', { policy: { matching: 'fuzzy' } }, threw('servicePolicy')],
  'pol-blank-attr': [
    'assertion',
    { policy: { requiredAttributes: 'role-and-blank' } },
    threw('servicePolicy'),
  ],
  'pol-level': ['assertion', { policy: { requiredLevel: 'L3' } }, threw('servicePolicy')],

  'ok-baseline': ['assertion', {}, accepted()],
  'ok-strict': [
    'assertion',
    {
      policy: { refusesGeneric: 'yes', requiredAttributes: 'role-and-context', requiredLevel: 'L2' },
    },
    accepted(),
  ],
  'ok-generic': ['assertion', { assertion: { audience: 'generic' } }, accepted()],
  'ok-normalised': [
    'assertion',
    { assertion: { audience: 'host-case' }, policy: { matching: 'normalised' } },
    accepted(),
  ],
  'ok-verified': ['assertion', { assertion: { verifier: 'verified' } }, accepted([])],
  'ok-deprecated': [
    'assertion',
    { assertion: { signature: 'deprecated' } },
    accepted(['deprecated-signature-algorithm', 'deprecated-digest-algorithm', NOT_VERIFIED]),
  ],

  'st-not-xml': ['assertion', { assertion: { structure: 'not-xml' } }, fails(['malformed'], 'fail-hard')],
  'st-empty': ['assertion', { assertion: { structure: 'empty' } }, fails(['malformed'], 'fail-hard')],
  'st-root': [
    'assertion',
    { assertion: { structure: 'root-response' } },
    fails(['malformed'], 'fail-hard'),
  ],
  'st-version': ['assertion', { assertion: { structure: 'saml-1.1' } }, fails(['malformed'], 'fail-hard')],
  'st-doctype': ['assertion', { assertion: { structure: 'doctype' } }, fails(['malformed'], 'fail-hard')],
  'st-advice': ['assertion', { assertion: { structure: 'advice' } }, fails(['malformed'], 'fail-hard')],

  'sig-absent': [
    'assertion',
    { assertion: { signature: 'absent' } },
    fails(['signature-absent'], 'fail-hard'),
  ],
  'sig-no-value': [
    'assertion',
    { assertion: { signature: 'no-value' } },
    fails(['signature-malformed'], 'fail-hard'),
  ],
  'sig-unattested': [
    'assertion',
    { assertion: { signature: 'unattested' } },
    fails(['signature-malformed'], 'fail-hard'),
  ],
  'sig-double': [
    'assertion',
    { assertion: { signature: 'double' } },
    fails(['signature-malformed'], 'fail-hard'),
  ],
  'sig-unbound': [
    'assertion',
    { assertion: { signature: 'unbound', audience: 'other' } },
    fails(['signature-not-bound'], 'fail-hard'),
  ],
  'sig-verifier': [
    'assertion',
    { assertion: { verifier: 'not-verified' } },
    fails(['signature-verification-failed'], 'fail-hard'),
  ],

  'win-early': ['assertion', { assertion: { now: '08:00:00' } }, fails(['not-yet-valid'], 'fail-hard')],
  'win-expired': ['assertion', { assertion: { now: '14:00:00' } }, fails(['expired'], 'refresh')],
  'win-tightened': ['assertion', { assertion: { now: '12:59:30' } }, fails(['expired'], 'refresh')],
  'win-skew': ['assertion', { assertion: { now: '08:59:30' } }, accepted()],
  'win-short': [
    'assertion',
    { assertion: { window: 'three-seconds', now: '09:58:59' } },
    fails(['not-yet-valid', 'expired'], 'fail-hard'),
  ],

  'aud-mismatch': [
    'assertion',
    { assertion: { audience: 'other' } },
    fails(['audience-mismatch'], 'rerequest-scoped'),
  ],
  'aud-absent': [
    'assertion',
    { assertion: { audience: 'generic' }, policy: { refusesGeneric: 'yes' } },
    fails(['audience-absent'], 'rerequest-scoped'),
  ],
  'aud-every': [
    'assertion',
    { assertion: { audience: 'second-misses' } },
    fails(['audience-mismatch'], 'rerequest-scoped'),
  ],
  'aud-case': [
    'assertion',
    { assertion: { audience: 'host-case' } },
    fails(['audience-mismatch'], 'rerequest-scoped'),
  ],

  'att-role': [
    'assertion',
    { assertion: { role: 'missing' }, policy: { requiredAttributes: 'role' } },
    fails(['attribute-missing'], 'rerequest-scoped'),
  ],
  'att-two': [
    'assertion',
    {
      assertion: { role: 'missing', requestContext: 'missing' },
      policy: { requiredAttributes: 'role-and-context' },
    },
    fails(['attribute-missing', 'attribute-missing'], 'rerequest-scoped'),
  ],
  'att-responsible': [
    'assertion',
    { assertion: { responsibleParty: 'missing' } },
    fails(['attribute-missing'], 'rerequest-scoped'),
  ],
  'att-level-missing': [
    'assertion',
    { assertion: { authLevel: 'missing' }, policy: { requiredLevel: 'L2' } },
    fails(['authentication-level-not-attested'], 'step-up-auth'),
  ],
  'att-level-two': [
    'assertion',
    { assertion: { authLevel: 'L2-and-L1' } },
    fails(['authentication-level-not-attested'], 'step-up-auth'),
  ],

  'id-mismatch': [
    'assertion',
    { assertion: { responsibleParty: 'different' } },
    fails(['identity-mismatch'], 'fail-hard'),
  ],
  'id-second': [
    'assertion',
    { assertion: { responsibleParty: 'second' } },
    fails(['identity-mismatch'], 'fail-hard'),
  ],
  'id-case': ['assertion', { assertion: { responsibleParty: 'lower-case' } }, accepted()],

  'rem-refresh': ['assertion', { assertion: { now: '14:00:00' } }, fails(['expired'], 'refresh')],
  'rem-scoped': [
    'assertion',
    { assertion: { now: '14:00:00', audience: 'other' } },
    fails(['expired', 'audience-mismatch'], 'rerequest-scoped'),
  ],
  'rem-stepup': [
    'assertion',
    { assertion: { authLevel: 'missing', audience: 'other' }, policy: { requiredLevel: 'L2' } },
    fails(['audience-mismatch', 'authentication-level-not-attested'], 'step-up-auth'),
  ],
  'rem-absorb': [
    'assertion',
    { assertion: { responsibleParty: 'different', now: '14:00:00' } },
    fails(['expired', 'identity-mismatch'], 'fail-hard'),
  ],

  'time-clock': ['assertion', { assertion: { now: 'not-a-date' } }, threw('validateAssertion')],
  'time-margin': ['assertion', { assertion: { clockSkew: 'negative' } }, threw('validateAssertion')],
};

describe('the prototype catalogue', () => {
  it('has all 64 scenarios', () => {
    expect(Object.keys(CATALOGUE)).toHaveLength(64);
  });

  it.each(Object.entries(CATALOGUE))('%s is reachable from controls', (_id, [side, patch, expected]) => {
    const view = compose(stateWith(patch));
    const actual =
      side === 'request' ? summariseRequest(view.request) : summariseAssertion(view.result);
    expect(actual).toEqual(expected);
  });
});

describe('presets', () => {
  const outcomes: Record<keyof typeof PRESETS, Summary> = {
    happy: accepted(),
    scoped: fails(['expired', 'audience-mismatch'], 'rerequest-scoped'),
    stepup: fails(['audience-mismatch', 'authentication-level-not-attested'], 'step-up-auth'),
    lifted: fails(['signature-not-bound'], 'fail-hard'),
    people: fails(['identity-mismatch'], 'fail-hard'),
    sha1: accepted(['deprecated-signature-algorithm', 'deprecated-digest-algorithm', NOT_VERIFIED]),
  };

  it.each(Object.entries(outcomes))('%s produces the outcome its label names', (id, expected) => {
    const state = applyPreset(INITIAL_STATE, id as keyof typeof PRESETS);
    expect(summariseAssertion(compose(state).result)).toEqual(expected);
  });

  it('keeps the request and stops following it', () => {
    const before = stateWith({ request: { username: 'encrypted' }, followRequest: true });
    const after = applyPreset(before, 'scoped');
    expect(after.request).toEqual(before.request);
    expect(after.followRequest).toBe(false);
  });

  it('starts on the happy path', () => {
    expect(applyPreset(INITIAL_STATE, 'happy')).toEqual(INITIAL_STATE);
  });
});

describe('following the request', () => {
  it('is off to begin with, and the assertion keeps its own controls', () => {
    const view = compose(stateWith({ request: { audiences: 'other' } }));
    expect(view.following).toBe('off');
    expect(summariseAssertion(view.result)).toEqual(accepted());
  });

  it('scopes the assertion to the audiences the request asked for', () => {
    const view = compose(stateWith({ request: { audiences: 'other' }, followRequest: true }));
    expect(view.following).toBe('on');
    expect(view.assertion.audience).toBe('other');
    expect(summariseAssertion(view.result)).toEqual(fails(['audience-mismatch'], 'rerequest-scoped'));
  });

  it('puts two requested audiences in one restriction', () => {
    const view = compose(stateWith({ request: { audiences: 'two' }, followRequest: true }));
    expect(view.assertion.audience).toBe('both-in-one');
    expect(view.result.outcome === 'valid' && view.result.audiences).toEqual([SERVICE, OTHER_SERVICE]);
  });

  it('issues a generic assertion when the request named no audience', () => {
    const view = compose(
      stateWith({
        request: { audiences: 'none' },
        policy: { refusesGeneric: 'yes' },
        followRequest: true,
      }),
    );
    expect(view.assertion.audience).toBe('generic');
    expect(summariseAssertion(view.result)).toEqual(fails(['audience-absent'], 'rerequest-scoped'));
  });

  it('requires the authentication level the request asked for', () => {
    const view = compose(
      stateWith({
        request: { authenticationLevel: 'L2' },
        assertion: { authLevel: 'missing' },
        followRequest: true,
      }),
    );
    expect(view.policy.requiredLevel).toBe('L2');
    expect(summariseAssertion(view.result)).toEqual(
      fails(['authentication-level-not-attested'], 'step-up-auth'),
    );
  });

  it('requires no level when the request asked for none', () => {
    const view = compose(stateWith({ policy: { requiredLevel: 'L2' }, followRequest: true }));
    expect(view.policy.requiredLevel).toBe('none');
  });

  it('falls back to the assertion’s own controls when the request is refused', () => {
    const view = compose(
      stateWith({
        request: { messageId: 'bare', audiences: 'other' },
        followRequest: true,
      }),
    );
    expect(view.following).toBe('request-refused');
    expect(view.assertion.audience).toBe('this');
    expect(summariseAssertion(view.result)).toEqual(accepted());
  });
});

describe('controls the prototype lacked', () => {
  const assertion = (patch: Patch): Summary => summariseAssertion(compose(stateWith(patch)).result);
  const request = (patch: Patch): Summary => summariseRequest(compose(stateWith(patch)).request);

  it.each(['missing', 'blank', 'two'] as const)('a Subject NameID that is %s is malformed', (subject) => {
    expect(assertion({ assertion: { subject } })).toEqual(fails(['malformed'], 'fail-hard'));
  });

  it('refuses a SignatureMethod with no Algorithm', () => {
    expect(assertion({ assertion: { signature: 'no-algorithm' } })).toEqual(
      fails(['signature-malformed'], 'fail-hard'),
    );
  });

  it('refuses a Reference with no URI as unbound', () => {
    expect(assertion({ assertion: { signature: 'no-uri' } })).toEqual(
      fails(['signature-not-bound'], 'fail-hard'),
    );
  });

  it('warns about each deprecated algorithm on its own', () => {
    expect(assertion({ assertion: { signature: 'rsa-sha1-only' } })).toEqual(
      accepted(['deprecated-signature-algorithm', NOT_VERIFIED]),
    );
    expect(assertion({ assertion: { signature: 'sha1-digest-only' } })).toEqual(
      accepted(['deprecated-digest-algorithm', NOT_VERIFIED]),
    );
  });

  it('asks for a step-up when only authnL1 is attested and authnL2 is required', () => {
    expect(assertion({ assertion: { authLevel: 'L1' }, policy: { requiredLevel: 'L2' } })).toEqual(
      fails(['authentication-level-not-attested'], 'step-up-auth'),
    );
  });

  it('reports authnL3 when no level is required', () => {
    const { result } = compose(stateWith({ assertion: { authLevel: 'L3' } }));
    expect(result.outcome === 'valid' && result.authenticationLevel).toBe(L3);
  });

  it('holds the window bounds exactly when there are no margins', () => {
    const margins = { clockSkew: 'zero', flightTime: 'zero' } as const;
    expect(assertion({ assertion: { ...margins, now: '09:00:00' } })).toEqual(accepted());
    expect(assertion({ assertion: { ...margins, now: '13:00:00' } })).toEqual(
      fails(['expired'], 'refresh'),
    );
  });

  it('throws for a negative flight time', () => {
    expect(assertion({ assertion: { flightTime: 'negative' } })).toEqual(threw('validateAssertion'));
  });

  it('accepts one restriction naming several audiences and reports them all', () => {
    const { result } = compose(stateWith({ assertion: { audience: 'both-in-one' } }));
    expect(result.outcome === 'valid' && result.audiences).toEqual([SERVICE, OTHER_SERVICE]);
  });

  it.each(['trailing-slash', 'path-case'] as const)(
    'normalised matching still refuses an audience with a %s',
    (audience) => {
      expect(assertion({ assertion: { audience }, policy: { matching: 'normalised' } })).toEqual(
        fails(['audience-mismatch'], 'rerequest-scoped'),
      );
    },
  );

  it('refuses a request window that ends before it begins, and a blank recipient', () => {
    expect(request({ request: { window: 'inverted' } })).toEqual(refusedRequest());
    expect(request({ request: { recipient: 'blank' } })).toEqual(refusedRequest());
  });

  it('builds a request for another service', () => {
    expect(request({ request: { audiences: 'other' } })).toEqual(built());
  });
});

describe('the derived panel', () => {
  const fact = (state: ComposerState, label: string): string | undefined =>
    compose(state).derived.find((d) => d.label === label)?.value;

  it('shows the request ID and the message ID it derives back to', () => {
    expect(fact(INITIAL_STATE, 'AuthnRequest ID')).toBe(deriveRequestId(MESSAGE_ID));
    expect(fact(INITIAL_STATE, 'Message ID, derived back')).toBe(MESSAGE_ID);
  });

  it('names the ApplicationID shape', () => {
    expect(fact(INITIAL_STATE, 'ApplicationID shape')).toBe('bare');
    const caret = stateWith({ request: { applicationId: 'caret-separated' } });
    expect(fact(caret, 'ApplicationID shape')).toBe('caret-separated');
    expect(summariseRequest(compose(caret).request)).toEqual(built());
  });

  it('says whether the request context is in Appendix A.2', () => {
    expect(fact(INITIAL_STATE, 'Request context in A.2')).toBe('yes');
    expect(fact(stateWith({ request: { requestContext: 'C.1.6' } }), 'Request context in A.2')).toBe('no');
  });
});

describe('the result', () => {
  it('builds an envelope and reports its bytes', () => {
    const { request } = compose(INITIAL_STATE);
    expect(request.outcome === 'built' && request.xml).toContain('AuthnRequest');
    expect(request.outcome === 'built' && request.byteLength).toBeGreaterThan(0);
  });

  it('names a failure that is not established to be unrecoverable as such', () => {
    const { result } = compose(stateWith({ assertion: { now: '14:00:00' } }));
    expect(result.outcome === 'invalid' && result.failures[0]?.unrecoverable).toBe(false);
  });

  it('carries the audience a step-up must ask for', () => {
    const { result } = compose(applyPreset(INITIAL_STATE, 'stepup'));
    expect(result.outcome === 'invalid' && result.remedy).toEqual({
      action: 'step-up-auth',
      withAudience: SERVICE,
      withAuthenticationLevel: L2,
    });
  });
});

describe('every control', () => {
  const everyOption = [
    ...REQUEST_CONTROLS,
    ...ASSERTION_SECTIONS.flatMap((section) => section.controls),
  ].flatMap((control) => control.options.map((option) => [control, option.value] as const));

  it('offers only values compose understands', () => {
    for (const [control, value] of everyOption) {
      const state = setControl(INITIAL_STATE, control, value);
      const group = state[control.group] as unknown as Record<string, string>;
      expect(group[control.key]).toBe(value);
      expect(() => compose(state)).not.toThrow();
    }
  });

  it('offers every request context, and C.1.6 outside Appendix A.2', () => {
    const context = REQUEST_CONTROLS.find((c) => c.key === 'requestContext');
    expect(context?.options).toHaveLength(43);
    expect(context?.options.at(-1)).toMatchObject({ value: 'C.1.6', note: 'outside A.2' });
  });
});
