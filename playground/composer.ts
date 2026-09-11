/**
 * The playground's behaviour, with no DOM: a {@link ComposerState} of control
 * choices goes in, the library runs, and a {@link ComposerView} comes out.
 *
 * Several choices are deliberately invalid input — `urn:rve:authnL3`, the
 * matching mode `fuzzy`, request context C.1.6 — because showing what the
 * library refuses is half the page. Those are the only casts here, and each
 * sits where the invalid value enters a library type.
 */

import {
  applicationIdShape,
  buildRve1bRequest,
  deriveMessageId,
  deriveRequestId,
  isRequestContext,
  RECOMMENDED_CLOCK_SKEW_MS,
  RECOMMENDED_FLIGHT_TIME_MS,
  REQUEST_CONTEXTS,
  rve1bRequest,
  servicePolicy,
  validateAssertion,
  ASSERTION_ATTRIBUTES,
  type AssertionFailure,
  type AssertionTimeModel,
  type AssertionValidationOptions,
  type AssertionWarning,
  type AudienceMatching,
  type AuthenticationLevel,
  type Remedy,
  type RequestContext,
  type Rve1bRequestInput,
  type ServicePolicy,
  type ServicePolicyInput,
  type Username,
} from '../src/index.js';
import {
  APPLICATION_ID,
  assertionXml,
  L1,
  L2,
  L3,
  MESSAGE_ID,
  NOW,
  OPERATOR,
  OTHER_OPERATOR,
  OTHER_SERVICE,
  requestInput,
  SERVICE,
  type AssertionShape,
  type SignatureKind,
} from './fixtures.js';

export interface RequestState {
  readonly messageId: 'valid' | 'bare' | 'not-uuid';
  readonly username: 'plaintext' | 'encrypted' | 'blank-plaintext' | 'blank-ciphertext';
  readonly recipient: 'absolute' | 'relative' | 'blank';
  readonly applicationId: 'bare' | 'caret-separated' | 'blank';
  readonly requestContext: RequestContext | 'C.1.6';
  readonly authenticationLevel: 'not-asked' | 'L2' | 'L3';
  readonly issueInstant: 'now' | 'not-a-date';
  readonly window: 'four-hours' | 'empty' | 'same-second' | 'inverted';
  readonly audiences: 'this' | 'two' | 'other' | 'none' | 'relative';
  readonly patientId: 'omitted' | 'present' | 'blank';
  readonly otpCode: 'omitted' | 'present' | 'blank';
  readonly authorisingOrganisations: 'none' | 'two' | 'one-blank';
}

type ClockTime =
  | '08:00:00'
  | '08:59:30'
  | '09:00:00'
  | '09:58:59'
  | '10:00:00'
  | '12:59:30'
  | '13:00:00'
  | '14:00:00';

type Margin = 'zero' | 'recommended' | 'negative';

export interface AssertionState {
  readonly structure:
    | 'well-formed'
    | 'not-xml'
    | 'empty'
    | 'root-response'
    | 'saml-1.1'
    | 'doctype'
    | 'advice';
  readonly signature: SignatureKind;
  readonly verifier: 'none' | 'verified' | 'not-verified';
  readonly window: 'nine-to-one' | 'three-seconds';
  readonly now: ClockTime | 'not-a-date';
  readonly clockSkew: Margin;
  readonly flightTime: Margin;
  readonly audience:
    | 'this'
    | 'other'
    | 'generic'
    | 'host-case'
    | 'path-case'
    | 'trailing-slash'
    | 'both-in-one'
    | 'second-misses';
  readonly subject: 'operator' | 'missing' | 'blank' | 'two';
  readonly responsibleParty: 'same' | 'different' | 'second' | 'lower-case' | 'missing';
  readonly role: 'present' | 'missing';
  readonly requestContext: 'present' | 'missing';
  readonly authLevel: 'L2' | 'missing' | 'L2-and-L1' | 'L1' | 'L3';
}

export interface PolicyState {
  readonly audience: 'this' | 'relative';
  readonly refusesGeneric: 'no' | 'yes';
  readonly requiredAttributes: 'none' | 'role' | 'role-and-context' | 'role-and-blank';
  readonly requiredLevel: 'none' | 'L2' | 'L3';
  readonly matching: 'exact' | 'normalised' | 'fuzzy';
}

export interface ComposerState {
  readonly request: RequestState;
  readonly assertion: AssertionState;
  readonly policy: PolicyState;
  /** Whether the built request decides the audience restriction and required level. */
  readonly followRequest: boolean;
}

export const REQUEST_DEFAULTS: RequestState = {
  messageId: 'valid',
  username: 'plaintext',
  recipient: 'absolute',
  applicationId: 'bare',
  requestContext: 'C.1.1',
  authenticationLevel: 'not-asked',
  issueInstant: 'now',
  window: 'four-hours',
  audiences: 'this',
  patientId: 'omitted',
  otpCode: 'omitted',
  authorisingOrganisations: 'none',
};

const HAPPY_ASSERTION: AssertionState = {
  structure: 'well-formed',
  signature: 'current',
  verifier: 'none',
  window: 'nine-to-one',
  now: '10:00:00',
  clockSkew: 'recommended',
  flightTime: 'recommended',
  audience: 'this',
  subject: 'operator',
  responsibleParty: 'same',
  role: 'present',
  requestContext: 'present',
  authLevel: 'L2',
};

const BASELINE_POLICY: PolicyState = {
  audience: 'this',
  refusesGeneric: 'no',
  requiredAttributes: 'none',
  requiredLevel: 'none',
  matching: 'exact',
};

interface Preset {
  readonly label: string;
  readonly assertion: AssertionState;
  readonly policy: PolicyState;
}

export const PRESETS = {
  happy: { label: 'Happy path', assertion: HAPPY_ASSERTION, policy: BASELINE_POLICY },
  scoped: {
    label: 'Expired + wrong audience',
    assertion: { ...HAPPY_ASSERTION, now: '14:00:00', audience: 'other' },
    policy: BASELINE_POLICY,
  },
  stepup: {
    label: 'Step-up',
    assertion: { ...HAPPY_ASSERTION, authLevel: 'missing', audience: 'other' },
    policy: { ...BASELINE_POLICY, requiredLevel: 'L2' },
  },
  lifted: {
    label: 'Lifted signature',
    assertion: { ...HAPPY_ASSERTION, signature: 'unbound', audience: 'other' },
    policy: BASELINE_POLICY,
  },
  people: {
    label: 'Two people',
    assertion: { ...HAPPY_ASSERTION, responsibleParty: 'different' },
    policy: BASELINE_POLICY,
  },
  sha1: {
    label: 'SHA-1 warnings',
    assertion: { ...HAPPY_ASSERTION, signature: 'deprecated' },
    policy: BASELINE_POLICY,
  },
} satisfies Record<string, Preset>;

export type PresetId = keyof typeof PRESETS;

export const INITIAL_STATE: ComposerState = {
  request: REQUEST_DEFAULTS,
  assertion: PRESETS.happy.assertion,
  policy: PRESETS.happy.policy,
  followRequest: false,
};

/** Replaces the assertion and service policy, and stops following the request. */
export function applyPreset(state: ComposerState, id: PresetId): ComposerState {
  const preset = PRESETS[id];
  return { ...state, assertion: preset.assertion, policy: preset.policy, followRequest: false };
}

export interface ControlOption {
  readonly value: string;
  readonly label: string;
  /** A qualifier shown after the label, such as "outside A.2". */
  readonly note?: string;
}

interface ControlBase {
  readonly label: string;
  /** Whether the option labels are literal values, set in the utility face. */
  readonly mono: boolean;
  readonly options: readonly ControlOption[];
}

export type Control =
  | (ControlBase & { readonly group: 'request'; readonly key: keyof RequestState })
  | (ControlBase & { readonly group: 'assertion'; readonly key: keyof AssertionState })
  | (ControlBase & { readonly group: 'policy'; readonly key: keyof PolicyState });

export interface ControlSection {
  readonly title: string;
  readonly controls: readonly Control[];
}

function option(value: string, label: string, note?: string): ControlOption {
  return note === undefined ? { value, label } : { value, label, note };
}

const options = (pairs: readonly (readonly [string, string])[]): ControlOption[] =>
  pairs.map(([value, label]) => option(value, label));

export const REQUEST_CONTROLS: readonly Control[] = [
  {
    group: 'request',
    key: 'messageId',
    label: 'Message ID',
    mono: false,
    options: options([
      ['valid', 'urn:uuid:…8ebd'],
      ['bare', 'Bare UUID'],
      ['not-uuid', 'Not a UUID'],
    ]),
  },
  {
    group: 'request',
    key: 'username',
    label: 'Username',
    mono: false,
    options: options([
      ['plaintext', 'Plaintext'],
      ['encrypted', 'Encrypted'],
      ['blank-plaintext', 'Blank plaintext'],
      ['blank-ciphertext', 'Blank ciphertext'],
    ]),
  },
  {
    group: 'request',
    key: 'recipient',
    label: 'Recipient',
    mono: false,
    options: options([
      ['absolute', 'https://iap…/ws'],
      ['relative', '/ws'],
      ['blank', 'Blank'],
    ]),
  },
  {
    group: 'request',
    key: 'applicationId',
    label: 'ApplicationID',
    mono: false,
    options: options([
      ['bare', 'Bare OID'],
      ['caret-separated', 'Caret-separated'],
      ['blank', 'Blank'],
    ]),
  },
  {
    group: 'request',
    key: 'requestContext',
    label: 'Request context',
    mono: true,
    options: [...REQUEST_CONTEXTS.map((context) => option(context, context)), option('C.1.6', 'C.1.6', 'outside A.2')],
  },
  {
    group: 'request',
    key: 'authenticationLevel',
    label: 'Authentication level',
    mono: false,
    options: options([
      ['not-asked', 'Not asked'],
      ['L2', 'authnL2'],
      ['L3', 'authnL3'],
    ]),
  },
  {
    group: 'request',
    key: 'issueInstant',
    label: 'Issue instant',
    mono: false,
    options: options([
      ['now', '10:00:00Z'],
      ['not-a-date', 'Not a date'],
    ]),
  },
  {
    group: 'request',
    key: 'window',
    label: 'Requested window',
    mono: false,
    options: options([
      ['four-hours', '4 hours'],
      ['empty', 'Ends as it begins'],
      ['same-second', 'Same whole second'],
      ['inverted', 'Ends before it begins'],
    ]),
  },
  {
    group: 'request',
    key: 'audiences',
    label: 'Audiences',
    mono: false,
    options: options([
      ['this', 'This service'],
      ['two', 'Two services'],
      ['other', 'Another service'],
      ['none', 'None (generic)'],
      ['relative', 'Not a URL'],
    ]),
  },
  {
    group: 'request',
    key: 'patientId',
    label: 'Patient ID',
    mono: false,
    options: options([
      ['omitted', 'Omitted'],
      ['present', 'Present'],
      ['blank', 'Blank'],
    ]),
  },
  {
    group: 'request',
    key: 'otpCode',
    label: 'OTP code',
    mono: false,
    options: options([
      ['omitted', 'Omitted'],
      ['present', 'Present'],
      ['blank', 'Blank'],
    ]),
  },
  {
    group: 'request',
    key: 'authorisingOrganisations',
    label: 'Authorising organisations',
    mono: false,
    options: options([
      ['none', 'None'],
      ['two', 'Two codes'],
      ['one-blank', 'One blank'],
    ]),
  },
];

const MARGIN_OPTIONS = (recommended: string): ControlOption[] =>
  options([
    ['zero', '0 s'],
    ['recommended', recommended],
    ['negative', '−1 ms'],
  ]);

export const ASSERTION_SECTIONS: readonly ControlSection[] = [
  {
    title: 'Document',
    controls: [
      {
        group: 'assertion',
        key: 'structure',
        label: 'Structure',
        mono: false,
        options: options([
          ['well-formed', 'Well-formed'],
          ['not-xml', 'Not XML'],
          ['empty', 'Empty'],
          ['root-response', 'Root is Response'],
          ['saml-1.1', 'SAML 1.1'],
          ['doctype', 'DOCTYPE'],
          ['advice', 'Assertion in Advice'],
        ]),
      },
    ],
  },
  {
    title: 'Signature',
    controls: [
      {
        group: 'assertion',
        key: 'signature',
        label: 'Signature element',
        mono: false,
        options: options([
          ['current', 'RSA-SHA256'],
          ['deprecated', 'RSA-SHA1 + SHA-1'],
          ['rsa-sha1-only', 'RSA-SHA1 only'],
          ['sha1-digest-only', 'SHA-1 digest only'],
          ['absent', 'Absent'],
          ['no-value', 'No SignatureValue'],
          ['unattested', 'DSA-SHA1'],
          ['no-algorithm', 'No Algorithm'],
          ['no-uri', 'Reference without URI'],
          ['unbound', 'Bound elsewhere'],
          ['double', 'Two signatures'],
        ]),
      },
      {
        group: 'assertion',
        key: 'verifier',
        label: 'Caller’s verifier',
        mono: false,
        options: options([
          ['none', 'Not supplied'],
          ['verified', 'Returns verified'],
          ['not-verified', 'Returns not-verified'],
        ]),
      },
    ],
  },
  {
    title: 'Time',
    controls: [
      {
        group: 'assertion',
        key: 'window',
        label: 'Assertion window',
        mono: true,
        options: options([
          ['nine-to-one', '09:00–13:00'],
          ['three-seconds', '10:00:00–10:00:03'],
        ]),
      },
      {
        group: 'assertion',
        key: 'now',
        label: 'Clock',
        mono: true,
        options: options([
          ['08:00:00', '08:00'],
          ['08:59:30', '08:59:30'],
          ['09:00:00', '09:00'],
          ['09:58:59', '09:58:59'],
          ['10:00:00', '10:00'],
          ['12:59:30', '12:59:30'],
          ['13:00:00', '13:00'],
          ['14:00:00', '14:00'],
          ['not-a-date', 'Not a date'],
        ]),
      },
      {
        group: 'assertion',
        key: 'clockSkew',
        label: 'Clock skew',
        mono: true,
        options: MARGIN_OPTIONS('60 s'),
      },
      {
        group: 'assertion',
        key: 'flightTime',
        label: 'Flight time',
        mono: true,
        options: MARGIN_OPTIONS('5 s'),
      },
    ],
  },
  {
    title: 'Identity',
    controls: [
      {
        group: 'assertion',
        key: 'subject',
        label: 'Subject NameID',
        mono: false,
        options: options([
          ['operator', 'Operator tax code'],
          ['missing', 'Missing'],
          ['blank', 'Blank'],
          ['two', 'Two NameIDs'],
        ]),
      },
      {
        group: 'assertion',
        key: 'responsibleParty',
        label: 'ResponsibleParty',
        mono: false,
        options: options([
          ['same', 'Same operator'],
          ['different', 'Different operator'],
          ['second', 'Second party added'],
          ['lower-case', 'Same, lower case'],
          ['missing', 'Missing'],
        ]),
      },
    ],
  },
  {
    title: 'Scope and attributes',
    controls: [
      {
        group: 'assertion',
        key: 'audience',
        label: 'Audience restriction',
        mono: false,
        options: options([
          ['this', 'This service'],
          ['other', 'Another service'],
          ['generic', 'None (generic)'],
          ['both-in-one', 'Both services in one'],
          ['second-misses', 'Second restriction misses'],
          ['host-case', 'Host in capitals'],
          ['path-case', 'Path in lower case'],
          ['trailing-slash', 'Trailing slash'],
        ]),
      },
      {
        group: 'assertion',
        key: 'role',
        label: 'Role attribute',
        mono: false,
        options: options([
          ['present', 'Present'],
          ['missing', 'Missing'],
        ]),
      },
      {
        group: 'assertion',
        key: 'requestContext',
        label: 'RequestContext attribute',
        mono: false,
        options: options([
          ['present', 'Present'],
          ['missing', 'Missing'],
        ]),
      },
      {
        group: 'assertion',
        key: 'authLevel',
        label: 'authLevel attribute',
        mono: false,
        options: options([
          ['L2', 'authnL2'],
          ['missing', 'Missing'],
          ['L2-and-L1', 'authnL2 + authnL1'],
          ['L1', 'authnL1 only'],
          ['L3', 'authnL3 only'],
        ]),
      },
    ],
  },
  {
    title: 'Service policy',
    controls: [
      {
        group: 'policy',
        key: 'audience',
        label: 'Service audience',
        mono: false,
        options: options([
          ['this', 'This service'],
          ['relative', 'Registry (relative)'],
        ]),
      },
      {
        group: 'policy',
        key: 'refusesGeneric',
        label: 'Refuses generic assertions',
        mono: false,
        options: options([
          ['no', 'No'],
          ['yes', 'Yes'],
        ]),
      },
      {
        group: 'policy',
        key: 'requiredAttributes',
        label: 'Required attributes',
        mono: false,
        options: options([
          ['none', 'None'],
          ['role', 'Role'],
          ['role-and-context', 'Role + RequestContext'],
          ['role-and-blank', 'Role + a blank name'],
        ]),
      },
      {
        group: 'policy',
        key: 'requiredLevel',
        label: 'Required authentication level',
        mono: false,
        options: options([
          ['none', 'None'],
          ['L2', 'authnL2'],
          ['L3', 'authnL3'],
        ]),
      },
      {
        group: 'policy',
        key: 'matching',
        label: 'Audience matching',
        mono: true,
        options: options([
          ['exact', 'exact'],
          ['normalised', 'normalised'],
          ['fuzzy', 'fuzzy'],
        ]),
      },
    ],
  },
];

/** Returns `state` with one control moved to `value`. */
export function setControl(state: ComposerState, control: Control, value: string): ComposerState {
  switch (control.group) {
    case 'request':
      return { ...state, request: { ...state.request, [control.key]: value } };
    case 'assertion':
      return { ...state, assertion: { ...state.assertion, [control.key]: value } };
    case 'policy':
      return { ...state, policy: { ...state.policy, [control.key]: value } };
  }
}

/** Whether a control is decided by the request while the page follows it. */
export function followsRequest(control: Control): boolean {
  return (
    (control.group === 'assertion' && control.key === 'audience') ||
    (control.group === 'policy' && control.key === 'requiredLevel')
  );
}

// -------------------------------------------------------------- request --

const HOUR = 3_600_000;
const at = (offsetMs: number): Date => new Date(NOW.getTime() + offsetMs);

const MESSAGE_IDS: Record<RequestState['messageId'], string> = {
  valid: MESSAGE_ID,
  bare: '9376254e-da05-41f5-9af3-ac56d63d8ebd',
  'not-uuid': 'urn:uuid:not-a-uuid',
};

const USERNAMES: Record<RequestState['username'], Username> = {
  plaintext: { form: 'plaintext', value: 'm.rossi' },
  encrypted: { form: 'encrypted', ciphertext: 'bQ0xZGVhZGJlZWY=' },
  'blank-plaintext': { form: 'plaintext', value: '  ' },
  'blank-ciphertext': { form: 'encrypted', ciphertext: '' },
};

const RECIPIENTS: Record<RequestState['recipient'], string> = {
  absolute: 'https://iap.example-aulss.veneto.it/ws',
  relative: '/ws',
  blank: '',
};

const APPLICATION_IDS: Record<RequestState['applicationId'], string> = {
  bare: APPLICATION_ID,
  'caret-separated': `${APPLICATION_ID}^PediatraDesk^2.4`,
  blank: '',
};

const REQUEST_WINDOWS: Record<RequestState['window'], readonly [Date, Date]> = {
  'four-hours': [NOW, at(4 * HOUR)],
  empty: [NOW, NOW],
  'same-second': [at(100), at(900)],
  inverted: [NOW, at(-HOUR)],
};

const REQUEST_AUDIENCES: Record<RequestState['audiences'], readonly string[]> = {
  this: [SERVICE],
  two: [SERVICE, OTHER_SERVICE],
  other: [OTHER_SERVICE],
  none: [],
  relative: ['fser/Registry'],
};

const LEVELS = { L2, L3: L3 as AuthenticationLevel } as const;

function requestInputFor(request: RequestState): Rve1bRequestInput {
  const [notBefore, notOnOrAfter] = REQUEST_WINDOWS[request.window];
  return requestInput({
    messageId: MESSAGE_IDS[request.messageId],
    username: USERNAMES[request.username],
    recipient: RECIPIENTS[request.recipient],
    applicationId: APPLICATION_IDS[request.applicationId],
    requestContext: request.requestContext as RequestContext,
    authenticationLevel:
      request.authenticationLevel === 'not-asked' ? undefined : LEVELS[request.authenticationLevel],
    issueInstant: request.issueInstant === 'now' ? NOW : new Date(Number.NaN),
    notBefore,
    notOnOrAfter,
    audiences: REQUEST_AUDIENCES[request.audiences],
    patientId: { omitted: undefined, present: 'PTNTAX80A01H501Z', blank: ' ' }[request.patientId],
    otpCode: { omitted: undefined, present: '482913', blank: '' }[request.otpCode],
    authorisingOrganisations: {
      none: undefined,
      two: ['050101', '050102'],
      'one-blank': ['050101', ''],
    }[request.authorisingOrganisations],
  });
}

export type RequestResult =
  | {
      readonly outcome: 'built';
      readonly xml: string;
      readonly requestId: string;
      readonly byteLength: number;
    }
  | {
      readonly outcome: 'thrown';
      readonly where: 'rve1bRequest';
      readonly errorName: string;
      readonly message: string;
    };

function describeError(error: unknown): { errorName: string; message: string } {
  return error instanceof Error
    ? { errorName: error.name, message: error.message }
    : { errorName: 'Error', message: String(error) };
}

function runRequest(request: RequestState): RequestResult {
  try {
    const checked = rve1bRequest(requestInputFor(request));
    const bytes = buildRve1bRequest(checked);
    return {
      outcome: 'built',
      xml: new TextDecoder().decode(bytes),
      requestId: checked.requestId,
      byteLength: bytes.length,
    };
  } catch (error) {
    return { outcome: 'thrown', where: 'rve1bRequest', ...describeError(error) };
  }
}

export interface DerivedFact {
  readonly label: string;
  readonly value: string;
  /** Whether the fact is the one a well-formed request would have. */
  readonly holds: boolean;
}

/** What the library's vocabulary helpers make of the request's inputs. */
function derive(request: RequestState): DerivedFact[] {
  const input = requestInputFor(request);
  const facts: DerivedFact[] = [];

  try {
    const requestId = deriveRequestId(input.messageId);
    facts.push({ label: 'AuthnRequest ID', value: requestId, holds: true });
    facts.push({ label: 'Message ID, derived back', value: deriveMessageId(requestId), holds: true });
  } catch (error) {
    facts.push({ label: 'AuthnRequest ID', value: `${describeError(error).errorName}: none derived`, holds: false });
  }

  const shape = applicationIdShape(input.applicationId);
  facts.push({ label: 'ApplicationID shape', value: shape, holds: shape !== 'unrecognised' });

  const known = isRequestContext(request.requestContext);
  facts.push({ label: 'Request context in A.2', value: known ? 'yes' : 'no', holds: known });

  return facts;
}

export type Following = 'off' | 'on' | 'request-refused';

const FOLLOWED_AUDIENCE: Record<RequestState['audiences'], AssertionState['audience'] | undefined> = {
  this: 'this',
  two: 'both-in-one',
  other: 'other',
  none: 'generic',
  relative: undefined,
};

const FOLLOWED_LEVEL: Record<RequestState['authenticationLevel'], PolicyState['requiredLevel'] | undefined> = {
  'not-asked': 'none',
  L2: 'L2',
  L3: undefined,
};

/**
 * The assertion and policy the page actually judges. While following, the IAP
 * scopes the assertion to exactly the audiences the request asked for, in one
 * restriction, and the service requires the level the request asked for. The
 * level the assertion attests stays its own control, so a step-up stays
 * reachable. A refused request has nothing to follow.
 */
function follow(
  state: ComposerState,
  request: RequestResult,
): { following: Following; assertion: AssertionState; policy: PolicyState } {
  if (!state.followRequest) {
    return { following: 'off', assertion: state.assertion, policy: state.policy };
  }
  if (request.outcome !== 'built') {
    return { following: 'request-refused', assertion: state.assertion, policy: state.policy };
  }

  const audience = FOLLOWED_AUDIENCE[state.request.audiences] ?? state.assertion.audience;
  const requiredLevel = FOLLOWED_LEVEL[state.request.authenticationLevel] ?? state.policy.requiredLevel;
  return {
    following: 'on',
    assertion: { ...state.assertion, audience },
    policy: { ...state.policy, requiredLevel },
  };
}

const STRUCTURES: Record<AssertionState['structure'], Partial<AssertionShape>> = {
  'well-formed': {},
  'not-xml': { raw: 'this is not xml' },
  empty: { raw: '' },
  'root-response': { root: 'Response' },
  'saml-1.1': { version: '1.1' },
  doctype: { doctype: true },
  advice: { advice: true },
};

const ASSERTION_WINDOWS: Record<AssertionState['window'], Partial<AssertionShape>> = {
  'nine-to-one': { notBefore: '2026-09-10T09:00:00Z', notOnOrAfter: '2026-09-10T13:00:00Z' },
  'three-seconds': { notBefore: '2026-09-10T10:00:00Z', notOnOrAfter: '2026-09-10T10:00:03Z' },
};

const RESTRICTIONS: Record<AssertionState['audience'], AssertionShape['restrictions']> = {
  this: [[SERVICE]],
  other: [[OTHER_SERVICE]],
  generic: [],
  'host-case': [['https://FSER.regione.veneto.it/Registry']],
  'path-case': [['https://fser.regione.veneto.it/registry']],
  'trailing-slash': [[`${SERVICE}/`]],
  'both-in-one': [[SERVICE, OTHER_SERVICE]],
  'second-misses': [[SERVICE], [OTHER_SERVICE]],
};

const SUBJECTS: Record<AssertionState['subject'], readonly string[]> = {
  operator: [OPERATOR],
  missing: [],
  blank: [''],
  two: [OPERATOR, OPERATOR],
};

const RESPONSIBLE_PARTIES: Record<AssertionState['responsibleParty'], readonly string[] | null> = {
  same: [OPERATOR],
  different: [OTHER_OPERATOR],
  second: [OPERATOR, OTHER_OPERATOR],
  'lower-case': [OPERATOR.toLowerCase()],
  missing: null,
};

const ATTESTED_LEVELS: Record<AssertionState['authLevel'], readonly string[] | null> = {
  L2: [L2],
  missing: null,
  'L2-and-L1': [L2, L1],
  L1: [L1],
  L3: [L3],
};

const MARGINS: Record<Margin, (recommended: number) => number> = {
  zero: () => 0,
  recommended: (recommended) => recommended,
  negative: () => -1,
};

function shapeFor(assertion: AssertionState): Partial<AssertionShape> {
  return {
    ...STRUCTURES[assertion.structure],
    ...ASSERTION_WINDOWS[assertion.window],
    signature: assertion.signature,
    restrictions: RESTRICTIONS[assertion.audience],
    subject: SUBJECTS[assertion.subject],
    responsibleParty: RESPONSIBLE_PARTIES[assertion.responsibleParty],
    role: assertion.role === 'present' ? 'R.1.1' : null,
    requestContext: assertion.requestContext === 'present' ? 'C.1.1' : null,
    authLevel: ATTESTED_LEVELS[assertion.authLevel],
  };
}

function timeFor(assertion: AssertionState): AssertionTimeModel {
  return {
    now: new Date(assertion.now === 'not-a-date' ? Number.NaN : `2026-09-10T${assertion.now}Z`),
    clockSkewMs: MARGINS[assertion.clockSkew](RECOMMENDED_CLOCK_SKEW_MS),
    flightTimeMs: MARGINS[assertion.flightTime](RECOMMENDED_FLIGHT_TIME_MS),
  };
}

function optionsFor(assertion: AssertionState): AssertionValidationOptions {
  const { verifier } = assertion;
  return verifier === 'none' ? {} : { verifySignature: () => verifier };
}

const REQUIRED_ATTRIBUTES: Record<PolicyState['requiredAttributes'], readonly string[] | undefined> = {
  none: undefined,
  role: [ASSERTION_ATTRIBUTES.ROLE],
  'role-and-context': [ASSERTION_ATTRIBUTES.ROLE, ASSERTION_ATTRIBUTES.REQUEST_CONTEXT],
  'role-and-blank': [ASSERTION_ATTRIBUTES.ROLE, ' '],
};

function policyInputFor(policy: PolicyState): ServicePolicyInput {
  const requiredAttributes = REQUIRED_ATTRIBUTES[policy.requiredAttributes];
  return {
    audience: policy.audience === 'this' ? SERVICE : 'Registry',
    refusesGenericAssertions: policy.refusesGeneric === 'yes',
    audienceMatching: policy.matching as AudienceMatching,
    ...(requiredAttributes === undefined ? {} : { requiredAttributes }),
    ...(policy.requiredLevel === 'none'
      ? {}
      : { requiredAuthenticationLevel: LEVELS[policy.requiredLevel] }),
  };
}

export type AssertionResult =
  | {
      readonly outcome: 'valid';
      readonly xml: string;
      readonly operatorTaxCode: string;
      readonly audiences: readonly string[];
      readonly authenticationLevel: string | undefined;
      readonly usableUntil: string;
      readonly warnings: readonly AssertionWarning[];
    }
  | {
      readonly outcome: 'invalid';
      readonly xml: string;
      readonly failures: readonly AssertionFailure[];
      readonly remedy: Remedy;
    }
  | {
      readonly outcome: 'thrown';
      readonly xml: string;
      readonly where: 'servicePolicy' | 'validateAssertion';
      readonly errorName: string;
      readonly message: string;
    };

function runAssertion(assertion: AssertionState, policyState: PolicyState): AssertionResult {
  const xml = assertionXml(shapeFor(assertion));

  let policy: ServicePolicy;
  try {
    policy = servicePolicy(policyInputFor(policyState));
  } catch (error) {
    return { outcome: 'thrown', xml, where: 'servicePolicy', ...describeError(error) };
  }

  try {
    const bytes = new TextEncoder().encode(xml);
    const result = validateAssertion(bytes, timeFor(assertion), policy, optionsFor(assertion));
    return result.valid
      ? {
          outcome: 'valid',
          xml,
          operatorTaxCode: result.operatorTaxCode,
          audiences: result.audiences,
          authenticationLevel: result.authenticationLevel,
          usableUntil: result.usableUntil.toISOString(),
          warnings: result.warnings,
        }
      : { outcome: 'invalid', xml, failures: result.failures, remedy: result.remedy };
  } catch (error) {
    return { outcome: 'thrown', xml, where: 'validateAssertion', ...describeError(error) };
  }
}

export interface ComposerView {
  readonly request: RequestResult;
  readonly derived: readonly DerivedFact[];
  readonly following: Following;
  /** The assertion controls as judged, after following the request. */
  readonly assertion: AssertionState;
  /** The service policy controls as judged, after following the request. */
  readonly policy: PolicyState;
  readonly result: AssertionResult;
}

export function compose(state: ComposerState): ComposerView {
  const request = runRequest(state.request);
  const { following, assertion, policy } = follow(state, request);
  return {
    request,
    derived: derive(state.request),
    following,
    assertion,
    policy,
    result: runAssertion(assertion, policy),
  };
}
