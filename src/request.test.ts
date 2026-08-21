import { describe, expect, it } from 'vitest';

import {
  deriveMessageId,
  deriveRequestId,
  rve1bRequest,
  TWO_FACTOR_AUTHENTICATION_LEVEL,
} from './request.js';
import type { Rve1bRequestInput } from './request.js';
import { RequestInputError } from './types.js';

const MESSAGE_ID = 'urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301';
const REQUEST_ID = 'msgId_3f2504e0-4f89-41d3-9a0c-0305e82c3301';

describe('deriveRequestId', () => {
  it('strips the urn:uuid: scheme prefix and applies the msgId_ prefix', () => {
    expect(deriveRequestId(MESSAGE_ID)).toBe(REQUEST_ID);
  });

  it('rejects a message ID whose scheme-specific part is not a UUID', () => {
    expect(() => deriveRequestId('urn:uuid:not-a-uuid')).toThrow(RequestInputError);
  });

  it('preserves the case of an uppercase UUID rather than normalising it', () => {
    // Decision D-001 in docs/spec-questions.md.
    expect(deriveRequestId('urn:uuid:3F2504E0-4F89-41D3-9A0C-0305E82C3301')).toBe(
      'msgId_3F2504E0-4F89-41D3-9A0C-0305E82C3301',
    );
  });

  it('rejects a bare UUID carrying no scheme prefix', () => {
    // Decision D-002 in docs/spec-questions.md.
    expect(() => deriveRequestId('3f2504e0-4f89-41d3-9a0c-0305e82c3301')).toThrow(
      RequestInputError,
    );
  });

  it('rejects a scheme prefix that is not in canonical lowercase', () => {
    // Decision D-003 in docs/spec-questions.md.
    expect(() => deriveRequestId('URN:UUID:3f2504e0-4f89-41d3-9a0c-0305e82c3301')).toThrow(
      RequestInputError,
    );
  });

  it('rejects a scheme other than urn:uuid:', () => {
    expect(() => deriveRequestId('urn:example:3f2504e0-4f89-41d3-9a0c-0305e82c3301')).toThrow(
      RequestInputError,
    );
  });
});

describe('deriveMessageId', () => {
  it('is the inverse of deriveRequestId', () => {
    expect(deriveMessageId(REQUEST_ID)).toBe(MESSAGE_ID);
  });

  it('rejects an identifier carrying no msgId_ prefix', () => {
    expect(() => deriveMessageId('3f2504e0-4f89-41d3-9a0c-0305e82c3301')).toThrow(
      RequestInputError,
    );
  });

  it('rejects an identifier whose remainder is not a UUID', () => {
    expect(() => deriveMessageId('msgId_not-a-uuid')).toThrow(RequestInputError);
  });
});

describe('the derivation round trip', () => {
  it.each([
    'urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301',
    'urn:uuid:3F2504E0-4F89-41D3-9A0C-0305E82C3301',
    'urn:uuid:00000000-0000-0000-0000-000000000000',
  ])('recovers %s from the identifier derived from it', (messageId) => {
    expect(deriveMessageId(deriveRequestId(messageId))).toBe(messageId);
  });
});

/**
 * A request that builds, so that each test below can name the one field it is
 * about rather than restating a whole envelope's worth of input.
 */
const VALID: Rve1bRequestInput = {
  messageId: 'urn:uuid:9376254e-da05-41f5-9af3-ac56d63d8ebd',
  recipient: 'https://iap.ulssx.veneto.it/ws',
  username: { form: 'plaintext', value: 'a-directory-server-username' },
  applicationId: '2.16.840.1.113883.2.9.2.50.4.5.0999',
  requestContext: 'C.1.1',
  issueInstant: new Date('2026-08-21T09:00:00Z'),
  notBefore: new Date('2026-08-21T09:00:00Z'),
  notOnOrAfter: new Date('2026-08-21T13:00:00Z'),
};

function withInput(overrides: Partial<Rve1bRequestInput>): Rve1bRequestInput {
  return { ...VALID, ...overrides };
}

describe('rve1bRequest', () => {
  it('derives the request identifier from the message ID', () => {
    expect(rve1bRequest(VALID).requestId).toBe('msgId_9376254e-da05-41f5-9af3-ac56d63d8ebd');
  });

  it('rejects a message ID it cannot derive an identifier from', () => {
    expect(() => rve1bRequest(withInput({ messageId: 'not-a-urn' }))).toThrow(RequestInputError);
  });
});

describe('the validity window', () => {
  it('rejects a window that ends before it begins', () => {
    expect(() =>
      rve1bRequest(
        withInput({
          notBefore: new Date('2026-08-21T13:00:00Z'),
          notOnOrAfter: new Date('2026-08-21T09:00:00Z'),
        }),
      ),
    ).toThrow(RequestInputError);
  });

  it('rejects a window that ends at the instant it begins', () => {
    // NotOnOrAfter excludes its own instant, so an equal pair asks the IAP for
    // an assertion that is valid for no time at all.
    const instant = new Date('2026-08-21T09:00:00Z');
    expect(() => rve1bRequest(withInput({ notBefore: instant, notOnOrAfter: instant }))).toThrow(
      RequestInputError,
    );
  });

  it('rejects a window whose bounds collapse onto one another once truncated', () => {
    // The check runs on the truncated values because those are what is emitted;
    // a sub-second window is not a window on the wire.
    expect(() =>
      rve1bRequest(
        withInput({
          notBefore: new Date('2026-08-21T09:00:00.100Z'),
          notOnOrAfter: new Date('2026-08-21T09:00:00.900Z'),
        }),
      ),
    ).toThrow(RequestInputError);
  });

  it('accepts an issue instant outside the requested window', () => {
    // Decision D-005 in docs/spec-questions.md: §4.2.5.2's own worked request
    // does this, so refusing it would refuse the specification's example.
    expect(() =>
      rve1bRequest(withInput({ issueInstant: new Date('2027-01-20T13:51:13Z') })),
    ).not.toThrow();
  });

  it.each([
    ['issueInstant' as const],
    ['notBefore' as const],
    ['notOnOrAfter' as const],
  ])('rejects an invalid date given as %s', (field) => {
    expect(() => rve1bRequest(withInput({ [field]: new Date('nonsense') }))).toThrow(
      RequestInputError,
    );
  });
});

describe('timestamp lexical form', () => {
  it('emits whole seconds, UTC, with a Z suffix', () => {
    // Decision D-004 in docs/spec-questions.md.
    const request = rve1bRequest(withInput({ issueInstant: new Date('2026-08-21T09:00:00.750Z') }));
    expect(request.issueInstant).toBe('2026-08-21T09:00:00Z');
  });

  it('truncates towards the past rather than rounding', () => {
    const request = rve1bRequest(withInput({ issueInstant: new Date('2026-08-21T09:00:00.999Z') }));
    expect(request.issueInstant).toBe('2026-08-21T09:00:00Z');
  });

  it('normalises an instant given in a non-UTC offset', () => {
    const request = rve1bRequest(withInput({ issueInstant: new Date('2026-08-21T11:00:00+02:00') }));
    expect(request.issueInstant).toBe('2026-08-21T09:00:00Z');
  });
});

describe('the recipient', () => {
  it('rejects a relative reference, which is not the absolute IRI WS-Addressing requires', () => {
    expect(() => rve1bRequest(withInput({ recipient: '/ws' }))).toThrow(RequestInputError);
  });

  it('rejects a blank recipient', () => {
    expect(() => rve1bRequest(withInput({ recipient: '   ' }))).toThrow(RequestInputError);
  });
});

describe('the username', () => {
  it('rejects a blank plaintext username', () => {
    expect(() => rve1bRequest(withInput({ username: { form: 'plaintext', value: '  ' } }))).toThrow(
      RequestInputError,
    );
  });

  it('rejects a blank ciphertext', () => {
    expect(() =>
      rve1bRequest(withInput({ username: { form: 'encrypted', ciphertext: '' } })),
    ).toThrow(RequestInputError);
  });

  it('carries an encrypted username through unaltered', () => {
    const request = rve1bRequest(
      withInput({ username: { form: 'encrypted', ciphertext: 'q1w2e3==' } }),
    );
    expect(request.username).toEqual({ form: 'encrypted', ciphertext: 'q1w2e3==' });
  });
});

describe('the ApplicationID', () => {
  it.each(['2.16.840.1.113883.2.9.2.50.4.5.0999', 'product^1.4^install-7', 'anything at all'])(
    'accepts %s, because the library enforces no format',
    (applicationId) => {
      // Q-003 in docs/spec-questions.md: the prose describes one form and the
      // worked example carries another, so neither is enforced.
      expect(() => rve1bRequest(withInput({ applicationId }))).not.toThrow();
    },
  );

  it('rejects a blank ApplicationID, which is an absent value rather than a format', () => {
    expect(() => rve1bRequest(withInput({ applicationId: ' ' }))).toThrow(RequestInputError);
  });
});

describe('the request context', () => {
  it('rejects a code outside the regional code system even when the compiler was told otherwise', () => {
    // Q-004 in docs/spec-questions.md. `C.1.6` is the code §4.2.5.2's own
    // worked request declares, and Appendix A.2, Table 5 does not define it.
    const input = withInput({}) as { requestContext: string };
    input.requestContext = 'C.1.6';
    expect(() => rve1bRequest(input as Rve1bRequestInput)).toThrow(RequestInputError);
  });
});

describe('the optional attributes', () => {
  it('reports an omitted patient identifier as absent rather than blank', () => {
    expect(rve1bRequest(VALID).patientId).toBeUndefined();
  });

  it('rejects a blank patient identifier, which is neither present nor omitted', () => {
    expect(() => rve1bRequest(withInput({ patientId: '' }))).toThrow(RequestInputError);
  });

  it('rejects a blank OTP code', () => {
    expect(() => rve1bRequest(withInput({ otpCode: ' ' }))).toThrow(RequestInputError);
  });

  it('rejects a blank authorising organisation code', () => {
    expect(() => rve1bRequest(withInput({ authorisingOrganisations: ['090', ''] }))).toThrow(
      RequestInputError,
    );
  });

  it('accepts the one authentication level the specification attests', () => {
    const request = rve1bRequest(
      withInput({ authenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL }),
    );
    expect(request.authenticationLevel).toBe('urn:rve:authnL2');
  });

  it('rejects an authentication level the specification does not attest', () => {
    const input = withInput({}) as { authenticationLevel?: string };
    input.authenticationLevel = 'urn:rve:authnL3';
    expect(() => rve1bRequest(input as Rve1bRequestInput)).toThrow(RequestInputError);
  });
});

describe('the audiences', () => {
  it('defaults to none', () => {
    expect(rve1bRequest(VALID).audiences).toEqual([]);
  });

  it('rejects an audience that is not a complete URL', () => {
    expect(() => rve1bRequest(withInput({ audiences: ['demVisualizzaErogatoCUP'] }))).toThrow(
      RequestInputError,
    );
  });

  it('accepts several audiences', () => {
    const audiences = [
      'https://sar.regione.veneto.it/demVisualizzaErogatoCUP',
      'https://fser.regione.veneto.it/Registry',
    ];
    expect(rve1bRequest(withInput({ audiences })).audiences).toEqual(audiences);
  });
});
