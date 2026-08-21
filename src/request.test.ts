import { describe, expect, it } from 'vitest';

import { deriveMessageId, deriveRequestId } from './request.js';
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
