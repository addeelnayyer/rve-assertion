import { describe, expect, it } from 'vitest';

import {
  applicationIdShape,
  isRequestContext,
  REQUEST_CONTEXTS,
  RVE_1B_USER_CLIENT_AUTHENTICATION,
} from './request-vocabulary.js';

describe('REQUEST_CONTEXTS', () => {
  it('carries no duplicate code', () => {
    expect(new Set(REQUEST_CONTEXTS).size).toBe(REQUEST_CONTEXTS.length);
  });
});

describe('isRequestContext', () => {
  it.each(['C.1.1', 'C.4', 'C.4.2', 'C.11.1', 'C.13.1'])('accepts %s, a code the table defines', (code) => {
    expect(isRequestContext(code)).toBe(true);
  });

  it('rejects a well-formed code the table does not define', () => {
    expect(isRequestContext('C.99.9')).toBe(false);
  });

  it('rejects a code that differs only in case', () => {
    expect(isRequestContext('c.1.1')).toBe(false);
  });

  it.each([
    ['a number', 1.1],
    ['null', null],
    ['undefined', undefined],
    ['an object', { code: 'C.1.1' }],
  ])('rejects %s rather than assuming the value is a string', (_label, value) => {
    expect(isRequestContext(value)).toBe(false);
  });

  it("rejects C.1.6, the request context code §4.2.5.2's worked request carries", () => {
    // Not a defect. Question Q-004 in docs/spec-questions.md: the prose confines
    // the attribute to Appendix A.2's table, and that table does not define
    // C.1.6. The library follows the prose and refuses to build the example.
    expect(isRequestContext('C.1.6')).toBe(false);
  });
});

describe('RVE_1B_USER_CLIENT_AUTHENTICATION', () => {
  it('is the code §4.2.5.2 pins for the transaction', () => {
    expect(RVE_1B_USER_CLIENT_AUTHENTICATION).toBe('A.1.1');
  });
});

describe('applicationIdShape', () => {
  it("reports the prose's caret-separated form", () => {
    expect(applicationIdShape('1.2.3.4.5.6.7.8.9.1234^3^ulss8-pd-0142')).toBe(
      'caret-separated',
    );
  });

  it("reports the bare form the worked examples carry", () => {
    // Question Q-003 in docs/spec-questions.md: §4.2.5.2's own example
    // contradicts its own prose here, so both forms are attested.
    expect(applicationIdShape('1.2.3.4.5.6.7.8.9.1234')).toBe('bare');
  });

  it.each([
    ['a caret-separated value of the wrong arity', 'app^3'],
    ['a caret-separated value with an empty segment', 'app^^install'],
    ['a value that is empty', ''],
    ['a value that is only whitespace', '   '],
    ['a value carrying whitespace around a separator', 'app ^ 3 ^ install'],
  ])('reports %s as unrecognised', (_label, applicationId) => {
    expect(applicationIdShape(applicationId)).toBe('unrecognised');
  });

  it('is advisory: it reports on a value it does not recognise rather than throwing', () => {
    expect(() => applicationIdShape('^^^')).not.toThrow();
  });
});

describe('isRequestContext — a value that is not a string', () => {
  // The guard exists for values arriving from tenant configuration, where the
  // compiler was never involved: a JSON file can hand over a number as easily
  // as a code, and a lookup that assumed a string would be asking a Set about
  // something that cannot be in it.
  it.each([42, null, undefined, {}, ['C.1.1']])('rejects %s', (value) => {
    expect(isRequestContext(value)).toBe(false);
  });
});
