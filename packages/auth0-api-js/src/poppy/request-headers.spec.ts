import { describe, expect, test } from 'vitest';

import { readPoppyRequestHeaders, type PoppyRequestHeaders } from './request-headers.js';

// What the reader returns for a record that has none of the three headers.
const NONE: PoppyRequestHeaders = {
  session: undefined,
  sessionMalformed: false,
  authorization: undefined,
  authorizationMalformed: false,
  dpop: undefined,
};

/** What the reader returns when the record holds the given headers and nothing else. */
function only(headers: Partial<PoppyRequestHeaders>): PoppyRequestHeaders {
  return { ...NONE, ...headers };
}

/** Passes a record that the type does not allow, as a JavaScript caller or a framework can. */
function read(headers: unknown): PoppyRequestHeaders {
  return readPoppyRequestHeaders(headers as Parameters<typeof readPoppyRequestHeaders>[0]);
}

describe('readPoppyRequestHeaders', () => {
  test('reads a record with none of the headers', () => {
    expect(read({})).toStrictEqual(NONE);
  });

  test('reads the three headers of one record, each on its own', () => {
    expect(read({ 'poppy-session': 'a.b.c', authorization: 'Bearer t', dpop: 'p1' })).toStrictEqual(
      only({ session: 'a.b.c', authorization: 'Bearer t', dpop: 'p1' })
    );
    // A malformed Session does not change what the other two give, and the other way round.
    expect(
      read({ 'poppy-session': ['a.b.c', 'd.e.f'], authorization: ['Bearer t'], dpop: ['p1', 'p2'] })
    ).toStrictEqual(only({ sessionMalformed: true, authorization: 'Bearer t', dpop: 'p1, p2' }));
    expect(read({ 'poppy-session': 'a.b.c', authorization: ['Bearer a', 'Bearer b'] })).toStrictEqual(
      only({ session: 'a.b.c', authorizationMalformed: true })
    );
    expect(read({ 'poppy-session': 'a.b.c', authorization: 'Bearer a, Bearer b', dpop: 'p1' })).toStrictEqual(
      only({ session: 'a.b.c', authorizationMalformed: true, dpop: 'p1' })
    );
  });

  test('returns a new object for each call', () => {
    expect(read({})).not.toBe(read({}));
  });

  describe('Poppy-Session', () => {
    test.each<[string, Record<string, unknown>]>([
      ['the usual name', { 'Poppy-Session': 'a.b.c' }],
      ['lower case', { 'poppy-session': 'a.b.c' }],
      ['upper case and an array of one', { 'POPPY-SESSION': ['a.b.c'] }],
      ['mixed case', { 'pOpPy-SeSsIoN': 'a.b.c' }],
      ['spaces and tabs around the value', { 'poppy-session': ' \t a.b.c\t ' }],
      ['an array of one with spaces around the value', { 'poppy-session': ['\ta.b.c '] }],
      ['other headers around it', { host: 'api.example.com', 'poppy-session': 'a.b.c', accept: '*/*' }],
    ])('reads one value from %s', (_label, headers) => {
      expect(read(headers)).toStrictEqual(only({ session: 'a.b.c' }));
    });

    test.each<[string, Record<string, unknown>]>([
      ['an empty record', {}],
      ['other headers only', { host: 'api.example.com', accept: '*/*' }],
      ['the header set to undefined', { 'poppy-session': undefined }],
      ['an empty array', { 'poppy-session': [] }],
      ['a name that has a prefix', { 'x-poppy-session': 'a.b.c' }],
      ['a name that has a suffix', { 'poppy-session-id': 'a.b.c' }],
      ['a name that has a space at the end', { 'poppy-session ': 'a.b.c' }],
      ['a name that is shorter', { 'poppy-sessio': 'a.b.c' }],
      ['the value of a header as the name', { 'a.b.c': 'poppy-session' }],
    ])('finds no header in %s', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test.each<[string, Record<string, unknown>]>([
      ['two values in an array', { 'poppy-session': ['a.b.c', 'd.e.f'] }],
      ['the same value twice in an array', { 'poppy-session': ['a.b.c', 'a.b.c'] }],
      ['three values in an array', { 'poppy-session': ['a.b.c', 'd.e.f', 'g.h.i'] }],
      ['two values joined with a comma and a space', { 'poppy-session': 'a.b.c, d.e.f' }],
      ['two values joined with a comma', { 'poppy-session': 'a.b.c,d.e.f' }],
      ['a comma at the end', { 'poppy-session': 'a.b.c,' }],
      ['a comma at the start', { 'poppy-session': ',a.b.c' }],
      ['a comma and nothing else', { 'poppy-session': ',' }],
      ['an array of one with a comma in it', { 'poppy-session': ['a.b.c, d.e.f'] }],
      ['an empty value', { 'poppy-session': '' }],
      ['an array of one empty value', { 'poppy-session': [''] }],
      ['spaces only', { 'poppy-session': '   ' }],
      ['tabs only', { 'poppy-session': '\t\t' }],
      ['a value and an empty value in an array', { 'poppy-session': ['a.b.c', ''] }],
      ['an empty value and a value in an array', { 'poppy-session': ['', 'a.b.c'] }],
      ['two keys that differ in case', { 'Poppy-Session': 'a.b.c', 'poppy-session': 'a.b.c' }],
      ['two keys that differ in case, with other values', { 'Poppy-Session': 'a.b.c', 'POPPY-SESSION': 'd.e.f' }],
      ['two keys that differ in case, one an array of one', { 'Poppy-Session': ['a.b.c'], 'poppy-session': 'd.e.f' }],
      ['two keys that differ in case, one empty', { 'Poppy-Session': 'a.b.c', 'poppy-session': '' }],
      ['three keys that differ in case', { 'Poppy-Session': 'a', 'poppy-session': 'b', 'POPPY-SESSION': 'c' }],
      [
        'two keys that differ in case, with other headers between them',
        { 'Poppy-Session': 'a.b.c', host: 'h', 'poppy-session': 'd.e.f' },
      ],
    ])('is malformed with %s, and gives no value', (_label, headers) => {
      expect(read(headers)).toStrictEqual(only({ sessionMalformed: true }));
    });

    test.each<[string, Record<string, unknown>]>([
      ['a number', { 'poppy-session': 42 }],
      ['null', { 'poppy-session': null }],
      ['true', { 'poppy-session': true }],
      ['an object', { 'poppy-session': { 0: 'a.b.c' } }],
      ['an array with no string', { 'poppy-session': [42, null, undefined, {}] }],
    ])('ignores %s as the value', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test.each<[string, Record<string, unknown>]>([
      ['a number', { 'poppy-session': ['a.b.c', 42] }],
      ['undefined', { 'poppy-session': [undefined, 'a.b.c'] }],
      ['an object', { 'poppy-session': [{ toString: () => 'x' }, 'a.b.c'] }],
      ['a header with a value that is not a string', { 'Poppy-Session': 'a.b.c', 'poppy-session': 42 }],
    ])('ignores a value that is not a string, with %s next to a string', (_label, headers) => {
      expect(read(headers)).toStrictEqual(only({ session: 'a.b.c' }));
    });

    test.each<[string, string]>([
      ['a line feed', '\na.b.c'],
      ['a carriage return', 'a.b.c\r'],
      ['a vertical tab', '\va.b.c'],
      ['a form feed', 'a.b.c\f'],
      ['a no-break space', '\u00a0a.b.c'],
      ['an ideographic space', 'a.b.c\u3000'],
      ['a space inside', 'a.b c.d'],
    ])('keeps %s in the value, because only spaces and tabs are optional whitespace', (_label, value) => {
      // The value is not one of the malformed cases. It stays as it came, and the parser of the Session JWT rejects it.
      expect(read({ 'poppy-session': value })).toStrictEqual(only({ session: value }));
    });

    test.each<[string, string]>([
      ['a line feed', '\n'],
      ['a no-break space', '\u00a0'],
    ])('does not read a value of %s only as empty', (_label, value) => {
      expect(read({ 'poppy-session': value })).toStrictEqual(only({ session: value }));
    });
  });

  describe('Authorization', () => {
    test.each<[string, Record<string, unknown>]>([
      ['the usual name', { Authorization: 'Bearer abc' }],
      ['lower case', { authorization: 'Bearer abc' }],
      ['upper case and an array of one', { AUTHORIZATION: ['Bearer abc'] }],
      ['spaces and tabs around the value', { authorization: '\t Bearer abc  ' }],
      ['other headers around it', { host: 'api.example.com', authorization: 'Bearer abc', accept: '*/*' }],
    ])('reads one value from %s', (_label, headers) => {
      expect(read(headers)).toStrictEqual(only({ authorization: 'Bearer abc' }));
    });

    // A header whose only value is empty is read as a header that was not sent.
    test.each<[string, Record<string, unknown>]>([
      ['an empty value', { authorization: '' }],
      ['spaces and tabs only', { authorization: '  \t' }],
      ['an array of one empty value', { authorization: [''] }],
      ['an array of one value of spaces', { AUTHORIZATION: [' '] }],
    ])('reads %s as a header that was not sent, so it is not malformed', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test.each<[string, Record<string, unknown>]>([
      ['an empty record', {}],
      ['the header set to undefined', { authorization: undefined }],
      ['an empty array', { authorization: [] }],
      ['a name that has a prefix', { 'x-authorization': 'Bearer abc' }],
      ['a name that is shorter', { authorizatio: 'Bearer abc' }],
      ['a value that is not a string', { authorization: 42 }],
    ])('finds no header in %s', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test.each<[string, Record<string, unknown>]>([
      ['two values in an array', { authorization: ['Bearer a', 'Bearer b'] }],
      ['the same value twice in an array', { authorization: ['Bearer a', 'Bearer a'] }],
      ['three values in an array', { authorization: ['Bearer a', 'Bearer b', 'Bearer c'] }],
      ['two keys that differ in case', { Authorization: 'Bearer a', authorization: 'Bearer b' }],
      ['two keys that differ in case, one an array of one', { Authorization: ['Bearer a'], AUTHORIZATION: 'Bearer b' }],
      ['two keys that differ in case, with the same value', { Authorization: 'Bearer a', authorization: 'Bearer a' }],
      // With more than one value an empty one counts as a value, so a header that was sent twice is never read as sent
      // once.
      ['an empty value next to a value in an array', { authorization: ['Bearer a', ''] }],
      ['a value after an empty value in an array', { authorization: ['', 'Bearer a'] }],
      ['two empty values in an array', { authorization: ['', ''] }],
      ['two keys that differ in case, one empty', { Authorization: 'Bearer a', authorization: '' }],
      ['two keys that differ in case, both empty', { Authorization: '', authorization: '' }],
      // A Bearer or DPoP credential has no comma, so a comma means that several headers were joined into one text, as a
      // Fetch API record does with a header that was sent twice.
      ['two credentials joined with a comma and a space', { authorization: 'Bearer a, Bearer b' }],
      ['two credentials joined with a comma', { authorization: 'Bearer a,Bearer b' }],
      ['a comma at the end', { authorization: 'Bearer a,' }],
      ['a comma at the start', { authorization: ',Bearer a' }],
      ['a comma and nothing else', { authorization: ',' }],
      ['a comma after the spaces and tabs around the value are trimmed', { authorization: ' \tBearer a, Bearer b\t ' }],
      ['an array of one with a comma in it', { authorization: ['Bearer a, Bearer b'] }],
      ['a scheme that has commas, which this API does not take', { authorization: 'Digest username="a", realm="b"' }],
    ])('is malformed with %s, and gives no value', (_label, headers) => {
      expect(read(headers)).toStrictEqual(only({ authorizationMalformed: true }));
    });
  });

  describe('DPoP', () => {
    test.each<[string, Record<string, unknown>]>([
      ['the usual name', { DPoP: 'p1' }],
      ['lower case', { dpop: 'p1' }],
      ['upper case and an array of one', { DPOP: ['p1'] }],
      ['spaces and tabs around the value', { dpop: ' \tp1\t ' }],
      ['other headers around it', { host: 'api.example.com', dpop: 'p1', accept: '*/*' }],
    ])('reads one value from %s', (_label, headers) => {
      expect(read(headers)).toStrictEqual(only({ dpop: 'p1' }));
    });

    test.each<[string, Record<string, unknown>, string]>([
      ['an array of two', { dpop: ['p1', 'p2'] }, 'p1, p2'],
      ['an array of three', { dpop: ['p1', 'p2', 'p3'] }, 'p1, p2, p3'],
      ['two keys that differ in case', { DPoP: 'p1', dpop: 'p2' }, 'p1, p2'],
      ['two keys that differ in case, one an array of two', { DPoP: ['p1', 'p2'], dpop: 'p3' }, 'p1, p2, p3'],
      ['two keys that differ in case, in the other order', { dpop: 'p3', DPoP: ['p1', 'p2'] }, 'p3, p1, p2'],
      ['an array of two with spaces and tabs around the values', { dpop: [' p1\t', '\tp2 '] }, 'p1, p2'],
      ['a value that is joined already', { dpop: 'p1, p2' }, 'p1, p2'],
      ['two empty values', { dpop: ['', ''] }, ', '],
      // With more than one value an empty one counts as a value, so the joined text is still not a proof.
      ['a value and an empty value', { dpop: ['p1', ''] }, 'p1, '],
      ['an empty value and a value', { dpop: ['', 'p1'] }, ', p1'],
      ['two keys that differ in case, one empty', { DPoP: 'p1', dpop: '' }, 'p1, '],
      ['two keys that differ in case, both empty', { DPoP: '', dpop: '' }, ', '],
    ])('joins the values of %s with a comma and a space', (_label, headers, joined) => {
      // More than one proof is not an error here: `verifyAccessToken` rejects the joined text, which is not a JWT.
      expect(read(headers)).toStrictEqual(only({ dpop: joined }));
    });

    // A header whose only value is empty is read as a header that was not sent.
    test.each<[string, Record<string, unknown>]>([
      ['an empty value', { dpop: '' }],
      ['spaces and tabs only', { DPoP: ' \t ' }],
      ['an array of one empty value', { dpop: [''] }],
      ['an array of one value of spaces', { DPOP: [' '] }],
    ])('reads %s as a header that was not sent', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test.each<[string, Record<string, unknown>]>([
      ['an empty record', {}],
      ['the header set to undefined', { dpop: undefined }],
      ['an empty array', { dpop: [] }],
      ['a name that has a prefix', { 'x-dpop': 'p1' }],
      ['a name that has a suffix', { 'dpop-nonce': 'p1' }],
      ['a value that is not a string', { dpop: 42 }],
    ])('finds no header in %s', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test('never flags the values as malformed', () => {
      expect(read({ dpop: ['p1', 'p2'] })).toMatchObject({ sessionMalformed: false, authorizationMalformed: false });
    });
  });

  // A Fetch API request gives its headers through `Object.fromEntries(request.headers)`. The names come in lower
  // case, and a header that was sent twice is one value with the two joined by a comma and a space.
  describe('a record made with Object.fromEntries from a Fetch API Headers object', () => {
    test('has the three headers, which are read', () => {
      const headers = new Headers({ 'Poppy-Session': 'a.b.c', Authorization: 'Bearer t', DPoP: 'p1' });

      expect(Object.keys(Object.fromEntries(headers)).sort()).toEqual(['authorization', 'dpop', 'poppy-session']);
      expect(read(Object.fromEntries(headers))).toStrictEqual(
        only({ session: 'a.b.c', authorization: 'Bearer t', dpop: 'p1' })
      );
    });

    test('has a Poppy-Session header that was sent twice as one value with a comma, which is malformed', () => {
      const headers = new Headers([
        ['Poppy-Session', 'a.b.c'],
        ['poppy-session', 'd.e.f'],
      ]);

      expect(Object.fromEntries(headers)).toEqual({ 'poppy-session': 'a.b.c, d.e.f' });
      expect(read(Object.fromEntries(headers))).toStrictEqual(only({ sessionMalformed: true }));
    });

    test('has a DPoP header that was sent twice as one value, which stays joined for the token step to refuse', () => {
      const headers = new Headers([
        ['DPoP', 'p1'],
        ['dpop', 'p2'],
      ]);

      expect(read(Object.fromEntries(headers))).toStrictEqual(only({ dpop: 'p1, p2' }));
    });

    test('has an Authorization header that was sent twice as one value with a comma, which is malformed', () => {
      // A Bearer or DPoP credential has no comma, so the joined text is two headers and not one token.
      const headers = new Headers([
        ['Authorization', 'Bearer t1'],
        ['authorization', 'Bearer t2'],
      ]);

      expect(Object.fromEntries(headers)).toEqual({ authorization: 'Bearer t1, Bearer t2' });
      expect(read(Object.fromEntries(headers))).toStrictEqual(only({ authorizationMalformed: true }));
    });

    test('has an Authorization header and a DPoP header with no value, which read as not sent', () => {
      const headers = new Headers({ Authorization: '', DPoP: ' ' });

      expect(Object.fromEntries(headers)).toEqual({ authorization: '', dpop: '' });
      expect(read(Object.fromEntries(headers))).toStrictEqual(NONE);
    });
  });

  describe('records that are not what the type says', () => {
    test.each<[string, unknown]>([
      ['undefined', undefined],
      ['null', null],
      ['a string', 'poppy-session: a.b.c'],
      ['a number', 42],
      ['true', true],
      ['an array of header names', ['poppy-session', 'authorization']],
    ])('finds no header in %s, and does not throw', (_label, headers) => {
      expect(read(headers)).toStrictEqual(NONE);
    });

    test('finds no header in names that an object has already', () => {
      // `__proto__` is made by `JSON.parse`, because an object literal would set the prototype with it.
      const headers = JSON.parse(
        '{"__proto__":"x","constructor":"y","toString":"z","hasOwnProperty":"w","valueOf":"v"}'
      );

      expect(read(headers)).toStrictEqual(NONE);
    });

    test('ignores the headers a record inherits, and reads the ones it owns', () => {
      const inherited = Object.create({ 'poppy-session': 'x.y.z', authorization: 'Bearer x', dpop: 'x' });
      inherited['poppy-session'.toUpperCase()] = 'a.b.c';

      expect(read(inherited)).toStrictEqual(only({ session: 'a.b.c' }));
    });

    test('does not change the record or its arrays, and works on frozen ones', () => {
      const sessions = Object.freeze(['a.b.c']);
      const proofs = Object.freeze([' p1 ', 'p2']);
      const headers = Object.freeze({ 'poppy-session': sessions, dpop: proofs, authorization: ' Bearer t ' });

      expect(read(headers)).toStrictEqual(only({ session: 'a.b.c', dpop: 'p1, p2', authorization: 'Bearer t' }));
      expect(headers).toStrictEqual({ 'poppy-session': ['a.b.c'], dpop: [' p1 ', 'p2'], authorization: ' Bearer t ' });
    });

    test('reads a value with a very long run of spaces, which a pattern that trims could take minutes over', () => {
      // A trim with a quadratic pattern does not finish inside the time limit of the test.
      const spaces = ' '.repeat(100_000);

      expect(read({ 'poppy-session': `${spaces}a.b.c${spaces}` })).toStrictEqual(only({ session: 'a.b.c' }));
      expect(read({ 'poppy-session': `a${spaces}b` })).toStrictEqual(only({ session: `a${spaces}b` }));
      expect(read({ 'poppy-session': spaces })).toStrictEqual(only({ sessionMalformed: true }));
    });
  });
});
