import { describe, test, expect } from 'vitest';
import { getToken } from './token.js';
import { InvalidRequestError } from './errors.js';

describe('getToken', () => {
  const validToken = 'mF_9.B5f-4.1JqM';

  describe('Authorization header method', () => {
    test.each([
      { case: 'standard Bearer', authHeader: `Bearer ${validToken}` },
      { case: 'lowercase bearer', authHeader: `bearer ${validToken}` },
      { case: 'uppercase BEARER', authHeader: `BEARER ${validToken}` },
      { case: 'mixed case BeArEr', authHeader: `BeArEr ${validToken}` },
    ])('should extract token from $case header', ({ authHeader }) => {
      const headers = { authorization: authHeader };
      expect(getToken(headers)).toBe(validToken);
    });

    test.each([
      {
        case: 'Basic auth',
        auth: `Basic ${validToken}`,
      },
      {
        case: 'Bearer without token',
        auth: 'Bearer',
      },
      {
        case: 'non-string authorization',
        auth: 123 as unknown as string,
      },
    ])('should reject $case', ({ auth }) => {
      const headers = { authorization: auth };
      expect(() => getToken(headers)).toThrow(InvalidRequestError);
    });
  });

  describe('Query parameter method', () => {
    test('should extract token from access_token query parameter', () => {
      const headers = {};
      const query = { access_token: validToken };
      expect(getToken(headers, query)).toBe(validToken);
    });

    test.each([
      {
        case: 'non-string access_token in query',
        headers: {},
        query: { access_token: 123 as unknown as string },
      },
      {
        case: 'missing query object',
        headers: {},
        query: undefined,
      },
      {
        case: 'empty query object',
        headers: {},
        query: {},
      },
    ])('should reject when $case', ({ headers, query }) => {
      expect(() => getToken(headers, query)).toThrow(InvalidRequestError);
    });
  });

  describe('Form body method', () => {
    test.each([
      {
        case: 'standard form body with correct content-type',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        query: undefined,
        body: { access_token: validToken },
        expected: validToken,
      },
      {
        case: 'content-type with charset parameter',
        headers: {
          'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
        },
        query: {},
        body: { access_token: validToken },
        expected: validToken,
      },
      {
        case: 'case-insensitive content-type matching',
        headers: { 'content-type': 'APPLICATION/X-WWW-FORM-URLENCODED' },
        query: {},
        body: { access_token: validToken },
        expected: validToken,
      },
    ])(
      'should extract token from $case',
      ({ headers, query, body, expected }) => {
        expect(getToken(headers, query, body)).toBe(expected);
      }
    );

    test.each([
      {
        case: 'body without proper content-type',
        headers: { 'content-type': 'application/json' },
        query: {},
        body: { access_token: validToken },
      },
      {
        case: 'body with missing content-type',
        headers: {},
        query: {},
        body: { access_token: validToken },
      },
      {
        case: 'non-string access_token in body',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        query: {},
        body: { access_token: 123 as unknown as string },
      },
      {
        case: 'missing body object',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        query: {},
        body: undefined,
      },
    ])('should reject token from $case', ({ headers, query, body }) => {
      expect(() => getToken(headers, query, body)).toThrow(InvalidRequestError);
    });
  });

  describe('Multiple method validation', () => {
    test.each([
      {
        case: 'header and query',
        headers: { authorization: `Bearer ${validToken}` },
        query: { access_token: validToken },
        body: undefined,
      },
      {
        case: 'header and body',
        headers: {
          authorization: `Bearer ${validToken}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        query: {},
        body: { access_token: validToken },
      },
      {
        case: 'query and body',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        query: { access_token: validToken },
        body: { access_token: validToken },
      },
      {
        case: 'all three methods',
        headers: {
          authorization: `Bearer ${validToken}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        query: { access_token: validToken },
        body: { access_token: validToken },
      },
    ])(
      'should reject when $case both contain tokens',
      ({ headers, query, body }) => {
        expect(() => getToken(headers, query, body)).toThrow(
          InvalidRequestError
        );
      }
    );
  });

  describe('No token found scenarios', () => {
    test.each([
      {
        case: 'no token in any method',
        headers: {},
        query: {},
        body: {},
      },
      {
        case: 'only empty objects provided',
        headers: {},
        query: undefined,
        body: undefined,
      },
      {
        case: 'empty authorization header',
        headers: { authorization: '' },
        query: undefined,
        body: undefined,
      },
    ])('should throw when $case', ({ headers, query, body }) => {
      expect(() => getToken(headers, query, body)).toThrow(InvalidRequestError);
    });
  });
});
