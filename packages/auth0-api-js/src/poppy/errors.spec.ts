import { describe, expect, test } from 'vitest';

import { ALLOWED_DPOP_ALGORITHMS, buildChallenges } from '../dpop-api.js';
import { AuthError, InvalidConfigurationError } from '../errors.js';
import type { InvalidSessionReason } from '../types.js';
import {
  DEFAULT_RETRY_AFTER_SECONDS,
  INVALID_SESSION_MESSAGES,
  POPPY_UNAVAILABLE_MESSAGE,
  SESSION_ENDED_MESSAGE,
  SIGN_IN_REQUIRED_MESSAGE,
} from './constants.js';
import { InvalidSessionError, PoppyUnavailableError, SessionEndedError, SignInRequiredError } from './errors.js';

const INVALID_SESSION_REASONS = Object.keys(INVALID_SESSION_MESSAGES) as InvalidSessionReason[];

function errorFrom(action: () => unknown): Error {
  try {
    action();
  } catch (error) {
    return error as Error;
  }
  throw new Error('Expected the action to throw.');
}

describe('InvalidSessionError', () => {
  test('has a default message for each of the 11 reasons', () => {
    expect([...INVALID_SESSION_REASONS].sort()).toEqual([
      'agent_metadata_invalid',
      'agent_not_allowed',
      'ath_mismatch',
      'claim_mismatch',
      'delegation_invalid',
      'iat_out_of_window',
      'malformed_session',
      'missing_session',
      'session_mismatch',
      'signature_invalid',
      'token_client_mismatch',
    ]);
    for (const reason of INVALID_SESSION_REASONS) {
      expect(INVALID_SESSION_MESSAGES[reason]).not.toBe('');
    }
  });

  test.each(INVALID_SESSION_REASONS)('%s | is a 400 invalid_session AuthError with its default message', (reason) => {
    const error = new InvalidSessionError(reason);

    expect(error).toBeInstanceOf(AuthError);
    expect(error).toBeInstanceOf(InvalidSessionError);
    expect(error.name).toBe('InvalidSessionError');
    expect(error.code).toBe('invalid_session');
    expect(error.statusCode).toBe(400);
    expect(error.reason).toBe(reason);
    expect(error.message).toBe(INVALID_SESSION_MESSAGES[reason]);
    expect(error.headers).toBeUndefined();
  });

  test('uses the given message instead of the default', () => {
    const error = new InvalidSessionError('claim_mismatch', 'The htu is not the URL of this API.');

    expect(error.reason).toBe('claim_mismatch');
    expect(error.message).toBe('The htu is not the URL of this API.');
  });

  test('keeps an empty message as given', () => {
    expect(new InvalidSessionError('claim_mismatch', '').message).toBe('');
  });
});

describe('SessionEndedError', () => {
  test('is a 400 session_ended AuthError with the default message', () => {
    const error = new SessionEndedError();

    expect(error).toBeInstanceOf(AuthError);
    expect(error).toBeInstanceOf(SessionEndedError);
    expect(error.name).toBe('SessionEndedError');
    expect(error.code).toBe('session_ended');
    expect(error.statusCode).toBe(400);
    expect(error.message).toBe(SESSION_ENDED_MESSAGE);
    expect(error.headers).toBeUndefined();
  });

  test('uses the given message instead of the default', () => {
    expect(new SessionEndedError('This cart was closed.').message).toBe('This cart was closed.');
  });
});

describe('SignInRequiredError', () => {
  test('is a 401 sign_in_required AuthError with the default message and a scope challenge', () => {
    const error = new SignInRequiredError({ scope: 'orders:write' });

    expect(error).toBeInstanceOf(AuthError);
    expect(error).toBeInstanceOf(SignInRequiredError);
    expect(error.name).toBe('SignInRequiredError');
    expect(error.code).toBe('sign_in_required');
    expect(error.statusCode).toBe(401);
    expect(error.message).toBe(SIGN_IN_REQUIRED_MESSAGE);
    expect(error.scope).toBe('orders:write');
    expect(error.headers).toEqual({
      'www-authenticate': ['Bearer realm="api", scope="orders:write"', 'DPoP scope="orders:write", algs="ES256"'],
    });
    expect(error.headers).toEqual(buildChallenges('allowed', ALLOWED_DPOP_ALGORITHMS, { scope: 'orders:write' }));
  });

  test('joins a scope list with spaces', () => {
    const error = new SignInRequiredError({ scope: ['orders:write', 'orders:read'] });

    expect(error.scope).toBe('orders:write orders:read');
    expect(error.headers).toEqual({
      'www-authenticate': [
        'Bearer realm="api", scope="orders:write orders:read"',
        'DPoP scope="orders:write orders:read", algs="ES256"',
      ],
    });
  });

  test('takes a space-separated scope string as it is', () => {
    const error = new SignInRequiredError({ scope: 'orders:write orders:read' });

    expect(error.scope).toBe('orders:write orders:read');
    expect(error.headers).toEqual(new SignInRequiredError({ scope: ['orders:write', 'orders:read'] }).headers);
  });

  test.each([
    ['a string with extra spaces', '  orders:write   orders:read '],
    ['a list entry with two scopes and an empty entry', ['orders:write orders:read', '']],
    ['list entries with extra spaces', [' orders:write ', '  orders:read']],
    ['a list with a blank entry between the scopes', ['orders:write', ' ', 'orders:read']],
  ])('%s | gives the scopes joined by single spaces', (_label, scope) => {
    const error = new SignInRequiredError({ scope });

    expect(error.scope).toBe('orders:write orders:read');
    expect(error.headers).toEqual({
      'www-authenticate': [
        'Bearer realm="api", scope="orders:write orders:read"',
        'DPoP scope="orders:write orders:read", algs="ES256"',
      ],
    });
  });

  test.each([
    ['allowed', ['Bearer realm="api", scope="a"', 'DPoP scope="a", algs="ES256"']],
    ['required', ['DPoP scope="a", algs="ES256"']],
    ['disabled', ['Bearer realm="api", scope="a"']],
  ] as const)('dpopMode "%s" | builds the matching challenges', (dpopMode, challenges) => {
    const error = new SignInRequiredError({ scope: 'a', dpopMode });

    expect(error.headers).toEqual({ 'www-authenticate': challenges });
  });

  test('uses the given message instead of the default', () => {
    const error = new SignInRequiredError({ scope: 'a', message: 'Sign in to place an order.' });

    expect(error.message).toBe('Sign in to place an order.');
  });

  describe('scope validation (RFC 6749 section 3.3)', () => {
    test.each([
      ['a double quote', 'bad"scope'],
      ['a double quote in the second scope', 'orders:write bad"scope'],
      ['an empty string', ''],
      ['only spaces', '   '],
      ['an empty list', []],
      ['a list of empty and blank entries', ['', ' ']],
      ['a list with a double quote', ['orders:write', 'bad"scope']],
      ['a backslash', String.raw`orders\write`],
      ['a tab, because only spaces separate scopes', 'orders:write\torders:read'],
      ['a line break and a second header', 'orders:write\r\nSet-Cookie: session=1'],
      ['a non-ASCII character', 'ordérs:write'],
      ['the DEL character', 'orders:write\x7F'],
    ])('rejects %s', (_label, scope) => {
      expect(() => new SignInRequiredError({ scope })).toThrow(InvalidConfigurationError);
      expect(() => new SignInRequiredError({ scope })).toThrow(/^Invalid poppy configuration: /);
    });

    test('does not repeat the rejected scope in the message', () => {
      const error = errorFrom(() => new SignInRequiredError({ scope: 'secret"scope' }));

      expect(error.message).toMatch(/^Invalid poppy configuration: /);
      expect(error.message).not.toContain('secret');
    });

    test('accepts exactly the printable ASCII except double quote and backslash, with space as the separator', () => {
      const accepted: number[] = [];
      for (let code = 0; code < 128; code++) {
        try {
          new SignInRequiredError({ scope: `a${String.fromCharCode(code)}b` });
          accepted.push(code);
        } catch (error) {
          expect(error).toBeInstanceOf(InvalidConfigurationError);
        }
      }

      // A scope is %x21 / %x23-5B / %x5D-7E characters. %x20 is not one of them: it separates two scopes.
      const expected = Array.from({ length: 128 }, (_, code) => code).filter(
        (code) => code === 0x20 || code === 0x21 || (code >= 0x23 && code <= 0x5b) || (code >= 0x5d && code <= 0x7e)
      );
      expect(accepted).toEqual(expected);
      expect(new SignInRequiredError({ scope: 'a b' }).scope).toBe('a b');
    });

    test.each(['https://api.example.com/orders.read', 'urn:example:scope', 'read:orders', 'openid', '!', '~', '[]'])(
      'accepts the scope token %s',
      (scope) => {
        expect(new SignInRequiredError({ scope }).scope).toBe(scope);
      }
    );
  });
});

describe('PoppyUnavailableError', () => {
  test('is a 503 temporarily_unavailable AuthError that asks to retry in 30 seconds', () => {
    const error = new PoppyUnavailableError();

    expect(error).toBeInstanceOf(AuthError);
    expect(error).toBeInstanceOf(PoppyUnavailableError);
    expect(error.name).toBe('PoppyUnavailableError');
    expect(error.code).toBe('temporarily_unavailable');
    expect(error.statusCode).toBe(503);
    expect(error.message).toBe(POPPY_UNAVAILABLE_MESSAGE);
    expect(error.retryAfter).toBe(30);
    expect(error.retryAfter).toBe(DEFAULT_RETRY_AFTER_SECONDS);
    expect(error.headers).toEqual({ 'retry-after': '30' });
  });

  test('uses the given message and retry delay', () => {
    const error = new PoppyUnavailableError('The agent host timed out.', 120);

    expect(error.message).toBe('The agent host timed out.');
    expect(error.retryAfter).toBe(120);
    expect(error.headers).toEqual({ 'retry-after': '120' });
  });

  test('falls back to the default delay when only a message is given', () => {
    const error = new PoppyUnavailableError('The agent host timed out.');

    expect(error.retryAfter).toBe(30);
    expect(error.headers).toEqual({ 'retry-after': '30' });
  });
});
