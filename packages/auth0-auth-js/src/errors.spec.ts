import { describe, it, expect } from 'vitest';
import { TokenByCodeError } from './errors.js';
import { PasswordlessStartError, PasswordlessVerifyError, PasswordlessChallengeError } from './passwordless/errors.js';
import { SignUpError, ChangePasswordError } from './database/errors.js';

describe('ApiError statusCode/headers fields', () => {
  it('statusCode and headers are undefined by default', () => {
    const err = new TokenByCodeError('msg');
    expect(err.statusCode).toBeUndefined();
    expect(err.headers).toBeUndefined();
  });

  it('statusCode can be set post-construction', () => {
    const err = new TokenByCodeError('msg');
    err.statusCode = 401;
    expect(err.statusCode).toBe(401);
  });

  it('headers can be set post-construction and values are readable', () => {
    const err = new TokenByCodeError('msg');
    err.headers = new Headers({ 'x-custom': 'val' });
    expect(err.headers.get('x-custom')).toBe('val');
  });

  it('set-then-throw-then-catch preserves statusCode and headers', () => {
    const throwAndCatch = () => {
      const err = new TokenByCodeError('oops');
      err.statusCode = 429;
      err.headers = new Headers({ 'retry-after': '60' });
      throw err;
    };
    expect(throwAndCatch).toThrow(TokenByCodeError);
    try {
      throwAndCatch();
    } catch (e) {
      expect(e).toBeInstanceOf(TokenByCodeError);
      const err = e as TokenByCodeError;
      expect(err.statusCode).toBe(429);
      expect(err.headers?.get('retry-after')).toBe('60');
    }
  });
});

describe('PasswordlessError statusCode/headers fields', () => {
  it('PasswordlessStartError: statusCode and headers are undefined by default', () => {
    const err = new PasswordlessStartError('msg');
    expect(err.statusCode).toBeUndefined();
    expect(err.headers).toBeUndefined();
  });

  it('PasswordlessVerifyError: statusCode and headers can be set post-construction', () => {
    const err = new PasswordlessVerifyError('msg');
    err.statusCode = 403;
    err.headers = new Headers({ 'x-req-id': 'abc' });
    expect(err.statusCode).toBe(403);
    expect(err.headers.get('x-req-id')).toBe('abc');
  });
});

describe('PasswordlessChallengeError headers field', () => {
  it('accepts headers as 5th constructor argument', () => {
    const headers = new Headers({ 'x-req-id': 'xyz' });
    const err = new PasswordlessChallengeError('msg', 400, undefined, undefined, headers);
    expect(err.statusCode).toBe(400);
    expect(err.headers?.get('x-req-id')).toBe('xyz');
  });

  it('headers defaults to undefined when not passed', () => {
    const err = new PasswordlessChallengeError('msg', 400);
    expect(err.headers).toBeUndefined();
  });

  it('statusCode is 0 for network errors (sentinel convention)', () => {
    const err = new PasswordlessChallengeError('network error', 0);
    expect(err.statusCode).toBe(0);
  });
});

describe('DatabaseError (SignUpError / ChangePasswordError) statusCode/headers fields', () => {
  it('SignUpError: statusCode and headers are undefined by default', () => {
    const err = new SignUpError('msg');
    expect(err.statusCode).toBeUndefined();
    expect(err.headers).toBeUndefined();
  });

  it('ChangePasswordError: statusCode and headers can be set post-construction', () => {
    const err = new ChangePasswordError('msg');
    err.statusCode = 400;
    err.headers = new Headers({ 'content-type': 'application/json' });
    expect(err.statusCode).toBe(400);
    expect(err.headers.get('content-type')).toBe('application/json');
  });
});
