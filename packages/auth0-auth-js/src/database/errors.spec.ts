import { expect, test } from 'vitest';
import { SignUpError, ChangePasswordError } from './errors.js';

test('SignUpError carries code, name, message, cause', () => {
  const cause = { error: 'invalid_signup', error_description: 'Invalid sign up' };
  const err = new SignUpError('Invalid sign up', cause);
  expect(err).toBeInstanceOf(Error);
  expect(err.name).toBe('SignUpError');
  expect(err.code).toBe('signup_error');
  expect(err.message).toBe('Invalid sign up');
  expect(err.cause).toEqual(cause);
});

test('ChangePasswordError carries code and name', () => {
  const err = new ChangePasswordError('boom');
  expect(err.name).toBe('ChangePasswordError');
  expect(err.code).toBe('change_password_error');
  expect(err.cause).toBeUndefined();
});
