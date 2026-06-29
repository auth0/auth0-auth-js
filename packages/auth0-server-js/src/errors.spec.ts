import { describe, expect, test } from 'vitest';
import { SessionExpiredError, StartLinkUserError } from './errors.js';

describe('StartLinkUserError', () => {
  test('sets name and code', () => {
    const error = new StartLinkUserError('link failed');

    expect(error.message).toBe('link failed');
    expect(error.name).toBe('StartLinkUserError');
    expect(error.code).toBe('start_link_user_error');
  });
});

describe('SessionExpiredError', () => {
  test('sets name, code, and default message', () => {
    const error = new SessionExpiredError();

    expect(error.name).toBe('SessionExpiredError');
    expect(error.code).toBe('session_expired');
    expect(error.message.length).toBeGreaterThan(0);
  });

  test('accepts a custom message', () => {
    const error = new SessionExpiredError('ceiling reached');

    expect(error.message).toBe('ceiling reached');
    expect(error.code).toBe('session_expired');
  });
});
