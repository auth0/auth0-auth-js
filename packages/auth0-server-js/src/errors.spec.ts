import { describe, expect, test } from 'vitest';
import {
  PoppyError,
  PoppyErrorCode,
  SessionExpiredError,
  StartLinkUserError,
  TokenExchangeErrorCode,
} from './errors.js';

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

describe('TokenExchangeErrorCode', () => {
  test('exposes the Session Transfer Token codes', () => {
    expect(TokenExchangeErrorCode.ACTOR_UNAVAILABLE).toBe('actor_unavailable');
    expect(TokenExchangeErrorCode.SETACTOR_REQUIRED).toBe('setactor_required');
    expect(TokenExchangeErrorCode.SESSION_TRANSFER_DISABLED).toBe('session_transfer_disabled');
  });
});

describe('PoppyErrorCode', () => {
  test('has the three codes, with the same strings as the Next.js SDK', () => {
    expect(PoppyErrorCode).toStrictEqual({
      INVALID_GUEST: 'invalid_poppy_guest',
      GUEST_NOT_SUPPORTED: 'poppy_guest_not_supported',
      SIGN_IN_REQUIRED: 'poppy_sign_in_required',
    });
  });
});

describe('PoppyError', () => {
  const codes = Object.values(PoppyErrorCode);

  test.each(codes)('sets name, code and a fixed message for %s', (code) => {
    const error = new PoppyError(code);

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('PoppyError');
    expect(error.code).toBe(code);
    expect(error.message.length).toBeGreaterThan(0);
    expect(error.reason).toBeUndefined();
  });

  test('has a different message for each code', () => {
    expect(new Set(codes.map((code) => new PoppyError(code).message)).size).toBe(codes.length);
  });

  test('keeps the reason apart from the message', () => {
    const reason = 'act.poppy_sid is missing or invalid';
    const error = new PoppyError(PoppyErrorCode.INVALID_GUEST, reason);

    expect(error.reason).toBe(reason);
    expect(error.message).not.toContain(reason);
    expect(error.message).toBe(new PoppyError(PoppyErrorCode.INVALID_GUEST).message);
  });
});
