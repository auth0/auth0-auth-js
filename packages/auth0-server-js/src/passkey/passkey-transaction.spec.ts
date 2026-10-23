import { describe, expect, test } from 'vitest';
import { base64url } from 'jose';
import { PasskeyGetTokenError } from '@auth0/auth0-auth-js';
import {
  assertVerificationCodes,
  createPasskeyTransaction,
  getTransactionAfterWrongCode,
  isPasskeyTransactionData,
  isSameChallenge,
  readSignedChallenge,
  redactAuthSession,
} from './passkey-transaction.js';
import type { PasskeyTransactionData } from './passkey-transaction.js';
import type { PasskeyGetTokenApiErrorResponse } from '@auth0/auth0-auth-js';
import type { TransactionData } from '../types.js';

const clientDataFor = (challenge: string, extra: Record<string, unknown> = {}) =>
  base64url.encode(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://app.example.com', ...extra }));

describe('isPasskeyTransactionData', () => {
  const entry = {
    authSession: 'auth_session',
    challenge: 'challenge',
    domain: 'auth0.local',
    expiresAt: 1760608800,
    realm: 'db',
    organization: 'org_123',
  };

  test('accepts a complete entry, with or without realm and organization', () => {
    expect(isPasskeyTransactionData(entry)).toBe(true);
    expect(isPasskeyTransactionData({ ...entry, realm: undefined, organization: undefined })).toBe(true);
    expect(isPasskeyTransactionData({ ...entry, verificationRequired: ['email', 'phone'] })).toBe(true);
  });

  test.each([
    ['authSession', ''],
    ['authSession', undefined],
    ['challenge', undefined],
    ['challenge', 42],
    ['domain', ''],
    ['domain', undefined],
    ['expiresAt', '1760608800'],
    ['expiresAt', Number.NaN],
    ['expiresAt', Number.POSITIVE_INFINITY],
    ['expiresAt', undefined],
    ['realm', 42],
    ['organization', null],
    ['verificationRequired', 'email'],
    ['verificationRequired', [42]],
    ['verificationRequired', null],
  ])('rejects an entry whose %s is %s', (field, value) => {
    expect(isPasskeyTransactionData({ ...entry, [field]: value } as TransactionData)).toBe(false);
  });
});

describe('createPasskeyTransaction', () => {
  const fields = { authSession: 'auth_session', challenge: 'challenge', domain: 'auth0.local', expiresAt: 1760608800 };

  test('keeps the identifiers that need a code, and leaves out an empty list', () => {
    expect(createPasskeyTransaction({ ...fields, verificationRequired: ['email'] }).verificationRequired).toEqual([
      'email',
    ]);
    expect(createPasskeyTransaction({ ...fields, verificationRequired: [] })).not.toHaveProperty('verificationRequired');
    expect(createPasskeyTransaction(fields)).not.toHaveProperty('verificationRequired');
  });
});

describe('assertVerificationCodes', () => {
  const errorFor = (verification: unknown, verificationRequired: string[]) => {
    try {
      assertVerificationCodes(verification, verificationRequired);
    } catch (e: unknown) {
      return e;
    }
  };

  test.each([
    ['a code for every identifier', { email: '123456', phone: '654321' }, ['email', 'phone']],
    ['a code with spaces around it', { email: ' 123456 ' }, ['email']],
    ['a blank code for an identifier that is not listed', { email: '123456', phone: '' }, ['email']],
    ['a code that is set but is not a string, which Auth0 rejects', { email: 123456 }, ['email']],
    ['no codes when none are needed', undefined, []],
  ])('accepts %s', (_, verification, verificationRequired) => {
    expect(errorFor(verification, verificationRequired)).toBeUndefined();
  });

  test.each([
    [undefined, ['email'], 'Missing required parameter: verification.email'],
    [null, ['email'], 'Missing required parameter: verification.email'],
    [{}, ['phone'], 'Missing required parameter: verification.phone'],
    [{ email: null }, ['email'], 'Missing required parameter: verification.email'],
    // auth-js leaves a falsy value out of the request.
    [{ email: 0 }, ['email'], 'Missing required parameter: verification.email'],
    [{ phone: false }, ['phone'], 'Missing required parameter: verification.phone'],
    [{ phone: '654321' }, ['email'], 'Missing required parameter: verification.email'],
    [{ email: '123456' }, ['email', 'phone'], 'Missing required parameter: verification.phone'],
    [{ email: '' }, ['email'], '"verification.email" is not allowed to be empty'],
    [{ phone: ' \t\n' }, ['phone'], '"verification.phone" is not allowed to be empty'],
    [{ email: '' }, ['phone', 'email'], 'Missing required parameter: verification.phone'],
    [{ phone: '', email: undefined }, ['phone', 'email'], '"verification.phone" is not allowed to be empty'],
  ])('rejects %j when %j need a code: %s', (verification, verificationRequired, message) => {
    const error = errorFor(verification, verificationRequired);

    expect(error).toBeInstanceOf(PasskeyGetTokenError);
    expect((error as PasskeyGetTokenError).message).toBe(message);
  });

  test('throws an invalid_request error like the one Auth0 returns for a missing code', () => {
    const error = errorFor({}, ['email']) as PasskeyGetTokenError;

    expect(error.name).toBe('PasskeyGetTokenError');
    expect(error.code).toBe('passkey_get_token_error');
    expect(error.cause).toMatchObject({
      error: 'invalid_request',
      error_description: 'Missing required parameter: verification.email',
    });
    expect(error.isRetryable).toBe(false);
    expect(error.authSession).toBeUndefined();
    expect(error.verificationRequired).toBeUndefined();
    expect(error.statusCode).toBeUndefined();
  });
});

describe('getTransactionAfterWrongCode', () => {
  const transaction = {
    authSession: 'auth_session',
    challenge: 'challenge',
    domain: 'auth0.local',
    expiresAt: 1760608800,
    realm: 'db',
    organization: 'org_123',
    verificationRequired: ['email', 'phone'],
  };

  const wrongCode = (fields: Partial<PasskeyGetTokenApiErrorResponse> = {}) =>
    new PasskeyGetTokenError('Invalid or expired session', {
      error: 'invalid_grant',
      error_description: 'Invalid or expired session',
      auth_session: 'auth_session',
      ...fields,
    });

  test('keeps only the identifiers Auth0 still lists, and everything else', () => {
    expect(getTransactionAfterWrongCode(transaction, wrongCode({ verification_required: ['phone'] }))).toEqual({
      ...transaction,
      verificationRequired: ['phone'],
    });
  });

  test('stores the list Auth0 returns when none was stored', () => {
    const withoutList = { ...transaction, verificationRequired: undefined };

    expect(getTransactionAfterWrongCode(withoutList, wrongCode({ verification_required: ['email'] }))).toEqual({
      ...transaction,
      verificationRequired: ['email'],
    });
  });

  test('keeps the stored auth session when Auth0 returns an empty one', () => {
    const error = wrongCode({ auth_session: '', verification_required: ['phone'] });

    expect(error.isRetryable).toBe(true);
    expect(getTransactionAfterWrongCode(transaction, error)).toEqual({
      ...transaction,
      verificationRequired: ['phone'],
    });
  });

  test('keeps the stored list when Auth0 returns none', () => {
    expect(getTransactionAfterWrongCode(transaction, wrongCode({ auth_session: 'auth_session_renewed' }))).toEqual({
      ...transaction,
      authSession: 'auth_session_renewed',
    });
  });

  test.each<[string, PasskeyTransactionData, Partial<PasskeyGetTokenApiErrorResponse>]>([
    ['the same list', transaction, { verification_required: ['email', 'phone'] }],
    ['no list', transaction, {}],
    ['an empty list', transaction, { verification_required: [] }],
    ['no list for a transaction without one', { ...transaction, verificationRequired: undefined }, {}],
  ])('returns undefined for the same auth session and %s', (_, stored, fields) => {
    expect(getTransactionAfterWrongCode(stored, wrongCode(fields))).toBeUndefined();
  });

  test.each<[string, string[], Array<'email' | 'phone'>]>([
    ['other identifiers', ['email'], ['phone']],
    ['the same identifiers in another order', ['email', 'phone'], ['phone', 'email']],
  ])('counts a list of the same length with %s as a change', (_, stored, returned) => {
    const error = wrongCode({ verification_required: returned });

    expect(getTransactionAfterWrongCode({ ...transaction, verificationRequired: stored }, error)).toEqual({
      ...transaction,
      verificationRequired: returned,
    });
  });
});

describe('readSignedChallenge', () => {
  const challenge = base64url.encode(new Uint8Array([251, 255, 191, 1, 2]));

  test('reads the challenge the credential was created for', () => {
    expect(readSignedChallenge(clientDataFor(challenge))).toBe(challenge);
  });

  test('reads a clientDataJSON in padded base64, and of any length', () => {
    const clientData = JSON.stringify({ type: 'webauthn.get', challenge, extra: 'x'.repeat(100_000) });

    expect(readSignedChallenge(btoa(clientData))).toBe(challenge);
  });

  test.each([
    ['missing', undefined],
    ['not a string', 42],
    ['empty', ''],
    ['not base64url', '%%%'],
    ['not JSON', base64url.encode('not json')],
    ['JSON null', base64url.encode('null')],
    ['without a challenge', base64url.encode(JSON.stringify({ type: 'webauthn.get' }))],
    ['with an empty challenge', clientDataFor('')],
  ])('returns undefined for a clientDataJSON that is %s', (_, clientDataJSON) => {
    expect(readSignedChallenge(clientDataJSON)).toBeUndefined();
  });

  test('reads a long run of padding in linear time', () => {
    const startedAt = performance.now();

    expect(readSignedChallenge('='.repeat(100_000) + 'x')).toBeUndefined();
    expect(performance.now() - startedAt).toBeLessThan(250);
  });
});

describe('isSameChallenge', () => {
  const challenge = base64url.encode(new Uint8Array([251, 255, 191, 1, 2]));

  test('compares the challenges', () => {
    expect(isSameChallenge(challenge, challenge)).toBe(true);
    expect(isSameChallenge(challenge, base64url.encode('another challenge'))).toBe(false);
  });

  test('ignores padding and the base64 alphabet on either side', () => {
    const standard = challenge.replace(/-/g, '+').replace(/_/g, '/') + '=';

    expect(isSameChallenge(standard, challenge)).toBe(true);
    expect(isSameChallenge(challenge, standard)).toBe(true);
  });

  test('normalizes a long run of padding in linear time', () => {
    const startedAt = performance.now();

    expect(isSameChallenge('='.repeat(100_000) + 'x', challenge)).toBe(false);
    expect(performance.now() - startedAt).toBeLessThan(250);
  });
});

describe('redactAuthSession', () => {
  const retryableError = () =>
    new PasskeyGetTokenError('Invalid or expired session', {
      error: 'invalid_grant',
      error_description: 'Invalid or expired session',
      auth_session: 'auth_session_123',
      verification_required: ['email'],
    });

  test('removes the auth session and keeps everything else', () => {
    const error = retryableError();

    redactAuthSession(error);

    expect(error.authSession).toBeUndefined();
    expect(error.cause?.auth_session).toBeUndefined();
    expect(error.isRetryable).toBe(true);
    expect(error.verificationRequired).toEqual(['email']);
    expect(error.cause).toMatchObject({ error: 'invalid_grant', verification_required: ['email'] });
    expect(JSON.stringify(error)).not.toContain('auth_session_123');
  });

  test('removes the raw response body, which would contain the auth session', () => {
    const error = retryableError();
    error.body = JSON.stringify({ error: 'invalid_grant', auth_session: 'auth_session_123' });

    redactAuthSession(error);

    expect(error.body).toBeUndefined();
    expect(JSON.stringify(error)).not.toContain('auth_session_123');
  });

  test('still removes cause.auth_session when authSession cannot be deleted', () => {
    const error = retryableError();
    Object.defineProperty(error, 'authSession', { configurable: false });

    expect(() => redactAuthSession(error)).not.toThrow();
    expect(error.cause?.auth_session).toBeUndefined();
  });

  test('still removes authSession when the cause cannot be changed', () => {
    const error = retryableError();
    Object.freeze(error.cause);

    expect(() => redactAuthSession(error)).not.toThrow();
    expect(error.authSession).toBeUndefined();
  });

  test('never throws, even when reading the cause throws', () => {
    const error = retryableError();
    Object.defineProperty(error, 'cause', {
      get: () => {
        throw new Error('cause unavailable');
      },
    });

    expect(() => redactAuthSession(error)).not.toThrow();
    expect(error.authSession).toBeUndefined();
  });

  test('leaves other errors alone', () => {
    const error = Object.assign(new Error('other'), { authSession: 'auth_session_123' });

    redactAuthSession(error);

    expect(error.authSession).toBe('auth_session_123');
  });
});
