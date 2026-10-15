import { describe, expect, test } from 'vitest';
import { base64url } from 'jose';
import { PasskeyGetTokenError } from '@auth0/auth0-auth-js';
import { isCredentialForChallenge, isPasskeyTransactionData, redactAuthSession } from './passkey-transaction.js';
import type { TransactionData } from '../types.js';

const credentialFor = (challenge: string) => ({
  id: 'cred_123',
  rawId: 'cred_123',
  type: 'public-key',
  response: {
    clientDataJSON: base64url.encode(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://app.example.com' })),
  },
});

describe('isPasskeyTransactionData', () => {
  const entry = {
    kind: 'passkey',
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
  });

  test.each([
    ['kind', 'other'],
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
  ])('rejects an entry whose %s is %s', (field, value) => {
    expect(isPasskeyTransactionData({ ...entry, [field]: value } as TransactionData)).toBe(false);
  });
});

describe('isCredentialForChallenge', () => {
  const challenge = base64url.encode(new Uint8Array([251, 255, 191, 1, 2]));

  test('matches the challenge the credential was created for', () => {
    expect(isCredentialForChallenge(credentialFor(challenge), challenge)).toBe(true);
    expect(isCredentialForChallenge(credentialFor(challenge), base64url.encode('another challenge'))).toBe(false);
  });

  test('ignores padding and the base64 alphabet on either side', () => {
    const standard = challenge.replace(/-/g, '+').replace(/_/g, '/') + '=';

    expect(isCredentialForChallenge(credentialFor(standard), challenge)).toBe(true);
    expect(isCredentialForChallenge(credentialFor(challenge), standard)).toBe(true);
  });

  test('reads a clientDataJSON of any length', () => {
    const credential = credentialFor(challenge);
    credential.response.clientDataJSON = base64url.encode(
      JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://app.example.com', extra: 'x'.repeat(100_000) })
    );

    expect(isCredentialForChallenge(credential, challenge)).toBe(true);
  });

  test.each([
    ['the challenge', (hostile: string) => isCredentialForChallenge(credentialFor(challenge), hostile)],
    [
      'the clientDataJSON',
      (hostile: string) => {
        const credential = credentialFor(challenge);
        credential.response.clientDataJSON = hostile;
        return isCredentialForChallenge(credential, challenge);
      },
    ],
  ])('normalizes a long run of padding in %s in linear time', (_, check) => {
    const hostile = '='.repeat(100_000) + 'x';
    const startedAt = performance.now();

    expect(check(hostile)).toBe(false);
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
