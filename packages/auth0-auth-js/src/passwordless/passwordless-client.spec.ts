import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { PasswordlessClient } from './passwordless-client.js';
import { PasswordlessStartError } from './errors.js';
import { MissingClientAuthError, isMfaRequiredError, type OAuth2Error } from '../errors.js';
import { PASSWORDLESS_OTP_GRANT_TYPE } from './passwordless-client.js';
import type { GrantRequestFn } from './types.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const startUrl = `https://${domain}/passwordless/start`;

const exportPrivateKeyToPem = async (privateKey: CryptoKey): Promise<string> => {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  const keyBase64 = Buffer.from(pkcs8).toString('base64');
  const keyLines = keyBase64.match(/.{1,64}/g) ?? [keyBase64];
  return `-----BEGIN PRIVATE KEY-----\n${keyLines.join('\n')}\n-----END PRIVATE KEY-----`;
};

const generateRsaKeyPair = () =>
  crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: { name: 'SHA-256' } },
    true,
    ['sign', 'verify']
  ) as Promise<CryptoKeyPair>;

// Captures the last request body/headers seen by the /passwordless/start handler.
let lastBody: Record<string, unknown> | null;
let lastHeaders: Headers | null;
let requestCount: number;

const restHandlers = [
  http.post(startUrl, async ({ request }) => {
    requestCount += 1;
    lastHeaders = request.headers;
    lastBody = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({}, { status: 200 });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  lastBody = null;
  lastHeaders = null;
  requestCount = 0;
  server.resetHandlers();
});
afterAll(() => server.close());

const secretClient = (grantRequest?: GrantRequestFn) =>
  new PasswordlessClient({
    domain,
    clientId,
    clientSecret,
    grantRequest: grantRequest ?? vi.fn().mockResolvedValue({}),
  });

describe('PasswordlessClient - sendEmail', () => {
  test('UT-1: sends code (default) with client_secret', async () => {
    await secretClient().sendEmail({ email: 'user@example.com', send: 'code' });

    expect(lastBody).toMatchObject({
      client_id: clientId,
      connection: 'email',
      email: 'user@example.com',
      send: 'code',
      client_secret: clientSecret,
    });
  });

  test('UT-2: sends link with authParams (camelCase key, no auth_params)', async () => {
    const authParams = { redirect_uri: 'https://app/cb', scope: 'openid', state: 'xyz' };
    await secretClient().sendEmail({ email: 'user@example.com', send: 'link', authParams });

    expect(lastBody!.send).toBe('link');
    expect(lastBody!.authParams).toEqual(authParams);
    expect(lastBody!).not.toHaveProperty('auth_params');
  });

  test('UT-3: link WITHOUT authParams resolves and omits the key', async () => {
    server.use(http.post(startUrl, () => new HttpResponse(null, { status: 204 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com', send: 'link' })).resolves.toBeUndefined();
  });

  test('UT-28: forwards language as the x-request-language header, not a body field', async () => {
    await secretClient().sendEmail({ email: 'user@example.com', send: 'code', language: 'fr-CA' });

    expect(lastHeaders!.get('x-request-language')).toBe('fr-CA');
    expect(lastBody!).not.toHaveProperty('language');
  });

  test('UT-28b: omits the x-request-language header when language is not provided', async () => {
    await secretClient().sendEmail({ email: 'user@example.com', send: 'code' });

    expect(lastHeaders!.has('x-request-language')).toBe(false);
  });

  test('UT-4: accepts 204 No Content', async () => {
    server.use(http.post(startUrl, () => new HttpResponse(null, { status: 204 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).resolves.toBeUndefined();
  });

  test('UT-5: accepts 200 with empty object body', async () => {
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).resolves.toBeUndefined();
  });

  test('UT-6: throws PasswordlessStartError on 400 with error body', async () => {
    server.use(
      http.post(startUrl, () =>
        HttpResponse.json({ error: 'invalid_request', error_description: 'Invalid email' }, { status: 400 })
      )
    );
    await expect(secretClient().sendEmail({ email: 'bad' })).rejects.toMatchObject({
      name: 'PasswordlessStartError',
      cause: { error_description: 'Invalid email' },
    });
  });

  test('UT-7: throws PasswordlessStartError on 401 unauthorized_client', async () => {
    server.use(http.post(startUrl, () => HttpResponse.json({ error: 'unauthorized_client' }, { status: 401 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-8: throws PasswordlessStartError on non-JSON error body (no cause)', async () => {
    server.use(http.post(startUrl, () => new HttpResponse('boom', { status: 400 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).rejects.toMatchObject({
      name: 'PasswordlessStartError',
      cause: undefined,
    });
  });

  test('UT-9: throws PasswordlessStartError on network error', async () => {
    server.use(http.post(startUrl, () => HttpResponse.error()));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-10: injects client_assertion for private_key_jwt with correct JWT claims', async () => {
    const { privateKey } = await generateRsaKeyPair();
    const pem = await exportPrivateKeyToPem(privateKey);
    const client = new PasswordlessClient({ domain, clientId, clientAssertionSigningKey: pem, clientAssertionSigningAlg: 'RS256' });

    await client.sendEmail({ email: 'user@example.com' });

    expect(lastBody!.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    const jwt = lastBody!.client_assertion as string;
    expect(typeof jwt).toBe('string');
    expect(decodeProtectedHeader(jwt).alg).toBe('RS256');
    const claims = decodeJwt(jwt);
    expect(claims.iss).toBe(clientId);
    expect(claims.sub).toBe(clientId);
    expect(claims.aud).toBe(`https://${domain}/`);
    expect(typeof claims.jti).toBe('string');
    const ttl = (claims.exp as number) - (claims.iat as number);
    expect(ttl).toBe(120);
    expect(lastBody!).not.toHaveProperty('client_secret');
  });

  test('UT-11: client_assertion accepts a CryptoKey input', async () => {
    const { privateKey } = await generateRsaKeyPair();
    const client = new PasswordlessClient({ domain, clientId, clientAssertionSigningKey: privateKey });

    await client.sendEmail({ email: 'user@example.com' });

    const jwt = lastBody!.client_assertion as string;
    expect(typeof jwt).toBe('string');
    expect(decodeJwt(jwt).aud).toBe(`https://${domain}/`);
  });

  test('UT-12: throws MissingClientAuthError when no client auth configured', async () => {
    const client = new PasswordlessClient({ domain, clientId });
    await expect(client.sendEmail({ email: 'user@example.com' })).rejects.toThrow(MissingClientAuthError);
  });

  test('UT-13: useMtls produces no body auth fields', async () => {
    const client = new PasswordlessClient({ domain, clientId, useMtls: true });
    await client.sendEmail({ email: 'user@example.com' });

    expect(lastBody!).not.toHaveProperty('client_secret');
    expect(lastBody!).not.toHaveProperty('client_assertion');
  });
});

describe('PasswordlessClient - sendSms', () => {
  test('UT-14: sends SMS with E.164 phone; no delivery_method', async () => {
    await secretClient().sendSms({ phoneNumber: '+14155550100' });

    expect(lastBody).toMatchObject({
      client_id: clientId,
      connection: 'sms',
      phone_number: '+14155550100',
      client_secret: clientSecret,
    });
    expect(lastBody!).not.toHaveProperty('delivery_method');
    expect(lastBody!).not.toHaveProperty('deliveryMethod');
  });

  test('UT-15: throws PasswordlessStartError on non-E.164 phone before request', async () => {
    await expect(secretClient().sendSms({ phoneNumber: '12025551234' })).rejects.toThrow(/E\.164/);
    expect(requestCount).toBe(0);
  });

  test('UT-16: accepts +44; rejects missing-+ before request', async () => {
    await expect(secretClient().sendSms({ phoneNumber: '+447911123456' })).resolves.toBeUndefined();
    expect(requestCount).toBe(1);
    await expect(secretClient().sendSms({ phoneNumber: '447911123456' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-16b: forwards language as the x-request-language header, not a body field', async () => {
    await secretClient().sendSms({ phoneNumber: '+14155550100', language: 'pt-BR' });

    expect(lastHeaders!.get('x-request-language')).toBe('pt-BR');
    expect(lastBody!).not.toHaveProperty('language');
  });

  test('UT-17: throws PasswordlessStartError on API error', async () => {
    server.use(http.post(startUrl, () => HttpResponse.json({ error: 'sms_provider_error' }, { status: 400 })));
    await expect(secretClient().sendSms({ phoneNumber: '+14155550100' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-18: telemetry-wrapped customFetch is used and headers pass through', async () => {
    const customFetch = vi.fn((...args: Parameters<typeof fetch>) => fetch(...args));
    const client = new PasswordlessClient({ domain, clientId, clientSecret, customFetch });

    await client.sendSms({ phoneNumber: '+14155550100' });

    expect(customFetch).toHaveBeenCalledTimes(1);
    const [, init] = customFetch.mock.calls[0];
    expect((init as RequestInit).method).toBe('POST');
  });
});

// Challenge methods: challengeWithEmail and challengeWithPhoneNumber

let challengeLastBody: Record<string, unknown> | null;
let challengeRequestCount: number;

const challengeUrl = `https://${domain}/otp/challenge`;

const restHandlersChallenge = [
  http.post(challengeUrl, async ({ request }) => {
    challengeRequestCount += 1;
    challengeLastBody = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({ auth_session: 'opaque-session-token' }, { status: 200 });
  }),
];

describe('PasswordlessClient - challengeWithEmail', () => {
  afterEach(() => {
    challengeLastBody = null;
    challengeRequestCount = 0;
    server.resetHandlers();
  });

  test('Happy path email challenge', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    const result = await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db-conn',
    });

    expect(result).toEqual({ authSession: 'opaque-session-token' });
    expect(challengeLastBody).toMatchObject({
      client_id: clientId,
      email: 'user@example.com',
      connection: 'db-conn',
      allow_signup: false,
      client_secret: clientSecret,
    });
  });

  test('allowSignup true in wire', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db',
      allowSignup: true,
    });

    expect(challengeLastBody!.allow_signup).toBe(true);
    expect(challengeLastBody!).not.toHaveProperty('allowSignup');
  });

  test('allowSignup defaults to false', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db',
    });

    expect(challengeLastBody!.allow_signup).toBe(false);
  });

  test('Client secret injected', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db',
    });

    expect(challengeLastBody!.client_secret).toBe(clientSecret);
  });

  test('MissingClientAuthError when no auth configured', async () => {
    const client = new PasswordlessClient({ domain, clientId });

    await expect(
      client.challengeWithEmail({ email: 'user@example.com', connection: 'db' })
    ).rejects.toThrow(MissingClientAuthError);

    expect(challengeRequestCount).toBe(0);
  });

  test('200 without auth_session throws PasswordlessChallengeError', async () => {
    server.use(
      http.post(challengeUrl, async ({ request }) => {
        challengeRequestCount += 1;
        challengeLastBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({}, { status: 200 });
      })
    );
    const client = secretClient();

    await expect(
      client.challengeWithEmail({ email: 'user@example.com', connection: 'db' })
    ).rejects.toMatchObject({
      name: 'PasswordlessChallengeError',
      statusCode: 200,
      message: expect.stringContaining('auth_session'),
    });
    expect(challengeRequestCount).toBe(1);
  });

  test('non-2xx response throws PasswordlessChallengeError with statusCode and validationErrors', async () => {
    server.use(
      http.post(challengeUrl, async ({ request }) => {
        challengeRequestCount += 1;
        challengeLastBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(
          {
            error: 'invalid_request',
            error_description: 'The connection is not configured for email OTP.',
            validation_errors: [{ field: 'connection', message: 'email_otp is not enabled' }],
          },
          { status: 400 }
        );
      })
    );
    const client = secretClient();

    await expect(
      client.challengeWithEmail({ email: 'user@example.com', connection: 'db' })
    ).rejects.toMatchObject({
      name: 'PasswordlessChallengeError',
      statusCode: 400,
      message: 'The connection is not configured for email OTP.',
      cause: { error: 'invalid_request' },
      validationErrors: [{ field: 'connection', message: 'email_otp is not enabled' }],
    });
    expect(challengeRequestCount).toBe(1);
  });
});

describe('PasswordlessClient - challengeWithPhoneNumber', () => {
  afterEach(() => {
    challengeLastBody = null;
    challengeRequestCount = 0;
    server.resetHandlers();
  });

  test('Happy path phone challenge', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    const result = await client.challengeWithPhoneNumber({
      phoneNumber: '+14155550100',
      connection: 'db-conn',
    });

    expect(result).toEqual({ authSession: 'opaque-session-token' });
    expect(challengeLastBody).toMatchObject({
      phone_number: '+14155550100',
      connection: 'db-conn',
      delivery_method: 'text',
      allow_signup: false,
      client_secret: clientSecret,
    });
  });

  test('delivery_method defaults to text', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithPhoneNumber({
      phoneNumber: '+14155550100',
      connection: 'db',
    });

    expect(challengeLastBody!.delivery_method).toBe('text');
  });

  test('delivery_method voice explicit', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithPhoneNumber({
      phoneNumber: '+14155550100',
      connection: 'db',
      deliveryMethod: 'voice',
    });

    expect(challengeLastBody!.delivery_method).toBe('voice');
  });

  test('E.164 invalid - no plus prefix throws synchronously', async () => {
    const client = secretClient();

    await expect(
      client.challengeWithPhoneNumber({ phoneNumber: '14155550100', connection: 'db' })
    ).rejects.toMatchObject({
      name: 'PasswordlessChallengeError',
      statusCode: 0,
      message: expect.stringContaining('E.164'),
    });

    expect(challengeRequestCount).toBe(0);
  });

  test('E.164 valid minimum boundary +10', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    const result = await client.challengeWithPhoneNumber({
      phoneNumber: '+10',
      connection: 'db',
    });

    expect(challengeRequestCount).toBe(1);
    expect(challengeLastBody!.phone_number).toBe('+10');
    expect(result.authSession).toBeDefined();
  });

  test('E.164 valid maximum boundary +123456789012345', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    const result = await client.challengeWithPhoneNumber({
      phoneNumber: '+123456789012345',
      connection: 'db',
    });

    expect(challengeRequestCount).toBe(1);
    expect(challengeLastBody!.phone_number).toBe('+123456789012345');
    expect(result.authSession).toBeDefined();
  });
});

// Token exchange: getTokenByPasswordlessDbConnection

describe('PasswordlessClient - getTokenByPasswordlessDbConnection', () => {
  test('Happy path token exchange', async () => {
    const mockGrantRequest = vi.fn().mockResolvedValue({
      access_token: 'at_123',
      token_type: 'Bearer',
      expires_in: 3600,
    });
    const client = secretClient(mockGrantRequest);

    const result = await client.getTokenByPasswordlessDbConnection({
      authSession: 'FE...auth123',
      otp: '654321',
    });

    expect(mockGrantRequest).toHaveBeenCalledTimes(1);
    const [grantType, params] = mockGrantRequest.mock.calls[0];
    expect(grantType).toBe(PASSWORDLESS_OTP_GRANT_TYPE);
    expect(params.get('auth_session')).toBe('FE...auth123');
    expect(params.get('otp')).toBe('654321');
    expect(result).toEqual({ access_token: 'at_123', token_type: 'Bearer', expires_in: 3600 });
  });

  test('scope appended to params', async () => {
    const mockGrantRequest = vi.fn().mockResolvedValue({
      access_token: 'at_123',
      token_type: 'Bearer',
    });
    const client = secretClient(mockGrantRequest);

    await client.getTokenByPasswordlessDbConnection({
      authSession: 'auth123',
      otp: '654321',
      scope: 'openid profile email',
    });

    const [, params] = mockGrantRequest.mock.calls[0];
    expect(params.get('scope')).toBe('openid profile email');
    expect(params.get('auth_session')).toBe('auth123');
    expect(params.get('otp')).toBe('654321');
  });

  test('audience appended to params', async () => {
    const mockGrantRequest = vi.fn().mockResolvedValue({
      access_token: 'at_123',
      token_type: 'Bearer',
    });
    const client = secretClient(mockGrantRequest);

    await client.getTokenByPasswordlessDbConnection({
      authSession: 'auth123',
      otp: '654321',
      audience: 'https://api.example.com',
    });

    const [, params] = mockGrantRequest.mock.calls[0];
    expect(params.get('audience')).toBe('https://api.example.com');
    expect(params.get('auth_session')).toBe('auth123');
    expect(params.get('otp')).toBe('654321');
  });

  test('scope and audience both omitted', async () => {
    const mockGrantRequest = vi.fn().mockResolvedValue({
      access_token: 'at_123',
      token_type: 'Bearer',
    });
    const client = secretClient(mockGrantRequest);

    await client.getTokenByPasswordlessDbConnection({
      authSession: 'auth123',
      otp: '654321',
    });

    const [, params] = mockGrantRequest.mock.calls[0];
    // URLSearchParams.prototype.entries() should yield exactly 2 entries
    const entries = Array.from(params.entries());
    expect(entries).toHaveLength(2);
    expect(entries).toEqual([
      ['auth_session', 'auth123'],
      ['otp', '654321'],
    ]);
  });

  test('grantRequest rejection throws PasswordlessVerifyError', async () => {
    const mockGrantRequest = vi.fn().mockRejectedValue(new Error('Invalid OTP code'));
    const client = secretClient(mockGrantRequest);

    await expect(
      client.getTokenByPasswordlessDbConnection({
        authSession: 'auth123',
        otp: 'invalid',
      })
    ).rejects.toMatchObject({
      name: 'PasswordlessVerifyError',
      message: 'There was an error while trying to request a token.',
    });
  });

  test('MFA required (403 mfa_required) surfaces in cause', async () => {
    const mockGrantRequest = vi.fn().mockRejectedValue({
      error: 'mfa_required',
      error_description: 'MFA is required',
      cause: {
        mfa_token: 'FE...mfa123',
      },
    });
    const client = secretClient(mockGrantRequest);

    try {
      await client.getTokenByPasswordlessDbConnection({
        authSession: 'auth123',
        otp: '654321',
      });
      throw new Error('Expected to reject');
    } catch (error) {
      expect(error).toMatchObject({
        name: 'PasswordlessVerifyError',
      });
      const errorWithCause = error as Error & { cause?: OAuth2Error };
      expect(errorWithCause.cause).toMatchObject({
        error: 'mfa_required',
        mfa_token: 'FE...mfa123',
      });
      expect(isMfaRequiredError(error)).toBe(true);
    }
  });

  test('throws PasswordlessVerifyError when no grantRequest delegate is configured', async () => {
    const client = new PasswordlessClient({ domain, clientId, clientSecret });

    await expect(
      client.getTokenByPasswordlessDbConnection({ authSession: 'auth123', otp: '654321' })
    ).rejects.toMatchObject({
      name: 'PasswordlessVerifyError',
      message: expect.stringContaining('Missing grant request delegate'),
    });
  });
});
