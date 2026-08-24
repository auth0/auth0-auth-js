import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { PasswordlessClient } from './passwordless-client.js';
import { PasswordlessStartError, PasswordlessDbGetTokenError, PasswordlessChallengeError } from './errors.js';
import { MissingClientAuthError, isMfaRequiredError, type OAuth2Error } from '../errors.js';
import { TokenResponse } from '../types.js';
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
    const [, init] = customFetch.mock.calls[0]!;
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

    expect(result).toMatchObject({ authSession: 'opaque-session-token' });
    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
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

  test('200 with empty body resolves to an undefined authSession', async () => {
    // The auth_session guard was intentionally removed: we trust the server
    // contract that a 200 always carries auth_session. A contract-violating 200
    // resolves to { authSession: undefined } (and fails at the token exchange).
    server.use(
      http.post(challengeUrl, async ({ request }) => {
        challengeRequestCount += 1;
        challengeLastBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({}, { status: 200 });
      })
    );
    const client = secretClient();

    const result = await client.challengeWithEmail({ email: 'user@example.com', connection: 'db' });

    expect(result).toMatchObject({ authSession: undefined });
    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
    expect(challengeRequestCount).toBe(1);
  });

  test('200 with non-JSON body throws a distinct parse-failure PasswordlessChallengeError', async () => {
    // A 2xx with a non-JSON body means an intermediary (WAF, maintenance page,
    // proxy) answered instead of Auth0. This must surface as a diagnosable
    // PasswordlessChallengeError, not a raw SyntaxError or a misleading message.
    server.use(
      http.post(challengeUrl, async ({ request }) => {
        challengeRequestCount += 1;
        challengeLastBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.text('<html>maintenance</html>', { status: 200 });
      })
    );
    const client = secretClient();

    await expect(
      client.challengeWithEmail({ email: 'user@example.com', connection: 'db' })
    ).rejects.toMatchObject({
      name: 'PasswordlessChallengeError',
      statusCode: 200,
      message: expect.stringContaining('could not parse'),
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

    expect(result).toMatchObject({ authSession: 'opaque-session-token' });
    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
    expect(challengeLastBody).toMatchObject({
      phone_number: '+14155550100',
      connection: 'db-conn',
      allow_signup: false,
      client_secret: clientSecret,
    });
    // delivery_method is omitted when not provided (server applies its default).
    expect(challengeLastBody!).not.toHaveProperty('delivery_method');
  });

  test('delivery_method omitted when not provided', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithPhoneNumber({
      phoneNumber: '+14155550100',
      connection: 'db',
    });

    expect(challengeLastBody!).not.toHaveProperty('delivery_method');
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

  test('delivery_method text sent when explicitly provided', async () => {
    server.use(...restHandlersChallenge);
    const client = secretClient();

    await client.challengeWithPhoneNumber({
      phoneNumber: '+14155550100',
      connection: 'db',
      deliveryMethod: 'text',
    });

    expect(challengeLastBody!.delivery_method).toBe('text');
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
    const [grantType, params] = mockGrantRequest.mock.calls[0]!;
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

    const [, params] = mockGrantRequest.mock.calls[0]!;
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

    const [, params] = mockGrantRequest.mock.calls[0]!;
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

    const [, params] = mockGrantRequest.mock.calls[0]!;
    // URLSearchParams.prototype.entries() should yield exactly 2 entries
    const entries = Array.from(params.entries());
    expect(entries).toHaveLength(2);
    expect(entries).toEqual([
      ['auth_session', 'auth123'],
      ['otp', '654321'],
    ]);
  });

  test('grantRequest rejection throws PasswordlessDbGetTokenError', async () => {
    const mockGrantRequest = vi.fn().mockRejectedValue(new Error('Invalid OTP code'));
    const client = secretClient(mockGrantRequest);

    // Assert the concrete class (not just the name) so callers can rely on
    // `instanceof PasswordlessDbGetTokenError` to distinguish this from the
    // legacy PasswordlessVerifyError (email/SMS verify) flow.
    await expect(
      client.getTokenByPasswordlessDbConnection({
        authSession: 'auth123',
        otp: 'invalid',
      })
    ).rejects.toThrow(PasswordlessDbGetTokenError);

    await expect(
      client.getTokenByPasswordlessDbConnection({
        authSession: 'auth123',
        otp: 'invalid',
      })
    ).rejects.toMatchObject({
      name: 'PasswordlessDbGetTokenError',
      message: 'There was an error while trying to request a token.',
    });
  });

  test('MFA required (403 mfa_required) surfaces in cause', async () => {
    // Reject with the shape openid-client actually throws: an Error whose
    // `error` is 'mfa_required' and whose `mfa_token` / `mfa_requirements` are
    // nested under `cause`. This genuinely exercises toOAuth2Error's lifting of
    // those fields to the top level (which isMfaRequiredError depends on).
    const openIdClientError = Object.assign(new Error('MFA is required'), {
      error: 'mfa_required',
      error_description: 'MFA is required',
      cause: {
        mfa_token: 'FE...mfa123',
        mfa_requirements: { challenge: [{ type: 'otp' }] },
      },
    });
    const mockGrantRequest = vi.fn().mockRejectedValue(openIdClientError);
    const client = secretClient(mockGrantRequest);

    try {
      await client.getTokenByPasswordlessDbConnection({
        authSession: 'auth123',
        otp: '654321',
      });
      throw new Error('Expected to reject');
    } catch (error) {
      expect(error).toMatchObject({
        name: 'PasswordlessDbGetTokenError',
      });
      const errorWithCause = error as Error & { cause?: OAuth2Error };
      // mfa_token / mfa_requirements were lifted from the nested cause by toOAuth2Error.
      expect(errorWithCause.cause).toMatchObject({
        error: 'mfa_required',
        mfa_token: 'FE...mfa123',
        mfa_requirements: { challenge: [{ type: 'otp' }] },
      });
      expect(isMfaRequiredError(error)).toBe(true);
    }
  });

  test('throws PasswordlessDbGetTokenError when no grantRequest delegate is configured', async () => {
    const client = new PasswordlessClient({ domain, clientId, clientSecret });

    await expect(
      client.getTokenByPasswordlessDbConnection({ authSession: 'auth123', otp: '654321' })
    ).rejects.toMatchObject({
      name: 'PasswordlessDbGetTokenError',
      message: expect.stringContaining('Missing grant request delegate'),
    });
  });
});

// HTTP Response Metadata Tests (TCR1, TCR2, TCR3 — Phase 10)

describe('PasswordlessClient - HttpResponseMetadata (TCR1 — success path)', () => {
  afterEach(() => {
    challengeLastBody = null;
    challengeRequestCount = 0;
    server.resetHandlers();
  });

  test('T1.14: challengeWithEmail 200 — httpResponse present with status/headers', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json({ auth_session: 'session-123' }, {
          status: 200,
          headers: { 'x-request-id': 'req-email-001', 'content-type': 'application/json' }
        })
      )
    );
    const client = secretClient();

    const result = await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db-conn',
    });

    expect(result).toMatchObject({ authSession: 'session-123' });
    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
    expect(typeof result.httpResponse?.statusText).toBe('string');
    expect(result.httpResponse?.headers).toBeInstanceOf(Headers);
    expect(result.httpResponse?.headers.get('x-request-id')).toBe('req-email-001');
  });

  test('T1.15: challengeWithPhoneNumber 200 — httpResponse present with status/headers', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json({ auth_session: 'session-phone-456' }, {
          status: 200,
          headers: { 'x-request-id': 'req-phone-001' }
        })
      )
    );
    const client = secretClient();

    const result = await client.challengeWithPhoneNumber({
      phoneNumber: '+14155550100',
      connection: 'db-conn',
    });

    expect(result).toMatchObject({ authSession: 'session-phone-456' });
    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
    expect(result.httpResponse?.statusText).toBe('OK');
    expect(result.httpResponse?.headers.get('x-request-id')).toBe('req-phone-001');
  });

  test('Native Headers .get() works on challengeWithEmail httpResponse', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json({ auth_session: 'session-abc' }, {
          status: 200,
          headers: {
            'x-request-id': 'test-id-123',
            'x-rate-limit': '100',
            'retry-after': '60'
          }
        })
      )
    );
    const client = secretClient();

    const result = await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db',
    });

    expect(result.httpResponse?.headers.get('x-request-id')).toBe('test-id-123');
    expect(result.httpResponse?.headers.get('x-rate-limit')).toBe('100');
    expect(result.httpResponse?.headers.get('retry-after')).toBe('60');
    expect(typeof result.httpResponse?.headers.get).toBe('function');
  });

  test('challengeWithEmail 200 — backwards compatible (old code ignoring httpResponse works)', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json({ auth_session: 'session-xyz' }, { status: 200 })
      )
    );
    const client = secretClient();

    const result = await client.challengeWithEmail({
      email: 'user@example.com',
      connection: 'db',
    });

    // Old code pattern: access only authSession, no httpResponse
    const session: string = result.authSession;
    expect(session).toBe('session-xyz');

    // httpResponse is optional, can be accessed if needed
    const metadata = result.httpResponse;
    expect(metadata?.status).toBe(200);
  });

  test('T1.11: getTokenByPasswordlessDbConnection 200 — httpResponse present with status/statusText/headers', async () => {
    const mockGrantRequest = vi.fn(async () => {
      const response = new TokenResponse(
        'at_123',
        Math.floor(Date.now() / 1000) + 3600,
        'idt_123'
      );
      response.tokenType = 'Bearer';
      response.httpResponse = {
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'x-request-id': 'req-token-001' }),
      };
      return response;
    });
    const client = secretClient(mockGrantRequest);

    const result = await client.getTokenByPasswordlessDbConnection({
      authSession: 'FE...auth123',
      otp: '654321',
    });

    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
    expect(typeof result.httpResponse?.statusText).toBe('string');
    expect(result.httpResponse?.headers).toBeInstanceOf(Headers);
    expect(result.accessToken).toBe('at_123');
  });

  test('Native Headers .get() works on getTokenByPasswordlessDbConnection httpResponse', async () => {
    const mockGrantRequest = vi.fn(async () => {
      const response = new TokenResponse(
        'at_456',
        Math.floor(Date.now() / 1000) + 3600,
        'idt_456'
      );
      response.tokenType = 'Bearer';
      response.httpResponse = {
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'x-rate-limit': '100', 'retry-after': '60' }),
      };
      return response;
    });
    const client = secretClient(mockGrantRequest);

    const result = await client.getTokenByPasswordlessDbConnection({
      authSession: 'FE...auth456',
      otp: '123456',
    });

    expect(result.httpResponse?.headers.get('x-rate-limit')).toBe('100');
    expect(result.httpResponse?.headers.get('retry-after')).toBe('60');
    expect(typeof result.httpResponse?.headers.get).toBe('function');
  });
});

describe('PasswordlessClient - HttpResponseMetadata (TCR2 — error path)', () => {
  afterEach(() => {
    challengeLastBody = null;
    challengeRequestCount = 0;
    server.resetHandlers();
  });

  test('T2.7: challengeWithEmail 400 — error has statusCode/headers/body', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json(
          {
            error: 'invalid_request',
            error_description: 'Invalid email format',
            validation_errors: [{ field: 'email', message: 'Invalid email' }]
          },
          {
            status: 400,
            headers: {
              'x-error-id': 'err-001',
              'content-type': 'application/json'
            }
          }
        )
      )
    );
    const client = secretClient();

    try {
      await client.challengeWithEmail({
        email: 'bad-email',
        connection: 'db',
      });
      throw new Error('Expected to reject');
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessChallengeError);
      const error = e as InstanceType<typeof PasswordlessChallengeError>;
      expect(error.statusCode).toBe(400);
      expect(error.headers).toBeInstanceOf(Headers);
      expect(error.body).toBeDefined();
      expect(typeof error.body).toBe('string');
      expect(error.body).toContain('invalid_request');
      expect(error.headers?.get('x-error-id')).toBe('err-001');
      expect(error.cause?.error_description).toBe('Invalid email format');
    }
  });

  test('T2.7b: challengeWithPhoneNumber 400 — error has statusCode/headers/body', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json(
          { error: 'invalid_request', error_description: 'Phone not configured' },
          {
            status: 400,
            headers: { 'x-request-id': 'err-phone-002' }
          }
        )
      )
    );
    const client = secretClient();

    try {
      await client.challengeWithPhoneNumber({
        phoneNumber: '+14155550100',
        connection: 'sms',
      });
      throw new Error('Expected to reject');
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessChallengeError);
      const error = e as InstanceType<typeof PasswordlessChallengeError>;
      expect(error.statusCode).toBe(400);
      expect(error.headers?.get('x-request-id')).toBe('err-phone-002');
      expect(error.body).toContain('invalid_request');
    }
  });

  test('T2.11: PasswordlessChallengeError statusCode field set (required + base optional aligned)', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json(
          { error: 'too_many_requests', error_description: 'Rate limited' },
          {
            status: 429,
            headers: { 'retry-after': '30' }
          }
        )
      )
    );
    const client = secretClient();

    try {
      await client.challengeWithEmail({
        email: 'user@example.com',
        connection: 'db',
      });
      throw new Error('Expected to reject');
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessChallengeError);
      const error = e as InstanceType<typeof PasswordlessChallengeError>;
      // Both fields should be present and aligned
      expect(error.statusCode).toBe(429); // Required field from ctor param
      expect(error.headers?.get('retry-after')).toBe('30');
    }
  });

  test('Native Headers .get() works on error.headers', async () => {
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json(
          { error: 'unauthorized', error_description: 'Invalid connection' },
          {
            status: 401,
            headers: { 'www-authenticate': 'Bearer realm="auth0"' }
          }
        )
      )
    );
    const client = secretClient();

    try {
      await client.challengeWithEmail({
        email: 'user@example.com',
        connection: 'invalid',
      });
      throw new Error('Expected to reject');
    } catch (e) {
      if (e instanceof PasswordlessChallengeError) {
        expect(e.headers?.get('www-authenticate')).toContain('Bearer');
        expect(typeof e.headers?.get).toBe('function');
      }
    }
  });

  test('Error body is raw string (not parsed JSON, not prettified)', async () => {
    const errorBody = { error: 'invalid_request', error_description: 'Code expired' };
    server.use(
      http.post(challengeUrl, () =>
        HttpResponse.json(errorBody, { status: 400 })
      )
    );
    const client = secretClient();

    try {
      await client.challengeWithEmail({
        email: 'user@example.com',
        connection: 'db',
      });
      throw new Error('Expected to reject');
    } catch (e) {
      if (e instanceof PasswordlessChallengeError) {
        expect(typeof e.body).toBe('string');
        expect(e.body).toContain('invalid_request');
        expect(e.body).not.toContain('\n'); // Not prettified
        // Verify it can be parsed by caller if needed
        const parsed = JSON.parse(e.body!);
        expect(parsed.error).toBe('invalid_request');
      }
    }
  });
});

describe('PasswordlessClient - void methods (no success metadata)', () => {
  afterEach(() => {
    lastBody = null;
    lastHeaders = null;
    requestCount = 0;
    server.resetHandlers();
  });

  test('sendEmail 200 — void return, no httpResponse metadata', async () => {
    server.use(
      http.post(startUrl, () =>
        HttpResponse.json({}, {
          status: 200,
          headers: { 'x-request-id': 'req-void-001' }
        })
      )
    );
    const client = secretClient();

    const result = await client.sendEmail({
      email: 'user@example.com',
      send: 'code',
    });

    // void method returns undefined
    expect(result).toBeUndefined();
  });

  test('sendSms 200 — void return, no httpResponse metadata', async () => {
    server.use(
      http.post(startUrl, () =>
        HttpResponse.json({}, {
          status: 200,
          headers: { 'x-request-id': 'req-void-002' }
        })
      )
    );
    const client = secretClient();

    const result = await client.sendSms({
      phoneNumber: '+14155550100',
    });

    // void method returns undefined
    expect(result).toBeUndefined();
  });

  test('sendEmail error still carries error metadata', async () => {
    server.use(
      http.post(startUrl, () =>
        HttpResponse.json(
          { error: 'invalid_request', error_description: 'Invalid email' },
          {
            status: 400,
            headers: { 'x-error-id': 'err-void-001' }
          }
        )
      )
    );
    const client = secretClient();

    try {
      await client.sendEmail({
        email: 'bad-email',
      });
      throw new Error('Expected to reject');
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessStartError);
      const error = e as InstanceType<typeof PasswordlessStartError>;
      expect(error.statusCode).toBe(400);
      expect(error.headers?.get('x-error-id')).toBe('err-void-001');
      expect(error.body).toBeDefined();
    }
  });
});

describe('PasswordlessClient - HttpResponseMetadata (TCR3 — concurrency)', () => {
  afterEach(() => {
    challengeLastBody = null;
    challengeRequestCount = 0;
    server.resetHandlers();
  });

  test('T3.1: concurrent challengeWithEmail calls — each result has correct httpResponse', async () => {
    // Branch on request content (email), not call order: Promise.allSettled does not
    // guarantee which request the mock server observes first, so keying off a counter
    // is racy. Content-based routing keeps the concurrency-isolation assertion sound.
    server.use(
      http.post(challengeUrl, async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        challengeLastBody = body;
        const isGood = body.email === 'good@example.com';
        const requestId = isGood ? 'req-concurrent-good' : 'req-concurrent-bad';

        if (isGood) {
          return HttpResponse.json(
            { auth_session: 'session-200' },
            { status: 200, headers: { 'x-request-id': requestId } }
          );
        }
        return HttpResponse.json(
          { error: 'invalid_request', error_description: 'Bad request' },
          { status: 400, headers: { 'x-request-id': requestId } }
        );
      })
    );
    const client = secretClient();

    const [success, error] = await Promise.allSettled([
      client.challengeWithEmail({ email: 'good@example.com', connection: 'db' }),
      client.challengeWithEmail({ email: 'bad@example.com', connection: 'db' }),
    ]);

    // Success call
    expect(success.status).toBe('fulfilled');
    if (success.status === 'fulfilled') {
      expect(success.value.httpResponse?.status).toBe(200);
      expect(success.value.httpResponse?.headers.get('x-request-id')).toBe('req-concurrent-good');
      expect(success.value.authSession).toBe('session-200');
    }

    // Error call
    expect(error.status).toBe('rejected');
    if (error.status === 'rejected') {
      expect(error.reason.statusCode).toBe(400);
      expect(error.reason.headers?.get('x-request-id')).toBe('req-concurrent-bad');
      // Verify NO cross-leakage (critical test for O#4 fix)
      expect(error.reason.statusCode).not.toBe(200);
    }
  });

  test('T3.2: multiple parallel calls — each captures own request-id header', async () => {
    let callCount = 0;
    server.use(
      http.post(challengeUrl, () => {
        callCount += 1;
        const requestId = `req-${callCount}`;
        return HttpResponse.json(
          { auth_session: `session-${callCount}` },
          {
            status: 200,
            headers: { 'x-request-id': requestId }
          }
        );
      })
    );
    const client = secretClient();

    const [result1, result2] = await Promise.all([
      client.challengeWithEmail({ email: 'email1@example.com', connection: 'db' }),
      client.challengeWithEmail({ email: 'email2@example.com', connection: 'db' }),
    ]);

    // Each call captures its own x-request-id
    expect(result1.httpResponse?.headers.get('x-request-id')).toBe('req-1');
    expect(result2.httpResponse?.headers.get('x-request-id')).toBe('req-2');
    expect(result1.authSession).toBe('session-1');
    expect(result2.authSession).toBe('session-2');
  });

  test('T3.3: concurrent error calls — each error has correct statusCode', async () => {
    let callCount = 0;
    server.use(
      http.post(challengeUrl, () => {
        callCount += 1;
        if (callCount === 1) {
          return HttpResponse.json(
            { error: 'too_many_requests', error_description: 'Rate limited' },
            { status: 429, headers: { 'retry-after': '30' } }
          );
        }
        return HttpResponse.json(
          { error: 'unauthorized', error_description: 'Invalid connection' },
          { status: 401, headers: { 'x-error-id': 'err-unauth' } }
        );
      })
    );
    const client = secretClient();

    const calls = await Promise.allSettled([
      client.challengeWithEmail({ email: 'user1@example.com', connection: 'db' }),
      client.challengeWithEmail({ email: 'user2@example.com', connection: 'db' }),
    ]);

    const [result1, result2] = calls as [PromiseSettledResult<{ statusCode?: number }>, PromiseSettledResult<{ statusCode?: number }>];

    expect(result1.status).toBe('rejected');
    expect(result2.status).toBe('rejected');

    // Each error has correct status (no cross-leakage)
    const errors = [
      result1.status === 'rejected' ? result1.reason : null,
      result2.status === 'rejected' ? result2.reason : null,
    ].filter((e): e is { statusCode?: number } => e !== null);
    const statuses = errors.map(e => e.statusCode).sort((a, b) => (a ?? 0) - (b ?? 0));

    expect(statuses).toContain(401);
    expect(statuses).toContain(429);
    expect(statuses[0]).not.toBe(statuses[1]); // Different values
  });
});
