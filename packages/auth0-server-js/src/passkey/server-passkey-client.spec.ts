import { expect, test, afterAll, afterEach, beforeAll, vi, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AuthClient } from '@auth0/auth0-auth-js';
import { ServerClient } from '../server-client.js';
// The error classes and types come from the package entry point on purpose, so the tests also prove
// that `instanceof` works with the SDK's own re-exports.
import { PasskeyGetTokenError, PasskeyRegisterError } from '../index.js';
import type { PasskeyVerificationCodes, PasskeyVerificationIdentifier } from '../index.js';
import { ServerPasskeyClient } from './server-passkey-client.js';
import { isPasskeyTransactionData } from './passkey-transaction.js';
import { TransactionSlot } from '../store/transaction-slot.js';
import { generateToken, jwks } from '../test-utils/tokens.js';
import { DefaultStateStore } from '../test-utils/default-state-store.js';
import { DefaultTransactionStore } from '../test-utils/default-transaction-store.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';

let idToken: string;

const buildOpenIdConfiguration = (customDomain: string) => ({
  issuer: `https://${customDomain}/`,
  authorization_endpoint: `https://${customDomain}/authorize`,
  token_endpoint: `https://${customDomain}/custom/token`,
  end_session_endpoint: `https://${customDomain}/logout`,
  pushed_authorization_request_endpoint: `https://${customDomain}/pushed-authorize`,
  jwks_uri: `https://${customDomain}/.well-known/jwks.json`,
});

// The API returns snake_case; the sub-client maps it to the camelCase SDK shape.
const registerApiResponse = {
  auth_session: 'auth_session_123',
  authn_params_public_key: {
    challenge: 'challenge_123',
    rp: { id: domain, name: 'Test' },
    user: { id: 'user_id', name: 'user@example.com', displayName: 'User' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000,
  },
};

const challengeApiResponse = {
  auth_session: 'auth_session_456',
  authn_params_public_key: {
    challenge: 'challenge_456',
    rpId: domain,
    timeout: 60000,
    userVerification: 'preferred',
  },
};

const fakePasskeyCredential = {
  id: 'cred_123',
  rawId: 'cred_123',
  type: 'public-key',
  response: {
    clientDataJSON: 'fake_client_data',
    authenticatorData: 'fake_authenticator_data',
    signature: 'fake_signature',
  },
};

const buildTokenResponse = () => ({
  access_token: 'passkey_access_token',
  id_token: idToken,
  refresh_token: 'passkey_refresh_token',
  token_type: 'Bearer',
  expires_in: 86400,
  scope: 'openid profile email',
});

/**
 * Reads the request body as a key/value map. The passkey grant is sent as JSON by the
 * SDK's passkey fetch shim; every other grant is form-encoded.
 */
const readTokenRequestBody = async (request: Request) => {
  const isJson = (request.headers.get('content-type') ?? '').includes('application/json');
  return isJson
    ? new Map(Object.entries((await request.json()) as Record<string, unknown>))
    : await request.formData();
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(buildOpenIdConfiguration(domain));
  }),

  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),

  // Passkey: Register
  http.post(`https://${domain}/passkey/register`, () => {
    return HttpResponse.json(registerApiResponse);
  }),

  // Passkey: Challenge
  http.post(`https://${domain}/passkey/challenge`, () => {
    return HttpResponse.json(challengeApiResponse);
  }),

  // Passkey: GetToken
  http.post(`https://${domain}/custom/token`, async ({ request }) => {
    const body = await readTokenRequestBody(request);

    if (body.get('grant_type') === 'urn:okta:params:oauth:grant-type:webauthn') {
      return HttpResponse.json(buildTokenResponse());
    }

    return HttpResponse.json({ error: 'unsupported_grant_type' }, { status: 400 });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  idToken = await generateToken(domain, 'sub_123', clientId);
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

const makeClient = (domainOption: string | (() => Promise<string>) = domain) =>
  new ServerClient({
    domain: domainOption,
    clientId,
    clientSecret,
    transactionStore: new DefaultTransactionStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
    stateStore: new DefaultStateStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
  });

describe('ServerPasskeyClient', () => {
  test('exposes a passkey sub-client with register, challenge, and getToken', () => {
    const sc = makeClient();
    expect(sc.passkey).toBeDefined();
    expect(typeof sc.passkey.register).toBe('function');
    expect(typeof sc.passkey.challenge).toBe('function');
    expect(typeof sc.passkey.getToken).toBe('function');
  });

  describe('per-request options (RequestOptions)', () => {
    // Each assertion reads the header off the request MSW actually received, so it only
    // passes when requestOptions travels from `ServerClient.passkey` into the outbound
    // fetch. Asserting the returned value alone would still pass if requestOptions were
    // dropped on the floor.
    const captureHeaderOn = (path: string, respond: () => Response, header = 'x-request-tag') => {
      const seen: (string | null)[] = [];
      server.use(http.post(`https://${domain}${path}`, ({ request }) => {
        seen.push(request.headers.get(header));
        return respond();
      }));
      return seen;
    };

    const captureRegisterHeader = (header?: string) =>
      captureHeaderOn('/passkey/register', () => HttpResponse.json(registerApiResponse), header);

    const captureChallengeHeader = () =>
      captureHeaderOn('/passkey/challenge', () => HttpResponse.json(challengeApiResponse));

    const captureTokenHeader = (header?: string) =>
      captureHeaderOn('/custom/token', () => HttpResponse.json(buildTokenResponse()), header);

    // A per-request customFetch also carries the token-endpoint discovery and JWKS
    // requests, so match on the URL rather than on the call count.
    const calledWith = (spy: ReturnType<typeof vi.fn>, fragment: string) =>
      spy.mock.calls.some(([input]) => String(input).includes(fragment));

    const getTokenOptions = { authSession: 'auth_session_456', credential: fakePasskeyCredential };

    test('passkey.register forwards per-request headers to the outbound request', async () => {
      const seen = captureRegisterHeader();

      const res = await makeClient().passkey.register({ email: 'user@example.com', name: 'User' }, undefined, {
        headers: { 'X-Request-Tag': 'register-1' },
      });

      expect(res.authSession).toBe('auth_session_123');
      expect(seen).toEqual(['register-1']);
    });

    test('passkey.register sends no per-request header when requestOptions is omitted', async () => {
      const seen = captureRegisterHeader();

      // The forwarded call first, the bare call second: the pair proves the header is
      // carried when supplied and that omitting requestOptions stays backward compatible.
      await makeClient().passkey.register({ email: 'user@example.com', name: 'User' }, undefined, {
        headers: { 'X-Request-Tag': 'register-2' },
      });
      const res = await makeClient().passkey.register({ email: 'user@example.com', name: 'User' });

      expect(res.authSession).toBe('auth_session_123');
      expect(seen).toEqual(['register-2', null]);
    });

    test('passkey.register forwards a per-request customFetch', async () => {
      const perRequestFetch = vi.fn().mockImplementation(fetch);

      await makeClient().passkey.register({ email: 'user@example.com', name: 'User' }, undefined, {
        customFetch: perRequestFetch,
      });

      expect(calledWith(perRequestFetch, '/passkey/register')).toBe(true);
    });

    test('passkey.register forwards an already-aborted per-request signal', async () => {
      const seen = captureRegisterHeader();
      const controller = new AbortController();
      controller.abort();

      await expect(
        makeClient().passkey.register({ email: 'user@example.com', name: 'User' }, undefined, {
          signal: controller.signal,
        })
      ).rejects.toThrowError();
      expect(seen).toEqual([]);
    });

    test('passkey.register forwards requestOptions in resolver mode', async () => {
      const seen = captureRegisterHeader();

      await makeClient(async () => domain).passkey.register(
        { email: 'user@example.com', name: 'User' },
        undefined,
        { headers: { 'X-Request-Tag': 'register-resolver' } }
      );

      expect(seen).toEqual(['register-resolver']);
    });

    test('passkey.challenge forwards per-request headers to the outbound request', async () => {
      const seen = captureChallengeHeader();

      const res = await makeClient().passkey.challenge(undefined, undefined, {
        headers: { 'X-Request-Tag': 'challenge-1' },
      });

      expect(res.authSession).toBe('auth_session_456');
      expect(seen).toEqual(['challenge-1']);
    });

    test('passkey.challenge sends no per-request header when requestOptions is omitted', async () => {
      const seen = captureChallengeHeader();

      await makeClient().passkey.challenge(undefined, undefined, {
        headers: { 'X-Request-Tag': 'challenge-2' },
      });
      const res = await makeClient().passkey.challenge();

      expect(res.authSession).toBe('auth_session_456');
      expect(seen).toEqual(['challenge-2', null]);
    });

    test('passkey.challenge forwards a per-request customFetch', async () => {
      const perRequestFetch = vi.fn().mockImplementation(fetch);

      await makeClient().passkey.challenge(undefined, undefined, { customFetch: perRequestFetch });

      expect(calledWith(perRequestFetch, '/passkey/challenge')).toBe(true);
    });

    test('passkey.challenge forwards an already-aborted per-request signal', async () => {
      const seen = captureChallengeHeader();
      const controller = new AbortController();
      controller.abort();

      await expect(
        makeClient().passkey.challenge(undefined, undefined, { signal: controller.signal })
      ).rejects.toThrowError();
      expect(seen).toEqual([]);
    });

    test('passkey.getToken forwards per-request headers to the token request', async () => {
      const seen = captureTokenHeader();

      await makeClient().passkey.getToken(getTokenOptions, undefined, {
        headers: { 'X-Request-Tag': 'token-1' },
      });

      expect(seen).toEqual(['token-1']);
    });

    test('passkey.getToken sends no per-request header when requestOptions is omitted', async () => {
      const seen = captureTokenHeader();

      await makeClient().passkey.getToken(getTokenOptions, undefined, {
        headers: { 'X-Request-Tag': 'token-2' },
      });
      const res = await makeClient().passkey.getToken(getTokenOptions);

      expect(res).toBeDefined();
      expect(seen).toEqual(['token-2', null]);
    });

    test('passkey.getToken forwards a per-request customFetch', async () => {
      const perRequestFetch = vi.fn().mockImplementation(fetch);

      await makeClient().passkey.getToken(getTokenOptions, undefined, { customFetch: perRequestFetch });

      expect(calledWith(perRequestFetch, '/custom/token')).toBe(true);
    });

    test('passkey.getToken forwards an already-aborted per-request signal', async () => {
      const seen = captureTokenHeader();
      const controller = new AbortController();
      controller.abort();

      await expect(
        makeClient().passkey.getToken(getTokenOptions, undefined, { signal: controller.signal })
      ).rejects.toThrowError();
      expect(seen).toEqual([]);
    });

    test('passkey.getToken forwards requestOptions in resolver mode', async () => {
      const seen = captureTokenHeader();

      await makeClient(async () => domain).passkey.getToken(getTokenOptions, undefined, {
        headers: { 'X-Request-Tag': 'token-resolver' },
      });

      expect(seen).toEqual(['token-resolver']);
    });

    // The signup example in EXAMPLES.md forwards the end user's IP address with this header, so
    // check that exact header, not only an arbitrary one.
    test('passkey.register forwards the auth0-forwarded-for header', async () => {
      const seen = captureRegisterHeader('auth0-forwarded-for');

      await makeClient().passkey.register({ email: 'user@example.com', name: 'User' }, undefined, {
        headers: { 'auth0-forwarded-for': '203.0.113.7' },
      });

      expect(seen).toEqual(['203.0.113.7']);
    });

    test('passkey.getToken forwards the auth0-forwarded-for header', async () => {
      const seen = captureTokenHeader('auth0-forwarded-for');

      await makeClient().passkey.getToken(getTokenOptions, undefined, {
        headers: { 'auth0-forwarded-for': '203.0.113.7' },
      });

      expect(seen).toEqual(['203.0.113.7']);
    });
  });

  describe('identifier verification', () => {
    // `register()` sends the one-time codes and `getToken()` carries them back. These tests pin the
    // request shapes the SDK sends, the error shapes it surfaces, and that a failed attempt never
    // persists a session. Tests that read the wire use a `ServerClient`. The others build a
    // `ServerPasskeyClient` over a real `AuthClient` with a stubbed store and hook, so they can tell
    // exactly when a session is written.
    type RegisterCall = { body: Record<string, unknown> };
    type TokenCall = { body: Awaited<ReturnType<typeof readTokenRequestBody>> };

    const ok = () => HttpResponse.json(buildTokenResponse());

    // A wrong code with attempts left: the same `auth_session` comes back, with the identifiers still to verify.
    // Auth0 uses the same description for a wrong code and for an ended session, so nothing may branch on it.
    const wrongCode = (remaining: string[]) => () =>
      HttpResponse.json(
        {
          error: 'invalid_grant',
          error_description: 'Invalid or expired session',
          auth_session: 'auth_session_123',
          verification_required: remaining,
        },
        { status: 400 }
      );

    const captureRegisterRequests = (extra: Record<string, unknown> = {}) => {
      const calls: RegisterCall[] = [];
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          calls.push({ body: (await request.json()) as Record<string, unknown> });
          return HttpResponse.json({ ...registerApiResponse, ...extra });
        })
      );
      return calls;
    };

    // Serves the nth response to the nth token request, and repeats the last one after that.
    const captureTokenRequests = (...responses: (() => Response)[]) => {
      const calls: TokenCall[] = [];
      server.use(
        http.post(`https://${domain}/custom/token`, async ({ request }) => {
          calls.push({ body: await readTokenRequestBody(request) });
          return (responses[Math.min(calls.length, responses.length) - 1] ?? ok)();
        })
      );
      return calls;
    };

    const makePasskeyClient = () => {
      const stateStore = { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() };
      const onUserSessionEstablished = vi.fn().mockResolvedValue(undefined);
      const authClient = new AuthClient({ domain, clientId, clientSecret });
      const client = new ServerPasskeyClient({
        resolveDomain: async () => domain,
        getAuthClient: () => authClient,
        stateStore,
        stateStoreIdentifier: '__a0_session',
        // Required by the constructor. register() and getToken() never use it.
        transaction: new TransactionSlot({
          store: new DefaultTransactionStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
          identifier: { option: 'passkeyTransactionIdentifier', identifier: '__a0_passkey_tx' },
          otherIdentifiers: [],
          isEntry: isPasskeyTransactionData,
        }),
        onUserSessionEstablished,
      });
      return { client, stateStore, onUserSessionEstablished };
    };

    const signupOptions = { authSession: 'auth_session_123', credential: fakePasskeyCredential };

    test.each(['text', 'voice'] as const)(
      'passkey.register sends deliveryMethod %s as delivery_method',
      async (deliveryMethod) => {
        const calls = captureRegisterRequests();

        await makeClient().passkey.register({ phoneNumber: '+15555550100', deliveryMethod });

        expect(calls).toHaveLength(1);
        expect(calls[0]!.body.delivery_method).toBe(deliveryMethod);
      }
    );

    test('passkey.register sends no delivery_method when deliveryMethod is not set', async () => {
      // Auth0 then uses the channel the connection supports.
      const calls = captureRegisterRequests();

      await makeClient().passkey.register({ phoneNumber: '+15555550100' });

      expect(calls).toHaveLength(1);
      expect(calls[0]!.body).not.toHaveProperty('delivery_method');
    });

    test.each<[string, PasskeyVerificationIdentifier[]]>([
      ['the email address', ['email']],
      ['the phone number', ['phone']],
      ['both identifiers', ['email', 'phone']],
    ])('passkey.register returns verificationRequired for %s', async (_label, verificationRequired) => {
      captureRegisterRequests({
        authn_params_public_key: { ...registerApiResponse.authn_params_public_key, timeout: 900000 },
        verification_required: verificationRequired,
      });

      const res = await makeClient().passkey.register({ email: 'user@example.com', phoneNumber: '+15555550100' });

      expect(res.verificationRequired).toEqual(verificationRequired);
      expect(res.authSession).toBe('auth_session_123');
      // The browser passes the timeout to `navigator.credentials.create()`. With verification it is the
      // 15 minutes the user has to enter the codes, so it must reach the browser unchanged.
      expect(res.authnParamsPublicKey.timeout).toBe(900000);
    });

    test('passkey.register leaves verificationRequired undefined when none is required', async () => {
      // Served by the default handler, which sends no `verification_required`.
      const res = await makeClient().passkey.register({ email: 'user@example.com' });

      expect(res.verificationRequired).toBeUndefined();
    });

    test.each<[string, () => Response, number, string, string]>([
      [
        'an unsupported phone channel',
        () =>
          HttpResponse.json(
            { error: 'invalid_request', error_description: 'The requested media is not supported for this connection' },
            { status: 400 }
          ),
        400,
        'invalid_request',
        'The requested media is not supported for this connection',
      ],
      [
        'a code that could not be sent',
        () =>
          HttpResponse.json(
            { error: 'server_error', error_description: 'Unable to start identifier verification' },
            { status: 500 }
          ),
        500,
        'server_error',
        'Unable to start identifier verification',
      ],
      [
        'a plain-text rate limit',
        () => new HttpResponse('Too Many Requests', { status: 429 }),
        429,
        'unknown_error',
        'Too many requests. Please try again later.',
      ],
    ])(
      'passkey.register surfaces %s as a PasskeyRegisterError',
      async (_label, respond, statusCode, causeError, message) => {
        server.use(http.post(`https://${domain}/passkey/register`, respond));

        const error = await makeClient()
          .passkey.register({ phoneNumber: '+15555550100', deliveryMethod: 'voice' })
          .catch((e) => e);

        expect(error).toBeInstanceOf(PasskeyRegisterError);
        expect(error.statusCode).toBe(statusCode);
        expect(error.cause.error).toBe(causeError);
        expect(error.message).toBe(message);
      }
    );

    test('passkey.getToken sends verification as a nested object, not a string', async () => {
      const calls = captureTokenRequests(ok);

      await makeClient().passkey.getToken({ ...signupOptions, verification: { email: '123456', phone: '654321' } });

      expect(calls).toHaveLength(1);
      expect(calls[0]!.body.get('verification')).toEqual({ email: '123456', phone: '654321' });
    });

    // This test and the next pin what `@auth0/auth0-auth-js` 1.17.0 does: it drops empty codes, and
    // leaves `verification` out when no code remains. If auth-js starts rejecting an empty
    // `verification` or an empty code on the client instead, update both tests.
    test('passkey.getToken leaves out an empty code and sends the others', async () => {
      const calls = captureTokenRequests(ok);

      await makeClient().passkey.getToken({ ...signupOptions, verification: { email: '123456', phone: '' } });

      expect(calls).toHaveLength(1);
      expect(calls[0]!.body.get('verification')).toEqual({ email: '123456' });
    });

    test.each<[string, PasskeyVerificationCodes | undefined]>([
      ['undefined', undefined],
      ['an empty object', {}],
      ['only empty codes', { email: '', phone: '' }],
      ['only undefined codes', { email: undefined }],
    ])('passkey.getToken omits verification when it is %s', async (_label, verification) => {
      const calls = captureTokenRequests(ok);

      await makeClient().passkey.getToken({ ...signupOptions, verification });

      expect(calls).toHaveLength(1);
      expect(calls[0]!.body.has('verification')).toBe(false);
    });

    test('passkey.getToken surfaces a wrong code as retryable and persists no session', async () => {
      captureTokenRequests(wrongCode(['email']));
      const { client, stateStore, onUserSessionEstablished } = makePasskeyClient();

      const error = await client.getToken({ ...signupOptions, verification: { email: '000000' } }).catch((e) => e);

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(error.isRetryable).toBe(true);
      expect(error.authSession).toBe('auth_session_123');
      expect(error.verificationRequired).toEqual(['email']);
      expect(error.statusCode).toBe(400);
      expect(error.cause.error).toBe('invalid_grant');
      expect(stateStore.set).not.toHaveBeenCalled();
      expect(onUserSessionEstablished).not.toHaveBeenCalled();
    });

    test('passkey.getToken retried with the same authSession and credential persists the session once', async () => {
      const calls = captureTokenRequests(wrongCode(['phone']), ok);
      const { client, stateStore, onUserSessionEstablished } = makePasskeyClient();

      // The email code is right and the phone code is wrong, so only `phone` is still listed.
      const first = await client
        .getToken({ ...signupOptions, verification: { email: '123456', phone: '000000' } })
        .catch((e) => e);

      expect(first).toBeInstanceOf(PasskeyGetTokenError);
      expect(first.isRetryable).toBe(true);
      expect(first.verificationRequired).toEqual(['phone']);
      expect(stateStore.set).not.toHaveBeenCalled();
      expect(onUserSessionEstablished).not.toHaveBeenCalled();

      // The retry sends a code only for the identifier that is still listed.
      await client.getToken({ ...signupOptions, verification: { phone: '654321' } });

      expect(stateStore.set).toHaveBeenCalledTimes(1);
      expect(onUserSessionEstablished).toHaveBeenCalledTimes(1);
      expect(calls).toHaveLength(2);
      expect(calls[0]!.body.get('verification')).toEqual({ email: '123456', phone: '000000' });
      expect(calls[1]!.body.get('verification')).toEqual({ phone: '654321' });
      // Both attempts carry the caller's own `authSession` and credential, so there is no second passkey prompt.
      expect(calls.map((call) => call.body.get('auth_session'))).toEqual([
        signupOptions.authSession,
        signupOptions.authSession,
      ]);
      expect(calls.map((call) => call.body.get('authn_response'))).toEqual([
        fakePasskeyCredential,
        fakePasskeyCredential,
      ]);
    });

    test.each<[string, number, Record<string, unknown>]>([
      // The same status, error and description as a wrong code: only the missing `auth_session` tells them apart.
      [
        'codes that can no longer be used',
        400,
        { error: 'invalid_grant', error_description: 'Invalid or expired session' },
      ],
      [
        'an unknown or already used session',
        403,
        { error: 'invalid_grant', error_description: 'Invalid or expired session' },
      ],
      [
        'a missing code',
        400,
        { error: 'invalid_request', error_description: 'Missing required parameter: verification.phone' },
      ],
      ['a rate limit', 429, { error: 'access_denied', error_description: 'Too Many Requests' }],
      [
        'mfa_required after the codes are accepted',
        403,
        {
          error: 'mfa_required',
          error_description: 'Multifactor authentication required',
          mfa_token: 'mfa_token_123',
          mfa_requirements: { challenge: [{ type: 'otp' }] },
        },
      ],
    ])('passkey.getToken surfaces %s as not retryable and persists no session', async (_label, status, body) => {
      captureTokenRequests(() => HttpResponse.json(body, { status }));
      const { client, stateStore, onUserSessionEstablished } = makePasskeyClient();

      const error = await client.getToken({ ...signupOptions, verification: { email: '123456' } }).catch((e) => e);

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(error.statusCode).toBe(status);
      expect(error.cause.error).toBe(body.error);
      expect(error.isRetryable).toBe(false);
      expect(error.authSession).toBeUndefined();
      expect(error.verificationRequired).toBeUndefined();
      expect(stateStore.set).not.toHaveBeenCalled();
      expect(onUserSessionEstablished).not.toHaveBeenCalled();
    });

    test('passkey.getToken surfaces a server error as not retryable and persists no session', async () => {
      // Auth0 can keep the attempt open after a temporary failure, but nothing on the error says so,
      // so it must not look retryable.
      captureTokenRequests(() =>
        HttpResponse.json({ error: 'server_error', error_description: 'Server error' }, { status: 500 })
      );
      const { client, stateStore, onUserSessionEstablished } = makePasskeyClient();

      const error = await client.getToken({ ...signupOptions, verification: { email: '123456' } }).catch((e) => e);

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(error.isRetryable).toBe(false);
      expect(error.authSession).toBeUndefined();
      expect(stateStore.set).not.toHaveBeenCalled();
      expect(onUserSessionEstablished).not.toHaveBeenCalled();
    });

    test('resolver mode: register and every getToken attempt use the same storeOptions', async () => {
      captureRegisterRequests({ verification_required: ['email'] });
      const tokenCalls = captureTokenRequests(wrongCode(['email']), ok);
      const resolveDomain = vi.fn().mockResolvedValue(domain);
      const stateStore = { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() };
      const sc = new ServerClient({
        domain: resolveDomain,
        clientId,
        clientSecret,
        transactionStore: new DefaultTransactionStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
        stateStore,
      });
      const storeOptions = { request: { headers: { host: 'brand-1.example.com' } } };

      const { authSession } = await sc.passkey.register({ email: 'user@example.com' }, storeOptions);
      const error = await sc.passkey
        .getToken({ authSession, credential: fakePasskeyCredential, verification: { email: '000000' } }, storeOptions)
        .catch((e) => e);
      await sc.passkey.getToken(
        { authSession, credential: fakePasskeyCredential, verification: { email: '123456' } },
        storeOptions
      );

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(tokenCalls.map((call) => call.body.get('auth_session'))).toEqual([authSession, authSession]);
      expect(resolveDomain.mock.calls).toEqual([[storeOptions], [storeOptions], [storeOptions]]);
      expect(stateStore.set).toHaveBeenCalledTimes(1);
      expect(stateStore.set.mock.calls[0]![3]).toBe(storeOptions);
    });
  });
});
