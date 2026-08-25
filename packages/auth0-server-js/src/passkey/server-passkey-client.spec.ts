import { expect, test, afterAll, afterEach, beforeAll, vi, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ServerClient } from '../server-client.js';
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
    const captureHeaderOn = (path: string, respond: () => Response) => {
      const seen: (string | null)[] = [];
      server.use(http.post(`https://${domain}${path}`, ({ request }) => {
        seen.push(request.headers.get('x-request-tag'));
        return respond();
      }));
      return seen;
    };

    const captureRegisterHeader = () =>
      captureHeaderOn('/passkey/register', () => HttpResponse.json(registerApiResponse));

    const captureChallengeHeader = () =>
      captureHeaderOn('/passkey/challenge', () => HttpResponse.json(challengeApiResponse));

    const captureTokenHeader = () =>
      captureHeaderOn('/custom/token', () => HttpResponse.json(buildTokenResponse()));

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
  });
});
