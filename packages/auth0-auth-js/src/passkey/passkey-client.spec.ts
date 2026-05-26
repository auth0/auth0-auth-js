import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { PasskeyClient } from './passkey-client.js';
import {
  PasskeyRegisterError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
} from './errors.js';
import type { GrantRequestFn } from './types.js';
import { TokenResponse } from '../types.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';

function createMockTokenResponse(): TokenResponse {
  const response = new TokenResponse(
    'eyJ_access_token',
    Math.floor(Date.now() / 1000) + 86400,
    'eyJ_id_token',
    'eyJ_refresh_token'
  );
  response.tokenType = 'Bearer';
  return response;
}

function createMockGrantRequest(): GrantRequestFn {
  return async () => createMockTokenResponse();
}

function createClient(overrides?: { customFetch?: typeof fetch; grantRequest?: GrantRequestFn }) {
  return new PasskeyClient({
    domain,
    clientId,
    grantRequest: overrides?.grantRequest ?? createMockGrantRequest(),
    ...(overrides?.customFetch && { customFetch: overrides.customFetch }),
  });
}

const mockSignupChallengeResponse = {
  auth_session: 'eyJ_signup_session',
  authn_params_public_key: {
    challenge: 'dGVzdC1jaGFsbGVuZ2U',
    rp: {
      id: 'example.auth0.com',
      name: 'My App',
    },
    user: {
      id: 'dXNlcl8xMjM',
      name: 'user@example.com',
      displayName: 'Jane Doe',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
    },
    timeout: 60000,
  },
};

const mockSignupChallengeResponseMinimal = {
  auth_session: 'eyJ_minimal_session',
  authn_params_public_key: {
    challenge: 'bWluaW1hbC1jaGFsbGVuZ2U',
    rp: {
      id: 'example.auth0.com',
      name: 'My App',
    },
    user: {
      id: 'dXNlcl8xMjM',
      name: 'user@example.com',
      displayName: 'user@example.com',
    },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  },
};

const mockLoginChallengeResponse = {
  auth_session: 'eyJ_login_session',
  authn_params_public_key: {
    challenge: 'dGVzdC1sb2dpbi1jaGFsbGVuZ2U',
    rpId: 'example.auth0.com',
    timeout: 60000,
    userVerification: 'preferred',
  },
};

const mockLoginChallengeResponseMinimal = {
  auth_session: 'eyJ_login_minimal',
  authn_params_public_key: {
    challenge: 'bWluaW1hbC1sb2dpbg',
    rpId: 'example.auth0.com',
  },
};

const mockCredentialCreation = {
  id: 'credential-id-123',
  rawId: 'Y3JlZGVudGlhbC1pZC0xMjM',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
    attestationObject: 'o2NmbXRkbm9uZQ',
  },
  clientExtensionResults: {},
};

const mockCredentialAssertion = {
  id: 'credential-id-456',
  rawId: 'Y3JlZGVudGlhbC1pZC00NTY',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0',
    authenticatorData: 'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA',
    signature: 'MEUCIQC-signature-base64url',
    userHandle: 'dXNlcl8xMjM',
  },
  clientExtensionResults: {},
};

const restHandlers = [
  http.post(`https://${domain}/passkey/register`, async ({ request }) => {
    const body = (await request.json()) as { client_id: string };

    if (body.client_id !== clientId) {
      return HttpResponse.json(
        { error: 'invalid_client', error_description: 'Invalid client ID' },
        { status: 401 }
      );
    }

    return HttpResponse.json(mockSignupChallengeResponse);
  }),

  http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
    const body = (await request.json()) as { client_id: string };

    if (body.client_id !== clientId) {
      return HttpResponse.json(
        { error: 'invalid_client', error_description: 'Invalid client ID' },
        { status: 401 }
      );
    }

    return HttpResponse.json(mockLoginChallengeResponse);
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  vi.clearAllMocks();
});

describe('PasskeyClient', () => {
  // ─── Constructor ───────────────────────────────────────────────────

  describe('constructor', () => {
    test('creates an instance with required options', () => {
      const client = createClient();
      expect(client).toBeInstanceOf(PasskeyClient);
    });

    test('constructs the base URL using https and the provided domain', async () => {
      let capturedUrl = '';
      server.use(
        http.post(`https://${domain}/passkey/challenge`, ({ request }) => {
          capturedUrl = request.url;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedUrl).toBe(`https://${domain}/passkey/challenge`);
    });

    test('uses the provided custom fetch implementation for HTTP requests', async () => {
      let fetchCalled = false;
      const customFetch: typeof fetch = async (...args) => {
        fetchCalled = true;
        return fetch(...args);
      };

      const client = createClient({ customFetch });
      await client.challenge();

      expect(fetchCalled).toBe(true);
    });

    test('falls back to the global fetch when no custom fetch is provided', async () => {
      const client = createClient();
      const result = await client.challenge();
      expect(result.authSession).toBe('eyJ_login_session');
    });
  });

  // ─── register ─────────────────────────────────────────────────────

  describe('register', () => {
    test('accepts email as a valid user identifier', async () => {
      const client = createClient();
      const result = await client.register({ email: 'user@example.com' });
      expect(result.authSession).toBeDefined();
    });

    test('accepts username as a valid user identifier', async () => {
      const client = createClient();
      const result = await client.register({ username: 'janedoe' });
      expect(result.authSession).toBeDefined();
    });

    test('accepts phoneNumber as a valid user identifier', async () => {
      const client = createClient();
      const result = await client.register({ phoneNumber: '+1234567890' });
      expect(result.authSession).toBeDefined();
    });

    test('sends a POST request to /passkey/register', async () => {
      let capturedUrl = '';
      server.use(
        http.post(`https://${domain}/passkey/register`, ({ request }) => {
          capturedUrl = request.url;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com' });

      expect(capturedUrl).toBe(`https://${domain}/passkey/register`);
    });

    test('sends the Content-Type: application/json header', async () => {
      let capturedContentType = '';
      server.use(
        http.post(`https://${domain}/passkey/register`, ({ request }) => {
          capturedContentType = request.headers.get('Content-Type') || '';
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com' });

      expect(capturedContentType).toBe('application/json');
    });

    test('sends client_id and email wrapped in user_profile in the request body', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com' });

      expect(capturedBody.client_id).toBe(clientId);
      expect(capturedBody.user_profile).toEqual({ email: 'user@example.com' });
    });

    test('includes all provided user_profile fields (email, name, phoneNumber, username)', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({
        email: 'user@example.com',
        name: 'Jane Doe',
        phoneNumber: '+1234567890',
        username: 'janedoe',
      });

      expect(capturedBody.user_profile).toEqual({
        email: 'user@example.com',
        name: 'Jane Doe',
        phone_number: '+1234567890',
        username: 'janedoe',
      });
    });

    test('omits optional user_profile fields that are not provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com' });

      const profile = capturedBody.user_profile as Record<string, unknown>;
      expect(profile.email).toBe('user@example.com');
      expect(profile).not.toHaveProperty('name');
      expect(profile).not.toHaveProperty('phone_number');
      expect(profile).not.toHaveProperty('username');
    });

    test('includes realm in the request body when provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({
        email: 'user@example.com',
        realm: 'Username-Password-Authentication',
      });

      expect(capturedBody.realm).toBe('Username-Password-Authentication');
    });

    test('does not include realm in the request body when not provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com' });

      expect(capturedBody).not.toHaveProperty('realm');
    });

    test('returns transformed response with camelCase authSession and authnParamsPublicKey', async () => {
      const client = createClient();
      const result = await client.register({ email: 'user@example.com' });

      expect(result.authSession).toBe('eyJ_signup_session');
      expect(result.authnParamsPublicKey).toEqual({
        challenge: 'dGVzdC1jaGFsbGVuZ2U',
        rp: { id: 'example.auth0.com', name: 'My App' },
        user: { id: 'dXNlcl8xMjM', name: 'user@example.com', displayName: 'Jane Doe' },
        pubKeyCredParams: [
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
        timeout: 60000,
      });
    });

    test('handles API response that omits optional fields (authenticatorSelection, timeout)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(mockSignupChallengeResponseMinimal);
        })
      );

      const client = createClient();
      const result = await client.register({ email: 'user@example.com' });

      expect(result.authSession).toBe('eyJ_minimal_session');
      expect(result.authnParamsPublicKey.authenticatorSelection).toBeUndefined();
      expect(result.authnParamsPublicKey.timeout).toBeUndefined();
      expect(result.authnParamsPublicKey.challenge).toBe('bWluaW1hbC1jaGFsbGVuZ2U');
    });

    test('throws PasskeyRegisterError when the API returns HTTP 400', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'invalid_request', error_description: 'Email is required' },
            { status: 400 }
          );
        })
      );

      const client = createClient();
      await expect(client.register({ email: 'user@example.com' })).rejects.toThrow(PasskeyRegisterError);
    });

    test('throws PasskeyRegisterError when passkeys are not enabled (HTTP 403)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'forbidden', error_description: 'Passkeys not enabled for connection' },
            { status: 403 }
          );
        })
      );

      const client = createClient();
      await expect(client.register({ email: 'user@example.com' })).rejects.toThrow(PasskeyRegisterError);
    });

    test('throws PasskeyRegisterError when the user already exists (HTTP 409)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'user_exists', error_description: 'User already exists' },
            { status: 409 }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'existing@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyRegisterError;
        expect(error).toBeInstanceOf(PasskeyRegisterError);
        expect(error.message).toBe('User already exists');
        expect(error.cause?.error).toBe('user_exists');
      }
    });

    test('uses error_description from the API response as the error message', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'invalid_request', error_description: 'Custom error message from API' },
            { status: 400 }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyRegisterError;
        expect(error.message).toBe('Custom error message from API');
      }
    });

    test('uses a fallback message when error_description is empty', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'server_error', error_description: '' },
            { status: 500 }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyRegisterError;
        expect(error.message).toBe('Failed to request signup challenge');
      }
    });

    test('includes the full API error details (error, error_description, message) in the cause', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'invalid_request', error_description: 'Email is required', message: 'Validation failed' },
            { status: 400 }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyRegisterError;
        expect(error.code).toBe('passkey_register_error');
        expect(error.name).toBe('PasskeyRegisterError');
        expect(error.cause).toEqual({
          error: 'invalid_request',
          error_description: 'Email is required',
          message: 'Validation failed',
        });
      }
    });

    test('handles non-JSON error response by constructing a fallback error object', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return new HttpResponse('Internal Server Error', {
            status: 500,
            statusText: 'Internal Server Error',
            headers: { 'Content-Type': 'text/plain' },
          });
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyRegisterError;
        expect(error).toBeInstanceOf(PasskeyRegisterError);
        expect(error.cause?.error).toBe('unknown_error');
        expect(error.cause?.error_description).toContain('500');
      }
    });

    test('does not include name in user_profile when it is an empty string', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com', name: '' });

      const profile = capturedBody.user_profile as Record<string, unknown>;
      expect(profile).not.toHaveProperty('name');
    });
  });

  // ─── challenge ────────────────────────────────────────────────────

  describe('challenge', () => {
    test('sends a POST request to /passkey/challenge', async () => {
      let capturedUrl = '';
      server.use(
        http.post(`https://${domain}/passkey/challenge`, ({ request }) => {
          capturedUrl = request.url;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedUrl).toBe(`https://${domain}/passkey/challenge`);
    });

    test('sends the Content-Type: application/json header', async () => {
      let capturedContentType = '';
      server.use(
        http.post(`https://${domain}/passkey/challenge`, ({ request }) => {
          capturedContentType = request.headers.get('Content-Type') || '';
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedContentType).toBe('application/json');
    });

    test('sends client_id in the request body', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedBody.client_id).toBe(clientId);
    });

    test('works without any options (options parameter is undefined)', async () => {
      const client = createClient();
      const result = await client.challenge();

      expect(result.authSession).toBe('eyJ_login_session');
      expect(result.authnParamsPublicKey.rpId).toBe('example.auth0.com');
    });

    test('works with an empty options object', async () => {
      const client = createClient();
      const result = await client.challenge({});

      expect(result.authSession).toBe('eyJ_login_session');
    });

    test('includes realm in the request body when provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge({ realm: 'Username-Password-Authentication' });

      expect(capturedBody.realm).toBe('Username-Password-Authentication');
    });

    test('does not include realm when not provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedBody).not.toHaveProperty('realm');
    });

    test('returns transformed response with camelCase authSession and authnParamsPublicKey', async () => {
      const client = createClient();
      const result = await client.challenge();

      expect(result.authSession).toBe('eyJ_login_session');
      expect(result.authnParamsPublicKey).toEqual({
        challenge: 'dGVzdC1sb2dpbi1jaGFsbGVuZ2U',
        rpId: 'example.auth0.com',
        timeout: 60000,
        userVerification: 'preferred',
      });
    });

    test('handles API response that omits optional fields (timeout, userVerification)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(mockLoginChallengeResponseMinimal);
        })
      );

      const client = createClient();
      const result = await client.challenge();

      expect(result.authSession).toBe('eyJ_login_minimal');
      expect(result.authnParamsPublicKey.challenge).toBe('bWluaW1hbC1sb2dpbg');
      expect(result.authnParamsPublicKey.rpId).toBe('example.auth0.com');
      expect(result.authnParamsPublicKey.timeout).toBeUndefined();
      expect(result.authnParamsPublicKey.userVerification).toBeUndefined();
    });

    test('throws PasskeyChallengeError when passkeys are not enabled (HTTP 403)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'forbidden', error_description: 'Passkeys not enabled for this tenant' },
            { status: 403 }
          );
        })
      );

      const client = createClient();
      await expect(client.challenge()).rejects.toThrow(PasskeyChallengeError);
    });

    test('throws PasskeyChallengeError when client is unauthorized (HTTP 401)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'invalid_client', error_description: 'Unknown client' },
            { status: 401 }
          );
        })
      );

      const client = createClient();
      await expect(client.challenge()).rejects.toThrow(PasskeyChallengeError);
    });

    test('uses error_description from the API response as the error message', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'forbidden', error_description: 'Connection not configured' },
            { status: 403 }
          );
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyChallengeError;
        expect(error.message).toBe('Connection not configured');
      }
    });

    test('uses a fallback message when error_description is empty', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'server_error', error_description: '' },
            { status: 500 }
          );
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyChallengeError;
        expect(error.message).toBe('Failed to request login challenge');
      }
    });

    test('includes the full API error details (error, error_description, message) in the cause', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'forbidden', error_description: 'Not enabled', message: 'Check config' },
            { status: 403 }
          );
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyChallengeError;
        expect(error.code).toBe('passkey_challenge_error');
        expect(error.name).toBe('PasskeyChallengeError');
        expect(error.cause).toEqual({
          error: 'forbidden',
          error_description: 'Not enabled',
          message: 'Check config',
        });
      }
    });

    test('handles non-JSON error response by constructing a fallback error object', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return new HttpResponse('Bad Gateway', {
            status: 502,
            statusText: 'Bad Gateway',
            headers: { 'Content-Type': 'text/plain' },
          });
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyChallengeError;
        expect(error).toBeInstanceOf(PasskeyChallengeError);
        expect(error.cause?.error).toBe('unknown_error');
        expect(error.cause?.error_description).toContain('502');
      }
    });
  });

  // ─── getTokenByPasskey ────────────────────────────────────────────

  describe('getTokenByPasskey', () => {
    test('calls the grantRequest delegate with the webauthn grant type', async () => {
      const grantRequest = vi.fn(createMockGrantRequest());
      const client = createClient({ grantRequest });

      await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
      });

      expect(grantRequest).toHaveBeenCalledTimes(1);
      const [grantType] = grantRequest.mock.calls[0]!;
      expect(grantType).toBe('urn:okta:params:oauth:grant-type:webauthn');
    });

    test('passes auth_session and JSON-serialized credential as form params', async () => {
      const grantRequest = vi.fn(createMockGrantRequest());
      const client = createClient({ grantRequest });

      await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
      });

      const [, params] = grantRequest.mock.calls[0]!;
      expect(params.get('auth_session')).toBe('eyJ_session');
      expect(params.get('authn_response')).toBe(JSON.stringify(mockCredentialCreation));
    });

    test('includes realm, scope, and audience params when provided', async () => {
      const grantRequest = vi.fn(createMockGrantRequest());
      const client = createClient({ grantRequest });

      await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
        realm: 'Username-Password-Authentication',
        scope: 'openid profile email',
        audience: 'https://api.example.com',
      });

      const [, params] = grantRequest.mock.calls[0]!;
      expect(params.get('realm')).toBe('Username-Password-Authentication');
      expect(params.get('scope')).toBe('openid profile email');
      expect(params.get('audience')).toBe('https://api.example.com');
    });

    test('does not include realm, scope, or audience when not provided', async () => {
      const grantRequest = vi.fn(createMockGrantRequest());
      const client = createClient({ grantRequest });

      await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
      });

      const [, params] = grantRequest.mock.calls[0]!;
      expect(params.has('realm')).toBe(false);
      expect(params.has('scope')).toBe(false);
      expect(params.has('audience')).toBe(false);
    });

    test('returns the TokenResponse from the grantRequest delegate', async () => {
      const client = createClient();
      const result = await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
      });

      expect(result.accessToken).toBe('eyJ_access_token');
      expect(result.idToken).toBe('eyJ_id_token');
      expect(result.refreshToken).toBe('eyJ_refresh_token');
      expect(result.tokenType).toBe('Bearer');
    });

    test('works with an assertion credential (login flow with authenticatorData and signature)', async () => {
      const grantRequest = vi.fn(createMockGrantRequest());
      const client = createClient({ grantRequest });

      await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialAssertion,
      });

      const [, params] = grantRequest.mock.calls[0]!;
      expect(params.get('authn_response')).toBe(JSON.stringify(mockCredentialAssertion));
    });

    test('works with a minimal credential that only has required response fields', async () => {
      const grantRequest = vi.fn(createMockGrantRequest());
      const client = createClient({ grantRequest });

      const minimalCredential = {
        id: 'cred-id',
        rawId: 'base64url-raw-id',
        type: 'public-key',
        response: {
          clientDataJSON: 'base64url-client-data',
          authenticatorData: 'base64url-auth-data',
          signature: 'base64url-signature',
        },
      };

      await client.getTokenByPasskey({
        authSession: 'session',
        credential: minimalCredential,
      });

      const [, params] = grantRequest.mock.calls[0]!;
      expect(params.get('authn_response')).toBe(JSON.stringify(minimalCredential));
    });

    test('throws PasskeyGetTokenError when the grantRequest delegate rejects', async () => {
      const grantRequest = vi.fn().mockRejectedValue(new Error('token exchange failed'));
      const client = createClient({ grantRequest });

      await expect(
        client.getTokenByPasskey({ authSession: 'invalid', credential: mockCredentialCreation })
      ).rejects.toThrow(PasskeyGetTokenError);
    });

    test('sets the error code to passkey_get_token_error', async () => {
      const grantRequest = vi.fn().mockRejectedValue(new Error('expired'));
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'expired', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error.code).toBe('passkey_get_token_error');
        expect(error.name).toBe('PasskeyGetTokenError');
      }
    });

    test('uses a descriptive fallback message for the error', async () => {
      const grantRequest = vi.fn().mockRejectedValue(new Error('network error'));
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error.message).toBe('Failed to exchange passkey credential for tokens.');
      }
    });

    test('preserves OAuth2Error details (error, error_description) in the error cause', async () => {
      const oauth2Error = {
        error: 'invalid_grant',
        error_description: 'Authentication session expired',
        message: 'The auth_session has expired',
      };
      const grantRequest = vi.fn().mockRejectedValue(oauth2Error);
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'expired', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error).toBeInstanceOf(PasskeyGetTokenError);
        expect(error.cause?.error).toBe('invalid_grant');
        expect(error.cause?.error_description).toBe('Authentication session expired');
      }
    });

    test('sets cause to undefined when the thrown error does not have OAuth2Error shape', async () => {
      const grantRequest = vi.fn().mockRejectedValue(new Error('network timeout'));
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error).toBeInstanceOf(PasskeyGetTokenError);
        expect(error.cause).toBeUndefined();
      }
    });

    test('sets cause to undefined when the thrown value is null', async () => {
      const grantRequest = vi.fn().mockRejectedValue(null);
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error).toBeInstanceOf(PasskeyGetTokenError);
        expect(error.cause).toBeUndefined();
      }
    });
  });

  // ─── customFetch ───────────────────────────────────────────────────

  describe('customFetch', () => {
    test('uses custom fetch for register requests', async () => {
      let fetchCalled = false;
      const customFetch: typeof fetch = async (...args) => {
        fetchCalled = true;
        return fetch(...args);
      };

      const client = createClient({ customFetch });
      await client.register({ email: 'user@example.com' });

      expect(fetchCalled).toBe(true);
    });

    test('uses custom fetch for challenge requests', async () => {
      let fetchCalled = false;
      const customFetch: typeof fetch = async (...args) => {
        fetchCalled = true;
        return fetch(...args);
      };

      const client = createClient({ customFetch });
      await client.challenge();

      expect(fetchCalled).toBe(true);
    });

    test('passes the correct URL, method, headers, and body to custom fetch', async () => {
      let capturedArgs: [RequestInfo | URL, RequestInit | undefined] | null = null;
      const customFetch: typeof fetch = async (input, init) => {
        capturedArgs = [input, init];
        return fetch(input, init);
      };

      const client = createClient({ customFetch });
      await client.challenge({ realm: 'my-connection' });

      expect(capturedArgs).not.toBeNull();
      expect(capturedArgs![0]).toBe(`https://${domain}/passkey/challenge`);
      expect(capturedArgs![1]?.method).toBe('POST');
      expect(capturedArgs![1]?.headers).toEqual({ 'Content-Type': 'application/json' });

      const body = JSON.parse(capturedArgs![1]?.body as string);
      expect(body.client_id).toBe(clientId);
      expect(body.realm).toBe('my-connection');
    });
  });

  // ─── Error class behavior ─────────────────────────────────────────

  describe('error classes', () => {
    test('PasskeyRegisterError extends Error', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'test', error_description: 'test error' },
            { status: 400 }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(PasskeyRegisterError);
      }
    });

    test('PasskeyChallengeError extends Error', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'test', error_description: 'test error' },
            { status: 400 }
          );
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(PasskeyChallengeError);
      }
    });

    test('PasskeyGetTokenError extends Error', async () => {
      const grantRequest = vi.fn().mockRejectedValue(new Error('fail'));
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(PasskeyGetTokenError);
      }
    });

    test('error cause only includes known fields from the API response (no extra fields)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            {
              error: 'invalid_request',
              error_description: 'Bad request',
              message: 'Detailed message',
              extra_field: 'should not appear',
            },
            { status: 400 }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyRegisterError;
        expect(error.cause).toEqual({
          error: 'invalid_request',
          error_description: 'Bad request',
          message: 'Detailed message',
        });
        expect(error.cause).not.toHaveProperty('extra_field');
      }
    });
  });
});
