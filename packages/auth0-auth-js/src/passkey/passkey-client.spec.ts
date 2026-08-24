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
import type { RequestOptions } from '../types.js';
import { TokenResponse } from '../types.js';
import { isMfaRequiredError, OrganizationValidationError } from '../errors.js';

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

function createClient(overrides?: {
  customFetch?: typeof fetch;
  grantRequest?: GrantRequestFn;
  clientSecret?: string;
  useMtls?: boolean;
}) {
  return new PasskeyClient({
    domain,
    clientId,
    grantRequest: overrides?.grantRequest ?? createMockGrantRequest(),
    ...(overrides?.customFetch && { customFetch: overrides.customFetch }),
    ...(overrides?.clientSecret !== undefined && { clientSecret: overrides.clientSecret }),
    ...(overrides?.useMtls !== undefined && { useMtls: overrides.useMtls }),
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

    test('sends client_secret in the request body for a confidential client', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: 'test-client-secret' });
      await client.register({ email: 'user@example.com' });

      expect(capturedBody.client_id).toBe(clientId);
      expect(capturedBody.client_secret).toBe('test-client-secret');
      expect(capturedBody.user_profile).toEqual({ email: 'user@example.com' });
    });

    test('does not include client_secret for a public client', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient();
      await client.register({ email: 'user@example.com' });

      expect(capturedBody).not.toHaveProperty('client_secret');
    });

    // mTLS authenticates via the client certificate on the TLS connection, and the
    // Auth0 mTLS strategy rejects the request outright ("Multiple authentication
    // methods provided") if a body-level credential is also present.
    test('does not include client_secret when mTLS is enabled', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: 'test-client-secret', useMtls: true });
      await client.register({ email: 'user@example.com' });

      expect(capturedBody.client_id).toBe(clientId);
      expect(capturedBody).not.toHaveProperty('client_secret');
    });

    // The passkey endpoints do not accept `client_assertion`: the Auth0 request
    // schema rejects any unknown field with `invalid_request`, and that validation
    // runs before client authentication. A private_key_jwt client therefore never
    // sends an assertion on these endpoints.
    test('does not add a client_assertion alongside client_secret', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: 'test-client-secret' });
      await client.register({ email: 'user@example.com' });

      expect(capturedBody).not.toHaveProperty('client_assertion');
      expect(capturedBody).not.toHaveProperty('client_assertion_type');
    });

    // A client configured only with a `clientAssertionSigningKey` has no credential
    // this endpoint accepts, so the SDK sends none and surfaces Auth0's rejection
    // as-is. It deliberately does not reject the call itself: if Auth0 later starts
    // accepting `client_assertion` here, an SDK-side refusal would block a config
    // the server had begun supporting.
    test('surfaces the Auth0 rejection when no acceptable credential is configured', async () => {
      const rejection = { error: 'unauthorized_client', error_description: 'Invalid client credentials' };
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(rejection, { status: 403 });
        })
      );

      const client = createClient();
      const error = await client.register({ email: 'user@example.com' }).catch((e) => e);

      expect(capturedBody).not.toHaveProperty('client_secret');
      expect(capturedBody).not.toHaveProperty('client_assertion');
      expect(error).toBeInstanceOf(PasskeyRegisterError);
      expect(error.code).toBe('passkey_register_error');
      expect(error.cause?.error).toBe(rejection.error);
      expect(error.cause?.error_description).toBe(rejection.error_description);
    });

    // Auth0 validates `client_secret` as a non-empty string, so sending `''` would
    // fail the request with `invalid_request` instead of falling back to public-client
    // authentication.
    test('omits an empty client_secret rather than sending a blank value', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/register`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockSignupChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: '' });
      await client.register({ email: 'user@example.com' });

      expect(capturedBody).not.toHaveProperty('client_secret');
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

    test('includes organization in the request body when provided', async () => {
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
        organization: 'org_abc123',
      });

      expect(capturedBody.organization).toBe('org_abc123');
    });

    test('includes extended user profile fields in user_profile when provided', async () => {
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
        givenName: 'Jane',
        familyName: 'Doe',
        nickname: 'janey',
        picture: 'https://example.com/photo.jpg',
        userMetadata: { preferred_language: 'en' },
      });

      const profile = capturedBody.user_profile as Record<string, unknown>;
      expect(profile.given_name).toBe('Jane');
      expect(profile.family_name).toBe('Doe');
      expect(profile.nickname).toBe('janey');
      expect(profile.picture).toBe('https://example.com/photo.jpg');
      expect(profile).not.toHaveProperty('user_metadata');
      expect(capturedBody.user_metadata).toEqual({ preferred_language: 'en' });
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

    test('sends client_secret in the request body for a confidential client', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: 'test-client-secret' });
      await client.challenge();

      expect(capturedBody.client_id).toBe(clientId);
      expect(capturedBody.client_secret).toBe('test-client-secret');
    });

    test('does not include client_secret for a public client', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedBody).not.toHaveProperty('client_secret');
    });

    // mTLS authenticates via the client certificate on the TLS connection, and the
    // Auth0 mTLS strategy rejects the request outright ("Multiple authentication
    // methods provided") if a body-level credential is also present.
    test('does not include client_secret when mTLS is enabled', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: 'test-client-secret', useMtls: true });
      await client.challenge();

      expect(capturedBody.client_id).toBe(clientId);
      expect(capturedBody).not.toHaveProperty('client_secret');
    });

    // The passkey endpoints do not accept `client_assertion`: the Auth0 request
    // schema rejects any unknown field with `invalid_request`, and that validation
    // runs before client authentication. A private_key_jwt client therefore never
    // sends an assertion on these endpoints.
    test('does not add a client_assertion alongside client_secret', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: 'test-client-secret' });
      await client.challenge();

      expect(capturedBody).not.toHaveProperty('client_assertion');
      expect(capturedBody).not.toHaveProperty('client_assertion_type');
    });

    // A client configured only with a `clientAssertionSigningKey` has no credential
    // this endpoint accepts, so the SDK sends none and surfaces Auth0's rejection
    // as-is. It deliberately does not reject the call itself: if Auth0 later starts
    // accepting `client_assertion` here, an SDK-side refusal would block a config
    // the server had begun supporting.
    test('surfaces the Auth0 rejection when no acceptable credential is configured', async () => {
      const rejection = { error: 'unauthorized_client', error_description: 'Invalid client credentials' };
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(rejection, { status: 403 });
        })
      );

      const client = createClient();
      const error = await client.challenge().catch((e) => e);

      expect(capturedBody).not.toHaveProperty('client_secret');
      expect(capturedBody).not.toHaveProperty('client_assertion');
      expect(error).toBeInstanceOf(PasskeyChallengeError);
      expect(error.code).toBe('passkey_challenge_error');
      expect(error.cause?.error).toBe(rejection.error);
      expect(error.cause?.error_description).toBe(rejection.error_description);
    });

    // Auth0 validates `client_secret` as a non-empty string, so sending `''` would
    // fail the request with `invalid_request` instead of falling back to public-client
    // authentication.
    test('omits an empty client_secret rather than sending a blank value', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient({ clientSecret: '' });
      await client.challenge();

      expect(capturedBody).not.toHaveProperty('client_secret');
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

    test('includes organization in the request body when provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge({ organization: 'org_abc123' });

      expect(capturedBody.organization).toBe('org_abc123');
    });

    test('does not include organization when not provided', async () => {
      let capturedBody: Record<string, unknown> = {};
      server.use(
        http.post(`https://${domain}/passkey/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockLoginChallengeResponse);
        })
      );

      const client = createClient();
      await client.challenge();

      expect(capturedBody).not.toHaveProperty('organization');
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

    test('includes organization param when provided', async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const grantRequest = vi.fn(async (_grantType: string, _params: URLSearchParams, _requestOptions?: RequestOptions) => {
        const response = new TokenResponse(
          'eyJ_access_token',
          Math.floor(Date.now() / 1000) + 86400,
          'eyJ_id_token',
          'eyJ_refresh_token',
          undefined,
          { org_id: 'org_abc123' } as unknown as TokenResponse['claims']
        );
        response.tokenType = 'Bearer';
        return response;
      });
      const client = createClient({ grantRequest });

      await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
        organization: 'org_abc123',
      });

      const call = grantRequest.mock.calls.at(0) as [string, URLSearchParams, unknown] | undefined;
      expect(call).toBeDefined();
      const params = call?.[1];
      expect(params?.get('organization')).toBe('org_abc123');
    });

    test('does not include realm, scope, audience, or organization when not provided', async () => {
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
      expect(params.has('organization')).toBe(false);
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

    test('uses fallback message for non-OAuth errors (e.g. network failures)', async () => {
      const grantRequest = vi.fn().mockRejectedValue(new Error('network error'));
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error).toBeInstanceOf(PasskeyGetTokenError);
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
        expect(error.message).toBe('Authentication session expired');
        expect(error.cause?.error).toBe('invalid_grant');
        expect(error.cause?.error_description).toBe('Authentication session expired');
      }
    });

    test('preserves mfa_token and mfa_requirements in the cause on an mfa_required error', async () => {
      // openid-client surfaces the token endpoint's mfa_required body nested under `cause`.
      const grantRequest = vi.fn().mockRejectedValue({
        error: 'mfa_required',
        error_description: 'Multifactor authentication required',
        cause: {
          mfa_token: 'mfa_tok_abc123',
          mfa_requirements: { challenge: [{ type: 'otp' }] },
        },
      });
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        const error = e as PasskeyGetTokenError;
        expect(error).toBeInstanceOf(PasskeyGetTokenError);
        expect(error.cause?.error).toBe('mfa_required');
        expect(error.cause?.mfa_token).toBe('mfa_tok_abc123');
        expect(error.cause?.mfa_requirements).toEqual({ challenge: [{ type: 'otp' }] });
      }
    });

    test('is recognized by isMfaRequiredError so the MFA flow can continue', async () => {
      const grantRequest = vi.fn().mockRejectedValue({
        error: 'mfa_required',
        error_description: 'Multifactor authentication required',
        cause: { mfa_token: 'mfa_tok_xyz789' },
      });
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(isMfaRequiredError(e)).toBe(true);
        if (isMfaRequiredError(e)) {
          // Narrowed: cause.mfa_token is guaranteed defined.
          expect(e.cause.mfa_token).toBe('mfa_tok_xyz789');
        }
      }
    });

    test('does not satisfy isMfaRequiredError when mfa_required has no mfa_token', async () => {
      // Auth0 can return mfa_required without an mfa_token (e.g. enrollment-required).
      // isMfaRequiredError requires a string mfa_token, so it must return false here,
      // while the error still reports error === 'mfa_required'.
      const grantRequest = vi.fn().mockRejectedValue({
        error: 'mfa_required',
        error_description: 'MFA enrollment required',
        cause: {},
      });
      const client = createClient({ grantRequest });

      try {
        await client.getTokenByPasskey({ authSession: 'session', credential: mockCredentialCreation });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(isMfaRequiredError(e)).toBe(false);
        const error = e as PasskeyGetTokenError;
        expect(error.cause?.error).toBe('mfa_required');
        expect(error.cause?.mfa_token).toBeUndefined();
      }
    });

    describe('organization validation', () => {
      // grantRequest returning a TokenResponse whose ID-token claims are the given object.
      const grantRequestWithClaims = (claims: Record<string, unknown>): GrantRequestFn => {
        return async () => {
          const response = new TokenResponse(
            'eyJ_access_token',
            Math.floor(Date.now() / 1000) + 86400,
            'eyJ_id_token',
            'eyJ_refresh_token',
            undefined,
            claims as unknown as TokenResponse['claims']
          );
          response.tokenType = 'Bearer';
          return response;
        };
      };

      test('passes when org_id matches', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_id: 'org_abc123' }) });
        const result = await client.getTokenByPasskey({
          authSession: 'eyJ_session',
          credential: mockCredentialCreation,
          organization: 'org_abc123',
        });
        expect(result.claims?.org_id).toBe('org_abc123');
      });

      test('throws OrganizationValidationError when org_id mismatches', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_id: 'org_other' }) });
        await expect(
          client.getTokenByPasskey({
            authSession: 'eyJ_session',
            credential: mockCredentialCreation,
            organization: 'org_abc123',
          })
        ).rejects.toMatchObject({ name: 'OrganizationValidationError', code: 'organization_validation_error' });
      });

      test('passes when org_name matches case-insensitively', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_name: 'acme-corp' }) });
        const result = await client.getTokenByPasskey({
          authSession: 'eyJ_session',
          credential: mockCredentialCreation,
          organization: 'ACME-Corp',
        });
        expect(result.claims?.org_name).toBe('acme-corp');
      });

      test('throws OrganizationValidationError when org_name mismatches', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_name: 'other-corp' }) });
        await expect(
          client.getTokenByPasskey({
            authSession: 'eyJ_session',
            credential: mockCredentialCreation,
            organization: 'acme-corp',
          })
        ).rejects.toMatchObject({ name: 'OrganizationValidationError', code: 'organization_validation_error' });
      });

      test('throws when org claim is missing', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({}) });
        await expect(
          client.getTokenByPasskey({
            authSession: 'eyJ_session',
            credential: mockCredentialCreation,
            organization: 'org_abc123',
          })
        ).rejects.toThrow(OrganizationValidationError);
      });

      test('throws a clear error when organization is only whitespace', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_name: 'acme-corp' }) });
        await expect(
          client.getTokenByPasskey({
            authSession: 'eyJ_session',
            credential: mockCredentialCreation,
            organization: '   ',
          })
        ).rejects.toThrow('organization must not be blank');
      });

      test('throws a clear error when organization is an empty string', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_name: 'acme-corp' }) });
        await expect(
          client.getTokenByPasskey({
            authSession: 'eyJ_session',
            credential: mockCredentialCreation,
            organization: '',
          })
        ).rejects.toThrow('organization must not be blank');
      });

      test('no validation when organization is not set', async () => {
        const client = createClient({ grantRequest: grantRequestWithClaims({ org_id: 'org_abc123' }) });
        const result = await client.getTokenByPasskey({
          authSession: 'eyJ_session',
          credential: mockCredentialCreation,
        });
        expect(result.accessToken).toBe('eyJ_access_token');
      });

      test('skips validation when org is requested but no ID token is returned', async () => {
        // grantRequest returns a TokenResponse with no ID-token claims.
        const grantRequest: GrantRequestFn = async () => {
          const response = new TokenResponse('eyJ_access_token', Math.floor(Date.now() / 1000) + 86400);
          response.tokenType = 'Bearer';
          return response;
        };
        const client = createClient({ grantRequest });
        const result = await client.getTokenByPasskey({
          authSession: 'eyJ_session',
          credential: mockCredentialCreation,
          organization: 'org_abc123',
        });
        expect(result.accessToken).toBe('eyJ_access_token');
      });
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
      // Headers can be a native Headers instance or plain object; check that content-type is present
      const headers = capturedArgs![1]?.headers;
      expect(headers).toBeDefined();
      if (headers instanceof Headers) {
        expect(headers.get('content-type')).toBe('application/json');
        expect(headers.get('Auth0-Client')).toBeDefined(); // Telemetry header should be present
      } else {
        expect(new Headers(headers).get('content-type')).toBe('application/json');
      }

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

  // ─── HttpResponseMetadata — success path ───────────────────────────

  describe('HttpResponseMetadata — success path', () => {
    test('T1.12 register 200 — httpResponse present with status/statusText/headers', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(mockSignupChallengeResponse, {
            status: 200,
            headers: { 'x-request-id': 'test-req-001' },
          });
        })
      );

      const client = createClient();
      const result = await client.register({ email: 'user@example.com' });

      expect(result.httpResponse).toBeDefined();
      expect(result.httpResponse?.status).toBe(200);
      expect(typeof result.httpResponse?.statusText).toBe('string');
      expect(result.httpResponse?.headers).toBeInstanceOf(Headers);
      expect(result.httpResponse?.headers.get('x-request-id')).toBe('test-req-001');
      expect(result.authSession).toBe('eyJ_signup_session');
    });

    test('T1.13 challenge 200 — httpResponse present with status/statusText/headers', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(mockLoginChallengeResponse, {
            status: 200,
            headers: { 'x-request-id': 'test-req-002' },
          });
        })
      );

      const client = createClient();
      const result = await client.challenge();

      expect(result.httpResponse).toBeDefined();
      expect(result.httpResponse?.status).toBe(200);
      expect(typeof result.httpResponse?.statusText).toBe('string');
      expect(result.httpResponse?.headers).toBeInstanceOf(Headers);
      expect(result.httpResponse?.headers.get('x-request-id')).toBe('test-req-002');
      expect(result.authSession).toBe('eyJ_login_session');
    });

    test('T1.9 getTokenByPasskey 200 — httpResponse present with status/statusText/headers', async () => {
      const mockGrantRequest = vi.fn(async () => {
        const response = createMockTokenResponse();
        response.httpResponse = {
          status: 200,
          statusText: 'OK',
          headers: new Headers({ 'x-request-id': 'req-token-001' }),
        };
        return response;
      });
      const client = createClient({ grantRequest: mockGrantRequest });

      const result = await client.getTokenByPasskey({
        authSession: 'eyJ_session',
        credential: mockCredentialCreation,
      });

      expect(result.httpResponse).toBeDefined();
      expect(result.httpResponse?.status).toBe(200);
      expect(typeof result.httpResponse?.statusText).toBe('string');
      expect(result.httpResponse?.headers).toBeInstanceOf(Headers);
      expect(result.accessToken).toBe('eyJ_access_token');
    });

    test('native Headers .get() works on register success httpResponse', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(mockSignupChallengeResponse, {
            status: 200,
            headers: {
              'x-request-id': 'req-native-headers',
              'retry-after': '60',
            },
          });
        })
      );

      const client = createClient();
      const result = await client.register({ email: 'user@example.com' });

      expect(result.httpResponse?.headers.get('x-request-id')).toBe('req-native-headers');
      expect(result.httpResponse?.headers.get('retry-after')).toBe('60');
      expect(typeof result.httpResponse?.headers.get).toBe('function');
    });

    test('native Headers .get() works on challenge success httpResponse', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(mockLoginChallengeResponse, {
            status: 200,
            headers: {
              'x-request-id': 'req-challenge-headers',
              'cache-control': 'no-cache',
            },
          });
        })
      );

      const client = createClient();
      const result = await client.challenge();

      expect(result.httpResponse?.headers.get('x-request-id')).toBe('req-challenge-headers');
      expect(result.httpResponse?.headers.get('cache-control')).toBe('no-cache');
      expect(typeof result.httpResponse?.headers.get).toBe('function');
    });

    test('backwards compatible: old code ignoring httpResponse works', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(mockSignupChallengeResponse, { status: 200 });
        })
      );

      const client = createClient();
      const result = await client.register({ email: 'user@example.com' });

      // Old code pattern (no httpResponse access)
      const authSession: string = result.authSession;
      expect(authSession).toBe('eyJ_signup_session');

      // httpResponse is optional
      const metadata = result.httpResponse;
      expect(metadata?.status).toBe(200);
    });
  });

  // ─── HttpResponseMetadata — error path ─────────────────────────────

  describe('HttpResponseMetadata — error path', () => {
    test('T2.6 register 400 — error has statusCode/headers/body', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'invalid_request', error_description: 'Email is required' },
            { status: 400, headers: { 'x-error-id': 'err-400' } }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        if (e instanceof PasskeyRegisterError) {
          expect(e.statusCode).toBe(400);
          expect(e.headers).toBeInstanceOf(Headers);
          expect(e.body).toBeDefined();
          expect(typeof e.body).toBe('string');
          expect(e.body).toContain('invalid_request');
          expect(e.headers?.get('x-error-id')).toBe('err-400');
        } else {
          throw e;
        }
      }
    });

    test('challenge 403 — error has statusCode/headers/body', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'forbidden', error_description: 'Passkeys not enabled' },
            { status: 403, headers: { 'www-authenticate': 'Bearer realm="example.com"' } }
          );
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        if (e instanceof PasskeyChallengeError) {
          expect(e.statusCode).toBe(403);
          expect(e.headers).toBeInstanceOf(Headers);
          expect(e.body).toBeDefined();
          expect(typeof e.body).toBe('string');
          expect(e.body).toContain('forbidden');
          expect(e.headers?.get('www-authenticate')).toContain('Bearer');
        } else {
          throw e;
        }
      }
    });

    test('native Headers .get() works on register error.headers', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'server_error', error_description: 'Internal error' },
            { status: 500, headers: { 'x-error-trace': 'trace-123' } }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        if (e instanceof PasskeyRegisterError) {
          expect(e.headers?.get('x-error-trace')).toBe('trace-123');
          expect(typeof e.headers?.get).toBe('function');
        } else {
          throw e;
        }
      }
    });

    test('error.body is raw string (not parsed JSON)', async () => {
      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(
            { error: 'invalid_client', error_description: 'Client not found' },
            { status: 401 }
          );
        })
      );

      const client = createClient();

      try {
        await client.challenge();
        expect.fail('Should have thrown');
      } catch (e) {
        if (e instanceof PasskeyChallengeError) {
          expect(typeof e.body).toBe('string');
          expect(e.body).toContain('invalid_client');
          // Verify it can be parsed by caller if needed
          const parsed = JSON.parse(e.body!);
          expect(parsed.error).toBe('invalid_client');
        } else {
          throw e;
        }
      }
    });

    test('register 429 — error has retry-after header', async () => {
      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(
            { error: 'too_many_requests', error_description: 'Rate limited' },
            { status: 429, headers: { 'retry-after': '120' } }
          );
        })
      );

      const client = createClient();

      try {
        await client.register({ email: 'user@example.com' });
        expect.fail('Should have thrown');
      } catch (e) {
        if (e instanceof PasskeyRegisterError) {
          expect(e.statusCode).toBe(429);
          expect(e.headers?.get('retry-after')).toBe('120');
        } else {
          throw e;
        }
      }
    });
  });

  // ─── HttpResponseMetadata — concurrency ────────────────────────────

  describe('HttpResponseMetadata — concurrency', () => {
    test('concurrent calls — no metadata cross-leakage (register vs challenge)', async () => {

      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          return HttpResponse.json(mockSignupChallengeResponse, {
            status: 200,
            headers: { 'x-request-id': 'register-call-1' },
          });
        }),
        http.post(`https://${domain}/passkey/challenge`, () => {
          return HttpResponse.json(mockLoginChallengeResponse, {
            status: 200,
            headers: { 'x-request-id': 'challenge-call-1' },
          });
        })
      );

      const client = createClient();

      const [registerResult, challengeResult] = await Promise.all([
        client.register({ email: 'user1@example.com' }),
        client.challenge(),
      ]);

      // Verify each call got correct metadata (no cross-leakage)
      expect(registerResult.httpResponse?.status).toBe(200);
      expect(registerResult.httpResponse?.headers.get('x-request-id')).toBe('register-call-1');
      expect(registerResult.authSession).toBe('eyJ_signup_session');

      expect(challengeResult.httpResponse?.status).toBe(200);
      expect(challengeResult.httpResponse?.headers.get('x-request-id')).toBe('challenge-call-1');
      expect(challengeResult.authSession).toBe('eyJ_login_session');

      // Verify no swapped metadata
      expect(registerResult.httpResponse?.headers.get('x-request-id')).not.toBe('challenge-call-1');
      expect(challengeResult.httpResponse?.headers.get('x-request-id')).not.toBe('register-call-1');
    });

    test('multiple parallel register calls — each captures own request-id header', async () => {
      let callCount = 0;

      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          callCount++;
          const requestId = `register-${callCount}`;
          return HttpResponse.json(mockSignupChallengeResponse, {
            status: 200,
            headers: { 'x-request-id': requestId },
          });
        })
      );

      const client = createClient();

      const [result1, result2, result3] = await Promise.all([
        client.register({ email: 'user1@example.com' }),
        client.register({ email: 'user2@example.com' }),
        client.register({ email: 'user3@example.com' }),
      ]);

      // Each call captures its own x-request-id
      expect(result1.httpResponse?.headers.get('x-request-id')).toBe('register-1');
      expect(result2.httpResponse?.headers.get('x-request-id')).toBe('register-2');
      expect(result3.httpResponse?.headers.get('x-request-id')).toBe('register-3');

      // All have status 200
      expect(result1.httpResponse?.status).toBe(200);
      expect(result2.httpResponse?.status).toBe(200);
      expect(result3.httpResponse?.status).toBe(200);
    });

    test('concurrent calls with different error statuses — each error has correct statusCode', async () => {
      let callCount = 0;

      server.use(
        http.post(`https://${domain}/passkey/challenge`, () => {
          callCount++;
          // First call: 401, Second call: 429
          if (callCount === 1) {
            return HttpResponse.json(
              { error: 'invalid_client', error_description: 'Client not found' },
              { status: 401 }
            );
          } else {
            return HttpResponse.json(
              { error: 'too_many_requests', error_description: 'Rate limited' },
              { status: 429 }
            );
          }
        })
      );

      const client = createClient();

      const results = await Promise.allSettled([
        client.challenge(),
        client.challenge(),
      ]);

      expect(results[0].status).toBe('rejected');
      expect(results[1].status).toBe('rejected');

      const errors = results.map((r) => (r.status === 'rejected' ? r.reason : null)).filter(Boolean);
      const statuses = (errors as Array<{ statusCode?: number }>).map((e) => e.statusCode).sort((a, b) => (a ?? 0) - (b ?? 0));

      expect(statuses).toContain(401);
      expect(statuses).toContain(429);
      expect(statuses[0]).not.toBe(statuses[1]);
    });

    test('concurrent success and error — each result has correct httpResponse/statusCode', async () => {
      let callCount = 0;

      server.use(
        http.post(`https://${domain}/passkey/register`, () => {
          callCount++;
          // First call: success, Second call: error
          if (callCount === 1) {
            return HttpResponse.json(mockSignupChallengeResponse, {
              status: 200,
              headers: { 'x-request-id': 'success-call' },
            });
          } else {
            return HttpResponse.json(
              { error: 'invalid_request', error_description: 'Invalid' },
              { status: 400, headers: { 'x-request-id': 'error-call' } }
            );
          }
        })
      );

      const client = createClient();

      const [success, error] = await Promise.allSettled([
        client.register({ email: 'user@example.com' }),
        client.register({ email: 'bad@example.com' }),
      ]);

      // Success call
      expect(success.status).toBe('fulfilled');
      if (success.status === 'fulfilled') {
        expect(success.value.httpResponse?.status).toBe(200);
        expect(success.value.httpResponse?.headers.get('x-request-id')).toBe('success-call');
      }

      // Error call
      expect(error.status).toBe('rejected');
      const errorReason = error.status === 'rejected' ? error.reason as { statusCode?: number; headers?: Headers } : null;
      expect(errorReason?.statusCode).toBe(400);
      expect(errorReason?.headers?.get('x-request-id')).toBe('error-call');

      // Verify NO cross-leakage
      if (success.status === 'fulfilled') {
        expect(success.value.httpResponse?.status).not.toBe(400);
      }
      expect(errorReason?.statusCode).not.toBe(200);
    });
  });
});
