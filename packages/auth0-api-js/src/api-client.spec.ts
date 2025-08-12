import {
  expect,
  test,
  afterAll,
  beforeAll,
  afterEach,
  beforeEach,
  describe,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './test-utils/tokens.js';
import { ApiClient } from './api-client.js';

const domain = 'auth0.local';
let accessToken: string;
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
  pushed_authorization_request_endpoint: `https://${domain}/pushed-authorize`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
  http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
    const info = await request.formData();
    const shouldFailTokenExchange =
      info.get('auth_req_id') === 'auth_req_should_fail' ||
      info.get('code') === '<code_should_fail>' ||
      info.get('subject_token') === '<subject_token_should_fail>' ||
      info.get('refresh_token') === '<refresh_token_should_fail>';

    return shouldFailTokenExchange
      ? HttpResponse.json(
          { error: '<error_code>', error_description: '<error_description>' },
          { status: 400 }
        )
      : HttpResponse.json({
          access_token: accessToken,
          expires_in: 60,
          token_type: 'Bearer',
          scope: '<scope>',
        });
  }),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
});

afterEach(() => {
  mockOpenIdConfiguration = {
    issuer: `https://${domain}/`,
    authorization_endpoint: `https://${domain}/authorize`,
    backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
    token_endpoint: `https://${domain}/custom/token`,
    end_session_endpoint: `https://${domain}/logout`,
    pushed_authorization_request_endpoint: `https://${domain}/pushed-authorize`,
    jwks_uri: `https://${domain}/.well-known/jwks.json`,
  };
  server.resetHandlers();
});

test('verifyAccessToken - should verify an access token successfully', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  const payload = await apiClient.verifyAccessToken({ accessToken });

  expect(payload).toBeDefined();
});

test('verifyAccessToken - should fail when no iss claim in token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', undefined, false);

  await expect(
    apiClient.verifyAccessToken({ accessToken })
  ).rejects.toThrowError('missing required "iss" claim');
});

test('verifyAccessToken - should fail when invalid iss claim in token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(
    domain,
    'user_123',
    '<audience>',
    'https://invalid-issuer.local'
  );

  await expect(
    apiClient.verifyAccessToken({ accessToken })
  ).rejects.toThrowError('unexpected "iss" claim value');
});

test('verifyAccessToken - should fail when no aud claim in token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123');

  await expect(
    apiClient.verifyAccessToken({ accessToken })
  ).rejects.toThrowError('missing required "aud" claim');
});

test('verifyAccessToken - should fail when invalid iss claim in token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(
    domain,
    'user_123',
    '<invalid_audience>'
  );

  await expect(
    apiClient.verifyAccessToken({ accessToken })
  ).rejects.toThrowError('unexpected "aud" claim value');
});

test('verifyAccessToken - should fail when no iat claim in token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(
    domain,
    'user_123',
    '<audience>',
    undefined,
    false,
    undefined
  );

  await expect(
    apiClient.verifyAccessToken({ accessToken })
  ).rejects.toThrowError('missing required "iat" claim');
});

test('verifyAccessToken - should fail when no exp claim in token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(
    domain,
    'user_123',
    '<audience>',
    undefined,
    undefined,
    false
  );

  await expect(
    apiClient.verifyAccessToken({ accessToken })
  ).rejects.toThrowError('missing required "exp" claim');
});

test('verifyAccessToken - should throw when no audience configured', async () => {
  expect(
    () =>
      new ApiClient({
        domain,
        //eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any)
  ).toThrowError(`The argument 'audience' is required but was not provided.`);
});

describe('Resource Server Client', () => {

  test('getTokenForConnection - should throw error when client credentials are not provided', async () => {
    const apiClient = new ApiClient({
      domain,
      audience: '<audience>',
    });

    await expect(
      apiClient.getTokenForConnection({
        connection: 'test-connection',
        accessToken: 'test-access-token',
      })
    ).rejects.toThrow('This operation requires client credentials');
  });

  test('getTokenForConnection - should retrieve connection token', async () => {
    const apiClient = new ApiClient({
      domain,
      audience: '<audience>',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
    });

    const result = await apiClient.getTokenForConnection({
      connection: 'github',
      accessToken: 'access-token-123',
      loginHint: 'github|12345',
    });

    expect(result).toEqual({
      accessToken: accessToken,
      expiresAt: expect.any(Number),
      scope: '<scope>',
      connection: 'github',
      loginHint: 'github|12345',
    });
  });

  test('getTokenForConnection - should handle errors gracefully', async () => {
    const apiClient = new ApiClient({
      domain,
      audience: '<audience>',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
    });

    await expect(
      apiClient.getTokenForConnection({
        connection: 'invalid-connection',
        accessToken: '<subject_token_should_fail>',
      })
    ).rejects.toThrow('Failed to retrieve connection token');
  });
});
