import {
  expect,
  test,
  afterAll,
  beforeAll,
  afterEach,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './test-utils/tokens.js';
import { ApiClient } from './api-client.js';

const domain = 'auth0.local';
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
  token_endpoint: `https://${domain}/oauth/token`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

afterEach(() => {
  mockOpenIdConfiguration = {
    issuer: `https://${domain}/`,
    jwks_uri: `https://${domain}/.well-known/jwks.json`,
    token_endpoint: `https://${domain}/oauth/token`,
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

test('getAccessTokenForConnection - should throw when no clientId configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  await expect(
    apiClient.getAccessTokenForConnection({
      connection: 'my-connection',
      accessToken: 'my-access-token',
    })
  ).rejects.toThrowError(
    'Client credentials are required to use getAccessTokenForConnection'
  );
});

test('getAccessTokenForConnection - should throw when no clientSecret configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
  });

  await expect(
    apiClient.getAccessTokenForConnection({
      connection: 'my-connection',
      accessToken: 'my-access-token',
    })
  ).rejects.toThrowError(
    'The client secret or client assertion signing key must be provided.'
  );
});

test('getAccessTokenForConnection - should return a token set when the exchange is successful', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      if (
        body.get('grant_type') ===
          "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" &&
        body.get('client_id') === 'my-client-id' &&
        body.get('client_secret') === 'my-client-secret' &&
        body.get('subject_token') === 'my-access-token' &&
        body.get('subject_token_type') ===
          "urn:ietf:params:oauth:token-type:access_token" &&
        body.get('connection') === 'my-connection'
      ) {
        return HttpResponse.json(
          {
            access_token: 'new-access-token',
            expires_in: 86400,
            scope: 'openid profile email',
            token_type: 'Bearer',
          },
          { status: 200 }
        );
      }

      return HttpResponse.json(
        { error: 'invalid_request', error_description: 'The request parameters are invalid.' },
        { status: 400 }
      );
    })
  );

  const tokenSet = await apiClient.getAccessTokenForConnection({
    connection: 'my-connection',
    accessToken: 'my-access-token',
    loginHint: 'login-hint',
  });

  expect(tokenSet).toStrictEqual({
    accessToken: 'new-access-token',
    expiresAt: expect.any(Number),
    scope: 'openid profile email',
    connection: 'my-connection',
    loginHint: 'login-hint',
  });
});

test('getAccessTokenForConnection - should throw when both accessToken and refreshToken are provided', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  await expect(
    apiClient.getAccessTokenForConnection({
      connection: 'my-connection',
      accessToken: 'my-access-token',
      refreshToken: 'my-refresh-token',
    })
  ).rejects.toThrowError('Provide either accessToken or refreshToken, not both.');
});