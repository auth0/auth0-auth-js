import {
  expect,
  test,
  afterAll,
  beforeAll,
  afterEach,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MissingClientAuthError, TokenExchangeError } from '@auth0/auth0-auth-js';
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
  ).rejects.toThrow(MissingClientAuthError);
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

test('getTokenByExchangeProfile - should throw when no clientId configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  await expect(
    apiClient.getTokenByExchangeProfile('my-subject-token', {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrow(MissingClientAuthError);
});

test('getTokenByExchangeProfile - should throw when no clientSecret configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
  });

  await expect(
    apiClient.getTokenByExchangeProfile('my-subject-token', {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrow(MissingClientAuthError);
});

test('getTokenByExchangeProfile - should return tokens when exchange succeeds', async () => {
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
        body.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange' &&
        body.get('client_id') === 'my-client-id' &&
        body.get('client_secret') === 'my-client-secret' &&
        body.get('subject_token') === 'my-subject-token' &&
        body.get('subject_token_type') === 'urn:my-company:mcp-token' &&
        body.get('audience') === 'https://api.backend.com' &&
        body.get('scope') === 'read:data write:data'
      ) {
        return HttpResponse.json(
          {
            access_token: 'exchanged-access-token',
            expires_in: 3600,
            scope: 'read:data write:data',
            token_type: 'Bearer',
            issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          },
          { status: 200 }
        );
      }

      return HttpResponse.json(
        { error: 'invalid_request', error_description: 'Invalid request parameters.' },
        { status: 400 }
      );
    })
  );

  const result = await apiClient.getTokenByExchangeProfile(
    'my-subject-token',
    {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
      scope: 'read:data write:data',
    }
  );

  expect(result).toMatchObject({
    accessToken: 'exchanged-access-token',
    expiresAt: expect.any(Number),
    scope: 'read:data write:data',
  });
  expect(result.tokenType?.toLowerCase()).toBe('bearer');
});

test('getTokenByExchangeProfile - should include idToken and refreshToken when present', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });
  const idToken = await generateToken(domain, 'user_123', 'my-client-id');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () => {
      return HttpResponse.json(
        {
          access_token: 'exchanged-access-token',
          expires_in: 3600,
          token_type: 'Bearer',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          id_token: idToken,
          refresh_token: 'refresh-token',
        },
        { status: 200 }
      );
    })
  );

  const result = await apiClient.getTokenByExchangeProfile('my-subject-token', {
    subjectTokenType: 'urn:my-company:mcp-token',
    audience: 'https://api.backend.com',
  });

  expect(result.idToken).toBe(idToken);
  expect(result.refreshToken).toBe('refresh-token');
});

test('getTokenByExchangeProfile - should handle exchange errors', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  server.use(
    http.post(`https://${domain}/oauth/token`, () => {
      return HttpResponse.json(
        { error: 'invalid_grant', error_description: 'Subject token validation failed.' },
        { status: 403 }
      );
    })
  );

  await expect(
    apiClient.getTokenByExchangeProfile('invalid-token', {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrowError(
    "Failed to exchange token of type 'urn:my-company:mcp-token' for audience 'https://api.backend.com'."
  );
});

test('getTokenByExchangeProfile - should throw when token is empty', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  await expect(
    apiClient.getTokenByExchangeProfile('', {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrow(TokenExchangeError);
});

test('getTokenByExchangeProfile - should propagate issued_token_type from token endpoint', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  server.use(
    http.post(`https://${domain}/oauth/token`, async () => {
      return HttpResponse.json(
        {
          access_token: 'exchanged-access-token',
          expires_in: 3600,
          token_type: 'Bearer',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        },
        { status: 200 }
      );
    })
  );

  const result = await apiClient.getTokenByExchangeProfile(
    'my-subject-token',
    {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
    }
  );

  expect(result.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
  expect(result.tokenType?.toLowerCase()).toBe('bearer');
});

test('getTokenByExchangeProfile - should include organization parameter when provided', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  let capturedOrganization: string | null = null;
  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      capturedOrganization = body.get('organization') as string;
      
      if (
        body.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange' &&
        body.get('client_id') === 'my-client-id' &&
        body.get('client_secret') === 'my-client-secret' &&
        body.get('subject_token') === 'my-subject-token' &&
        body.get('subject_token_type') === 'urn:my-company:mcp-token' &&
        body.get('audience') === 'https://api.backend.com' &&
        body.get('organization') === 'org_abc123'
      ) {
        return HttpResponse.json(
          {
            access_token: 'exchanged-access-token',
            expires_in: 3600,
            scope: 'read:data write:data',
            token_type: 'Bearer',
            issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          },
          { status: 200 }
        );
      }

      return HttpResponse.json(
        { error: 'invalid_request', error_description: 'Invalid request parameters.' },
        { status: 400 }
      );
    })
  );

  const result = await apiClient.getTokenByExchangeProfile(
    'my-subject-token',
    {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
      organization: 'org_abc123',
      scope: 'read:data write:data',
    }
  );

  expect(capturedOrganization).toBe('org_abc123');
  expect(result).toMatchObject({
    accessToken: 'exchanged-access-token',
    expiresAt: expect.any(Number),
    scope: 'read:data write:data',
  });
});

test('getTokenByExchangeProfile - should work without organization parameter (backward compatible)', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  let capturedOrganization: string | null = null;
  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      capturedOrganization = body.get('organization') as string;
      
      if (
        body.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange' &&
        body.get('subject_token') === 'my-subject-token' &&
        body.get('subject_token_type') === 'urn:my-company:mcp-token'
      ) {
        return HttpResponse.json(
          {
            access_token: 'exchanged-access-token',
            expires_in: 3600,
            token_type: 'Bearer',
          },
          { status: 200 }
        );
      }

      return HttpResponse.json(
        { error: 'invalid_request', error_description: 'Invalid request parameters.' },
        { status: 400 }
      );
    })
  );

  const result = await apiClient.getTokenByExchangeProfile(
    'my-subject-token',
    {
      subjectTokenType: 'urn:my-company:mcp-token',
      audience: 'https://api.backend.com',
    }
  );

  expect(capturedOrganization).toBeNull();
  expect(result.accessToken).toBe('exchanged-access-token');
});
