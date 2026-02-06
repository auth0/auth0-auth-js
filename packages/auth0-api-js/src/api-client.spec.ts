import {
  expect,
  test,
  afterAll,
  beforeAll,
  afterEach,
  vi,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MissingClientAuthError, TokenExchangeError } from '@auth0/auth0-auth-js';
import { generateToken, jwks } from './test-utils/tokens.js';
import { ApiClient } from './api-client.js';
import { SignJWT } from 'jose';

const domain = 'auth0.local';
const brandDomain = 'brand.local';
const brandIssuer = `https://${brandDomain}/`;
const brandJwksUri = `https://${brandDomain}/.well-known/jwks.json`;
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

const hsSecret = new TextEncoder().encode('test-secret');

const createHsToken = async (issuer: string, audience: string) =>
  await new SignJWT({ foo: 'bar' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(hsSecret);

const setupBrandHandlers = () => {
  server.use(
    http.get(`https://${brandDomain}/.well-known/openid-configuration`, () => {
      return HttpResponse.json({
        issuer: brandIssuer,
        jwks_uri: brandJwksUri,
        token_endpoint: `https://${brandDomain}/oauth/token`,
      });
    }),
    http.get(brandJwksUri, () => HttpResponse.json({ keys: jwks }))
  );
};

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

test('verifyAccessToken - should verify with domains list', async () => {
  setupBrandHandlers();
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [domain, brandDomain],
  });

  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');
  const payload = await apiClient.verifyAccessToken({ accessToken });

  expect(payload).toBeDefined();
});

test('verifyAccessToken - should fail when issuer not in domains list (no discovery call)', async () => {
  let discoveryCalls = 0;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, () => {
      discoveryCalls += 1;
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );

  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [domain],
  });
  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'unexpected "iss" claim value (issuer is not in the configured domain list)'
  );
  expect(discoveryCalls).toBe(0);
});

test('verifyAccessToken - should fail when discovery issuer mismatches token iss', async () => {
  setupBrandHandlers();
  server.use(
    http.get(`https://${brandDomain}/.well-known/openid-configuration`, () => {
      return HttpResponse.json({
        issuer: `https://${domain}/`,
        jwks_uri: brandJwksUri,
        token_endpoint: `https://${brandDomain}/oauth/token`,
      });
    })
  );

  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [brandDomain],
  });
  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    /"issuer" property does not match the expected value/
  );
});

test('verifyAccessToken - domains resolver receives context', async () => {
  setupBrandHandlers();
  const resolver = vi.fn(async ({ url, headers, unverifiedIss }) => {
    expect(url).toBe('https://api.example.com/private');
    expect(headers?.host).toBe('api.example.com');
    expect(unverifiedIss).toBe(brandIssuer);
    return [brandDomain];
  });
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: resolver,
  });
  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');

  await apiClient.verifyAccessToken({
    accessToken,
    url: 'https://api.example.com/private',
    headers: { host: 'api.example.com' },
  });

  expect(resolver).toHaveBeenCalledTimes(1);
});

test('verifyAccessToken - domains resolver must return an array', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => 'not-an-array' as unknown as string[],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'domain validation failed: domains resolver must return an array of domain strings'
  );
});

test('verifyAccessToken - domains resolver must not return empty array', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => [],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'domain validation failed: domains resolver returned no allowed domains'
  );
});

test('verifyAccessToken - domains resolver must return strings', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => [123 as unknown as string],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'domain validation failed: domains resolver returned a non-string domain'
  );
});

test('verifyAccessToken - domains resolver errors are surfaced', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => {
      throw new Error('resolver failed');
    },
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'domain validation failed: domains resolver failed'
  );
});

test('verifyAccessToken - domains resolver invalid domain is surfaced', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => ['auth0.local/path'],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'invalid domain URL (path segments are not allowed)'
  );
});

test('verifyAccessToken - should reject HS* tokens before discovery', async () => {
  let discoveryCalls = 0;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, () => {
      discoveryCalls += 1;
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );

  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });
  const accessToken = await createHsToken(`https://${domain}/`, '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'unsupported algorithm (symmetric algorithms are not supported)'
  );
  expect(discoveryCalls).toBe(0);
});

test('verifyAccessToken - should fail when no iss claim in token with domains', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [domain],
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', false);

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError('missing required "iss" claim');
});

test('verifyAccessToken - discovery cache TTL=0 triggers refetch', async () => {
  let discoveryCalls = 0;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, () => {
      discoveryCalls += 1;
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );

  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    discoveryCache: { ttl: 0, maxEntries: 100 },
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await apiClient.verifyAccessToken({ accessToken });
  await apiClient.verifyAccessToken({ accessToken });

  expect(discoveryCalls).toBe(2);
});

test('verifyAccessToken - discovery cache LRU evicts least recently used', async () => {
  const brandIssuerConfig = {
    issuer: brandIssuer,
    jwks_uri: brandJwksUri,
    token_endpoint: `https://${brandDomain}/oauth/token`,
  };
  let domainCalls = 0;
  let brandCalls = 0;

  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, () => {
      domainCalls += 1;
      return HttpResponse.json(mockOpenIdConfiguration);
    }),
    http.get(`https://${brandDomain}/.well-known/openid-configuration`, () => {
      brandCalls += 1;
      return HttpResponse.json(brandIssuerConfig);
    }),
    http.get(brandJwksUri, () => HttpResponse.json({ keys: jwks }))
  );

  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [domain, brandDomain],
    discoveryCache: { ttl: 600, maxEntries: 1 },
  });

  const tokenA = await generateToken(domain, '<sub>', '<audience>');
  const tokenB = await generateToken(brandDomain, '<sub>', '<audience>');

  await apiClient.verifyAccessToken({ accessToken: tokenA });
  await apiClient.verifyAccessToken({ accessToken: tokenB });
  await apiClient.verifyAccessToken({ accessToken: tokenA });

  expect(domainCalls).toBe(2);
  expect(brandCalls).toBe(1);
});

test('verifyAccessToken - should fail when discovery metadata missing jwks_uri', async () => {
  server.use(
    http.get(`https://${brandDomain}/.well-known/openid-configuration`, () => {
      return HttpResponse.json({
        issuer: brandIssuer,
      });
    })
  );

  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [brandDomain],
  });
  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError(
    'missing "jwks_uri" in discovery metadata'
  );
});

test('verifyAccessToken - jwks fetch non-ok response surfaces JWKS request failed', async () => {
  const customFetch = vi.fn(async (input) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify(mockOpenIdConfiguration), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.endsWith('/.well-known/jwks.json')) {
      return new Response('fail', { status: 500 });
    }
    return new Response('not found', { status: 404 });
  });

  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    customFetch,
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError('JWKS request failed');
});

test('verifyAccessToken - jwks fetch thrown error surfaces JWKS request failed', async () => {
  const customFetch = vi.fn(async (input) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify(mockOpenIdConfiguration), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.endsWith('/.well-known/jwks.json')) {
      throw new Error('network down');
    }
    return new Response('not found', { status: 404 });
  });

  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    customFetch,
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(apiClient.verifyAccessToken({ accessToken })).rejects.toThrowError('JWKS request failed');
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

test('ApiClient - should reject invalid domains configuration', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
        domains: [],
      })
  ).toThrowError('Invalid domains configuration: "domains" must not be empty');
});

test('ApiClient - should reject invalid domains list entries', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
        domains: ['auth0.local/path'],
      })
  ).toThrowError('Invalid domains configuration: invalid domain URL (path segments are not allowed)');
});

test('ApiClient - should reject invalid domains type', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
        domains: 'not-a-list' as unknown as string[],
      })
  ).toThrowError('Invalid domains configuration: "domains" must be an array or a function');
});

test('ApiClient - should reject empty domain', () => {
  expect(
    () =>
      new ApiClient({
        domain: '',
        audience: '<audience>',
      })
  ).toThrowError('Invalid domain configuration: domain must be a non-empty string');
});

test('ApiClient - should reject domain with credentials', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'user:pass@auth0.local',
        audience: '<audience>',
      })
  ).toThrowError('Invalid domain configuration: invalid domain URL (credentials are not allowed)');
});

test('ApiClient - should reject domain with query/fragment', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'auth0.local?foo=bar',
        audience: '<audience>',
      })
  ).toThrowError('Invalid domain configuration: invalid domain URL (query/fragment are not allowed)');
});

test('ApiClient - should reject invalid domain format', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'invalid domain',
        audience: '<audience>',
      })
  ).toThrowError('Invalid domain configuration: invalid domain URL');
});

test('ApiClient - should accept domain with https scheme', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'https://auth0.local',
        audience: '<audience>',
      })
  ).not.toThrow();
});

test('ApiClient - should reject domain with http scheme', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'http://auth0.local',
        audience: '<audience>',
      })
  ).toThrowError('Invalid domain configuration: invalid domain URL (https required)');
});

test('ApiClient - should accept domain with trailing slash', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'auth0.local/',
        audience: '<audience>',
      })
  ).not.toThrow();
});

test('ApiClient - should accept domains with https scheme', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
        domains: ['https://auth0.local'],
      })
  ).not.toThrow();
});

test('ApiClient - should reject domains with http scheme', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
        domains: ['http://auth0.local'],
      })
  ).toThrowError('Invalid domains configuration: invalid domain URL (https required)');
});

test('ApiClient - should reject domain with path segment', () => {
  expect(
    () =>
      new ApiClient({
        domain: 'auth0.local/path',
        audience: '<audience>',
      })
  ).toThrowError('Invalid domain configuration: invalid domain URL (path segments are not allowed)');
});

test('ApiClient - should reject algorithms with HS*', () => {
  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        algorithms: ['HS256'],
      })
  ).toThrowError('Invalid algorithms configuration: symmetric algorithms are not allowed');
});

test('ApiClient - should reject invalid algorithms configuration', () => {
  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        algorithms: [],
      })
  ).toThrowError('Invalid algorithms configuration: "algorithms" must be a non-empty array');

  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        algorithms: ['RS256', '' as unknown as string],
      })
  ).toThrowError('Invalid algorithms configuration: "algorithms" must be a non-empty array');
});

test('ApiClient - should accept algorithms list', () => {
  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        algorithms: ['RS256', 'RS256', 'ES256'],
      })
  ).not.toThrow();
});

test('ApiClient - should reject invalid discoveryCache values', () => {
  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        discoveryCache: { ttl: -1 },
      })
  ).toThrowError('Invalid discoveryCache configuration: "ttl" must be a non-negative number');

  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        discoveryCache: { ttl: Number.NaN },
      })
  ).toThrowError('Invalid discoveryCache configuration: "ttl" must be a number');

  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        discoveryCache: { maxEntries: -1 },
      })
  ).toThrowError('Invalid discoveryCache configuration: "maxEntries" must be a non-negative number');

  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        discoveryCache: { maxEntries: Number.NaN },
      })
  ).toThrowError('Invalid discoveryCache configuration: "maxEntries" must be a number');
});

test('ApiClient - should require domain when client credentials are provided', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        domains: [domain],
      } as unknown as import('./types.js').ApiClientOptions)
  ).toThrowError(`The argument 'domain' is required but was not provided.`);
});

test('ApiClient - should require domain or domains', () => {
  expect(
    () =>
      new ApiClient({
        audience: '<audience>',
      } as unknown as import('./types.js').ApiClientOptions)
  ).toThrowError(`The argument 'domain or domains' is required but was not provided.`);
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
