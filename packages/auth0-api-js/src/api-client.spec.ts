import {
  expect,
  test,
  describe,
  afterAll,
  beforeAll,
  afterEach,
  beforeEach,
  vi,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MissingClientAuthError, TokenExchangeError } from '@auth0/auth0-auth-js';
import { DownscopedTokenError } from './errors.js';
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

test('verifyAccessToken - returns the act claim when present', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>', undefined, undefined, undefined, {
    act: {
      sub: 'mcp_server_client_id',
      act: {
        sub: 'spa_client_id',
      },
    },
  });

  const payload = await apiClient.verifyAccessToken({ accessToken });

  expect(payload.act?.sub).toBe('mcp_server_client_id');
  expect(payload.act?.act?.sub).toBe('spa_client_id');
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

test('verifyAccessToken - when domains normalize to the same issuer URL, discovery is called only once', async () => {
  let discoveryCalls = 0;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, () => {
      discoveryCalls += 1;
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );

  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: [domain, `https://${domain}/`, `${domain}/`],
  });

  const accessToken = await generateToken(domain, '<sub>', '<audience>');
  const payload = await apiClient.verifyAccessToken({
    accessToken,
    httpUrl: 'https://api.example.com/private',
  });

  expect(payload).toBeDefined();
  expect(discoveryCalls).toBe(1);
});

test('verifyAccessToken - when both domain and domains are configured, verification uses domains', async () => {
  let defaultDomainDiscoveryCalls = 0;
  let brandDomainDiscoveryCalls = 0;

  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, () => {
      defaultDomainDiscoveryCalls += 1;
      return HttpResponse.json(mockOpenIdConfiguration);
    }),
    http.get(`https://${brandDomain}/.well-known/openid-configuration`, () => {
      brandDomainDiscoveryCalls += 1;
      return HttpResponse.json({
        issuer: brandIssuer,
        jwks_uri: brandJwksUri,
        token_endpoint: `https://${brandDomain}/oauth/token`,
      });
    }),
    http.get(brandJwksUri, () => HttpResponse.json({ keys: jwks }))
  );

  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    domains: [brandDomain],
  });

  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');
  const payload = await apiClient.verifyAccessToken({
    accessToken,
    httpUrl: 'https://api.example.com/private',
  });

  expect(payload).toBeDefined();
  expect(defaultDomainDiscoveryCalls).toBe(0);
  expect(brandDomainDiscoveryCalls).toBe(1);
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

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
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

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
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
    httpUrl: 'https://api.example.com/private',
    headers: { host: 'api.example.com' },
  });

  expect(resolver).toHaveBeenCalledTimes(1);
});

test('verifyAccessToken - domains resolver receives undefined url/headers when not provided', async () => {
  setupBrandHandlers();
  const resolver = vi.fn(async ({ url, headers, unverifiedIss }) => {
    expect(url).toBeUndefined();
    expect(headers).toBeUndefined();
    expect(unverifiedIss).toBe(brandIssuer);
    return [brandDomain];
  });

  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: resolver,
  });
  const accessToken = await generateToken(brandDomain, '<sub>', '<audience>');

  const payload = await apiClient.verifyAccessToken({ accessToken });

  expect(payload).toBeDefined();
  expect(resolver).toHaveBeenCalledTimes(1);
});

test('verifyAccessToken - domains resolver must return an array', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => 'not-an-array' as unknown as string[],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
    'domain validation failed: domains resolver must return an array of domain strings'
  );
});

test('verifyAccessToken - domains resolver must not return empty array', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => [],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
    'domain validation failed: domains resolver returned no allowed domains'
  );
});

test('verifyAccessToken - domains resolver must return strings', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => [123 as unknown as string],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
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

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
    'domain validation failed: domains resolver failed'
  );
});

test('verifyAccessToken - domains resolver invalid domain is surfaced', async () => {
  const apiClient = new ApiClient({
    audience: '<audience>',
    domains: async () => ['auth0.local/path'],
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
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

  await apiClient.verifyAccessToken({
    accessToken: tokenA,
    httpUrl: 'https://api.example.com/private',
  });
  await apiClient.verifyAccessToken({
    accessToken: tokenB,
    httpUrl: 'https://api.example.com/private',
  });
  await apiClient.verifyAccessToken({
    accessToken: tokenA,
    httpUrl: 'https://api.example.com/private',
  });

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

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      httpUrl: 'https://api.example.com/private',
    })
  ).rejects.toThrowError(
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
  ).toThrowError('Invalid algorithms configuration: each "algorithms" entry must be a non-empty string');
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

test('ApiClient - should allow both domain and domains configuration', () => {
  expect(
    () =>
      new ApiClient({
        domain,
        audience: '<audience>',
        domains: [domain, brandDomain],
      })
  ).not.toThrow();
});

test('verifyAccessToken - should verify token with custom algorithms option', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  const payload = await apiClient.verifyAccessToken({
    accessToken,
    algorithms: ['RS256', 'ES256']
  });

  expect(payload).toBeDefined();
});

test('verifyAccessToken - should fail when token algorithm not in allowed algorithms', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });
  const accessToken = await generateToken(domain, '<sub>', '<audience>');

  await expect(
    apiClient.verifyAccessToken({
      accessToken,
      algorithms: ['ES256', 'ES384']
    })
  ).rejects.toThrowError();
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

  const newAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');

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
            access_token: newAccessToken,
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
    accessToken: newAccessToken,
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

  const exchangedAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');

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
            access_token: exchangedAccessToken,
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
    accessToken: exchangedAccessToken,
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
  const exchangedAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () => {
      return HttpResponse.json(
        {
          access_token: exchangedAccessToken,
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

  const exchangedAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () => {
      return HttpResponse.json(
        {
          access_token: exchangedAccessToken,
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

  const exchangedAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');
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
            access_token: exchangedAccessToken,
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
    accessToken: exchangedAccessToken,
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

  const exchangedAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');
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
            access_token: exchangedAccessToken,
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
  expect(result.accessToken).toBe(exchangedAccessToken);
});

test('getTokenOnBehalfOf - should throw when no clientId configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  await expect(
    apiClient.getTokenOnBehalfOf('my-access-token', {
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrow(MissingClientAuthError);
});

test('getTokenOnBehalfOf - should throw when no clientSecret configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
  });

  await expect(
    apiClient.getTokenOnBehalfOf('my-access-token', {
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrow(MissingClientAuthError);
});

test('getTokenOnBehalfOf - should exchange an access token using fixed OBO token types', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const oboAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');
  let capturedOrganization: string | null = null;
  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      capturedOrganization = body.get('organization') as string | null;

      if (
        body.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange' &&
        body.get('client_id') === 'my-client-id' &&
        body.get('client_secret') === 'my-client-secret' &&
        body.get('subject_token') === 'my-access-token' &&
        body.get('subject_token_type') === 'urn:ietf:params:oauth:token-type:access_token' &&
        body.get('requested_token_type') === 'urn:ietf:params:oauth:token-type:access_token' &&
        body.get('audience') === 'https://api.backend.com' &&
        body.get('scope') === 'read:data write:data'
      ) {
        return HttpResponse.json(
          {
            access_token: oboAccessToken,
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

  const result = await apiClient.getTokenOnBehalfOf('my-access-token', {
    audience: 'https://api.backend.com',
    scope: 'read:data write:data',
  });

  expect(capturedOrganization).toBeNull();
  expect(result).toMatchObject({
    accessToken: oboAccessToken,
    expiresAt: expect.any(Number),
    scope: 'read:data write:data',
    issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  });
  expect(result.tokenType?.toLowerCase()).toBe('bearer');
});

test('getTokenOnBehalfOf - should not expose idToken or refreshToken', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });
  const idToken = await generateToken(domain, 'user_123', 'my-client-id');
  const oboAccessToken = await generateToken(domain, 'user_123', 'https://api.backend.com');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () => {
      return HttpResponse.json(
        {
          access_token: oboAccessToken,
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

  const result = await apiClient.getTokenOnBehalfOf('my-access-token', {
    audience: 'https://api.backend.com',
  });

  expect(result).not.toHaveProperty('idToken');
  expect(result).not.toHaveProperty('refreshToken');
  expect(result.accessToken).toBe(oboAccessToken);
});

test('getTokenOnBehalfOf - should handle exchange errors', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  server.use(
    http.post(`https://${domain}/oauth/token`, () => {
      return HttpResponse.json(
        { error: 'invalid_target', error_description: 'The target API is not allowed.' },
        { status: 400 }
      );
    })
  );

  await expect(
    apiClient.getTokenOnBehalfOf('my-access-token', {
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrowError(
    "Failed to exchange token of type 'urn:ietf:params:oauth:token-type:access_token' for audience 'https://api.backend.com'."
  );
});

// ---------------------------------------------------------------------------
// OBO cache-aside tests (store path)
// ---------------------------------------------------------------------------

function makeStoreMock() {
  return {
    get: vi
      .fn<(key: string) => Promise<{ accessToken: string; expiresAt: number; grantedScopes: string[] } | undefined>>()
      .mockResolvedValue(undefined),
    set: vi
      .fn<(key: string, value: { accessToken: string; expiresAt: number; grantedScopes: string[] }) => Promise<void>>()
      .mockResolvedValue(undefined),
    delete: vi.fn<(key: string) => Promise<void>>().mockResolvedValue(undefined),
  };
}

describe('getTokenOnBehalfOf - store path', () => {
  let store: ReturnType<typeof makeStoreMock>;
  let oboToken: string;
  let subjectToken: string;
  let apiClient: InstanceType<typeof ApiClient>;

  beforeEach(async () => {
    store = makeStoreMock();
    apiClient = new ApiClient({
      domain,
      audience: '<audience>',
      clientId: 'my-client-id',
      clientSecret: 'my-client-secret',
    });
    oboToken = await generateToken(domain, 'user_123', 'https://api.backend.com');
    subjectToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
      client_id: 'client-abc',
      org_id: 'org_xyz',
    });
    server.use(
      http.post(`https://${domain}/oauth/token`, async () =>
        HttpResponse.json({
          access_token: oboToken,
          expires_in: 3600,
          scope: 'read write',
          token_type: 'Bearer',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        }, { status: 200 })
      )
    );
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // T1
  test('getTokenOnBehalfOf - no store: does not call verifyAccessToken and returns exchange result', async () => {
    const spy = vi.spyOn(apiClient, 'verifyAccessToken');

    const result = await apiClient.getTokenOnBehalfOf(
      'my-access-token',
      { audience: 'https://api.backend.com', scope: 'read write' }
      // store arg omitted
    );

    expect(spy).toHaveBeenCalledTimes(0);
    expect(result.accessToken).toBe(oboToken);
    expect(result.scope).toBe('read write');
    expect(result.expiresAt).toBeTypeOf('number');
  });

  // T2
  test('getTokenOnBehalfOf - store path, cache miss: exchanges and stores result', async () => {
    store.get.mockResolvedValue(undefined);

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read write' },
      store
    );

    expect(store.get).toHaveBeenCalledTimes(1);
    expect(store.get).toHaveBeenCalledWith(expect.stringContaining('https://api.backend.com'));

    expect(store.set).toHaveBeenCalledTimes(1);
    const [key, cachedToken] = store.set.mock.calls[0]!;
    expect(key).toBe(store.get.mock.calls[0]![0]);
    expect(cachedToken.accessToken).toBe(oboToken);
    expect(cachedToken.expiresAt).toBeTypeOf('number');
    expect(cachedToken.grantedScopes).toEqual(['read', 'write']);

    expect(result.accessToken).toBe(oboToken);
    expect(result.scope).toBe('read write');
  });

  // T3
  test('getTokenOnBehalfOf - store path, cache hit (non-expired): returns cached token without exchange', async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    store.get.mockResolvedValue({
      accessToken: 'cached-access-token',
      expiresAt: nowSeconds + 3600,
      grantedScopes: ['read'],
    });
    const exchangeSpy = vi.spyOn(apiClient, 'getTokenByExchangeProfile');

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read' },
      store
    );

    expect(store.get).toHaveBeenCalledTimes(1);
    expect(store.set).toHaveBeenCalledTimes(0);
    expect(exchangeSpy).toHaveBeenCalledTimes(0);
    expect(result.accessToken).toBe('cached-access-token');
    expect(result.expiresAt).toBe(nowSeconds + 3600);
    expect(result.scope).toBe('read');
    expect(result).not.toHaveProperty('tokenType');
    expect(result).not.toHaveProperty('issuedTokenType');
  });

  // T4
  test('getTokenOnBehalfOf - store path, expired entry: treats as miss and re-exchanges', async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    store.get.mockResolvedValue({
      accessToken: 'stale-token',
      expiresAt: nowSeconds - 1,
      grantedScopes: ['read'],
    });

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read' },
      store
    );

    expect(store.set).toHaveBeenCalledTimes(1);
    expect(result.accessToken).toBe(oboToken);
  });

  // T5
  test('getTokenOnBehalfOf - store path, exchange returns partial scope: throws DownscopedTokenError without storing', async () => {
    store.get.mockResolvedValue(undefined);
    server.use(
      http.post(`https://${domain}/oauth/token`, async () =>
        HttpResponse.json({
          access_token: oboToken,
          expires_in: 3600,
          scope: 'read',
          token_type: 'Bearer',
        }, { status: 200 })
      )
    );

    let caughtError: unknown;
    await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read write' },
      store
    ).catch(e => { caughtError = e; });

    expect(caughtError).toBeInstanceOf(DownscopedTokenError);
    expect((caughtError as DownscopedTokenError).code).toBe('downscoped_token_error');
    expect((caughtError as DownscopedTokenError).statusCode).toBe(400);
    expect((caughtError as DownscopedTokenError).message).toContain('read, write');
    expect((caughtError as DownscopedTokenError).message).toContain('read');
    expect(store.set).toHaveBeenCalledTimes(0);
  });

  // T6
  test('getTokenOnBehalfOf - store path, no scope in options: skips downscope guard and stores result', async () => {
    store.get.mockResolvedValue(undefined);
    server.use(
      http.post(`https://${domain}/oauth/token`, async () =>
        HttpResponse.json({
          access_token: oboToken,
          expires_in: 3600,
          scope: 'read',
          token_type: 'Bearer',
        }, { status: 200 })
      )
    );

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com' },
      store
    );

    expect(result.accessToken).toBe(oboToken);
    expect(store.set).toHaveBeenCalledTimes(1);
  });

  // T7a
  test('getTokenOnBehalfOf - store path, exchange omits scope field: uses requestedScopes as grantedScopes', async () => {
    store.get.mockResolvedValue(undefined);
    server.use(
      http.post(`https://${domain}/oauth/token`, async () =>
        HttpResponse.json({
          access_token: oboToken,
          expires_in: 3600,
          token_type: 'Bearer',
        }, { status: 200 })
      )
    );

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read write' },
      store
    );

    expect(result.accessToken).toBe(oboToken);
    expect(store.set).toHaveBeenCalledTimes(1);
    const [, cachedToken] = store.set.mock.calls[0]!;
    expect(cachedToken.grantedScopes).toEqual(['read', 'write']);
    expect(result).not.toHaveProperty('scope');
  });

  // T7b
  test('getTokenOnBehalfOf - store path, exchange scope is strict subset: throws DownscopedTokenError', async () => {
    store.get.mockResolvedValue(undefined);
    server.use(
      http.post(`https://${domain}/oauth/token`, async () =>
        HttpResponse.json({
          access_token: oboToken,
          expires_in: 3600,
          scope: 'read',
          token_type: 'Bearer',
        }, { status: 200 })
      )
    );

    let caughtError: unknown;
    await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read write' },
      store
    ).catch(e => { caughtError = e; });

    expect(caughtError).toBeInstanceOf(DownscopedTokenError);
    expect(store.set).toHaveBeenCalledTimes(0);
  });

  // T8
  test('getTokenOnBehalfOf - store path, different issuers produce distinct cache keys', async () => {
    const domainA = 'tenant-a.auth0.local';
    const domainB = 'tenant-b.auth0.local';

    server.use(
      http.get(`https://${domainA}/.well-known/openid-configuration`, () =>
        HttpResponse.json({
          issuer: `https://${domainA}/`,
          jwks_uri: `https://${domainA}/.well-known/jwks.json`,
          token_endpoint: `https://${domainA}/oauth/token`,
        })
      ),
      http.get(`https://${domainA}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks })),
      http.post(`https://${domainA}/oauth/token`, async () =>
        HttpResponse.json({ access_token: oboToken, expires_in: 3600, scope: 'read', token_type: 'Bearer' }, { status: 200 })
      ),
      http.get(`https://${domainB}/.well-known/openid-configuration`, () =>
        HttpResponse.json({
          issuer: `https://${domainB}/`,
          jwks_uri: `https://${domainB}/.well-known/jwks.json`,
          token_endpoint: `https://${domainB}/oauth/token`,
        })
      ),
      http.get(`https://${domainB}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks })),
      http.post(`https://${domainB}/oauth/token`, async () =>
        HttpResponse.json({ access_token: oboToken, expires_in: 3600, scope: 'read', token_type: 'Bearer' }, { status: 200 })
      ),
    );

    const tokenA = await generateToken(domainA, 'user_123', '<audience>', undefined, undefined, undefined, { client_id: 'client-abc' });
    const tokenB = await generateToken(domainB, 'user_123', '<audience>', undefined, undefined, undefined, { client_id: 'client-abc' });

    const clientA = new ApiClient({ domain: domainA, audience: '<audience>', clientId: 'my-client-id', clientSecret: 'my-client-secret' });
    const clientB = new ApiClient({ domain: domainB, audience: '<audience>', clientId: 'my-client-id', clientSecret: 'my-client-secret' });

    const storeA = makeStoreMock();
    const storeB = makeStoreMock();

    await clientA.getTokenOnBehalfOf(tokenA, { audience: 'https://api.backend.com', scope: 'read' }, storeA);
    await clientB.getTokenOnBehalfOf(tokenB, { audience: 'https://api.backend.com', scope: 'read' }, storeB);

    const keyA = storeA.get.mock.calls[0]![0] as string;
    const keyB = storeB.get.mock.calls[0]![0] as string;
    expect(keyA).not.toBe(keyB);
    expect(keyA.startsWith('https://tenant-a.auth0.local/')).toBe(true);
    expect(keyB.startsWith('https://tenant-b.auth0.local/')).toBe(true);
  });

  // T9
  test('getTokenOnBehalfOf - store path, different audiences produce distinct cache keys', async () => {
    store.get.mockResolvedValue(undefined);

    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api-a.com', scope: 'read' }, store);
    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api-b.com', scope: 'read' }, store);

    expect(store.get).toHaveBeenCalledTimes(2);
    const keyA = store.get.mock.calls[0]![0] as string;
    const keyB = store.get.mock.calls[1]![0] as string;
    expect(keyA).not.toBe(keyB);
    expect(keyA).toContain('https://api-a.com');
    expect(keyB).toContain('https://api-b.com');
  });

  // T10
  test('getTokenOnBehalfOf - store path, store.get throws: error propagates and exchange is not called', async () => {
    store.get.mockRejectedValue(new Error('store unavailable'));
    const exchangeSpy = vi.spyOn(apiClient, 'getTokenByExchangeProfile');

    await expect(
      apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api.backend.com', scope: 'read' }, store)
    ).rejects.toThrow('store unavailable');

    expect(exchangeSpy).toHaveBeenCalledTimes(0);
  });

  // T11
  test('getTokenOnBehalfOf - store path, store.set throws: error propagates to caller', async () => {
    store.get.mockResolvedValue(undefined);
    store.set.mockRejectedValue(new Error('write failed'));

    await expect(
      apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api.backend.com', scope: 'read' }, store)
    ).rejects.toThrow('write failed');
  });

  // T12
  test('getTokenOnBehalfOf - store path, verifyAccessToken fails: propagates before store.get', async () => {
    vi.spyOn(apiClient, 'verifyAccessToken').mockRejectedValueOnce(new Error('verify failed'));

    await expect(
      apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api.backend.com', scope: 'read' }, store)
    ).rejects.toThrow('verify failed');

    expect(store.get).toHaveBeenCalledTimes(0);
  });

  // T13
  test('getTokenOnBehalfOf - store path, expiresAt exactly equals nowSeconds: treated as expired', async () => {
    const fixedNow = new Date('2026-01-01T00:00:00Z');
    const fixedNowSeconds = Math.floor(fixedNow.getTime() / 1000);
    vi.useFakeTimers();
    vi.setSystemTime(fixedNow);

    store.get.mockResolvedValue({
      accessToken: 'about-to-expire-token',
      expiresAt: fixedNowSeconds,
      grantedScopes: ['read'],
    });

    // Bypass verifyAccessToken to avoid jose clock issues under fake timers
    vi.spyOn(apiClient, 'verifyAccessToken').mockResolvedValueOnce({
      iss: `https://${domain}/`,
      sub: 'user_123',
      aud: '<audience>',
      iat: fixedNowSeconds - 60,
      exp: fixedNowSeconds + 7200,
      client_id: 'client-abc',
      org_id: 'org_xyz',
    } as unknown as import('./types.js').VerifiedAccessTokenClaims);

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: 'https://api.backend.com', scope: 'read' },
      store
    );

    expect(result.accessToken).toBe(oboToken);
    expect(store.set).toHaveBeenCalledTimes(1);
  });

  // T17
  test('getTokenOnBehalfOf - store path, token with azp but no client_id: key uses azp value', async () => {
    const tokenWithAzp = await generateToken(
      domain, 'user_123', '<audience>',
      undefined, undefined, undefined,
      { azp: 'azp-client-id' }
    );
    store.get.mockResolvedValue(undefined);

    await apiClient.getTokenOnBehalfOf(
      tokenWithAzp,
      { audience: 'https://api.backend.com', scope: 'read' },
      store
    );

    const key = store.get.mock.calls[0]![0] as string;
    const segments = key.split('|');
    // key format: iss|clientId|sub|orgId|audience|scopes
    expect(segments[1]).toBe('azp-client-id');
  });

  // T18
  test('getTokenOnBehalfOf - store path, token missing org_id/client_id/azp: key has empty strings in those slots', async () => {
    const bareToken = await generateToken(domain, 'user_123', '<audience>');
    store.get.mockResolvedValue(undefined);

    await apiClient.getTokenOnBehalfOf(
      bareToken,
      { audience: 'https://api.backend.com', scope: 'read' },
      store
    );

    const key = store.get.mock.calls[0]![0] as string;
    const segments = key.split('|');
    // iss|clientId|sub|orgId|audience|scopes
    expect(segments[1]).toBe('');
    expect(segments[3]).toBe('');
    expect(segments[4]).toBe('https://api.backend.com');
    expect(segments[5]).toBe('read');
  });

  // T19
  test('getTokenOnBehalfOf - store path, same principal different scope sets: produce distinct keys, no silent under-scoping', async () => {
    store.get.mockResolvedValue(undefined);

    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api.backend.com', scope: 'read' }, store);
    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api.backend.com', scope: 'read write' }, store);

    expect(store.get).toHaveBeenCalledTimes(2);
    const keyRead = store.get.mock.calls[0]![0] as string;
    const keyReadWrite = store.get.mock.calls[1]![0] as string;
    expect(keyRead).not.toBe(keyReadWrite);

    const seg1 = keyRead.split('|');
    const seg2 = keyReadWrite.split('|');
    expect(seg1[5]).toBe('read');
    expect(seg2[5]).toBe('read write');

    expect(store.set).toHaveBeenCalledTimes(2);
  });
});
