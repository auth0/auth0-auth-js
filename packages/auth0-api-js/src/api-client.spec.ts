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
import { AuthClient, MissingClientAuthError, TokenExchangeError, TokenByClientCredentialsError } from '@auth0/auth0-auth-js';
import { InvalidConfigurationError, InvalidRequestError, VerifyAccessTokenError } from './errors.js';
import type { CachedToken, TokenIndexMember, TokenStore, VerifiedToken } from './token-store.js';
import type { ApiClientOptions, VerifiedAccessTokenClaims } from './types.js';
import { generateToken, jwks } from './test-utils/tokens.js';
import { ApiClient } from './api-client.js';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import { createHash } from 'node:crypto';

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
  vi.restoreAllMocks();
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
  const validToken = await generateToken(domain, 'user_123', '<audience>');

  await expect(
    apiClient.getTokenOnBehalfOf(validToken, {
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
  const validToken = await generateToken(domain, 'user_123', '<audience>');

  await expect(
    apiClient.getTokenOnBehalfOf(validToken, {
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

  const subjectAccessToken = await generateToken(domain, 'user_123', '<audience>');
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
        body.get('subject_token') === subjectAccessToken &&
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

  const result = await apiClient.getTokenOnBehalfOf(subjectAccessToken, {
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
  const subjectAccessToken = await generateToken(domain, 'user_123', '<audience>');
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

  const result = await apiClient.getTokenOnBehalfOf(subjectAccessToken, {
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

  const subjectAccessToken = await generateToken(domain, 'user_123', '<audience>');
  server.use(
    http.post(`https://${domain}/oauth/token`, () => {
      return HttpResponse.json(
        { error: 'invalid_target', error_description: 'The target API is not allowed.' },
        { status: 400 }
      );
    })
  );

  await expect(
    apiClient.getTokenOnBehalfOf(subjectAccessToken, {
      audience: 'https://api.backend.com',
    })
  ).rejects.toThrowError(
    "Failed to exchange token of type 'urn:ietf:params:oauth:token-type:access_token' for audience 'https://api.backend.com'."
  );
});


// TC-01: Happy path. Returns a TokenSet with accessToken and an epoch-second expiresAt.
test('getClientCredentialsToken - should return TokenSet with accessToken and epoch-second expiresAt', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      if (body.get('grant_type') === 'client_credentials') {
        return HttpResponse.json(
          { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' },
          { status: 200 }
        );
      }
      return HttpResponse.json({ error: 'invalid_request', error_description: 'Unexpected grant type.' }, { status: 400 });
    })
  );

  const result = await apiClient.getClientCredentialsToken({});

  expect(result.accessToken).toBe(ccAccessToken);
  expect(Number.isInteger(result.expiresAt)).toBe(true);
  expect(result.expiresAt).toBeGreaterThan(1e9);
  expect(result.expiresAt).toBeLessThan(1e12);
  // Auth0 returned no scope here, so the result carries exactly three keys. An
  // unexpected extra field or a missing one fails this.
  expect(Object.keys(result).sort()).toEqual(['accessToken', 'expiresAt', 'tokenType']);
});

// TC-02: When audience is omitted, the configured audience is used as the fallback.
test('getClientCredentialsToken - should use configured audience when none provided', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: 'https://configured-api.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', 'https://configured-api.example.com');

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      if (body.get('audience') === 'https://configured-api.example.com') {
        return HttpResponse.json(
          { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' },
          { status: 200 }
        );
      }
      return HttpResponse.json({ error: 'invalid_request', error_description: 'Wrong audience.' }, { status: 400 });
    })
  );

  const result = await apiClient.getClientCredentialsToken({});

  expect(result.accessToken).toBe(ccAccessToken);
});

// TC-03: When audience is provided, the explicit value overrides the configured default.
test('getClientCredentialsToken - should use explicit audience when provided', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: 'https://default.example.com',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', 'https://override.example.com');

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      if (body.get('audience') === 'https://override.example.com') {
        return HttpResponse.json(
          { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' },
          { status: 200 }
        );
      }
      return HttpResponse.json({ error: 'invalid_request', error_description: 'Wrong audience.' }, { status: 400 });
    })
  );

  const result = await apiClient.getClientCredentialsToken({ audience: 'https://override.example.com' });

  expect(result.accessToken).toBe(ccAccessToken);
});

// TC-04: scope provided, forwarded unchanged to AuthClient.getTokenByClientCredentials
test('getClientCredentialsToken - should forward scope to the auth client when provided', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, () =>
      HttpResponse.json({ access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' }, { status: 200 })
    )
  );

  const spy = vi.spyOn(AuthClient.prototype, 'getTokenByClientCredentials');

  const result = await apiClient.getClientCredentialsToken({ scope: 'read:data write:data' });

  expect(result.accessToken).toBe(ccAccessToken);
  expect(spy).toHaveBeenCalledTimes(1);
  expect(spy.mock.calls[0]?.[0]).toStrictEqual({ audience: '<audience>', scope: 'read:data write:data' });
});

// TC-05: scope omitted, the scope key is absent from the options passed to the auth client
// (not present with an undefined value)
test('getClientCredentialsToken - should not forward a scope key to the auth client when scope is not provided', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, () =>
      HttpResponse.json({ access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' }, { status: 200 })
    )
  );

  const spy = vi.spyOn(AuthClient.prototype, 'getTokenByClientCredentials');

  const result = await apiClient.getClientCredentialsToken({});

  expect(result.accessToken).toBe(ccAccessToken);
  expect(spy).toHaveBeenCalledTimes(1);
  const forwarded = spy.mock.calls[0]?.[0] as object;
  expect(forwarded).toStrictEqual({ audience: '<audience>' });
  expect('scope' in forwarded).toBe(false);
});

// TC-06: empty string scope is a meaningful request for zero scopes and is forwarded as '',
// not dropped or collapsed to absent
test('getClientCredentialsToken - should forward an empty string scope to the auth client', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, () =>
      HttpResponse.json({ access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' }, { status: 200 })
    )
  );

  const spy = vi.spyOn(AuthClient.prototype, 'getTokenByClientCredentials');

  const result = await apiClient.getClientCredentialsToken({ scope: '' });

  expect(result.accessToken).toBe(ccAccessToken);
  expect(spy).toHaveBeenCalledTimes(1);
  expect(spy.mock.calls[0]?.[0]).toStrictEqual({ audience: '<audience>', scope: '' });
});

// TC-07: With no client authentication configured, MissingClientAuthError is thrown before any network call.
test('getClientCredentialsToken - should throw MissingClientAuthError when no client credentials configured', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
  });

  await expect(apiClient.getClientCredentialsToken({})).rejects.toThrow(MissingClientAuthError);
});

// TC-08: When the grant fails, TokenByClientCredentialsError propagates unchanged.
test('getClientCredentialsToken - should propagate TokenByClientCredentialsError on grant failure', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  server.use(
    http.post(`https://${domain}/oauth/token`, () => {
      return HttpResponse.json(
        { error: '<error_code>', error_description: '<error_description>' },
        { status: 400 }
      );
    })
  );

  const err = await apiClient.getClientCredentialsToken({ audience: '<audience_fail>' }).catch((e) => e);
  expect(err).toBeInstanceOf(TokenByClientCredentialsError);
  expect(err.code).toBe('token_by_client_credentials_error');
});

// TC-09: the result carries the documented TokenSet fields and nothing else
test('getClientCredentialsToken - should return only the documented TokenSet fields', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      if (body.get('grant_type') === 'client_credentials') {
        return HttpResponse.json(
          { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer', scope: 'read:data' },
          { status: 200 }
        );
      }
      return HttpResponse.json({ error: 'invalid_request', error_description: 'Unexpected grant type.' }, { status: 400 });
    })
  );

  const result = await apiClient.getClientCredentialsToken({ scope: 'read:data' });

  // Auth0 sent a scope, so all four keys are present and no others. Anything the
  // SDK starts copying out of the token response without a decision fails here.
  expect(Object.keys(result).sort()).toEqual(['accessToken', 'expiresAt', 'scope', 'tokenType']);
});

// TC-10: granted scope and tokenType are surfaced on the returned TokenSet
test('getClientCredentialsToken - surfaces granted scope and tokenType returned by Auth0', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () =>
      HttpResponse.json(
        { access_token: ccAccessToken, expires_in: 3600, scope: 'read:data write:data', token_type: 'Bearer' },
        { status: 200 }
      )
    )
  );

  const result = await apiClient.getClientCredentialsToken({ scope: 'read:data write:data' });

  expect(result.accessToken).toBe(ccAccessToken);
  expect(result.scope).toBe('read:data write:data');
  // The underlying OAuth client normalizes token_type, so 'Bearer' on the wire
  // arrives as 'bearer' here. Asserted exactly rather than through toLowerCase(),
  // which would hide a change in that behaviour.
  expect(result.tokenType).toBe('bearer');
});

// TC-11: when Auth0 downscopes the grant, the returned scope reflects what was granted
test('getClientCredentialsToken - returned scope reflects a downscoped grant', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () =>
      HttpResponse.json(
        { access_token: ccAccessToken, expires_in: 3600, scope: 'read:data', token_type: 'Bearer' },
        { status: 200 }
      )
    )
  );

  const result = await apiClient.getClientCredentialsToken({ scope: 'read:data write:data' });

  expect(result.scope).toBe('read:data'); // only the granted subset, detectable by caller
});

// TC-12: when Auth0 returns no scope, no scope key is fabricated
test('getClientCredentialsToken - omits scope when Auth0 returns none', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () =>
      HttpResponse.json(
        { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' },
        { status: 200 }
      )
    )
  );

  const result = await apiClient.getClientCredentialsToken({});

  expect(result).not.toHaveProperty('scope');
});

// TC-12b: an empty granted scope is distinct from an absent one. Auth0 returning scope: ''
// means it granted nothing, whereas an omitted scope means it did not report one. The empty
// string must survive on the TokenSet so a caller can tell the two cases apart.
test('getClientCredentialsToken - preserves an empty string scope returned by Auth0', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');

  server.use(
    http.post(`https://${domain}/oauth/token`, async () =>
      HttpResponse.json(
        { access_token: ccAccessToken, expires_in: 3600, scope: '', token_type: 'Bearer' },
        { status: 200 }
      )
    )
  );

  const result = await apiClient.getClientCredentialsToken({});

  expect(result.scope).toBe('');
  // The scope key must be genuinely present, not dropped by a truthiness check.
  expect(Object.keys(result).sort()).toEqual(['accessToken', 'expiresAt', 'scope', 'tokenType']);
});

// TC-13: clientId provided without any client auth method triggers MissingClientAuthError
// from the auth layer (distinct from TC-07 where no clientId is set at all)
test('getClientCredentialsToken - should throw MissingClientAuthError when clientId is provided without client auth credentials', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    // no clientSecret and no clientAssertionSigningKey
  });

  await expect(apiClient.getClientCredentialsToken({})).rejects.toThrow(MissingClientAuthError);
});

// The three tests below assert on the HTTP request body rather than a spy on the auth client,
// so they fail if a dependency that silently drops `scope` is installed.
async function captureClientCredentialsBody(call: (apiClient: ApiClient) => Promise<unknown>): Promise<URLSearchParams> {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });
  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');
  let captured: URLSearchParams | undefined;

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      captured = new URLSearchParams(await request.text());
      return HttpResponse.json(
        { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' },
        { status: 200 }
      );
    })
  );

  await call(apiClient);
  if (!captured) {
    throw new Error('the token endpoint was never called');
  }
  return captured;
}

test('getClientCredentialsToken - sends the requested scope in the token request body', async () => {
  const body = await captureClientCredentialsBody((c) => c.getClientCredentialsToken({ scope: 'read:data write:data' }));

  expect(body.get('grant_type')).toBe('client_credentials');
  expect(body.get('scope')).toBe('read:data write:data');
});

test('getClientCredentialsToken - sends no scope parameter when scope is not provided', async () => {
  const body = await captureClientCredentialsBody((c) => c.getClientCredentialsToken({}));

  expect(body.get('grant_type')).toBe('client_credentials');
  expect(body.has('scope')).toBe(false);
});

test('getClientCredentialsToken - sends an empty scope parameter when scope is an empty string', async () => {
  const body = await captureClientCredentialsBody((c) => c.getClientCredentialsToken({ scope: '' }));

  expect(body.has('scope')).toBe(true);
  expect(body.get('scope')).toBe('');
});

// TC-14: Verify client credentials are forwarded in the form-encoded token request body
test('getClientCredentialsToken - should forward client_id and client_secret in the token request body', async () => {
  const apiClient = new ApiClient({
    domain,
    audience: '<audience>',
    clientId: 'my-client-id',
    clientSecret: 'my-client-secret',
  });

  const ccAccessToken = await generateToken(domain, 'client_123', '<audience>');
  let capturedClientId: string | null = null;
  let capturedClientSecret: string | null = null;

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      capturedClientId = body.get('client_id') as string | null;
      capturedClientSecret = body.get('client_secret') as string | null;
      return HttpResponse.json(
        { access_token: ccAccessToken, expires_in: 3600, token_type: 'Bearer' },
        { status: 200 }
      );
    })
  );

  await apiClient.getClientCredentialsToken({});

  expect(capturedClientId).toBe('my-client-id');
  expect(capturedClientSecret).toBe('my-client-secret');
});

// ---------------------------------------------------------------------------
// On Behalf Of token caching
// ---------------------------------------------------------------------------

const backendAudience = 'https://api.backend.com';

/**
 * A TokenStore backed by a Map, with every method wrapped in a spy so tests can assert on
 * the calls as well as on the stored entries.
 */
function makeStore() {
  const map = new Map<string, CachedToken>();

  return {
    map,
    get: vi.fn((key: string): Promise<CachedToken | undefined> => Promise.resolve(map.get(key))),
    set: vi.fn((key: string, value: CachedToken): Promise<void> => {
      map.set(key, value);
      return Promise.resolve();
    }),
    delete: vi.fn((key: string): Promise<void> => {
      map.delete(key);
      return Promise.resolve();
    }),
  };
}

/**
 * A Map-backed IndexedTokenStore, so covering lookups can be observed end to end.
 */
function makeIndexedStore() {
  const base = makeStore();
  const indexes = new Map<string, Map<string, TokenIndexMember>>();

  return {
    ...base,
    indexes,
    addIndexMember: vi.fn((indexKey: string, member: TokenIndexMember): Promise<void> => {
      const members = indexes.get(indexKey) ?? new Map<string, TokenIndexMember>();
      members.set(member.tokenKey, member);
      indexes.set(indexKey, members);
      return Promise.resolve();
    }),
    listIndexMembers: vi.fn((indexKey: string): Promise<TokenIndexMember[]> =>
      Promise.resolve([...(indexes.get(indexKey)?.values() ?? [])])
    ),
  };
}

type ExchangeResponse = {
  accessToken: string;
  /** Omit to model an authorization server that returns no `scope` field. */
  scope?: string;
  tokenType?: string;
  issuedTokenType?: string;
};

/**
 * Serves the token endpoint and counts the exchanges that reach it.
 */
function useExchange(response: ExchangeResponse) {
  const state = { count: 0, requestedScopes: [] as Array<string | null>, audiences: [] as Array<string | null> };

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      state.count++;
      state.requestedScopes.push(body.get('scope') as string | null);
      state.audiences.push(body.get('audience') as string | null);

      return HttpResponse.json(
        {
          access_token: response.accessToken,
          expires_in: 3600,
          token_type: response.tokenType ?? 'Bearer',
          ...(response.scope !== undefined && { scope: response.scope }),
          ...(response.issuedTokenType !== undefined && { issued_token_type: response.issuedTokenType }),
        },
        { status: 200 }
      );
    })
  );

  return state;
}

type Client = InstanceType<typeof ApiClient>;

/**
 * Signs a subject token and verifies it with `client`, so the returned claims are the very
 * object `client.verifyAccessToken` produced. That object identity is what the pre-verified
 * escape hatch of getTokenOnBehalfOf requires.
 */
async function verifiedBy(
  client: Client,
  options: { sub?: string; issuerDomain?: string; audience?: string; claims?: Record<string, unknown> } = {}
): Promise<VerifiedToken> {
  const accessToken = await generateToken(
    options.issuerDomain ?? domain,
    options.sub ?? 'user_123',
    options.audience ?? '<audience>',
    undefined,
    undefined,
    undefined,
    { client_id: 'client-abc', org_id: 'org_xyz', ...options.claims }
  );

  return { accessToken, claims: await client.verifyAccessToken({ accessToken }) };
}

/**
 * Verifies, with `client`, a token whose `sub` claim has a type the shared token helper
 * refuses to sign. The token is signed with a key generated here and served as the JWKS,
 * so verification is entirely genuine. `client` must not have fetched the JWKS yet.
 */
async function verifiedWithRawSub(client: Client, sub: unknown): Promise<VerifiedToken> {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const publicJwk = { ...(await exportJWK(publicKey)), alg: 'RS256', use: 'sig' };
  server.use(http.get(`https://${domain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: [publicJwk] })));

  const accessToken = await new SignJWT({ sub: sub as string, client_id: 'client-abc', org_id: 'org_xyz' })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(`https://${domain}/`)
    .setAudience('<audience>')
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(privateKey);

  return { accessToken, claims: await client.verifyAccessToken({ accessToken }) };
}

const dpopHttpMethod = 'GET';
const dpopHttpUrl = 'https://api.example.com/resource';
let dpopKeyPair: ReturnType<typeof generateKeyPair> | undefined;

/**
 * Builds a DPoP-bound subject token and a valid proof for it, ready to hand to
 * `verifyAccessToken`.
 */
async function makeDpopRequest() {
  dpopKeyPair ??= generateKeyPair('ES256');
  const { publicKey, privateKey } = await dpopKeyPair;
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
    client_id: 'client-abc',
    org_id: 'org_xyz',
    cnf: { jkt },
  });
  const proof = await new SignJWT({
    htm: dpopHttpMethod,
    htu: dpopHttpUrl,
    iat: Math.floor(Date.now() / 1000),
    jti: 'proof-jti',
    ath: createHash('sha256').update(accessToken).digest('base64url'),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
    .sign(privateKey);

  return {
    accessToken,
    verifyOptions: {
      accessToken,
      scheme: 'dpop',
      dpopProof: proof,
      httpMethod: dpopHttpMethod,
      httpUrl: dpopHttpUrl,
    },
  };
}

/**
 * Calls getTokenOnBehalfOf with a store and the pre-verified token, using the token the
 * claims were verified from as the token being exchanged.
 */
function exchangeWith(
  client: Client,
  verifiedToken: VerifiedToken,
  options: { audience: string; scope?: string },
  store: TokenStore
) {
  return client.getTokenOnBehalfOf(verifiedToken.accessToken, options, { store, verified: verifiedToken });
}

const baseClientOptions = {
  domain,
  audience: '<audience>',
  clientId: 'my-client-id',
  clientSecret: 'my-client-secret',
} as const;

describe('getTokenOnBehalfOf - caching', () => {
  let oboToken: string;
  let subjectToken: string;
  let apiClient: InstanceType<typeof ApiClient>;
  let verified: VerifiedToken;

  beforeEach(async () => {
    apiClient = new ApiClient(baseClientOptions);
    oboToken = await generateToken(domain, 'user_123', backendAudience);
    subjectToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
      client_id: 'client-abc',
      org_id: 'org_xyz',
    });
    verified = { accessToken: subjectToken, claims: await apiClient.verifyAccessToken({ accessToken: subjectToken }) };
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Conditional verification of the subject token
  // -------------------------------------------------------------------------
  describe('verification of the subject token', () => {
    test('without a store, the subject token is not verified and the exchange still runs', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read write' });
      const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' });

      expect(verifySpy).toHaveBeenCalledTimes(0);
      expect(exchange.count).toBe(1);
      expect(result.accessToken).toBe(oboToken);
      expect(result.scope).toBe('read write');
    });

    test('with a store, the subject token is verified exactly once', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store });

      expect(verifySpy).toHaveBeenCalledTimes(1);
      expect(exchange.count).toBe(1);
    });

    test('with a store, a subject token that does not verify rejects and no exchange is attempted', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      const failure = new VerifyAccessTokenError('subject token rejected');
      vi.spyOn(apiClient, 'verifyAccessToken').mockRejectedValueOnce(failure);

      await expect(
        apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBe(failure);

      expect(exchange.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
    });
  });

  // -------------------------------------------------------------------------
  // The pre-verified token escape hatch
  // -------------------------------------------------------------------------
  describe('pre-verified subject token (context.verified)', () => {
    test('dpop mode "required" with a store and no context.verified is rejected, because the internal verification runs as a bearer token', async () => {
      // Documented limitation, pinned on purpose. The internal verification has no scheme,
      // proof or request headers, so it cannot satisfy dpop.mode "required". Callers in this
      // position verify at their ingress and pass the result in as context.verified.
      const dpopRequiredClient = new ApiClient({ ...baseClientOptions, dpop: { mode: 'required' } });
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const failure = await dpopRequiredClient
        .getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
        .catch((error: unknown) => error);

      expect(failure).toBeInstanceOf(InvalidRequestError);
      expect((failure as InvalidRequestError).cause).toEqual({ code: 'invalid_auth_scheme' });
      expect(exchange.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
    });

    test('dpop mode "required" with a store and context.verified succeeds, caches, and serves the second identical call from cache', async () => {
      const dpopRequiredClient = new ApiClient({ ...baseClientOptions, dpop: { mode: 'required' } });
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      // Verified at the ingress, where the proof and the request are available.
      const request = await makeDpopRequest();
      const dpopVerified = {
        accessToken: request.accessToken,
        claims: await dpopRequiredClient.verifyAccessToken(request.verifyOptions),
      };
      const verifySpy = vi.spyOn(dpopRequiredClient, 'verifyAccessToken');

      const first = await exchangeWith(dpopRequiredClient, dpopVerified, { audience: backendAudience, scope: 'read' }, store);
      const second = await exchangeWith(dpopRequiredClient, dpopVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(first).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read'],
        scope: 'read',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
      expect(exchange.count).toBe(1);
      expect(store.map.size).toBe(1);
      expect(second).toEqual(first);
      expect(verifySpy).toHaveBeenCalledTimes(0);
    });

    test('a DPoP-bound subject token (cnf.jkt) with a store and context.verified succeeds without a second verification', async () => {
      const request = await makeDpopRequest();
      const boundVerified = {
        accessToken: request.accessToken,
        claims: await apiClient.verifyAccessToken(request.verifyOptions),
      };
      expect(boundVerified.claims.cnf).toEqual({ jkt: expect.any(String) });
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');
      const store = makeStore();

      const result = await exchangeWith(apiClient, boundVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
      expect(verifySpy).toHaveBeenCalledTimes(0);
    });

    test('a DPoP-bound subject token without context.verified is rejected by the internal bearer verification', async () => {
      const boundToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
        cnf: { jkt: 'thumbprint-of-the-proof-key' },
      });
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await expect(
        apiClient.getTokenOnBehalfOf(boundToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(VerifyAccessTokenError);

      expect(exchange.count).toBe(0);
    });

    test('a configured domains resolver is not invoked by the exchange when context.verified is supplied', async () => {
      const resolver = vi.fn(() => [domain]);
      const resolverClient = new ApiClient({ ...baseClientOptions, domains: resolver });
      const resolverVerified = await verifiedBy(resolverClient);
      resolver.mockClear();
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const result = await exchangeWith(resolverClient, resolverVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
      expect(resolver).toHaveBeenCalledTimes(0);
    });

    test('context.verified for a different token than the one being exchanged is rejected before any exchange or store access', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const failure = await apiClient
        .getTokenOnBehalfOf(
          subjectToken,
          { audience: backendAudience, scope: 'read' },
          { store, verified: { accessToken: 'some-other-token', claims: verified.claims } }
        )
        .catch((error: unknown) => error);

      expect(failure).toBeInstanceOf(InvalidConfigurationError);
      expect(failure).not.toBeInstanceOf(InvalidRequestError);
      expect(exchange.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
    });

    test('without a store, context.verified for a different token than the one being exchanged is rejected before any exchange', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });

      const failure = await apiClient
        .getTokenOnBehalfOf(
          subjectToken,
          { audience: backendAudience, scope: 'read' },
          { verified: { accessToken: 'some-other-token', claims: verified.claims } }
        )
        .catch((error: unknown) => error);

      expect(failure).toBeInstanceOf(InvalidConfigurationError);
      expect(failure).not.toBeInstanceOf(InvalidRequestError);
      expect(exchange.count).toBe(0);
    });

    test('without a store, genuinely verified claims for one token paired with a different token to exchange are rejected', async () => {
      // The claims object is the original one this instance produced, so only the pairing
      // with the token being exchanged is wrong.
      const otherToken = await generateToken(domain, 'user_456', '<audience>', undefined, undefined, undefined, {
        client_id: 'client-abc',
        org_id: 'org_xyz',
      });
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });

      const failure = await apiClient
        .getTokenOnBehalfOf(otherToken, { audience: backendAudience, scope: 'read' }, { verified })
        .catch((error: unknown) => error);

      expect(failure).toBeInstanceOf(InvalidConfigurationError);
      expect(failure).not.toBeInstanceOf(InvalidRequestError);
      expect(exchange.count).toBe(0);
    });

    test('without a store, context.verified paired with the matching token is accepted and exchanges exactly once', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');

      const result = await apiClient.getTokenOnBehalfOf(
        subjectToken,
        { audience: backendAudience, scope: 'read' },
        { verified }
      );

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
      expect(verifySpy).toHaveBeenCalledTimes(0);
    });

    test('context.verified for the same token being exchanged is accepted and does not verify a second time', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');

      const result = await apiClient.getTokenOnBehalfOf(
        subjectToken,
        { audience: backendAudience, scope: 'read' },
        { store, verified }
      );

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read'],
        scope: 'read',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
      expect(exchange.count).toBe(1);
      expect(verifySpy).toHaveBeenCalledTimes(0);
    });

    test('context.verified is accepted while an organizationPolicy is configured and the organization is allowed', async () => {
      // Organization enforcement on this path is covered in api-client.verified-org.spec.ts.
      const policyClient = new ApiClient({
        ...baseClientOptions,
        organizationPolicy: 'required',
        organizationId: 'org_xyz',
      });
      const policyVerified = await verifiedBy(policyClient);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const result = await exchangeWith(policyClient, policyVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
    });

    describe('the claims must be the ones this instance verified', () => {
      async function expectRejectedWithoutSideEffects(
        attempt: (store: ReturnType<typeof makeStore>) => Promise<unknown>,
        exchange: { count: number },
        store: ReturnType<typeof makeStore>
      ) {
        const failure = await attempt(store).catch((error: unknown) => error);

        expect(failure).toBeInstanceOf(InvalidConfigurationError);
        expect(failure).not.toBeInstanceOf(InvalidRequestError);
        expect(exchange.count).toBe(0);
        expect(store.get).toHaveBeenCalledTimes(0);
        expect(store.set).toHaveBeenCalledTimes(0);
        expect(store.delete).toHaveBeenCalledTimes(0);
      }

      test('hand-built claims that were never verified are rejected, with no exchange and no store access', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');
        const forged = {
          accessToken: subjectToken,
          claims: {
            iss: `https://${domain}/`,
            sub: 'user_victim',
            aud: '<audience>',
            iat: 0,
            exp: 9999999999,
            client_id: 'client-abc',
            org_id: 'org_xyz',
          },
        };

        await expectRejectedWithoutSideEffects(
          () => exchangeWith(apiClient, forged, { audience: backendAudience, scope: 'read' }, store),
          exchange,
          store
        );
        expect(verifySpy).toHaveBeenCalledTimes(0);
      });

      test('a copy of genuinely verified claims is rejected, because only the original object is trusted', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();

        await expectRejectedWithoutSideEffects(
          () =>
            exchangeWith(
              apiClient,
              { accessToken: subjectToken, claims: { ...verified.claims } },
              { audience: backendAudience, scope: 'read' },
              store
            ),
          exchange,
          store
        );
      });

      test('a JSON round trip of genuinely verified claims is rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();

        await expectRejectedWithoutSideEffects(
          () =>
            exchangeWith(
              apiClient,
              { accessToken: subjectToken, claims: JSON.parse(JSON.stringify(verified.claims)) },
              { audience: backendAudience, scope: 'read' },
              store
            ),
          exchange,
          store
        );
      });

      test('claims verified by a different ApiClient instance are rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const otherClient = new ApiClient(baseClientOptions);
        const verifiedByOther = {
          accessToken: subjectToken,
          claims: await otherClient.verifyAccessToken({ accessToken: subjectToken }),
        };

        await expectRejectedWithoutSideEffects(
          () => exchangeWith(apiClient, verifiedByOther, { audience: backendAudience, scope: 'read' }, store),
          exchange,
          store
        );
      });

      test('claims verified from token A, paired with token B as both verified.accessToken and the argument, are rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const tokenB = await generateToken(domain, 'user_attacker', '<audience>', undefined, undefined, undefined, {
          client_id: 'client-abc',
          org_id: 'org_xyz',
        });
        expect(tokenB).not.toBe(subjectToken);

        await expectRejectedWithoutSideEffects(
          () =>
            exchangeWith(
              apiClient,
              { accessToken: tokenB, claims: verified.claims },
              { audience: backendAudience, scope: 'read' },
              store
            ),
          exchange,
          store
        );
      });

      test('claims verified from token A, with token A as verified.accessToken but token B as the argument, are rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const tokenB = await generateToken(domain, 'user_attacker', '<audience>');

        await expectRejectedWithoutSideEffects(
          () =>
            apiClient.getTokenOnBehalfOf(
              tokenB,
              { audience: backendAudience, scope: 'read' },
              { store, verified }
            ),
          exchange,
          store
        );
      });

      test('genuinely verified claims whose exp has passed are rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const exp = verified.claims.exp as number;

        // Move the clock instead of editing the claims, so the object stays genuinely verified.
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new Date((exp + 1) * 1000));

        await expectRejectedWithoutSideEffects(
          () => exchangeWith(apiClient, verified, { audience: backendAudience, scope: 'read' }, store),
          exchange,
          store
        );
      });

      test('genuinely verified claims whose exp is inside the leeway window are rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const exp = verified.claims.exp as number;

        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new Date((exp - 3) * 1000));

        await expectRejectedWithoutSideEffects(
          () => exchangeWith(apiClient, verified, { audience: backendAudience, scope: 'read' }, store),
          exchange,
          store
        );
      });

      test('genuinely verified claims whose exp is exactly at the leeway boundary are rejected', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const exp = verified.claims.exp as number;

        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new Date((exp - 5) * 1000));

        await expectRejectedWithoutSideEffects(
          () => exchangeWith(apiClient, verified, { audience: backendAudience, scope: 'read' }, store),
          exchange,
          store
        );
      });

      test('genuinely verified claims whose exp is just beyond the leeway window are accepted', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const exp = verified.claims.exp as number;

        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new Date((exp - 6) * 1000));

        const result = await exchangeWith(apiClient, verified, { audience: backendAudience, scope: 'read' }, store);

        expect(result.accessToken).toBe(oboToken);
        expect(exchange.count).toBe(1);
      });

      test.each([
        ['missing', undefined],
        ['a string', '9999999999'],
        ['NaN', Number.NaN],
        ['Infinity', Number.POSITIVE_INFINITY],
      ])('a change of exp to %s after verification is ignored, because the recorded copy keeps the real expiry', async (_label, badExp) => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        (verified.claims as Record<string, unknown>).exp = badExp;

        const result = await exchangeWith(apiClient, verified, { audience: backendAudience, scope: 'read' }, store);

        expect(result.accessToken).toBe(oboToken);
        expect(exchange.count).toBe(1);
        expect(store.set).toHaveBeenCalledTimes(1);
        expect(store.map.size).toBe(1);
        const [stored] = [...store.map.values()];
        // The cached entry expires with the exchanged token, never with the edited claim.
        expect(Number.isFinite(stored!.expiresAt)).toBe(true);
      });

      test('a change of exp after verification cannot extend a token whose real expiry has passed', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const exp = verified.claims.exp as number;
        (verified.claims as Record<string, unknown>).exp = exp + 100000;

        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(new Date((exp + 1) * 1000));

        await expectRejectedWithoutSideEffects(
          () => exchangeWith(apiClient, verified, { audience: backendAudience, scope: 'read' }, store),
          exchange,
          store
        );
      });

      test('the claims are rejected on a repeat call too, and a rejected call leaves nothing in the store', async () => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        const forged = { accessToken: subjectToken, claims: { ...verified.claims } };

        for (let attempt = 0; attempt < 2; attempt++) {
          await expectRejectedWithoutSideEffects(
            () => exchangeWith(apiClient, forged, { audience: backendAudience, scope: 'read' }, store),
            exchange,
            store
          );
        }
        expect(store.map.size).toBe(0);
      });
    });
  });

  // -------------------------------------------------------------------------
  // scopeMatching configuration
  // -------------------------------------------------------------------------
  describe('scopeMatching', () => {
    test.each([['Strict'], ['none'], [''], [42], [null], [{}]])(
      'an invalid value (%j) is rejected by the constructor',
      (value) => {
        expect(
          () => new ApiClient({ ...baseClientOptions, scopeMatching: value } as unknown as ApiClientOptions)
        ).toThrow(InvalidConfigurationError);
      }
    );

    test.each([['strict'], ['non_strict'], [undefined]])('%s is accepted by the constructor', (value) => {
      expect(
        () => new ApiClient({ ...baseClientOptions, scopeMatching: value } as unknown as ApiClientOptions)
      ).not.toThrow();
    });

    test('non_strict without a store is a configuration error and no exchange happens', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'non_strict' });
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });

      await expect(
        client.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' })
      ).rejects.toBeInstanceOf(InvalidConfigurationError);

      expect(exchange.count).toBe(0);
    });

    test('non_strict with a store that is not indexed is a configuration error and no exchange happens', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'non_strict' });
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await expect(
        exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store)
      ).rejects.toBeInstanceOf(InvalidConfigurationError);

      expect(exchange.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
    });

    test('non_strict with an indexed store serves a narrower request from the cached superset', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'non_strict' });
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read write' });
      const store = makeIndexedStore();

      const superset = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read write' }, store);
      const narrower = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(1);
      expect(narrower.accessToken).toBe(superset.accessToken);
      expect(store.indexes.size).toBe(1);
    });

    test('strict does not serve a narrower request from a cached superset', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'strict' });
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeIndexedStore();

      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read write' }, store);
      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(2);
      expect(store.indexes.size).toBe(0);
    });

    test('changing options.scopeMatching to non_strict after construction does not change behaviour', async () => {
      const options: { scopeMatching?: string } & typeof baseClientOptions = { ...baseClientOptions, scopeMatching: 'strict' };
      const client = new ApiClient(options as unknown as ApiClientOptions);
      options.scopeMatching = 'non_strict';
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      // Still strict: a plain store is accepted, and a narrower request misses.
      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read write' }, store);
      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(2);
    });

    test('changing options.scopeMatching to strict after construction does not change behaviour', async () => {
      const options: { scopeMatching?: string } & typeof baseClientOptions = { ...baseClientOptions, scopeMatching: 'non_strict' };
      const client = new ApiClient(options as unknown as ApiClientOptions);
      options.scopeMatching = 'strict';
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeIndexedStore();

      // Still non_strict: the narrower request is served from the cached superset.
      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read write' }, store);
      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(1);
    });

    test.each([
      ['clientId', 'mutated-client-id'],
      ['audience', 'https://mutated.example.com'],
    ])('changing options.%s after construction does not move the cache key', async (field, mutated) => {
      const options: Record<string, unknown> = { ...baseClientOptions };
      const client = new ApiClient(options as unknown as ApiClientOptions);
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);
      const keysBefore = [...store.map.keys()];

      options[field] = mutated;
      const second = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(second.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
      expect([...store.map.keys()]).toEqual(keysBefore);
    });
  });

  // -------------------------------------------------------------------------
  // Granted scope handling
  // -------------------------------------------------------------------------
  describe('granted scope', () => {
    test('getTokenByExchangeProfile keeps an empty granted scope as an empty string', async () => {
      useExchange({ accessToken: oboToken, scope: '' });

      const result = await apiClient.getTokenByExchangeProfile('my-subject-token', {
        subjectTokenType: 'urn:my-company:mcp-token',
        audience: backendAudience,
        scope: 'read write',
      });

      expect(result).toHaveProperty('scope', '');
    });

    test('an empty granted scope survives getTokenOnBehalfOf and is cached as an empty granted list', async () => {
      useExchange({ accessToken: oboToken, scope: '' });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(
        subjectToken,
        { audience: backendAudience, scope: 'read write' },
        { store, verified }
      );

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: [],
        scope: '',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
      const entries = [...store.map.values()];
      expect(entries).toHaveLength(1);
      expect(entries[0]!.grantedScopes).toEqual([]);
      expect(entries[0]!.scope).toBe('');
    });

    test('an empty grant is not served to a later request for the scopes that were asked for', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: '' });
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expect(exchange.count).toBe(2);
    });

    test('a response with no scope field has no scope key and is cached under the requested scopes', async () => {
      useExchange({ accessToken: oboToken });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(
        subjectToken,
        { audience: backendAudience, scope: 'write read' },
        { store, verified }
      );

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read', 'write'],
        tokenType: expect.stringMatching(/^bearer$/i),
      });
      expect(result).not.toHaveProperty('scope');
      const entries = [...store.map.values()];
      expect(entries).toHaveLength(1);
      expect(entries[0]!.grantedScopes).toEqual(['read', 'write']);
      expect(entries[0]).not.toHaveProperty('scope');
    });

    test('requesting two scopes and being granted one returns the token instead of throwing', async () => {
      useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(
        subjectToken,
        { audience: backendAudience, scope: 'read write' },
        { store, verified }
      );

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read'],
        scope: 'read',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
    });

    test('a narrowed grant is cached under the scopes it was granted, not the scopes requested', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      expect(exchange.count).toBe(1);
      expect([...store.map.values()][0]!.grantedScopes).toEqual(['read']);

      // A request for just the granted scope is a hit.
      const hit = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });
      expect(hit.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);

      // A repeat of the original two-scope request is not a hit, so the exchange runs again.
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      expect(exchange.count).toBe(2);
    });

    test('no requested scope: the token is cached under whatever the server granted', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience }, { store, verified });

      expect(result.scope).toBe('read');
      expect([...store.map.values()][0]!.grantedScopes).toEqual(['read']);
      expect(exchange.count).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Result shape
  // -------------------------------------------------------------------------
  describe('result shape on a cache hit', () => {
    test('a hit returns the scope string exactly as the first call returned it', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'write  read' });
      const store = makeStore();

      const first = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      const second = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(second.scope).toBe(first.scope);
      expect(second).toEqual(first);
    });

    test('a hit preserves tokenType and issuedTokenType', async () => {
      const exchange = useExchange({
        accessToken: oboToken,
        scope: 'read',
        tokenType: 'DPoP',
        issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      });
      const store = makeStore();

      const first = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });
      const second = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(first.tokenType?.toLowerCase()).toBe('dpop');
      expect(first.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
      expect(second.tokenType).toBe(first.tokenType);
      expect(second.issuedTokenType).toBe(first.issuedTokenType);
      expect(Object.keys(second).sort()).toEqual(Object.keys(first).sort());
    });

    test('when the first call returned no scope, the hit has no scope key either', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      const first = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });
      const second = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(first).not.toHaveProperty('scope');
      expect(second).not.toHaveProperty('scope');
      expect(second).toEqual(first);
    });
  });

  // -------------------------------------------------------------------------
  // Basic cache behaviour
  // -------------------------------------------------------------------------
  describe('cache behaviour', () => {
    test('a miss exchanges once and stores the token under its granted scopes', async () => {
      const exchange = useExchange({
        accessToken: oboToken,
        scope: 'read write',
        issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store });

      expect(exchange.count).toBe(1);
      expect(store.get).toHaveBeenCalledTimes(1);
      expect(store.set).toHaveBeenCalledTimes(1);
      const [key, cached] = store.set.mock.calls[0]!;
      expect(key).toBe(store.get.mock.calls[0]![0]);
      expect(cached.accessToken).toBe(oboToken);
      expect(cached.grantedScopes).toEqual(['read', 'write']);
      expect(result.accessToken).toBe(oboToken);
      expect(result.scope).toBe('read write');
    });

    test('a valid cached entry is returned without an exchange', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      const nowSeconds = Math.floor(Date.now() / 1000);
      store.get.mockResolvedValue({
        accessToken: 'cached-access-token',
        expiresAt: nowSeconds + 3600,
        grantedScopes: ['read'],
        scope: 'read',
      });

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(exchange.count).toBe(0);
      expect(store.set).toHaveBeenCalledTimes(0);
      expect(result).toEqual({
        accessToken: 'cached-access-token',
        expiresAt: nowSeconds + 3600,
        grantedScopes: ['read'],
        scope: 'read',
      });
    });

    test('an expired entry is treated as a miss and the token is exchanged again', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      store.get.mockResolvedValue({
        accessToken: 'stale-token',
        expiresAt: Math.floor(Date.now() / 1000) - 1,
        grantedScopes: ['read'],
      });

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(store.set).toHaveBeenCalledTimes(1);
      expect(result.accessToken).toBe(oboToken);
    });

    test.each([
      ['within the clock-skew leeway', 3, 1],
      ['exactly at the clock-skew leeway boundary', 5, 1],
      ['just beyond the clock-skew leeway', 6, 0],
    ])('a cached token expiring %s', async (_label, secondsUntilExpiry, expectedExchanges) => {
      const now = Math.floor(new Date('2026-01-01T00:00:00Z').getTime() / 1000);
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(new Date(now * 1000));
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      store.get.mockResolvedValue({
        accessToken: 'cached-token',
        expiresAt: now + secondsUntilExpiry,
        grantedScopes: ['read'],
        scope: 'read',
      });

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(exchange.count).toBe(expectedExchanges);
      expect(result.accessToken).toBe(expectedExchanges === 0 ? 'cached-token' : oboToken);
    });

    test('reordered scope strings are served from the same cache entry', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'write read' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(store.map.size).toBe(1);
      expect(result.accessToken).toBe(oboToken);
    });

    test('duplicate scopes are collapsed so the request matches the deduplicated set', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read read write write' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(store.map.size).toBe(1);
    });

    test('a token cached for one client is not served to another client sharing the store', async () => {
      const clientA = new ApiClient({ ...baseClientOptions, clientId: 'client-A', clientSecret: 'secret-A' });
      const clientB = new ApiClient({ ...baseClientOptions, clientId: 'client-B', clientSecret: 'secret-B' });
      const verifiedA = await verifiedBy(clientA);
      const verifiedB = await verifiedBy(clientB);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await exchangeWith(clientA, verifiedA, { audience: backendAudience, scope: 'read' }, store);
      const [keyA, valueA] = [...store.map.entries()][0]!;
      store.map.set(keyA, { ...valueA, accessToken: 'poisoned-by-A', expiresAt: 9999999999 });

      const resultB = await exchangeWith(clientB, verifiedB, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(2);
      expect(resultB.accessToken).toBe(oboToken);
      expect(store.map.size).toBe(2);
    });

    test('request values that would collide under a naive delimiter join stay distinct', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      // Joined with "|", both of these become "...|A|x|y".
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'A', scope: 'x|y' }, { store, verified });
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'A|x', scope: 'y' }, { store, verified });

      expect(exchange.count).toBe(2);
      expect(store.map.size).toBe(2);
    });

    test('a subject token with azp and no client_id is keyed on azp', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();
      const azpVerified = async (azp: string): Promise<VerifiedToken> => {
        const result = await verifiedBy(apiClient, { claims: { client_id: undefined, azp } });
        expect(result.claims).not.toHaveProperty('client_id');
        expect(result.claims).toHaveProperty('azp', azp);
        return result;
      };
      const one = await azpVerified('azp-one');
      const two = await azpVerified('azp-two');
      const twoAgain = await azpVerified('azp-two');

      await exchangeWith(apiClient, one, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(apiClient, two, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(apiClient, twoAgain, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(2);
      expect(store.map.size).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // Failing open
  // -------------------------------------------------------------------------
  describe('store failures', () => {
    test('a store.get that throws falls through to the exchange', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      store.get.mockRejectedValue(new Error('store unavailable'));

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
    });

    test('a store.set that throws still returns the freshly exchanged token', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      store.set.mockRejectedValue(new Error('write failed'));

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
    });

    test('an index that cannot be listed is treated as a miss', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'non_strict' });
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeIndexedStore();
      store.listIndexMembers.mockRejectedValue(new Error('index unavailable'));

      const result = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
    });

    const future = Math.floor(Date.now() / 1000) + 3600;
    test.each([
      ['expiresAt is a string', { accessToken: 'bad', expiresAt: String(future), grantedScopes: ['read'] }],
      ['grantedScopes is missing', { accessToken: 'bad', expiresAt: future }],
      ['grantedScopes holds a non-string', { accessToken: 'bad', expiresAt: future, grantedScopes: [1] }],
      ['accessToken is empty', { accessToken: '', expiresAt: future, grantedScopes: ['read'] }],
      ['scope is not a string', { accessToken: 'bad', expiresAt: future, grantedScopes: ['read'], scope: 7 }],
      ['the entry is not an object', 'not-an-entry'],
    ])('a malformed cached entry (%s) is treated as a miss', async (_label, entry) => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      store.get.mockResolvedValue(entry as unknown as CachedToken);

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Cache key isolation, one test per axis
  // -------------------------------------------------------------------------
  describe('cache key isolation', () => {
    function expectTwoExchangesTwoKeys(
      exchange: { count: number },
      store: ReturnType<typeof makeStore>
    ) {
      expect(exchange.count).toBe(2);
      expect(store.map.size).toBe(2);
      expect(new Set(store.set.mock.calls.map(([key]) => key)).size).toBe(2);
    }

    test('different exchanging clientId', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();
      const clientA = new ApiClient({ ...baseClientOptions, clientId: 'client-A' });
      const clientB = new ApiClient({ ...baseClientOptions, clientId: 'client-B' });

      await exchangeWith(clientA, await verifiedBy(clientA), { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(clientB, await verifiedBy(clientB), { audience: backendAudience, scope: 'read' }, store);

      expectTwoExchangesTwoKeys(exchange, store);
    });

    test('different configured audience', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();
      const clientX = new ApiClient({ ...baseClientOptions, audience: 'https://audience-x.example.com' });
      const clientY = new ApiClient({ ...baseClientOptions, audience: 'https://audience-y.example.com' });
      const verifiedX = await verifiedBy(clientX, { audience: 'https://audience-x.example.com' });
      const verifiedY = await verifiedBy(clientY, { audience: 'https://audience-y.example.com' });

      await exchangeWith(clientX, verifiedX, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(clientY, verifiedY, { audience: backendAudience, scope: 'read' }, store);

      expectTwoExchangesTwoKeys(exchange, store);
    });

    test('different requested downstream audience', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api-a.example.com', scope: 'read' }, { store, verified });
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: 'https://api-b.example.com', scope: 'read' }, { store, verified });

      expectTwoExchangesTwoKeys(exchange, store);
    });

    test.each([
      ['sub', { sub: 'user_one' }, { sub: 'user_two' }],
      ['org_id', { claims: { org_id: 'org_one' } }, { claims: { org_id: 'org_two' } }],
      ['sid (the session)', { claims: { sid: 'session-one' } }, { claims: { sid: 'session-two' } }],
    ])('different %s claim', async (_axis, base, other) => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      await exchangeWith(apiClient, await verifiedBy(apiClient, base), { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(apiClient, await verifiedBy(apiClient, other), { audience: backendAudience, scope: 'read' }, store);

      expectTwoExchangesTwoKeys(exchange, store);
    });

    test('different iss claim', async () => {
      setupBrandHandlers();
      const multiTenantClient = new ApiClient({ ...baseClientOptions, domains: [domain, brandDomain] });
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();
      const fromFirstTenant = await verifiedBy(multiTenantClient);
      const fromSecondTenant = await verifiedBy(multiTenantClient, { issuerDomain: brandDomain });
      expect(fromFirstTenant.claims.iss).not.toBe(fromSecondTenant.claims.iss);

      await exchangeWith(multiTenantClient, fromFirstTenant, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(multiTenantClient, fromSecondTenant, { audience: backendAudience, scope: 'read' }, store);

      expectTwoExchangesTwoKeys(exchange, store);
    });

    test('different requested scope sets', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();

      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });
      await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expectTwoExchangesTwoKeys(exchange, store);
    });

    test('the same session claim reuses one entry', async () => {
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeStore();
      const sameSession = await verifiedBy(apiClient, { claims: { sid: 'session-one' } });

      await exchangeWith(apiClient, sameSession, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(apiClient, sameSession, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(1);
      expect(store.map.size).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Inputs are snapshotted once, so mutating them during an await cannot split the
  // exchange from the cache entry
  // -------------------------------------------------------------------------
  describe('input snapshots', () => {
    const modes = ['strict', 'non_strict'] as const;

    /**
     * Runs `mutate` once, during the first awaited store read, then behaves normally. In
     * strict mode that read is the entry lookup; in non-strict mode it is the index listing.
     */
    function mutateDuringFirstRead(store: ReturnType<typeof makeIndexedStore>, mutate: () => void) {
      let done = false;
      const realGet = store.get.getMockImplementation()!;
      const realList = store.listIndexMembers.getMockImplementation()!;
      store.get.mockImplementation((key: string) => {
        if (!done) {
          done = true;
          mutate();
          return Promise.resolve(undefined);
        }
        return realGet(key);
      });
      store.listIndexMembers.mockImplementation((indexKey: string) => {
        if (!done) {
          done = true;
          mutate();
          return Promise.resolve([]);
        }
        return realList(indexKey);
      });
    }

    test.each(modes)(
      '%s: mutating options.audience and options.scope while the store is read exchanges and caches under the original values',
      async (mode) => {
        const client = new ApiClient({ ...baseClientOptions, scopeMatching: mode });
        const clientVerified = await verifiedBy(client);
        const exchange = useExchange({ accessToken: oboToken });
        const store = makeIndexedStore();
        const options = { audience: backendAudience, scope: 'read' };
        mutateDuringFirstRead(store, () => {
          options.audience = 'https://attacker.example.com';
          options.scope = 'admin';
        });

        const first = await client.getTokenOnBehalfOf(clientVerified.accessToken, options, {
          store,
          verified: clientVerified,
        });

        expect(options).toEqual({ audience: 'https://attacker.example.com', scope: 'admin' });
        expect(exchange.audiences).toEqual([backendAudience]);
        expect(exchange.requestedScopes).toEqual(['read']);
        expect(first.grantedScopes).toEqual(['read']);

        // The entry is reachable with the original values and not with the mutated ones.
        const original = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);
        expect(original).toEqual(first);
        expect(exchange.count).toBe(1);

        await exchangeWith(client, clientVerified, { audience: 'https://attacker.example.com', scope: 'admin' }, store);
        expect(exchange.count).toBe(2);
      }
    );

    test.each(modes.flatMap((mode) => (['sub', 'org_id', 'sid', 'iss'] as const).map((claim) => [mode, claim] as const)))(
      '%s: mutating the %s claim while the store is read leaves every key identical to the unmutated baseline',
      async (mode, claim) => {
        setupBrandHandlers();
        const client = new ApiClient({
          ...baseClientOptions,
          domains: [domain, brandDomain],
          scopeMatching: mode,
        });
        useExchange({ accessToken: oboToken });

        const baseTokenOptions = { claims: { sid: 'session-base' } };
        // A subject token that genuinely differs from the baseline in exactly the tested claim.
        const differingTokenOptions = {
          sub: claim === 'sub' ? 'user_other' : undefined,
          issuerDomain: claim === 'iss' ? brandDomain : undefined,
          claims: {
            sid: claim === 'sid' ? 'session-other' : 'session-base',
            ...(claim === 'org_id' && { org_id: 'org_other' }),
          },
        };

        const run = async (
          tokenOptions: Parameters<typeof verifiedBy>[1],
          mutate?: (claims: Record<string, unknown>) => void
        ) => {
          const store = makeIndexedStore();
          const subject = await verifiedBy(client, tokenOptions);
          const claims = subject.claims as Record<string, unknown>;
          if (mutate !== undefined) {
            mutateDuringFirstRead(store, () => mutate(claims));
          }

          await client.getTokenOnBehalfOf(
            subject.accessToken,
            { audience: backendAudience, scope: 'read' },
            { store, verified: subject }
          );

          return {
            claims,
            keys: {
              readKey: mode === 'strict' ? store.get.mock.calls[0]![0] : store.listIndexMembers.mock.calls[0]![0],
              writeKey: store.set.mock.calls[0]![0],
              indexWriteKey: store.addIndexMember.mock.calls[0]?.[0],
            },
          };
        };

        const baseline = await run(baseTokenOptions);
        const mutated = await run(baseTokenOptions, (claims) => {
          claims[claim] = 'mutated-value';
        });
        const control = await run(differingTokenOptions);

        // The caller's object really was changed, so equality below is not vacuous.
        expect(mutated.claims[claim]).toBe('mutated-value');
        expect(mutated.keys).toEqual(baseline.keys);
        // Control: a token that genuinely carries a different value for this claim does move the key.
        expect(control.keys.writeKey).not.toBe(baseline.keys.writeKey);
      }
    );

    test.each(modes)('%s: mutating the claims during the read cannot move the entry to another subject', async (mode) => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: mode });
      const exchange = useExchange({ accessToken: oboToken });
      const store = makeIndexedStore();
      const victim = await verifiedBy(client, { sub: 'user_victim' });
      const claims = victim.claims as Record<string, unknown>;
      mutateDuringFirstRead(store, () => {
        claims.sub = 'user_attacker';
      });

      await exchangeWith(client, victim, { audience: backendAudience, scope: 'read' }, store);
      expect(exchange.count).toBe(1);
      const entryKeys = [...store.map.keys()];
      expect(entryKeys).toHaveLength(1);

      // The entry belongs to the victim: a fresh, untouched verification of the same token
      // is served from it, under the very same key.
      const untouched = {
        accessToken: victim.accessToken,
        claims: await client.verifyAccessToken({ accessToken: victim.accessToken }),
      };
      expect(untouched.claims.sub).toBe('user_victim');
      await exchangeWith(client, untouched, { audience: backendAudience, scope: 'read' }, store);
      expect(exchange.count).toBe(1);

      // The tampered object still says user_attacker, but it is keyed by what was verified,
      // so it reaches the same victim entry and creates no entry of its own.
      expect(claims.sub).toBe('user_attacker');
      await exchangeWith(client, victim, { audience: backendAudience, scope: 'read' }, store);
      expect(exchange.count).toBe(1);
      expect([...store.map.keys()]).toEqual(entryKeys);

      // Control: a token genuinely issued to the other subject does not reach the victim entry.
      const attacker = await verifiedBy(client, { sub: 'user_attacker' });
      await exchangeWith(client, attacker, { audience: backendAudience, scope: 'read' }, store);
      expect(exchange.count).toBe(2);
      expect(store.map.size).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // Claims are recorded at verification time, so editing them afterwards has no effect
  // -------------------------------------------------------------------------
  describe('claims edited after verification', () => {
    test('a claims object whose sub was rewritten to another principal after verification is keyed to the original subject and never touches that principal entry', async () => {
      const sharedSession = { sid: 'shared-session' };
      const victimObo = await generateToken(domain, 'user_victim', backendAudience);
      const attackerObo = await generateToken(domain, 'user_attacker', backendAudience);
      const store = makeStore();

      // The victim legitimately exchanges and caches a token.
      const victimExchange = useExchange({ accessToken: victimObo, scope: 'read' });
      const victim = await verifiedBy(apiClient, { sub: 'user_victim', claims: sharedSession });
      await exchangeWith(apiClient, victim, { audience: backendAudience, scope: 'read' }, store);
      expect(victimExchange.count).toBe(1);
      const victimKey = store.set.mock.calls[0]![0];
      const victimEntryBefore = structuredClone(store.map.get(victimKey));
      expect(victimEntryBefore?.accessToken).toBe(victimObo);

      // The key the attacker's own token legitimately maps to, taken from an unmutated run.
      const attackerExchange = useExchange({ accessToken: attackerObo, scope: 'read' });
      const scratchStore = makeStore();
      const unmutated = await verifiedBy(apiClient, { sub: 'user_attacker', claims: sharedSession });
      await exchangeWith(apiClient, unmutated, { audience: backendAudience, scope: 'read' }, scratchStore);
      const attackerKey = scratchStore.set.mock.calls[0]![0];
      expect(attackerKey).not.toBe(victimKey);
      expect(attackerExchange.count).toBe(1);

      // The attack: verify the attacker's own token, then claim to be the victim.
      const attacker = await verifiedBy(apiClient, { sub: 'user_attacker', claims: sharedSession });
      (attacker.claims as Record<string, unknown>).sub = 'user_victim';
      store.get.mockClear();
      store.set.mockClear();

      const result = await exchangeWith(apiClient, attacker, { audience: backendAudience, scope: 'read' }, store);

      // The victim entry was neither returned nor read.
      expect(result.accessToken).toBe(attackerObo);
      expect(attackerExchange.count).toBe(2);
      expect(store.get.mock.calls.map(([key]) => key)).toEqual([attackerKey]);
      // The write went to the attacker's original key, and the victim entry is untouched.
      expect(store.set.mock.calls.map(([key]) => key)).toEqual([attackerKey]);
      expect(store.map.get(victimKey)).toEqual(victimEntryBefore);
      expect([...store.map.keys()].sort()).toEqual([attackerKey, victimKey].sort());
    });

    test('the recorded claims are a copy: editing the caller object after a successful call does not change what a later call keys on', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      const subject = await verifiedBy(apiClient, { claims: { sid: 'session-one' } });

      await exchangeWith(apiClient, subject, { audience: backendAudience, scope: 'read' }, store);
      const firstKey = store.set.mock.calls[0]![0];
      expect(exchange.count).toBe(1);

      const claims = subject.claims as Record<string, unknown>;
      claims.sub = 'user_other';
      claims.org_id = 'org_other';
      claims.sid = 'session-other';
      store.get.mockClear();

      await exchangeWith(apiClient, subject, { audience: backendAudience, scope: 'read' }, store);

      expect(store.get.mock.calls.map(([key]) => key)).toEqual([firstKey]);
      expect(exchange.count).toBe(1);
      expect(store.set).toHaveBeenCalledTimes(1);
      expect([...store.map.keys()]).toEqual([firstKey]);

      // Control: had the key followed the edited object, a genuinely different identity misses.
      const other = await verifiedBy(apiClient, { sub: 'user_other', claims: { org_id: 'org_other', sid: 'session-other' } });
      await exchangeWith(apiClient, other, { audience: backendAudience, scope: 'read' }, store);
      expect(exchange.count).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // Fail fast without client credentials
  // -------------------------------------------------------------------------
  describe('a client without credentials', () => {
    const noCredentials = { domain, audience: '<audience>' } as const;

    test('rejects with MissingClientAuthError before any verification or store access', async () => {
      const client = new ApiClient(noCredentials);
      const verifySpy = vi.spyOn(client, 'verifyAccessToken');
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await expect(
        client.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(verifySpy).toHaveBeenCalledTimes(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
      expect(store.delete).toHaveBeenCalledTimes(0);
      expect(exchange.count).toBe(0);
    });

    test('is not served from a shared store that an authenticated client populated', async () => {
      const authenticated = new ApiClient(baseClientOptions);
      const anonymous = new ApiClient(noCredentials);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      await authenticated.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store });
      store.get.mockClear();

      await expect(
        anonymous.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(store.get).toHaveBeenCalledTimes(0);
      expect(exchange.count).toBe(1);
    });

    test('reports the missing credentials ahead of a pre-verified mismatch', async () => {
      const client = new ApiClient(noCredentials);
      const clientVerified = await verifiedBy(client);
      const store = makeStore();

      await expect(
        client.getTokenOnBehalfOf(
          'some-other-token',
          { audience: backendAudience, scope: 'read' },
          { store, verified: clientVerified }
        )
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(store.get).toHaveBeenCalledTimes(0);
    });

    test('reports the missing credentials ahead of the non_strict indexed store requirement', async () => {
      const client = new ApiClient({ ...noCredentials, scopeMatching: 'non_strict' });
      const store = makeStore();

      await expect(
        client.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(store.get).toHaveBeenCalledTimes(0);
    });

    test('reports the missing credentials when no store is supplied either', async () => {
      const client = new ApiClient(noCredentials);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });

      await expect(
        client.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' })
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(exchange.count).toBe(0);
    });

    test('a client with a clientId but no secret and no signing key rejects with MissingClientAuthError, with no verification and no store call', async () => {
      const client = new ApiClient({ ...noCredentials, clientId: 'id-without-secret' });
      const verifySpy = vi.spyOn(client, 'verifyAccessToken');
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      await expect(
        client.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(verifySpy).toHaveBeenCalledTimes(0);
      expect(exchange.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
      expect(store.delete).toHaveBeenCalledTimes(0);
    });

    test('the same holds for an indexed store in non_strict mode', async () => {
      const client = new ApiClient({ ...noCredentials, clientId: 'id-without-secret', scopeMatching: 'non_strict' });
      const verifySpy = vi.spyOn(client, 'verifyAccessToken');
      const store = makeIndexedStore();

      await expect(
        client.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(MissingClientAuthError);

      expect(verifySpy).toHaveBeenCalledTimes(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
      expect(store.listIndexMembers).toHaveBeenCalledTimes(0);
      expect(store.addIndexMember).toHaveBeenCalledTimes(0);
    });
  });

  // -------------------------------------------------------------------------
  // Claims that cannot be keyed unambiguously make the call uncacheable
  // -------------------------------------------------------------------------
  describe('claims with the wrong type', () => {
    // iss is not in this list: a token whose iss is not the expected string never passes
    // verification, so it cannot reach the cache at all. See the dedicated test below.
    const keyedClaims = ['client_id', 'azp', 'sub', 'org_id', 'sid', 'jti'] as const;
    const badValues = [
      ['a number', 123],
      ['null', null],
    ] as const;

    test.each(keyedClaims.flatMap((claim) => badValues.map(([label, value]) => [claim, label, value] as const)))(
      '%s as %s: the call succeeds, the store is never touched, and every call exchanges',
      async (claim, _label, value) => {
        const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
        const store = makeStore();
        // A token genuinely signed with the wrong-typed claim, verified normally. Only these
        // claims are read as strings by the key; verification itself does not constrain them.
        const client = claim === 'sub' ? new ApiClient(baseClientOptions) : apiClient;
        const wrongTyped =
          claim === 'sub'
            ? await verifiedWithRawSub(client, value)
            : await verifiedBy(client, { claims: { [claim]: value } });
        expect((wrongTyped.claims as Record<string, unknown>)[claim]).toBe(value);

        const first = await exchangeWith(client, wrongTyped, { audience: backendAudience, scope: 'read' }, store);
        const second = await exchangeWith(client, wrongTyped, { audience: backendAudience, scope: 'read' }, store);

        const expected = {
          accessToken: oboToken,
          expiresAt: expect.any(Number),
          grantedScopes: ['read'],
          scope: 'read',
          tokenType: expect.stringMatching(/^bearer$/i),
        };
        expect(first).toEqual(expected);
        expect(second).toEqual(expected);
        expect(exchange.count).toBe(2);
        expect(store.get).toHaveBeenCalledTimes(0);
        expect(store.set).toHaveBeenCalledTimes(0);
        expect(store.delete).toHaveBeenCalledTimes(0);
      }
    );

    test('non_strict: the indexed store is never read or written either', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'non_strict' });
      const clientVerified = await verifiedWithRawSub(client, 42);
      expect((clientVerified.claims as Record<string, unknown>).sub).toBe(42);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeIndexedStore();

      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(2);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
      expect(store.listIndexMembers).toHaveBeenCalledTimes(0);
      expect(store.addIndexMember).toHaveBeenCalledTimes(0);
    });

    test.each([
      ['a number', 123],
      ['null', null],
    ])('iss as %s: verification rejects the token, so it never reaches the cache', async (_label, value) => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      // generateToken replaces iss unless told not to, so sign the token with the bad iss claim.
      const badIss = await generateToken(domain, 'user_123', '<audience>', false, undefined, undefined, {
        iss: value,
        client_id: 'client-abc',
        org_id: 'org_xyz',
      });

      await expect(
        apiClient.getTokenOnBehalfOf(badIss, { audience: backendAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(VerifyAccessTokenError);

      expect(exchange.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
    });

    test('a claim that is simply absent does not disable the cache', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      const withoutOrg = await verifiedBy(apiClient, { claims: { org_id: undefined } });
      expect(withoutOrg.claims).not.toHaveProperty('org_id');

      await exchangeWith(apiClient, withoutOrg, { audience: backendAudience, scope: 'read' }, store);
      await exchangeWith(apiClient, withoutOrg, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(1);
      expect(store.set).toHaveBeenCalledTimes(1);
    });

    test('an uncacheable call still verifies the subject token when no pre-verified token is supplied', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();
      vi.spyOn(apiClient, 'verifyAccessToken').mockResolvedValueOnce({
        ...verified.claims,
        sid: 123,
      } as unknown as VerifiedAccessTokenClaims);

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store });

      expect(result.accessToken).toBe(oboToken);
      expect(exchange.count).toBe(1);
      expect(store.get).toHaveBeenCalledTimes(0);
      expect(store.set).toHaveBeenCalledTimes(0);
    });
  });

  // -------------------------------------------------------------------------
  // grantedScopes on the result
  // -------------------------------------------------------------------------
  describe('grantedScopes on the result', () => {
    test('is the normalized, deduplicated, sorted granted set, while scope is replayed as sent', async () => {
      useExchange({ accessToken: oboToken, scope: 'write  read read' });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read', 'write'],
        scope: 'write  read read',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
    });

    test('is empty when the server granted an empty scope', async () => {
      useExchange({ accessToken: oboToken, scope: '' });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expect(result.grantedScopes).toEqual([]);
      expect(result.scope).toBe('');
    });

    test('equals the requested set, normalized, when the server omitted scope', async () => {
      useExchange({ accessToken: oboToken });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'write read read' }, { store, verified });

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read', 'write'],
        tokenType: expect.stringMatching(/^bearer$/i),
      });
    });

    test('is empty when the server omitted scope and none was requested', async () => {
      useExchange({ accessToken: oboToken });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience }, { store, verified });

      expect(result.grantedScopes).toEqual([]);
    });

    test('is present on a call without a store', async () => {
      useExchange({ accessToken: oboToken, scope: 'write read' });

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' });

      expect(result).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read', 'write'],
        scope: 'write read',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
    });

    test('is present and identical on a strict cache hit', async () => {
      const exchange = useExchange({ accessToken: oboToken, scope: 'write read' });
      const store = makeStore();

      const first = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });
      const second = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expect(exchange.count).toBe(1);
      expect(second).toEqual(first);
      expect(second.grantedScopes).toEqual(['read', 'write']);
    });

    test('reports the narrower grant when the server granted less than was requested', async () => {
      useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read write' }, { store, verified });

      expect(result.grantedScopes).toEqual(['read']);
    });

    test('on a non-strict hit for a narrower request reports the broader scopes the cached token carries', async () => {
      const client = new ApiClient({ ...baseClientOptions, scopeMatching: 'non_strict' });
      const clientVerified = await verifiedBy(client);
      const exchange = useExchange({ accessToken: oboToken, scope: 'read write admin' });
      const store = makeIndexedStore();

      const fresh = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read write admin' }, store);
      const narrower = await exchangeWith(client, clientVerified, { audience: backendAudience, scope: 'read' }, store);

      expect(exchange.count).toBe(1);
      expect(fresh.grantedScopes).toEqual(['admin', 'read', 'write']);
      expect(narrower).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['admin', 'read', 'write'],
        scope: 'read write admin',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
    });

    test('the returned array is a copy, so changing it cannot change what the cache serves next', async () => {
      useExchange({ accessToken: oboToken, scope: 'read' });
      const store = makeStore();

      const first = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });
      first.grantedScopes.push('admin');
      const second = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });
      second.grantedScopes.push('write');
      const third = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: backendAudience, scope: 'read' }, { store, verified });

      expect(third.grantedScopes).toEqual(['read']);
      expect([...store.map.values()][0]!.grantedScopes).toEqual(['read']);
    });
  });
});
