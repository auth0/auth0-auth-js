import { expect, test, afterAll, beforeAll, beforeEach, vi, afterEach, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AuthClient } from './auth-client.js';
import { NotSupportedError } from './errors.js';
import { ExchangeProfileOptions } from './types.js';

import { generateToken, jwks } from './test-utils/tokens.js';
import { pemToArrayBuffer } from './test-utils/pem.js';

const domain = 'auth0.local';
let accessToken: string;
let mtlsAccessToken: string;
let accessTokenWithAudienceAndBindingMessage: string;
let accessTokenWithAudience: string;
let accessTokenWithScope: string;
let accessTokenWithAudienceAndScope: string;
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
  pushed_authorization_request_endpoint: `https://${domain}/pushed-authorize`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
  mtls_endpoint_aliases: {
    token_endpoint: `https://mtls.${domain}/oauth/token`,
    userinfo_endpoint: `https://mtls.${domain}/userinfo`,
    revocation_endpoint: `https://mtls.${domain}/oauth/revoke`,
    pushed_authorization_request_endpoint: `https://mtls.${domain}/oauth/par`,
  },
};

const buildOpenIdConfiguration = (customDomain: string) => ({
  issuer: `https://${customDomain}/`,
  authorization_endpoint: `https://${customDomain}/authorize`,
  backchannel_authentication_endpoint: `https://${customDomain}/custom-authorize`,
  token_endpoint: `https://${customDomain}/custom/token`,
  end_session_endpoint: `https://${customDomain}/logout`,
  pushed_authorization_request_endpoint: `https://${customDomain}/pushed-authorize`,
  jwks_uri: `https://${customDomain}/.well-known/jwks.json`,
  mtls_endpoint_aliases: {
    token_endpoint: `https://mtls.${customDomain}/oauth/token`,
    userinfo_endpoint: `https://mtls.${customDomain}/userinfo`,
    revocation_endpoint: `https://mtls.${customDomain}/oauth/revoke`,
    pushed_authorization_request_endpoint: `https://mtls.${customDomain}/oauth/par`,
  },
});

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
  http.post(mockOpenIdConfiguration.backchannel_authentication_endpoint, async ({ request }) => {
    const info = await request.formData();
    const shouldFailBCAuthorize = !!info.get('should_fail_authorize');

    let auth_req_id = 'auth_req_123';

    if (info.get('audience') && info.get('binding_message')) {
      auth_req_id = 'auth_req_789';
    }

    if (info.get('should_fail_token_exchange')) {
      auth_req_id = 'auth_req_should_fail';
    }

    if (info.get('authorization_details')) {
      auth_req_id = 'auth_req_with_authorization_details';
    }

    return shouldFailBCAuthorize
      ? HttpResponse.json({ error: '<error_code>', error_description: '<error_description>' }, { status: 400 })
      : HttpResponse.json({
          auth_req_id: auth_req_id,
          interval: 0.5,
          expires_in: 60,
        });
  }),
  http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
    const info = await request.formData();
    let accessTokenToUse = accessToken;
    let idTokenToUse = await generateToken(domain, 'user_123', '<client_id>');
    let scopeToReturn = '<scope>';

    // Handle CTE grant type
    if (info.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange') {
      if (info.get('audience') === '<audience_should_fail_cte>') {
        return HttpResponse.json(
          { error: 'invalid_request', error_description: 'CTE audience not allowed' },
          { status: 403 }
        );
      }
      if (info.get('custom_param') === 'custom_value') {
        accessTokenToUse = await generateToken(domain, 'user_cte_custom');
        idTokenToUse = await generateToken(domain, 'user_cte_custom', '<client_id>');
      } else {
        idTokenToUse = await generateToken(domain, 'user_cte', '<client_id>');
      }

      return HttpResponse.json({
        access_token: accessTokenToUse,
        id_token: idTokenToUse,
        expires_in: 3600, // 1 hour
        token_type: 'Bearer',
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        scope: info.get('scope') || 'read:default',
      });
    }

    // Handle refresh_token grant type with audience and/or scope
    if (info.get('grant_type') === 'refresh_token') {
      const audience = info.get('audience');
      const scope = info.get('scope');

      if (audience && scope) {
        accessTokenToUse = accessTokenWithAudienceAndScope;
        scopeToReturn = scope.toString();
      } else if (audience) {
        accessTokenToUse = accessTokenWithAudience;
      } else if (scope) {
        accessTokenToUse = accessTokenWithScope;
        scopeToReturn = scope.toString();
      }
    }

    if (info.get('auth_req_id') === 'auth_req_789') {
      accessTokenToUse = accessTokenWithAudienceAndBindingMessage;
    }
    const shouldFailTokenExchange =
      info.get('auth_req_id') === 'auth_req_should_fail' ||
      info.get('code') === '<code_should_fail>' ||
      info.get('subject_token') === '<refresh_token_should_fail>' ||
      info.get('refresh_token') === '<refresh_token_should_fail>' ||
      info.get('audience') === '<audience_should_fail>';

    return shouldFailTokenExchange
      ? HttpResponse.json({ error: '<error_code>', error_description: '<error_description>' }, { status: 400 })
      : HttpResponse.json({
          access_token: accessTokenToUse,
          id_token: idTokenToUse,
          expires_in: 60,
          token_type: 'Bearer',
          scope: scopeToReturn,
          ...(info.get('auth_req_id') === 'auth_req_with_authorization_details'
            ? { authorization_details: [{ type: 'accepted' }] }
            : {}),
        });
  }),

  http.post(mockOpenIdConfiguration.mtls_endpoint_aliases.token_endpoint, async () => {
    return HttpResponse.json({
      access_token: mtlsAccessToken,
      id_token: await generateToken(domain, 'user_123', '<client_id>'),
      expires_in: 60,
      token_type: 'Bearer',
      scope: '<scope>',
    });
  }),

  http.post(mockOpenIdConfiguration.pushed_authorization_request_endpoint, async ({ request }) => {
    const info = await request.formData();
    return info.get('fail')
      ? HttpResponse.json({ error: '<error_code>', error_description: '<error_description>' }, { status: 400 })
      : HttpResponse.json(
          {
            request_uri: 'request_uri_123',
            expires_in: 60,
          },
          { status: 201 }
        );
  }),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
  mtlsAccessToken = await generateToken(domain, 'user_abc');
  accessTokenWithAudienceAndBindingMessage = await generateToken(domain, 'user_789');
  accessTokenWithAudience = await generateToken(domain, 'user_with_audience');
  accessTokenWithScope = await generateToken(domain, 'user_with_scope');
  accessTokenWithAudienceAndScope = await generateToken(domain, 'user_with_aud_scope');
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
    mtls_endpoint_aliases: {
      token_endpoint: `https://mtls.${domain}/oauth/token`,
      userinfo_endpoint: `https://mtls.${domain}/userinfo`,
      revocation_endpoint: `https://mtls.${domain}/oauth/revoke`,
      pushed_authorization_request_endpoint: `https://mtls.${domain}/oauth/par`,
    },
  };
  server.resetHandlers();
});

test('configuration - should use customFetch', async () => {
  const mockFetch = vi.fn().mockImplementation(fetch);
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    customFetch: mockFetch,
  });

  await authClient.buildAuthorizationUrl();

  expect(mockFetch).toHaveBeenCalledTimes(1);

  mockFetch.mockClear();

  const tokenResponse = await authClient.getTokenByCode(new URL(`https://${domain}?code=123`), {
    codeVerifier: '123',
  });

  expect(tokenResponse.accessToken).toBe(accessToken);
  expect(mockFetch).toHaveBeenCalledTimes(1);
});

test('configuration - should use private key JWT when passed as string', async () => {
  const mockFetch = vi.fn().mockImplementation(fetch);
  const clientAssertionSigningKeyRaw = `-----BEGIN PRIVATE KEY-----
  MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbTKOQLtaZ6U1k
  3fcYCMVoy8poieNPPcbj15TCLOm4Bbox73/UUxIArqczVcjtUGnL+jn5982V5EiB
  y8W51m5K9mIBgEFLYdLkXk+OW5UTE/AdMPtfsIjConGrrs3mxN4WSH9kvh9Yr41r
  hWUUSwqFyMOssbGE8K46Cv0WYvS7RXH9MzcyTcMSFp/60yUXH4rdHYZElF7XCdiE
  63WxebxI1Qza4xkjTlbp5EWfWBQB1Ms10JO8NjrtkCXrDI57Bij5YanPAVhctcO9
  z5/y9i5xEzcer8ZLO8VDiXSdEsuP/fe+UKDyYHUITD8u51p3O2JwCKvdTHduemej
  3Kd1RlHrAgMBAAECggEATWdzpASkQpcSdjPSb21JIIAt5VAmJ2YKuYjyPMdVh1qe
  Kdn7KJpZlFwRMBFrZjgn35Nmu1A4BFwbK5UdKUcCjvsABL+cTFsu8ORI+Fpi9+Tl
  r6gGUfQhkXF85bhBfN6n9P2J2akxrz/njrf6wXrrL+V5C498tQuus1YFls0+zIpD
  N+GngNOPHlGeY3gW4K/HjGuHwuJOvWNmE4KNQhBijdd50Am824Y4NV/SmsIo7z+s
  8CLjp/qtihwnE4rkUHnR6M4u5lpzXOnodzkDTG8euOJds0T8DwLNTx1b+ETim35i
  D/hOCVwl8QFoj2aatjuJ5LXZtZUEpGpBF2TQecB+gQKBgQDvaZ1jG/FNPnKdayYv
  z5yTOhKM6JTB+WjB0GSx8rebtbFppiHGgVhOd1bLIzli9uMOPdCNuXh7CKzIgSA6
  Q76Wxfuaw8F6CBIdlG9bZNL6x8wp6zF8tGz/BgW7fFKBwFYSWzTcStGr2QGtwr6F
  9p1gYPSGfdERGOQc7RmhoNNHcQKBgQDqfkhpPfJlP/SdFnF7DDUvuMnaswzUsM6D
  ZPhvfzdMBV8jGc0WjCW2Vd3pvsdPgWXZqAKjN7+A5HiT/8qv5ruoqOJSR9ZFZI/B
  8v+8gS9Af7K56mCuCFKZmOXUmaL+3J2FKtzAyOlSLjEYyLuCgmhEA9Zo+duGR5xX
  AIjx7N/ZGwKBgCZAYqQeJ8ymqJtcLkq/Sg3/3kzjMDlZxxIIYL5JwGpBemod4BGe
  QuSujpCAPUABoD97QuIR+xz1Qt36O5LzlfTzBwMwOa5ssbBGMhCRKGBnIcikylBZ
  Z3zLkojlES2n9FiUd/qmfZ+OWYVQsy4mO/jVJNyEJ64qou+4NjsrvfYRAoGAORki
  3K1+1nSqRY3vd/zS/pnKXPx4RVoADzKI4+1gM5yjO9LOg40AqdNiw8X2lj9143fr
  nH64nNQFIFSKsCZIz5q/8TUY0bDY6GsZJnd2YAg4JtkRTY8tPcVjQU9fxxtFJ+X1
  9uN1HNOulNBcCD1k0hr1HH6qm5nYUb8JmY8KOr0CgYB85pvPhBqqfcWi6qaVQtK1
  ukIdiJtMNPwePfsT/2KqrbnftQnAKNnhsgcYGo8NAvntX4FokOAEdunyYmm85mLp
  BGKYgVXJqnm6+TJyCRac1ro3noG898P/LZ8MOBoaYQtWeWRpDc46jPrA0FqUJy+i
  ca/T0LLtgmbMmxSv/MmzIg==
  -----END PRIVATE KEY-----`;

  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientAssertionSigningKey: clientAssertionSigningKeyRaw,
    discoveryCache: { ttl: 14, maxEntries: 5 },
    customFetch: mockFetch,
  });

  await authClient.buildAuthorizationUrl();

  expect(mockFetch).toHaveBeenCalledTimes(1);

  mockFetch.mockClear();

  const tokenResponse = await authClient.getTokenByCode(new URL(`https://${domain}?code=123`), {
    codeVerifier: '123',
  });

  expect(tokenResponse.accessToken).toBe(accessToken);
  expect(mockFetch).toHaveBeenCalledTimes(1);
});

test('configuration - should use private key JWT when passed as CryptoKey', async () => {
  const mockFetch = vi.fn().mockImplementation(fetch);
  const clientAssertionSigningKeyRaw = `-----BEGIN PRIVATE KEY-----
  MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbTKOQLtaZ6U1k
  3fcYCMVoy8poieNPPcbj15TCLOm4Bbox73/UUxIArqczVcjtUGnL+jn5982V5EiB
  y8W51m5K9mIBgEFLYdLkXk+OW5UTE/AdMPtfsIjConGrrs3mxN4WSH9kvh9Yr41r
  hWUUSwqFyMOssbGE8K46Cv0WYvS7RXH9MzcyTcMSFp/60yUXH4rdHYZElF7XCdiE
  63WxebxI1Qza4xkjTlbp5EWfWBQB1Ms10JO8NjrtkCXrDI57Bij5YanPAVhctcO9
  z5/y9i5xEzcer8ZLO8VDiXSdEsuP/fe+UKDyYHUITD8u51p3O2JwCKvdTHduemej
  3Kd1RlHrAgMBAAECggEATWdzpASkQpcSdjPSb21JIIAt5VAmJ2YKuYjyPMdVh1qe
  Kdn7KJpZlFwRMBFrZjgn35Nmu1A4BFwbK5UdKUcCjvsABL+cTFsu8ORI+Fpi9+Tl
  r6gGUfQhkXF85bhBfN6n9P2J2akxrz/njrf6wXrrL+V5C498tQuus1YFls0+zIpD
  N+GngNOPHlGeY3gW4K/HjGuHwuJOvWNmE4KNQhBijdd50Am824Y4NV/SmsIo7z+s
  8CLjp/qtihwnE4rkUHnR6M4u5lpzXOnodzkDTG8euOJds0T8DwLNTx1b+ETim35i
  D/hOCVwl8QFoj2aatjuJ5LXZtZUEpGpBF2TQecB+gQKBgQDvaZ1jG/FNPnKdayYv
  z5yTOhKM6JTB+WjB0GSx8rebtbFppiHGgVhOd1bLIzli9uMOPdCNuXh7CKzIgSA6
  Q76Wxfuaw8F6CBIdlG9bZNL6x8wp6zF8tGz/BgW7fFKBwFYSWzTcStGr2QGtwr6F
  9p1gYPSGfdERGOQc7RmhoNNHcQKBgQDqfkhpPfJlP/SdFnF7DDUvuMnaswzUsM6D
  ZPhvfzdMBV8jGc0WjCW2Vd3pvsdPgWXZqAKjN7+A5HiT/8qv5ruoqOJSR9ZFZI/B
  8v+8gS9Af7K56mCuCFKZmOXUmaL+3J2FKtzAyOlSLjEYyLuCgmhEA9Zo+duGR5xX
  AIjx7N/ZGwKBgCZAYqQeJ8ymqJtcLkq/Sg3/3kzjMDlZxxIIYL5JwGpBemod4BGe
  QuSujpCAPUABoD97QuIR+xz1Qt36O5LzlfTzBwMwOa5ssbBGMhCRKGBnIcikylBZ
  Z3zLkojlES2n9FiUd/qmfZ+OWYVQsy4mO/jVJNyEJ64qou+4NjsrvfYRAoGAORki
  3K1+1nSqRY3vd/zS/pnKXPx4RVoADzKI4+1gM5yjO9LOg40AqdNiw8X2lj9143fr
  nH64nNQFIFSKsCZIz5q/8TUY0bDY6GsZJnd2YAg4JtkRTY8tPcVjQU9fxxtFJ+X1
  9uN1HNOulNBcCD1k0hr1HH6qm5nYUb8JmY8KOr0CgYB85pvPhBqqfcWi6qaVQtK1
  ukIdiJtMNPwePfsT/2KqrbnftQnAKNnhsgcYGo8NAvntX4FokOAEdunyYmm85mLp
  BGKYgVXJqnm6+TJyCRac1ro3noG898P/LZ8MOBoaYQtWeWRpDc46jPrA0FqUJy+i
  ca/T0LLtgmbMmxSv/MmzIg==
  -----END PRIVATE KEY-----`;
  const clientAssertionSigningKey = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(clientAssertionSigningKeyRaw),
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }, // or SHA-512
    },
    true,
    ['sign']
  );
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientAssertionSigningKey: clientAssertionSigningKey,
    discoveryCache: { ttl: 15, maxEntries: 5 },
    customFetch: mockFetch,
  });

  await authClient.buildAuthorizationUrl();

  expect(mockFetch).toHaveBeenCalledTimes(1);

  mockFetch.mockClear();

  const tokenResponse = await authClient.getTokenByCode(new URL(`https://${domain}?code=123`), {
    codeVerifier: '123',
  });

  expect(tokenResponse.accessToken).toBe(accessToken);
  expect(mockFetch).toHaveBeenCalledTimes(1);
});

test('configuration - should throw when no key configured', async () => {
  const mockFetch = vi.fn().mockImplementation(fetch);

  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    customFetch: mockFetch,
  });

  await expect(authClient.buildAuthorizationUrl()).rejects.toThrowError(
    'The client secret or client assertion signing key must be provided.'
  );
});

test('configuration - should use mTLS when useMtls is true', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    useMtls: true,
    // For mTLS to actually work in an actual application,
    // a custom fetch implementation should be provided, containing the corresponding configuration for mTLS.
    customFetch: fetch,
  });

  const tokenResponse = await authClient.getTokenByCode(new URL(`https://${domain}?code=123`), {
    codeVerifier: '123',
  });

  expect(tokenResponse.accessToken).toBe(mtlsAccessToken);
});

test('configuration - should use mTLS when useMtls is true but no aliases', async () => {
  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.mtls_endpoint_aliases;

  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    discoveryCache: { ttl: 11, maxEntries: 3 },
    useMtls: true,
    // For mTLS to actually work in an actual application,
    // a custom fetch implementation should be provided, containing the corresponding configuration for mTLS.
    customFetch: fetch,
  });

  const tokenResponse = await authClient.getTokenByCode(new URL(`https://${domain}?code=123`), {
    codeVerifier: '123',
  });

  // When no aliases, we will end up calling the regular oauth/token endpoint,
  // and not the mTLS alias.
  // We know that in the case of our tests, that means it returns an `accessToken` instead of `mtlsAccessToken`.
  expect(tokenResponse.accessToken).toBe(accessToken);
});

test('configuration - should throw when useMtls is true but customFetch is not provided', () => {
  expect(() => {
    new AuthClient({
      domain,
      clientId: 'client123',
      useMtls: true,
      // customFetch is not provided
    });
  }).toThrow(NotSupportedError);
});

test('getServerMetadata - should return server metadata from discovery', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const metadata = await authClient.getServerMetadata();

  expect(metadata.issuer).toBe(`https://${domain}/`);
});

describe('discovery cache', () => {
  test('should reuse discovery metadata across instances with same cache config', async () => {
    const cacheDomain = 'cache.auth0.local';
    const cacheConfig = buildOpenIdConfiguration(cacheDomain);
    let discoveryCalls = 0;

    server.use(
      http.get(`https://${cacheDomain}/.well-known/openid-configuration`, () => {
        discoveryCalls += 1;
        return HttpResponse.json(cacheConfig);
      })
    );

    const discoveryCache = { ttl: 30, maxEntries: 5 };
    const authClientA = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });
    const authClientB = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });

    await authClientA.buildAuthorizationUrl();
    await authClientB.buildAuthorizationUrl();

    expect(discoveryCalls).toBe(1);
  });

  test('should de-dupe in-flight discovery requests', async () => {
    const cacheDomain = 'cache-inflight.auth0.local';
    const cacheConfig = buildOpenIdConfiguration(cacheDomain);
    let discoveryCalls = 0;
    let releaseDiscovery!: () => void;
    const discoveryBarrier = new Promise<void>((resolve) => {
      releaseDiscovery = resolve;
    });

    server.use(
      http.get(`https://${cacheDomain}/.well-known/openid-configuration`, async () => {
        discoveryCalls += 1;
        await discoveryBarrier;
        return HttpResponse.json(cacheConfig);
      })
    );

    const discoveryCache = { ttl: 30, maxEntries: 5 };
    const authClientA = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });
    const authClientB = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });

    const promiseA = authClientA.buildAuthorizationUrl();
    const promiseB = authClientB.buildAuthorizationUrl();

    releaseDiscovery();
    await Promise.all([promiseA, promiseB]);

    expect(discoveryCalls).toBe(1);
  });

  test('should separate cache entries for mTLS vs non-mTLS', async () => {
    const cacheDomain = 'cache-mtls.auth0.local';
    const cacheConfig = buildOpenIdConfiguration(cacheDomain);
    let discoveryCalls = 0;

    server.use(
      http.get(`https://${cacheDomain}/.well-known/openid-configuration`, () => {
        discoveryCalls += 1;
        return HttpResponse.json(cacheConfig);
      })
    );

    const discoveryCache = { ttl: 30, maxEntries: 5 };
    const authClientDefault = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });
    const authClientMtls = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
      useMtls: true,
      customFetch: fetch,
    });

    await authClientDefault.buildAuthorizationUrl();
    await authClientMtls.buildAuthorizationUrl();

    expect(discoveryCalls).toBe(2);
  });

  test('should share JWKS cache across instances', async () => {
    const cacheDomain = 'cache-jwks.auth0.local';
    const cacheConfig = buildOpenIdConfiguration(cacheDomain);
    let jwksCalls = 0;

    server.use(
      http.get(`https://${cacheDomain}/.well-known/openid-configuration`, () => {
        return HttpResponse.json(cacheConfig);
      }),
      http.get(`https://${cacheDomain}/.well-known/jwks.json`, () => {
        jwksCalls += 1;
        return HttpResponse.json({ keys: jwks });
      })
    );

    const discoveryCache = { ttl: 30, maxEntries: 5 };
    const authClientA = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });
    const authClientB = new AuthClient({
      domain: cacheDomain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      discoveryCache,
    });

    const logoutToken = await generateToken(cacheDomain, '<sub>', '<client_id>', undefined, undefined, undefined, {
      sid: '<sid>',
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
    });

    await authClientA.verifyLogoutToken({ logoutToken });
    await authClientB.verifyLogoutToken({ logoutToken });

    expect(jwksCalls).toBe(1);
  });
});

test('buildAuthorizationUrl - should throw when using PAR without PAR support', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 12, maxEntries: 4 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.pushed_authorization_request_endpoint;

  await expect(serverClient.buildAuthorizationUrl({ pushedAuthorizationRequests: true })).rejects.toThrowError(
    'The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par'
  );
});

test('buildAuthorizationUrl - should build the authorization url', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 16, maxEntries: 5 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const { authorizationUrl } = await serverClient.buildAuthorizationUrl();

  expect(authorizationUrl.host).toBe(domain);
  expect(authorizationUrl.pathname).toBe('/authorize');
  expect(authorizationUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(authorizationUrl.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(authorizationUrl.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(authorizationUrl.searchParams.get('response_type')).toBe('code');
  expect(authorizationUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorizationUrl.searchParams.size).toBe(6);
});

test('buildAuthorizationUrl - should build the authorization url for PAR', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 17, maxEntries: 5 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const { authorizationUrl } = await serverClient.buildAuthorizationUrl({
    pushedAuthorizationRequests: true,
  });

  expect(authorizationUrl.host).toBe(domain);
  expect(authorizationUrl.pathname).toBe('/authorize');
  expect(authorizationUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(authorizationUrl.searchParams.get('request_uri')).toBe('request_uri_123');
  expect(authorizationUrl.searchParams.size).toBe(2);
});

test('buildAuthorizationUrl - should throw when building the authorization url for PAR failed', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      fail: true,
    },
  });

  await expect(
    serverClient.buildAuthorizationUrl({
      pushedAuthorizationRequests: true,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'build_authorization_url_error',
      message: 'There was an error when trying to build the authorization URL.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('buildAuthorizationUrl - should fail when no authorization_endpoint defined', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 18, maxEntries: 5 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  mockOpenIdConfiguration.authorization_endpoint = undefined;

  await expect(
    serverClient.buildAuthorizationUrl({
      pushedAuthorizationRequests: true,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'build_authorization_url_error',
      message: 'There was an error when trying to build the authorization URL.',
      cause: expect.objectContaining({
        message: 'authorization server metadata does not contain a valid "as.authorization_endpoint"',
      }),
    })
  );
});

test('buildLinkUserUrl - should build the link user url', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const { linkUserUrl } = await serverClient.buildLinkUserUrl({
    connection: '<connection>',
    connectionScope: '<scope>',
    idToken: '<id_token>',
  });

  expect(linkUserUrl.host).toBe(domain);
  expect(linkUserUrl.pathname).toBe('/authorize');
  expect(linkUserUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(linkUserUrl.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(linkUserUrl.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(linkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(linkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(linkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(linkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(linkUserUrl.searchParams.get('requested_connection')).toBe('<connection>');
  expect(linkUserUrl.searchParams.get('requested_connection_scope')).toBe('<scope>');
  expect(linkUserUrl.searchParams.size).toBe(9);
});

test('buildLinkUserUrl - should fail when no authorization_endpoint defined', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 19, maxEntries: 5 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  mockOpenIdConfiguration.authorization_endpoint = undefined;

  await expect(
    serverClient.buildLinkUserUrl({
      connection: '<connection>',
      connectionScope: '<scope>',
      idToken: '<id_token>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'build_link_user_url_error',
      message: 'There was an error when trying to build the Link User URL.',
      cause: expect.objectContaining({
        message: 'authorization server metadata does not contain a valid "as.authorization_endpoint"',
      }),
    })
  );
});

test('buildUnlinkUserUrl - should build the unlink user url', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const { unlinkUserUrl } = await serverClient.buildUnlinkUserUrl({
    connection: '<connection>',
    idToken: '<id_token>',
  });

  expect(unlinkUserUrl.host).toBe(domain);
  expect(unlinkUserUrl.pathname).toBe('/authorize');
  expect(unlinkUserUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(unlinkUserUrl.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(unlinkUserUrl.searchParams.get('scope')).toBe('openid unlink_account');
  expect(unlinkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(unlinkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(unlinkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(unlinkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(unlinkUserUrl.searchParams.get('requested_connection')).toBe('<connection>');
  expect(unlinkUserUrl.searchParams.size).toBe(8);
});

test('buildUnlinkUserUrl - should fail when no authorization_endpoint defined', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 20, maxEntries: 5 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  mockOpenIdConfiguration.authorization_endpoint = undefined;

  await expect(
    serverClient.buildUnlinkUserUrl({
      connection: '<connection>',
      idToken: '<id_token>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'build_unlink_user_url_error',
      message: 'There was an error when trying to build the Unlink User URL.',
      cause: expect.objectContaining({
        message: 'authorization server metadata does not contain a valid "as.authorization_endpoint"',
      }),
    })
  );
});

test('backchannelAuthentication - should return the access token from the token endpoint when passing audience and binding_message', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
  });

  const response = await authClient.backchannelAuthentication({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
  });

  expect(response.accessToken).toBe(accessTokenWithAudienceAndBindingMessage);
});

test('backchannelAuthentication - should support RAR', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
  });

  const response = await authClient.backchannelAuthentication({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    authorizationParams: {
      authorization_details: JSON.stringify([
        {
          type: 'accepted',
        },
      ]),
    },
  });

  // When we send authorization_details, we should get it back in the response
  expect(response.authorizationDetails?.[0]!.type).toBe('accepted');
});

test('backchannelAuthentication - should forward the authorizationDetails parameter', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
  });

  const response = await authClient.backchannelAuthentication({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    authorizationDetails: [
      {
        type: 'accepted',
      },
    ],
  });

  // When we send authorization_details, we should get it back in the response
  expect(response.authorizationDetails?.[0]!.type).toBe('accepted');
});

test('backchannelAuthentication - should forward the requestExpiry parameter', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
  });

  // intercept the request to the backchannel authentication endpoint to verify the requested_expiry parameter
  let requestedExpiry: string | null = null;
  server.use(
    http.post(mockOpenIdConfiguration.backchannel_authentication_endpoint, async ({ request }) => {
      const info = await request.formData();
      requestedExpiry = info.get('requested_expiry') as string;
      return HttpResponse.json({
        auth_req_id: 'auth_req_123',
        interval: 0.5,
        expires_in: 60,
      });
    })
  );

  await authClient.backchannelAuthentication({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    requestedExpiry: 180,
  });

  expect(requestedExpiry).toBe('180');
});

test('backchannelAuthentication - should throw an error when bc-authorize failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      should_fail_authorize: true,
    },
  });

  await expect(
    authClient.backchannelAuthentication({
      loginHint: { sub: '<sub>' },
      bindingMessage: '<binding_message>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'backchannel_authentication_error',
      message: 'There was an error when trying to use Client-Initiated Backchannel Authentication.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('backchannelAuthentication - should throw an error when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      should_fail_token_exchange: true,
    },
  });

  await expect(
    authClient.backchannelAuthentication({
      loginHint: { sub: '<sub>' },
      bindingMessage: '<binding_message>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'backchannel_authentication_error',
      message: 'There was an error when trying to use Client-Initiated Backchannel Authentication.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('initiateBackchannelAuthentication — should return the auth_req_id, interval, and expires_in params', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
  });

  const response = await authClient.initiateBackchannelAuthentication({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
  });

  expect(response).toEqual({
    authReqId: 'auth_req_789',
    interval: 0.5,
    expiresIn: 60,
  });
});

test('initiateBackchannelAuthentication — should throw an error if calling the /bc-authorize endpoint fails', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      should_fail_authorize: true,
    },
  });

  await expect(
    authClient.initiateBackchannelAuthentication({
      loginHint: { sub: '<sub>' },
      bindingMessage: '<binding_message>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'backchannel_authentication_error',
      message: 'There was an error when trying to use Client-Initiated Backchannel Authentication.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('backchannelAuthenticationGrant — should exchange the auth_req_id for a token set', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
  });

  const response = await authClient.backchannelAuthenticationGrant({
    authReqId: 'auth_req_789',
  });

  expect(response.accessToken).toBe(accessTokenWithAudienceAndBindingMessage);
});

test('backchannelAuthenticationGrant - should throw an error when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      should_fail_token_exchange: true,
    },
  });

  await expect(
    authClient.backchannelAuthenticationGrant({
      authReqId: 'auth_req_should_fail',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'backchannel_authentication_error',
      message: 'There was an error when trying to use Client-Initiated Backchannel Authentication.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('getTokenByCode - should return the tokens', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenByCode(new URL(`https://${domain}?code=123`), { codeVerifier: 'abc' });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessToken);
});

test('getTokenByCode - should throw when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(
    authClient.getTokenByCode(new URL(`https://${domain}?code=<code_should_fail>`), { codeVerifier: 'abc' })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_by_code_error',
      message: 'There was an error while trying to request a token.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('getTokenByRefreshToken - should return the tokens', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenByRefreshToken({
    refreshToken: 'abc',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessToken);
});

test('getTokenByRefreshToken - should throw when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(
    authClient.getTokenByRefreshToken({
      refreshToken: '<refresh_token_should_fail>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_by_refresh_token_error',
      message: 'The access token has expired and there was an error while trying to refresh it.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('getTokenByRefreshToken - should request token with audience parameter', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenByRefreshToken({
    refreshToken: 'test_refresh_token',
    audience: 'https://api.example.com',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessTokenWithAudience);
});

test('getTokenByRefreshToken - should request token with scope parameter', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenByRefreshToken({
    refreshToken: 'test_refresh_token',
    scope: 'read:data write:data',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessTokenWithScope);
  expect(result.scope).toBe('read:data write:data');
});

test('getTokenByRefreshToken - should request token with both audience and scope parameters', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenByRefreshToken({
    refreshToken: 'test_refresh_token',
    audience: 'https://api.example.com',
    scope: 'openid profile read:data',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessTokenWithAudienceAndScope);
  expect(result.scope).toBe('openid profile read:data');
});

test('getTokenForConnection - should return the tokens when called with a refresh token subject token', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenForConnection({
    connection: '<connection>',
    refreshToken: '<refresh_token>',
    loginHint: '<sub>',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessToken);
});

test('getTokenForConnection - should return the tokens when called with an access token subject token', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenForConnection({
    connection: '<connection>',
    accessToken: '<access_token>',
    loginHint: '<sub>',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessToken);
});

test('getTokenForConnection - should throw when both an access and refresh tokens are specified', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(
    authClient.getTokenForConnection({
      connection: '<connection>',
      refreshToken: '<refresh_token>',
      accessToken: '<access_token>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_for_connection_error',
      message: 'Either a refresh or access token should be specified, but not both.',
    })
  );
});

test('getTokenForConnection - should throw when neither an access nor a refresh token is specified', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(
    authClient.getTokenForConnection({
      connection: '<connection>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_for_connection_error',
      message: 'Either a refresh or access token must be specified.',
    })
  );
});

test('getTokenForConnection - should throw when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(
    authClient.getTokenForConnection({
      connection: 'google-oauth2',
      refreshToken: '<refresh_token_should_fail>',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_for_connection_error',
      message: "Failed to exchange token for connection 'google-oauth2'.",
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('getTokenByClientCredentials - should return the tokens', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenByClientCredentials({ audience: 'abc' });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessToken);
});

test('getTokenByClientCredentials - should throw when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(authClient.getTokenByClientCredentials({ audience: '<audience_should_fail>' })).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_by_client_credentials_error',
      message: 'There was an error while trying to request a token.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('buildLogoutUrl - should build the logout url', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const url = await serverClient.buildLogoutUrl({
    returnTo: '/test_return_to',
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/logout');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('post_logout_redirect_uri')).toBe('/test_return_to');
  expect(url.searchParams.size).toBe(2);
});

test('buildLogoutUrl - should build the logout url when not using OIDC Logout', async () => {
  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.end_session_endpoint;

  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 13, maxEntries: 5 },
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const url = await serverClient.buildLogoutUrl({
    returnTo: '/test_return_to',
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/v2/logout');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('returnTo')).toBe('/test_return_to');
  expect(url.searchParams.size).toBe(2);
});

test('verifyLogoutToken - should verify the logout token', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
    sid: '<sid>',
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {},
    },
  });

  const result = await serverClient.verifyLogoutToken({
    logoutToken,
  });

  expect(result).toBeDefined();
  expect(result.sub).toBe('<sub>');
  expect(result.sid).toBe('<sid>');
});

test('verifyLogoutToken - should verify the logout token when no sid claim', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {},
    },
  });

  const result = await serverClient.verifyLogoutToken({
    logoutToken,
  });

  expect(result).toBeDefined();
  expect(result.sub).toBe('<sub>');
  expect(result.sid).toBeUndefined();
});

test('verifyLogoutToken - should verify the logout token when no sub claim', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(
    domain,
    //eslint-disable-next-line @typescript-eslint/no-explicit-any
    undefined as any,
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      sid: '<sid>',
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
    }
  );

  const result = await serverClient.verifyLogoutToken({
    logoutToken,
  });

  expect(result).toBeDefined();
  expect(result.sid).toBe('<sid>');
  expect(result.sub).toBeUndefined();
});

test('verifyLogoutToken - should fail verify the logout token when no sub and no sid claim', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(
    domain,
    //eslint-disable-next-line @typescript-eslint/no-explicit-any
    undefined as any,
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
    }
  );

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: 'either "sid" or "sub" (or both) claims must be present',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when sid claim is not a string', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(
    domain,
    //eslint-disable-next-line @typescript-eslint/no-explicit-any
    undefined as any,
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      sid: 1,
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
    }
  );

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"sid" claim must be a string',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when sub claim is not a string', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(
    domain,
    //eslint-disable-next-line @typescript-eslint/no-explicit-any
    1 as any,
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
    }
  );

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"sub" claim must be a string',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when nonce in claims', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
    nonce: '<nonce>',
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {},
    },
  });

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"nonce" claim is prohibited',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when no events claim', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>');

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"events" claim is missing',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when events claim is not an object', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
    events: 'http://schemas.openid.net/event/backchannel-logout',
  });

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"events" claim must be an object',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when events claim does not contain expected property', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
    events: {
      foo: {},
    },
  });

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim',
    })
  );
});

test('verifyLogoutToken - should fail verify the logout token when events claim contains expected property but it is not an object', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
    events: {
      'http://schemas.openid.net/event/backchannel-logout': '',
    },
  });

  await expect(
    authClient.verifyLogoutToken({
      logoutToken,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'verify_logout_token_error',
      message: '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object',
    })
  );
});

describe('exchangeToken', () => {
  const baseOptions: ExchangeProfileOptions = {
    subjectTokenType: 'urn:test:mcp-token',
    subjectToken: 'subject-token-123',
    audience: 'https://api.my-app.com',
  };

  test('should return tokens on successful exchange', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    const result = await authClient.exchangeToken(baseOptions);

    expect(result).toBeDefined();
    expect(result.accessToken).toBeTruthy();
    expect(result.scope).toBe('read:default');
    expect(result.claims?.sub).toBe('user_cte');
  });

  test('should propagate issued_token_type from token endpoint', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async () => {
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        });
      })
    );

    const result = await authClient.exchangeToken(baseOptions);

    expect(result.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(result.tokenType?.toLowerCase()).toBe('bearer');
  });

  test('rejects whitespace-only subject_token', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    await expect(
      authClient.exchangeToken({
        subjectTokenType: 'urn:test:mcp-token',
        subjectToken: '   ',
        audience: 'https://api.my-app.com',
      })
    ).rejects.toMatchObject({
      name: 'TokenExchangeError',
      code: 'token_exchange_error',
      message: 'subject_token cannot be blank or whitespace',
    });
  });

  test('rejects leading/trailing whitespace', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    await expect(
      authClient.exchangeToken({
        subjectTokenType: 'urn:test:mcp-token',
        subjectToken: '  abc.def.ghi  ',
        audience: 'https://api.my-app.com',
      })
    ).rejects.toThrowError('subject_token must not include leading or trailing whitespace');
  });

  test("rejects 'Bearer ' prefix (capital B)", async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    await expect(
      authClient.exchangeToken({
        subjectTokenType: 'urn:test:mcp-token',
        subjectToken: 'Bearer abc.def.ghi',
        audience: 'https://api.my-app.com',
      })
    ).rejects.toThrowError("subject_token must not include the 'Bearer ' prefix");
  });

  test("rejects 'bearer ' prefix (lowercase)", async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    await expect(
      authClient.exchangeToken({
        subjectTokenType: 'urn:test:mcp-token',
        subjectToken: 'bearer abc.def.ghi',
        audience: 'https://api.my-app.com',
      })
    ).rejects.toThrowError("subject_token must not include the 'Bearer ' prefix");
  });

  test("rejects 'BEARER ' prefix (uppercase)", async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    await expect(
      authClient.exchangeToken({
        subjectTokenType: 'urn:test:mcp-token',
        subjectToken: 'BEARER abc.def.ghi',
        audience: 'https://api.my-app.com',
      })
    ).rejects.toThrowError("subject_token must not include the 'Bearer ' prefix");
  });

  test('should include optional scope and custom parameters', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    const result = await authClient.exchangeToken({
      ...baseOptions,
      scope: 'openid profile read:data',
      extra: {
        custom_param: 'custom_value',
      },
    });

    expect(result.scope).toBe('openid profile read:data');
    expect(result.claims?.sub).toBe('user_cte_custom');
  });

  test('should throw TokenExchangeError on failure', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    await expect(
      authClient.exchangeToken({
        ...baseOptions,
        audience: '<audience_should_fail_cte>',
      })
    ).rejects.toThrowError(
      expect.objectContaining({
        name: 'TokenExchangeError',
        code: 'token_exchange_error',
        cause: expect.objectContaining({
          error: 'invalid_request',
          error_description: 'CTE audience not allowed',
        }),
      })
    );
  });

  test('should accept array parameters with exactly 20 items', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    const maxSizeArray = Array.from({ length: 20 }, (_, i) => `value${i}`);

    const result = await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        device_ids: maxSizeArray,
      },
    });

    expect(result).toBeDefined();
    expect(result.accessToken).toBeTruthy();
  });

  test('should throw TokenExchangeError when array parameter exceeds 20 items', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });
    const largeArray = Array.from({ length: 21 }, (_, i) => `value${i}`);

    await expect(
      authClient.exchangeToken({
        ...baseOptions,
        extra: {
          large_param: largeArray,
        },
      })
    ).rejects.toThrowError(
      expect.objectContaining({
        name: 'TokenExchangeError',
        code: 'token_exchange_error',
        message: "Parameter 'large_param' exceeds maximum array size of 20",
      })
    );
  });

  test('should throw TokenExchangeError when Token Vault exchange includes audience parameter', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    await expect(
      // @ts-expect-error Testing invalid parameter combination
      authClient.exchangeToken({
        connection: 'google-oauth2',
        subjectToken: 'subject-token-123',
        audience: 'https://api.example.com',
      })
    ).rejects.toThrowError(
      expect.objectContaining({
        name: 'TokenExchangeError',
        code: 'token_exchange_error',
        message: 'audience and resource parameters are not supported for Token Vault exchanges',
      })
    );
  });

  test('should throw TokenExchangeError when Token Vault exchange includes resource parameter', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    await expect(
      // @ts-expect-error Testing invalid parameter combination
      authClient.exchangeToken({
        connection: 'google-oauth2',
        subjectToken: 'subject-token-123',
        resource: 'https://resource.example.com',
      })
    ).rejects.toThrowError(
      expect.objectContaining({
        name: 'TokenExchangeError',
        code: 'token_exchange_error',
        message: 'audience and resource parameters are not supported for Token Vault exchanges',
      })
    );
  });

  test('should reject reserved parameters in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'scope' from extra is NOT sent
    let capturedScope: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedScope = info.get('scope') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: capturedScope || 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      scope: 'explicit:scope',
      extra: {
        scope: 'should_be_ignored', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that explicit scope wins, not the one from extra
    expect(capturedScope).toBe('explicit:scope');
  });

  test('should reject reserved audience parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'audience' from extra is NOT sent
    let capturedAudience: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedAudience = info.get('audience') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      audience: 'https://explicit-audience.com',
      extra: {
        audience: 'https://should-be-ignored.com', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that explicit audience wins, not the one from extra
    expect(capturedAudience).toBe('https://explicit-audience.com');
  });

  test('should reject reserved grant_type parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'grant_type' from extra is NOT sent
    let capturedGrantType: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedGrantType = info.get('grant_type') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        grant_type: 'should_be_ignored', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that the correct grant type is sent (RFC 8693), not the one from extra
    expect(capturedGrantType).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
  });

  test('should reject reserved client_id parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'client_id' from extra is NOT sent
    let capturedClientId: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedClientId = info.get('client_id') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        client_id: 'malicious_client_id', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that the configured client_id is sent, not the one from extra
    expect(capturedClientId).toBe('<client_id>');
  });

  test('should reject reserved client_secret parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'client_secret' from extra is NOT sent
    let capturedClientSecret: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedClientSecret = info.get('client_secret') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        client_secret: 'malicious_secret', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that the configured client_secret is sent, not the one from extra
    expect(capturedClientSecret).toBe('<client_secret>');
  });

  test('should reject reserved client_assertion parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'client_assertion' from extra is NOT sent
    let hasClientAssertion = false;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        hasClientAssertion = info.has('client_assertion');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        client_assertion: 'malicious_jwt', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that no client_assertion was sent (since we're using client_secret)
    expect(hasClientAssertion).toBe(false);
  });

  test('should reject reserved client_assertion_type parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'client_assertion_type' from extra is NOT sent
    let hasClientAssertionType = false;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        hasClientAssertionType = info.has('client_assertion_type');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        client_assertion_type: 'malicious_type', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that no client_assertion_type was sent (since we're using client_secret)
    expect(hasClientAssertionType).toBe(false);
  });

  test('should reject reserved aud parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'aud' from extra is NOT sent
    let capturedAud: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedAud = info.get('aud') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      audience: 'https://explicit-audience.com',
      extra: {
        aud: 'https://should-be-ignored.com', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that explicit audience is sent (not 'aud' from extra)
    expect(capturedAud).toBeNull();
  });

  test('should reject reserved resource parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'resource' from extra is NOT sent
    let hasResource = false;
    let capturedGrantType: string | null = null;
    let capturedCustomParam: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        hasResource = info.has('resource');
        capturedGrantType = info.get('grant_type') as string | null;
        capturedCustomParam = info.get('custom_param') as string | null;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        resource: 'https://should-be-ignored.com', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that resource from extra is NOT sent
    expect(hasResource).toBe(false);
    // Verify we're on the CTE path
    expect(capturedGrantType).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    // Verify that allowed custom params are still forwarded (denylist is selective)
    expect(capturedCustomParam).toBe('allowed');
  });

  test('should reject reserved resource_indicator parameter in extra field', async () => {
    const authClient = new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

    // Intercept the request to verify that 'resource_indicator' from extra is NOT sent
    let hasResourceIndicator = false;
    let capturedGrantType: string | null = null;
    let capturedCustomParam: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        hasResourceIndicator = info.has('resource_indicator');
        capturedGrantType = info.get('grant_type') as string | null;
        capturedCustomParam = info.get('custom_param') as string | null;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      ...baseOptions,
      extra: {
        resource_indicator: 'https://should-be-ignored.com', // This should be ignored due to denylist
        custom_param: 'allowed',
      },
    });

    // Verify that resource_indicator from extra is NOT sent
    expect(hasResourceIndicator).toBe(false);
    // Verify we're on the CTE path
    expect(capturedGrantType).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    // Verify that allowed custom params are still forwarded (denylist is selective)
    expect(capturedCustomParam).toBe('allowed');
  });
});

describe('Client Authentication for Token Exchange', () => {
  test('should send client_secret for Custom Token Exchange with client_secret_post', async () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    let capturedClientId: string | null = null;
    let capturedClientSecret: string | null = null;
    let capturedGrantType: string | null = null;

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedClientId = info.get('client_id') as string;
        capturedClientSecret = info.get('client_secret') as string;
        capturedGrantType = info.get('grant_type') as string;

        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
        });
      })
    );

    await authClient.exchangeToken({
      subjectTokenType: 'urn:test:mcp-token',
      subjectToken: 'test-token',
      audience: 'https://api.example.com',
    });

    expect(capturedGrantType).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(capturedClientId).toBe('<client_id>');
    expect(capturedClientSecret).toBe('<client_secret>');
  });

  test('should send client_assertion for Custom Token Exchange with private_key_jwt', async () => {
    const clientAssertionSigningKeyRaw = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbTKOQLtaZ6U1k
3fcYCMVoy8poieNPPcbj15TCLOm4Bbox73/UUxIArqczVcjtUGnL+jn5982V5EiB
y8W51m5K9mIBgEFLYdLkXk+OW5UTE/AdMPtfsIjConGrrs3mxN4WSH9kvh9Yr41r
hWUUSwqFyMOssbGE8K46Cv0WYvS7RXH9MzcyTcMSFp/60yUXH4rdHYZElF7XCdiE
63WxebxI1Qza4xkjTlbp5EWfWBQB1Ms10JO8NjrtkCXrDI57Bij5YanPAVhctcO9
z5/y9i5xEzcer8ZLO8VDiXSdEsuP/fe+UKDyYHUITD8u51p3O2JwCKvdTHduemej
3Kd1RlHrAgMBAAECggEATWdzpASkQpcSdjPSb21JIIAt5VAmJ2YKuYjyPMdVh1qe
Kdn7KJpZlFwRMBFrZjgn35Nmu1A4BFwbK5UdKUcCjvsABL+cTFsu8ORI+Fpi9+Tl
r6gGUfQhkXF85bhBfN6n9P2J2akxrz/njrf6wXrrL+V5C498tQuus1YFls0+zIpD
N+GngNOPHlGeY3gW4K/HjGuHwuJOvWNmE4KNQhBijdd50Am824Y4NV/SmsIo7z+s
8CLjp/qtihwnE4rkUHnR6M4u5lpzXOnodzkDTG8euOJds0T8DwLNTx1b+ETim35i
D/hOCVwl8QFoj2aatjuJ5LXZtZUEpGpBF2TQecB+gQKBgQDvaZ1jG/FNPnKdayYv
z5yTOhKM6JTB+WjB0GSx8rebtbFppiHGgVhOd1bLIzli9uMOPdCNuXh7CKzIgSA6
Q76Wxfuaw8F6CBIdlG9bZNL6x8wp6zF8tGz/BgW7fFKBwFYSWzTcStGr2QGtwr6F
9p1gYPSGfdERGOQc7RmhoNNHcQKBgQDqfkhpPfJlP/SdFnF7DDUvuMnaswzUsM6D
ZPhvfzdMBV8jGc0WjCW2Vd3pvsdPgWXZqAKjN7+A5HiT/8qv5ruoqOJSR9ZFZI/B
8v+8gS9Af7K56mCuCFKZmOXUmaL+3J2FKtzAyOlSLjEYyLuCgmhEA9Zo+duGR5xX
AIjx7N/ZGwKBgCZAYqQeJ8ymqJtcLkq/Sg3/3kzjMDlZxxIIYL5JwGpBemod4BGe
QuSujpCAPUABoD97QuIR+xz1Qt36O5LzlfTzBwMwOa5ssbBGMhCRKGBnIcikylBZ
Z3zLkojlES2n9FiUd/qmfZ+OWYVQsy4mO/jVJNyEJ64qou+4NjsrvfYRAoGAORki
3K1+1nSqRY3vd/zS/pnKXPx4RVoADzKI4+1gM5yjO9LOg40AqdNiw8X2lj9143fr
nH64nNQFIFSKsCZIz5q/8TUY0bDY6GsZJnd2YAg4JtkRTY8tPcVjQU9fxxtFJ+X1
9uN1HNOulNBcCD1k0hr1HH6qm5nYUb8JmY8KOr0CgYB85pvPhBqqfcWi6qaVQtK1
ukIdiJtMNPwePfsT/2KqrbnftQnAKNnhsgcYGo8NAvntX4FokOAEdunyYmm85mLp
BGKYgVXJqnm6+TJyCRac1ro3noG898P/LZ8MOBoaYQtWeWRpDc46jPrA0FqUJy+i
ca/T0LLtgmbMmxSv/MmzIg==
-----END PRIVATE KEY-----`;

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientAssertionSigningKey: clientAssertionSigningKeyRaw,
    });

    let capturedClientAssertion: string | null = null;
    let capturedClientAssertionType: string | null = null;
    let capturedGrantType: string | null = null;

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedClientAssertion = info.get('client_assertion') as string;
        capturedClientAssertionType = info.get('client_assertion_type') as string;
        capturedGrantType = info.get('grant_type') as string;

        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
        });
      })
    );

    await authClient.exchangeToken({
      subjectTokenType: 'urn:test:mcp-token',
      subjectToken: 'test-token',
      audience: 'https://api.example.com',
    });

    expect(capturedGrantType).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(capturedClientAssertionType).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    expect(capturedClientAssertion).toBeTruthy();
    expect((capturedClientAssertion as unknown as string).split('.')).toHaveLength(3); // Verify JWT structure
  });

  test('should send client_secret for Token Vault exchange', async () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    let capturedClientId: string | null = null;
    let capturedClientSecret: string | null = null;
    let capturedGrantType: string | null = null;

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedClientId = info.get('client_id') as string;
        capturedClientSecret = info.get('client_secret') as string;
        capturedGrantType = info.get('grant_type') as string;

        return HttpResponse.json({
          access_token: accessToken,
          expires_in: 3600,
          token_type: 'Bearer',
        });
      })
    );

    await authClient.getTokenForConnection({
      connection: 'google-oauth2',
      accessToken: 'auth0-token',
    });

    expect(capturedGrantType).toBe(
      'urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token'
    );
    expect(capturedClientId).toBe('<client_id>');
    expect(capturedClientSecret).toBe('<client_secret>');
  });

  test('should fail Custom Token Exchange when no client credentials provided', async () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      // No clientSecret or clientAssertionSigningKey
    });

    await expect(
      authClient.exchangeToken({
        subjectTokenType: 'urn:test:mcp-token',
        subjectToken: 'test-token',
        audience: 'https://api.example.com',
      })
    ).rejects.toThrowError(
      expect.objectContaining({
        name: 'MissingClientAuthError',
        code: 'missing_client_auth_error',
      })
    );
  });
});

describe('exchangeToken with Token Exchange Profile', () => {
  test('should include organization parameter when provided', async () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    let capturedOrganization: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedOrganization = info.get('organization') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        });
      })
    );

    await authClient.exchangeToken({
      subjectToken: 'custom_token_value',
      subjectTokenType: 'urn:acme:custom-token',
      audience: 'https://api.example.com',
      organization: 'org_abc123',
      scope: 'openid profile',
    });

    expect(capturedOrganization).toBe('org_abc123');
  });

  test('should work without organization parameter (backward compatible)', async () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    let capturedOrganization: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const info = await request.formData();
        capturedOrganization = info.get('organization') as string;
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'read:default',
        });
      })
    );

    await authClient.exchangeToken({
      subjectToken: 'custom_token_value',
      subjectTokenType: 'urn:acme:custom-token',
      audience: 'https://api.example.com',
      scope: 'openid profile',
    });

    expect(capturedOrganization).toBeNull();
  });
});

describe('Telemetry', () => {
  test('should include Auth0-Client header in discovery requests', async () => {
    let capturedHeader: string | null = null;
    server.use(
      http.get(`https://${domain}/.well-known/openid-configuration`, ({ request }) => {
        capturedHeader = request.headers.get('Auth0-Client');
        return HttpResponse.json(mockOpenIdConfiguration);
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    await authClient.buildAuthorizationUrl();

    expect(capturedHeader).toBeDefined();
    const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
    expect(decoded.name).toBe('@auth0/auth0-auth-js');
    expect(decoded.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  test('should include Auth0-Client header in token requests', async () => {
    let capturedHeader: string | null = null;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        capturedHeader = request.headers.get('Auth0-Client');
        await request.formData();
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_cte', '<client_id>'),
          expires_in: 3600,
          token_type: 'Bearer',
        });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    await authClient.getTokenByClientCredentials({ audience: '<audience>' });

    expect(capturedHeader).toBeDefined();
    const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
    expect(decoded.name).toBe('@auth0/auth0-auth-js');
    expect(decoded.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  test('should allow custom telemetry name and version', async () => {
    let capturedHeader: string | null = null;
    server.use(
      http.get(`https://${domain}/.well-known/openid-configuration`, ({ request }) => {
        capturedHeader = request.headers.get('Auth0-Client');
        return HttpResponse.json(mockOpenIdConfiguration);
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      telemetry: {
        name: 'my-custom-app',
        version: '2.0.0',
      },
    });

    await authClient.buildAuthorizationUrl();

    expect(capturedHeader).toBeDefined();
    const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
    expect(decoded.name).toBe('my-custom-app');
    expect(decoded.version).toBe('2.0.0');
  });

  test('should not include Auth0-Client header when telemetry is disabled', async () => {
    let capturedHeader: string | null = null;
    server.use(
      http.get(`https://${domain}/.well-known/openid-configuration`, ({ request }) => {
        capturedHeader = request.headers.get('Auth0-Client');
        return HttpResponse.json(mockOpenIdConfiguration);
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      telemetry: { enabled: false },
    });

    await authClient.buildAuthorizationUrl();

    expect(capturedHeader).toBeNull();
  });

  test('should include Auth0-Client header in JWKS requests', async () => {
    let capturedHeader: string | null = null;
    server.use(
      http.get(`https://${domain}/.well-known/jwks.json`, ({ request }) => {
        capturedHeader = request.headers.get('Auth0-Client');
        return HttpResponse.json({ keys: jwks });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    const logoutToken = await generateToken(domain, '<sub>', '<client_id>', undefined, undefined, undefined, {
      sid: '<sid>',
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
    });

    await authClient.verifyLogoutToken({ logoutToken });

    expect(capturedHeader).toBeDefined();
    const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
    expect(decoded.name).toBe('@auth0/auth0-auth-js');
    expect(decoded.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});
