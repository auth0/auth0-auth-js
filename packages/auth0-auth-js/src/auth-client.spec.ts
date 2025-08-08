import {
  expect,
  test,
  afterAll,
  beforeAll,
  beforeEach,
  vi,
  afterEach,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AuthClient, SUBJECT_TYPE_REFRESH_TOKEN } from './auth-client.js';

import { generateToken, jwks } from './test-utils/tokens.js';
import { pemToArrayBuffer } from './test-utils/pem.js';

const domain = 'auth0.local';
let accessToken: string;
let accessTokenWithAudienceAndBindingMessage: string;
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
  http.post(
    mockOpenIdConfiguration.backchannel_authentication_endpoint,
    async ({ request }) => {
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
        ? HttpResponse.json(
            { error: '<error_code>', error_description: '<error_description>' },
            { status: 400 }
          )
        : HttpResponse.json({
            auth_req_id: auth_req_id,
            interval: 0.5,
            expires_in: 60,
          });
    }
  ),
  http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
    const info = await request.formData();
    let accessTokenToUse = accessToken;
    if (info.get('auth_req_id') === 'auth_req_789') {
      accessTokenToUse = accessTokenWithAudienceAndBindingMessage;
    }
    const shouldFailTokenExchange =
      info.get('auth_req_id') === 'auth_req_should_fail' ||
      info.get('code') === '<code_should_fail>' ||
      info.get('subject_token') === '<refresh_token_should_fail>' ||
      info.get('refresh_token') === '<refresh_token_should_fail>';

    return shouldFailTokenExchange
      ? HttpResponse.json(
          { error: '<error_code>', error_description: '<error_description>' },
          { status: 400 }
        )
      : HttpResponse.json({
          access_token: accessTokenToUse,
          id_token: await generateToken(domain, 'user_123', '<client_id>'),
          expires_in: 60,
          token_type: 'Bearer',
          scope: '<scope>',
          ...(info.get('auth_req_id') === 'auth_req_with_authorization_details'
            ? { authorization_details: [{ type: 'accepted' }] }
            : {}),
        });
  }),

  http.post(
    mockOpenIdConfiguration.pushed_authorization_request_endpoint,
    async ({ request }) => {
      const info = await request.formData();
      return info.get('fail')
        ? HttpResponse.json(
            { error: '<error_code>', error_description: '<error_description>' },
            { status: 400 }
          )
        : HttpResponse.json(
            {
              request_uri: 'request_uri_123',
              expires_in: 60,
            },
            { status: 201 }
          );
    }
  ),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
  accessTokenWithAudienceAndBindingMessage = await generateToken(
    domain,
    'user_789'
  );
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

  const tokenResponse = await authClient.getTokenByCode(
    new URL(`https://${domain}?code=123`),
    {
      codeVerifier: '123',
    }
  );

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
    customFetch: mockFetch,
  });

  await authClient.buildAuthorizationUrl();

  expect(mockFetch).toHaveBeenCalledTimes(1);

  mockFetch.mockClear();

  const tokenResponse = await authClient.getTokenByCode(
    new URL(`https://${domain}?code=123`),
    {
      codeVerifier: '123',
    }
  );

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
    customFetch: mockFetch,
  });

  await authClient.buildAuthorizationUrl();

  expect(mockFetch).toHaveBeenCalledTimes(1);

  mockFetch.mockClear();

  const tokenResponse = await authClient.getTokenByCode(
    new URL(`https://${domain}?code=123`),
    {
      codeVerifier: '123',
    }
  );

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

  await expect(authClient.buildAuthorizationUrl()).rejects.toThrowError('The client secret or client assertion signing key must be provided.');
});

test('buildAuthorizationUrl - should throw when using PAR without PAR support', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.pushed_authorization_request_endpoint;

  await expect(
    serverClient.buildAuthorizationUrl({ pushedAuthorizationRequests: true })
  ).rejects.toThrowError(
    'The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par'
  );
});

test('buildAuthorizationUrl - should build the authorization url', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const { authorizationUrl } = await serverClient.buildAuthorizationUrl();

  expect(authorizationUrl.host).toBe(domain);
  expect(authorizationUrl.pathname).toBe('/authorize');
  expect(authorizationUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(authorizationUrl.searchParams.get('redirect_uri')).toBe(
    '/test_redirect_uri'
  );
  expect(authorizationUrl.searchParams.get('scope')).toBe(
    'openid profile email offline_access'
  );
  expect(authorizationUrl.searchParams.get('response_type')).toBe('code');
  expect(authorizationUrl.searchParams.get('code_challenge')).toBeTypeOf(
    'string'
  );
  expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe(
    'S256'
  );
  expect(authorizationUrl.searchParams.size).toBe(6);
});

test('buildAuthorizationUrl - should build the authorization url for PAR', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
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
  expect(authorizationUrl.searchParams.get('request_uri')).toBe(
    'request_uri_123'
  );
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
        message:
          'authorization server metadata does not contain a valid "as.authorization_endpoint"',
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
  expect(linkUserUrl.searchParams.get('redirect_uri')).toBe(
    '/test_redirect_uri'
  );
  expect(linkUserUrl.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(linkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(linkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(linkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(linkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(linkUserUrl.searchParams.get('requested_connection')).toBe(
    '<connection>'
  );
  expect(linkUserUrl.searchParams.get('requested_connection_scope')).toBe(
    '<scope>'
  );
  expect(linkUserUrl.searchParams.size).toBe(9);
});

test('buildLinkUserUrl - should fail when no authorization_endpoint defined', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
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
        message:
          'authorization server metadata does not contain a valid "as.authorization_endpoint"',
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
  expect(unlinkUserUrl.searchParams.get('redirect_uri')).toBe(
    '/test_redirect_uri'
  );
  expect(unlinkUserUrl.searchParams.get('scope')).toBe('openid unlink_account');
  expect(unlinkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(unlinkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(unlinkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(unlinkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(unlinkUserUrl.searchParams.get('requested_connection')).toBe(
    '<connection>'
  );
  expect(unlinkUserUrl.searchParams.size).toBe(8);
});

test('buildUnlinkUserUrl - should fail when no authorization_endpoint defined', async () => {
  const serverClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
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
        message:
          'authorization server metadata does not contain a valid "as.authorization_endpoint"',
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
      message:
        'There was an error when trying to use Client-Initiated Backchannel Authentication.',
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
      message:
        'There was an error when trying to use Client-Initiated Backchannel Authentication.',
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

  const result = await authClient.getTokenByCode(
    new URL(`https://${domain}?code=123`),
    { codeVerifier: 'abc' }
  );

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
    authClient.getTokenByCode(
      new URL(`https://${domain}?code=<code_should_fail>`),
      { codeVerifier: 'abc' }
    )
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
      message:
        'The access token has expired and there was an error while trying to refresh it.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('getTokenForConnection - should return the tokens', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  const result = await authClient.getTokenForConnection({
    connection: '<connection>',
    subjectToken: '<refresh_token>',
    subjectTokenType: SUBJECT_TYPE_REFRESH_TOKEN,
    loginHint: '<sub>',
  });

  expect(result).toBeDefined();
  expect(result.accessToken).toBe(accessToken);
});

test('getTokenForConnection - should throw when token exchange failed', async () => {
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
  });

  await expect(
    authClient.getTokenForConnection({
      connection: '<connection>',
      subjectToken: '<refresh_token_should_fail>',
      subjectTokenType: SUBJECT_TYPE_REFRESH_TOKEN,
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'token_for_connection_error',
      message:
        'There was an error while trying to retrieve an access token for a connection.',
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
  expect(url.searchParams.get('post_logout_redirect_uri')).toBe(
    '/test_return_to'
  );
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

  const logoutToken = await generateToken(
    domain,
    '<sub>',
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

  const logoutToken = await generateToken(
    domain,
    '<sub>',
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

  const logoutToken = await generateToken(
    domain,
    '<sub>',
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      nonce: '<nonce>',
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

  const logoutToken = await generateToken(
    domain,
    '<sub>',
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      events: 'http://schemas.openid.net/event/backchannel-logout',
    }
  );

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

  const logoutToken = await generateToken(
    domain,
    '<sub>',
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      events: {
        foo: {},
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
      message:
        '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim',
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

  const logoutToken = await generateToken(
    domain,
    '<sub>',
    '<client_id>',
    undefined,
    undefined,
    undefined,
    {
      events: {
        'http://schemas.openid.net/event/backchannel-logout': '',
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
      message:
        '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object',
    })
  );
});
