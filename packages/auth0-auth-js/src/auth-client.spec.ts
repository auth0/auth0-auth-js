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
import { AuthClient } from './auth-client.js';

import { generateToken } from './test-utils/tokens.js';

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
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
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
      info.get('auth_req_id') === 'auth_req_should_fail';

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
      message:
        'There was an error when trying to build the authorization URL. Check the server logs for more information.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
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
  expect(linkUserUrl.searchParams.get('scope')).toBe('openid link_account');
  expect(linkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(linkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(linkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(linkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(linkUserUrl.searchParams.get('requested_connection')).toBe('<connection>');
  expect(linkUserUrl.searchParams.get('requested_connection_scope')).toBe('<scope>');
  expect(linkUserUrl.searchParams.get('prompt')).toBe('login');
  expect(linkUserUrl.searchParams.size).toBe(10);
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
      code: 'login_backchannel_error',
      message:
        'There was an error when trying to use Client-Initiated Backchannel Authentication. Check the server logs for more information.',
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
      code: 'login_backchannel_error',
      message:
        'There was an error when trying to use Client-Initiated Backchannel Authentication. Check the server logs for more information.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});
