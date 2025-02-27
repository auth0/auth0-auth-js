import { expect, test, afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { Auth0Client } from './auth0-client.js';

import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';
import { StateData } from './types.js';

const domain = 'auth0.local';
let accessToken: string;
let accessTokenWithLoginHint: string;
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
  http.post(mockOpenIdConfiguration.backchannel_authentication_endpoint, async ({ request }) => {
    const info = await request.formData();

    let auth_req_id = 'auth_req_123';

    if (info.get('audience') && info.get('binding_message')) {
      auth_req_id = 'auth_req_789';
    }

    if (info.get('should_fail_token_exchange')) {
      auth_req_id = 'auth_req_should_fail';
    }

    const shouldFailBCAuthorize = !!info.get('should_fail_authorize');

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

    if (info.get('auth_req_id') === 'auth_req_789') {
      accessTokenToUse = accessTokenWithAudienceAndBindingMessage;
    } else if (info.get('login_hint')) {
      accessTokenToUse = accessTokenWithLoginHint;
    }

    const shouldFailTokenExchange =
      info.get('auth_req_id') === 'auth_req_should_fail' ||
      info.get('code') === '<code_should_fail>' ||
      info.get('subject_token') === '<refresh_token_should_fail>' ||
      info.get('refresh_token') === '<refresh_token_should_fail>';

    return shouldFailTokenExchange
      ? HttpResponse.json({ error: '<error_code>', error_description: '<error_description>' }, { status: 400 })
      : HttpResponse.json({
          access_token: accessTokenToUse,
          id_token: await generateToken(domain, 'user_123', '<client_id>'),
          expires_in: 60,
          token_type: 'Bearer',
          scope: '<scope>',
        });
  }),
  http.post(mockOpenIdConfiguration.pushed_authorization_request_endpoint, () => {
    return HttpResponse.json(
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
  accessTokenWithLoginHint = await generateToken(domain, 'user_456');
  accessTokenWithAudienceAndBindingMessage = await generateToken(domain, 'user_789');
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

test('should create an instance', () => {
  const auth0Client = new Auth0Client({
    domain: '',
    clientId: '',
    clientSecret: '',
    secret: '<secret>',
  });

  expect(auth0Client).toBeDefined();
});

test('init - should call discovery', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();

  // If discovery wouldn't work, it would timeout.
  // Additionally, discovery is used implicitly in tests below.
  expect(true).toBe(true);
});

test('startInteractiveLogin - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  await expect(auth0Client.startInteractiveLogin()).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('startInteractiveLogin - should throw when redirect_uri not provided', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();

  await expect(auth0Client.startInteractiveLogin()).rejects.toThrowError(
    "The argument 'authorizationParams.redirect_uri' is required but was not provided."
  );
});

test('startInteractiveLogin - should build the authorization url', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  await auth0Client.init();
  const url = await auth0Client.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(7);
});

test('startInteractiveLogin - should build the authorization url for PAR', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  await auth0Client.init();
  const url = await auth0Client.startInteractiveLogin({ pushedAuthorizationRequests: true });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('request_uri')).toBe('request_uri_123');
  expect(url.searchParams.size).toBe(2);
});

test('startInteractiveLogin - should throw when using PAR without PAR support', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.pushed_authorization_request_endpoint;

  await auth0Client.init();

  await expect(auth0Client.startInteractiveLogin({ pushedAuthorizationRequests: true })).rejects.toThrowError(
    'The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par'
  );
});

test('startInteractiveLogin - should build the authorization url with audience when provided', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '/test_redirect_uri',
    },
  });

  await auth0Client.init();
  const url = await auth0Client.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('audience')).toBe('<audience>');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(8);
});

test('startInteractiveLogin - should build the authorization url with scope when provided', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
    },
  });

  await auth0Client.init();
  const url = await auth0Client.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('scope')).toBe('<scope>');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(7);
});

test('startInteractiveLogin - should build the authorization url with custom parameter when provided', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
  });

  await auth0Client.init();
  const url = await auth0Client.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('foo')).toBe('<bar>');
  expect(url.searchParams.get('scope')).toBe('<scope>');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(8);
});

test('completeInteractiveLogin - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await expect(auth0Client.completeInteractiveLogin(new URL(`https://${domain}`))).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('completeInteractiveLogin - should throw when no state query param', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();

  await expect(auth0Client.completeInteractiveLogin(new URL(`https://${domain}?code=123`))).rejects.toThrowError(
    'The state parameter is missing.'
  );
});

test('completeInteractiveLogin - should throw when no transaction', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();

  await expect(
    auth0Client.completeInteractiveLogin(new URL(`https://${domain}?code=123&state=abc`))
  ).rejects.toThrowError('The state parameter is invalid.');
});

test('completeInteractiveLogin - should throw when state not found in transaction', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({});

  await expect(
    auth0Client.completeInteractiveLogin(new URL(`https://${domain}?code=123&state=abc`))
  ).rejects.toThrowError('The state parameter is invalid.');
});

test('completeInteractiveLogin - should throw when state mismatch', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await expect(
    auth0Client.completeInteractiveLogin(new URL(`https://${domain}?code=123&state=abc`))
  ).rejects.toThrowError('The state parameter is invalid.');
});

test('completeInteractiveLogin - should throw an error when token exchange failed', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn().mockResolvedValue({ state: 'abc' }),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  await expect(
    auth0Client.completeInteractiveLogin(new URL(`https://${domain}?code=<code_should_fail>&state=abc`))
  ).rejects.toThrowError(
    expect.objectContaining({
      code: 'failed_to_request_token',
      message: 'There was an error while trying to request a token. Check the server logs for more information.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('completeInteractiveLogin - should return the appState', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz', appState: { foo: '<bar>'} });

  const { appState } = await auth0Client.completeInteractiveLogin<{foo: string}>(new URL(`https://${domain}?code=123&state=xyz`));

  expect(appState.foo).toBe('<bar>');
});

test('completeInteractiveLogin - should delete stored transaction', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await auth0Client.completeInteractiveLogin(new URL(`https://${domain}?code=123&state=xyz`));

  expect(mockTransactionStore.delete).toBeCalled();
});

test('loginBackchannel - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  await expect(auth0Client.loginBackchannel({ login_hint: { sub: '<sub>' } })).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('loginBackchannel - should return the access token from the token endpoint', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  const token = await auth0Client.loginBackchannel({ login_hint: { sub: '<sub>' } });

  expect(token).toBe(accessToken);
});

test('loginBackchannel - should return the access token from the token endpoint when passing audience and binding_message', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      audience: '<audience>',
    },
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  const token = await auth0Client.loginBackchannel({
    binding_message: '<binding_message>',
    login_hint: { sub: '<sub>' },
  });

  expect(token).toBe(accessTokenWithAudienceAndBindingMessage);
});

test('loginBackchannel - should throw an error when bc-authorize failed', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      should_fail_authorize: true,
    },
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  await expect(
    auth0Client.loginBackchannel({ login_hint: { sub: '<sub>' } })
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

test('loginBackchannel - should throw an error when token exchange failed', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      should_fail_token_exchange: true,
    },
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  await expect(auth0Client.loginBackchannel({ login_hint: { sub: '<sub>' } })).rejects.toThrowError(
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

test('getUser - should return from the cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        access_token: '<access_token>',
        expires_at: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const user = await auth0Client.getUser();

  expect(user).toStrictEqual(stateData.user);
});

test('getUser - should return undefined when nothing in the cache', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await auth0Client.init();

  const user = await auth0Client.getUser();

  expect(user).toBeUndefined();
});

test('getAccessToken - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await expect(auth0Client.getAccessToken()).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('getAccessToken - should throw when nothing in cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  mockStateStore.get.mockResolvedValue(null);

  await expect(auth0Client.getAccessToken()).rejects.toThrowError(
    'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
  );
});

test('getAccessToken - should throw when no refresh token but access token expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '',
    tokenSets: [
      {
        audience: '<audience>',
        access_token: '<access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(auth0Client.getAccessToken()).rejects.toThrowError(
    'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
  );
});

test('getAccessToken - should return from the cache when not expired and no refresh token', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: undefined,
    tokenSets: [
      {
        audience: 'default',
        access_token: '<access_token>',
        expires_at: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessToken();

  expect(accessToken).toBe('<access_token>');
});

test('getAccessToken - should return from the cache when not expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        audience: 'default',
        access_token: '<access_token>',
        expires_at: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessToken();

  expect(accessToken).toBe('<access_token>');
});

test('getAccessToken - should return from the cache when not expired and using scopes', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '',
      scope: '<scope>',
    },
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        audience: 'default',
        access_token: '<access_token>',
        expires_at: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessToken();

  expect(accessToken).toBe('<access_token>');
});

test('getAccessToken - should return from auth0 when access_token expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '',
    },
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        access_token: '<access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
      {
        audience: '<another_audience>',
        access_token: '<another_access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<another_scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const token = await auth0Client.getAccessToken();

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessToken).toBe(token);
  expect(state.tokenSets.length).toBe(2);
});

test('getAccessToken - should return from auth0 and append to the state when audience differ', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '',
    },
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience_2>',
        access_token: '<access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessToken();

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessToken).toBe(accessToken);
  expect(state.tokenSets.length).toBe(2);
});

test('getAccessToken - should return from auth0 and append to the state when scope differ', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '',
      scope: '<scope>',
    },
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        access_token: '<access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<scope2>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessToken();

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessToken).toBe(accessToken);
  expect(state.tokenSets.length).toBe(2);
});

test('getAccessToken - should throw an error when refresh_token grant failed', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token_should_fail>',
    tokenSets: [
      {
        audience: 'default',
        access_token: '<access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  await expect(auth0Client.getAccessToken()).rejects.toThrowError(
    expect.objectContaining({
      code: 'failed_to_refresh_token',
      message:
        'The access token has expired and there was an error while trying to refresh it. Check the server logs for more information.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('getAccessTokenForConnection - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await expect(auth0Client.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('getAccessTokenForConnection - should throw when nothing in cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  mockStateStore.get.mockResolvedValue(null);

  await expect(auth0Client.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
  );
});

test('getAccessTokenForConnection - should throw when no refresh token', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(auth0Client.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
  );
});

test('getAccessTokenForConnection - should pass login_hint when calling auth0', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '',
    },
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        login_hint: '<login_hint>',
        expires_at: (Date.now() - 500) / 1000,
        access_token: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenForConnection = await auth0Client.getAccessTokenForConnection({
    connection: '<connection>',
    login_hint: '<login_hint>',
  });

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenForConnection).toBe(accessTokenWithLoginHint);
  expect(state.connectionTokenSets.length).toBe(1);
  expect(state.connectionTokenSets[0].access_token).toBe(accessTokenForConnection);
});

test('getAccessTokenForConnection - should return from the cache when not expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        expires_at: (Date.now() + 500) / 1000,
        access_token: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessTokenForConnection({ connection: '<connection>' });

  expect(accessToken).toBe('<access_token_for_connection>');
});

test('getAccessTokenForConnection - should return from the cache when not expired and no refresh token', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: undefined,
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        expires_at: (Date.now() + 500) / 1000,
        access_token: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessToken = await auth0Client.getAccessTokenForConnection({ connection: '<connection>' });

  expect(accessToken).toBe('<access_token_for_connection>');
});

test('getAccessTokenForConnection - should return from auth0 when access_token expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '',
    },
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        expires_at: (Date.now() - 500) / 1000,
        access_token: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenForConnection = await auth0Client.getAccessTokenForConnection({ connection: '<connection>' });

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenForConnection).toBe(accessToken);
  expect(state.connectionTokenSets.length).toBe(1);
  expect(state.connectionTokenSets[0].access_token).toBe(accessTokenForConnection);
});

test('getAccessTokenForConnection - should return from auth0 append to the state when connection differ', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '',
    },
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection_2>',
        expires_at: (Date.now() - 500) / 1000,
        access_token: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenForConnection = await auth0Client.getAccessTokenForConnection({ connection: '<connection>' });

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenForConnection).toBe(accessToken);
  expect(state.connectionTokenSets.length).toBe(2);
});

test('getAccessTokenForConnection - should throw an error when refresh_token grant failed', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  await auth0Client.init();

  const stateData: StateData = {
    user: { sub: '<sub>' },
    id_token: '<id_token>',
    refresh_token: '<refresh_token_should_fail>',
    tokenSets: [
      {
        audience: '<audience>',
        access_token: '<access_token>',
        expires_at: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  await expect(auth0Client.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    expect.objectContaining({
      code: 'failed_to_retrieve',
      message:
        'There was an error while trying to retrieve an access token for a connection. Check the server logs for more information.',
      cause: expect.objectContaining({
        error: '<error_code>',
        error_description: '<error_description>',
      }),
    })
  );
});

test('buildLogoutUrl - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await expect(auth0Client.buildLogoutUrl({ returnTo: '/' })).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('buildLogoutUrl - should build the logout url', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();
  const url = await auth0Client.buildLogoutUrl({
    returnTo: '/test_redirect_uri',
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/logout');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('post_logout_redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.size).toBe(2);
});
