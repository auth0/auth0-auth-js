import { expect, test, afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { ServerClient } from './server-client.js';

import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';
import { StateData } from './types.js';
import { DefaultStateStore } from './test-utils/default-state-store.js';
import { DefaultTransactionStore } from './test-utils/default-transaction-store.js';
import { StatelessStateStore } from './store/stateless-state-store.js';

const domain = 'auth0.local';
let accessToken: string;
let mtlsAccessToken: string;
let accessTokenWithLoginHint: string;
let accessTokenWithAudienceAndBindingMessage: string;
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
  pushed_authorization_request_endpoint: `https://${domain}/pushed-authorize`,
  mtls_endpoint_aliases: {
    token_endpoint: `https://mtls.${domain}/oauth/token`,
    userinfo_endpoint: `https://mtls.${domain}/userinfo`,
    revocation_endpoint: `https://mtls.${domain}/oauth/revoke`,
    pushed_authorization_request_endpoint: `https://mtls.${domain}/oauth/par`,
  },
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

    if (info.get('authorization_details')) {
      auth_req_id = 'auth_req_with_authorization_details';
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
          ...(info.get('auth_req_id') === 'auth_req_with_authorization_details'
            ? { authorization_details: [{ type: 'accepted' }] }
            : {}),
        });
  }),

  http.post(
    mockOpenIdConfiguration.mtls_endpoint_aliases.token_endpoint,
    async () => {
      return HttpResponse.json({
        access_token: mtlsAccessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
      });
    }
  ),

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
  mtlsAccessToken = await generateToken(domain, 'mtls_user_123');
});

afterEach(() => {
  mockOpenIdConfiguration = {
    issuer: `https://${domain}/`,
    authorization_endpoint: `https://${domain}/authorize`,
    backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
    token_endpoint: `https://${domain}/custom/token`,
    end_session_endpoint: `https://${domain}/logout`,
    pushed_authorization_request_endpoint: `https://${domain}/pushed-authorize`,
    mtls_endpoint_aliases: {
      token_endpoint: `https://mtls.${domain}/oauth/token`,
      userinfo_endpoint: `https://mtls.${domain}/userinfo`,
      revocation_endpoint: `https://mtls.${domain}/oauth/revoke`,
      pushed_authorization_request_endpoint: `https://mtls.${domain}/oauth/par`,
    },
  };
  server.resetHandlers();
});

test('should create an instance', () => {
  const serverClient = new ServerClient({
    domain: '',
    clientId: '',
    clientSecret: '',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  expect(serverClient).toBeDefined();
});

test('should not create an instance when no stateStore provided', () => {
  expect(() => new ServerClient({
    domain: '',
    clientId: '',
    clientSecret: '',
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    //eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any)).toThrowError(`The argument 'stateStore' is required but was not provided.`);
});

test('should not create an instance when no transactionStore provided', () => {
  expect(() => new ServerClient({
    domain: '',
    clientId: '',
    clientSecret: '',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    //eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any)).toThrowError(`The argument 'transactionStore' is required but was not provided.`);
});

test('configuration - should use mTLS when useMtls is true', async () => {
  const mockTransactionStore = {
    get: vi.fn().mockResolvedValue({
      codeVerifier: 'test-code-verifier',
    }),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    useMtls: true,
    // For mTLS to actually work in an actual application,
    // a custom fetch implementation should be provided, containing the corresponding configuration for mTLS.
    customFetch: fetch,
    stateStore: mockStateStore,
    transactionStore: mockTransactionStore,
  });

  await serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`));

  // Verify that the mTLS token endpoint was called (indirectly through the auth client)
  expect(mockStateStore.set).toHaveBeenCalled();
  const stateData = mockStateStore.set.mock.calls[0]?.[1];

  // The access token should be the mTLS token since useMtls is true
  expect(stateData).toBeDefined();
  expect(stateData.tokenSets[0].accessToken).toBe(mtlsAccessToken);
});

test('configuration - should use mTLS when useMtls is true but no aliasses', async () => {
  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.mtls_endpoint_aliases;

  const mockTransactionStore = {
    get: vi.fn().mockResolvedValue({
      codeVerifier: 'test-code-verifier',
    }),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    useMtls: true,
    // For mTLS to actually work in an actual application,
    // a custom fetch implementation should be provided, containing the corresponding configuration for mTLS.
    customFetch: fetch,
    stateStore: mockStateStore,
    transactionStore: mockTransactionStore,
  });

  await serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`));

  // Verify that the state was set
  expect(mockStateStore.set).toHaveBeenCalled();
  const stateData = mockStateStore.set.mock.calls[0]?.[1];

  // When no aliasses, we will end up calling the regular oauth/token endpoint,
  // and not the mTLS alias.
  // We know that in the case of our tests, that means it returns an `accessToken` instead of `mtlsAccessToken`.
  expect(stateData).toBeDefined();
  expect(stateData.tokenSets[0].accessToken).toBe(accessToken);
});

test('startInteractiveLogin - should throw when redirect_uri not provided', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await expect(serverClient.startInteractiveLogin()).rejects.toThrowError(
    "The argument 'authorizationParams.redirect_uri' is required but was not provided."
  );
});

test('startInteractiveLogin - should build the authorization url', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(6);
});

test('startInteractiveLogin - should build the authorization url for PAR', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  const url = await serverClient.startInteractiveLogin({ pushedAuthorizationRequests: true });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('request_uri')).toBe('request_uri_123');
  expect(url.searchParams.size).toBe(2);
});

test('startInteractiveLogin - should throw when using PAR without PAR support', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  // @ts-expect-error Ignore the fact that this property is not defined as optional in the test.
  delete mockOpenIdConfiguration.pushed_authorization_request_endpoint;

  await expect(serverClient.startInteractiveLogin({ pushedAuthorizationRequests: true })).rejects.toThrowError(
    'The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par'
  );
});

test('startInteractiveLogin - should build the authorization url with audience when provided', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      audience: '<audience>',
      redirect_uri: '/test_redirect_uri',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('audience')).toBe('<audience>');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(7);
});

test('startInteractiveLogin - should build the authorization url with scope when provided', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('scope')).toBe('<scope>');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(6);
});

test('startInteractiveLogin - should build the authorization url with custom parameter when provided', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('foo')).toBe('<bar>');
  expect(url.searchParams.get('scope')).toBe('<scope>');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(7);
});

test('startInteractiveLogin - should build the authorization url and override global authorizationParams', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
  });

  const url = await serverClient.startInteractiveLogin({
    authorizationParams: {
      redirect_uri: '/test_redirect_uri2',
      scope: '<scope2>',
      foo: '<bar2>',
    },
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri2');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('foo')).toBe('<bar2>');
  expect(url.searchParams.get('scope')).toBe('<scope2>');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(7);
});

test('startInteractiveLogin - should put appState in transaction store', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  await serverClient.startInteractiveLogin({
    appState: {
      returnTo: 'foo',
    },
  });
  expect(mockTransactionStore.set).toHaveBeenCalledWith(
    '__a0_tx',
    expect.objectContaining({
      appState: {
        returnTo: 'foo',
      },
    }),
    false,
    undefined
  );
});

test('startLinkUser - should throw when no idToken in the store', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.startLinkUser({
      connection: '<connection>',
      connectionScope: '<connection_scope>',
    })
  ).rejects.toThrowError(
    'Unable to start the user linking process without a logged in user. Ensure to login using the SDK before starting the user linking process.'
  );
});

test('startLinkUser - should build the link user url', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: {
      get: vi.fn().mockResolvedValue({}),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  mockStateStore.get.mockResolvedValue({
    user: { sub: '<sub>' },
    idToken: '<id_token>',
  });

  const linkUserUrl = await serverClient.startLinkUser({
    connection: '<connection>',
    connectionScope: '<connection_scope>',
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
  expect(linkUserUrl.searchParams.get('requested_connection_scope')).toBe('<connection_scope>');
  expect(linkUserUrl.searchParams.size).toBe(9);
});

test('startLinkUser - should put appState in transaction store', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockStateStore.get.mockResolvedValue({
    user: { sub: '<sub>' },
    idToken: '<id_token>',
  });

  await serverClient.startLinkUser({
    connection: '<connection>',
    connectionScope: '<connection_scope>',
    appState: {
      returnTo: 'foo',
    },
  });
  expect(mockTransactionStore.set).toHaveBeenCalledWith(
    '__a0_tx',
    expect.objectContaining({
      appState: {
        returnTo: 'foo',
      },
    }),
    false,
    undefined
  );
});

test('startUnlinkUser - should throw when no idToken in the store', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.startUnlinkUser({
      connection: '<connection>',
    })
  ).rejects.toThrowError(
    'Unable to start the user unlinking process without a logged in user. Ensure to login using the SDK before starting the user unlinking process.'
  );
});

test('startUnlinkUser - should build the unlink user url', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: {
      get: vi.fn().mockResolvedValue({}),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  mockStateStore.get.mockResolvedValue({
    user: { sub: '<sub>' },
    idToken: '<id_token>',
  });

  const linkUserUrl = await serverClient.startUnlinkUser({
    connection: '<connection>',
  });

  expect(linkUserUrl.host).toBe(domain);
  expect(linkUserUrl.pathname).toBe('/authorize');
  expect(linkUserUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(linkUserUrl.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(linkUserUrl.searchParams.get('scope')).toBe('openid unlink_account');
  expect(linkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(linkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(linkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(linkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(linkUserUrl.searchParams.get('requested_connection')).toBe('<connection>');
  expect(linkUserUrl.searchParams.size).toBe(8);
});

test('startUnlinkUser - should put appState in transaction store', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockStateStore.get.mockResolvedValue({
    user: { sub: '<sub>' },
    idToken: '<id_token>',
  });

  await serverClient.startUnlinkUser({
    connection: '<connection>',
    appState: {
      returnTo: 'foo',
    },
  });
  expect(mockTransactionStore.set).toHaveBeenCalledWith(
    '__a0_tx',
    expect.objectContaining({
      appState: {
        returnTo: 'foo',
      },
    }),
    false,
    undefined
  );
});

test('completeInteractiveLogin - should throw when no transaction', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await expect(
    serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123&state=abc`))
  ).rejects.toThrowError('The transaction is missing.');
});

test('completeInteractiveLogin - should throw an error when token exchange failed', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn().mockResolvedValue({}),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=<code_should_fail>`))
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

test('completeInteractiveLogin - should return the appState', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  mockTransactionStore.get.mockResolvedValue({ appState: { foo: '<bar>' } });

  const { appState } = await serverClient.completeInteractiveLogin<{ foo: string }>(
    new URL(`https://${domain}?code=123`)
  );

  expect(appState!.foo).toBe('<bar>');
});

test('completeInteractiveLogin - should delete stored transaction', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`));

  expect(mockTransactionStore.delete).toBeCalled();
});

test('completeInteractiveLogin - should call cookieHandler.setCookie with custom cookie options', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const cookieHandlerMock = {
    setCookie: vi.fn(),
    getCookie: vi.fn(),
    getCookies: vi.fn().mockReturnValue([]),
    deleteCookie: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: new StatelessStateStore(
      {
        secret: 'abc',
        cookie: {
          name: '__a0_s',
          sameSite: 'none',
          secure: false,
          path: '/custom_path',
        },
      },
      cookieHandlerMock
    ),
  });

  mockTransactionStore.get.mockResolvedValue({ appState: { foo: '<bar>' } });

  await serverClient.completeInteractiveLogin<{ foo: string }>(new URL(`https://${domain}?code=123`));

  expect(cookieHandlerMock.setCookie).toHaveBeenCalledWith(
    expect.any(String),
    expect.anything(),
    expect.objectContaining({ path: '/custom_path', secure: false, sameSite: 'none' }),
    undefined
  );
});

test('completeLinkUser - should throw when no transaction', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(serverClient.completeLinkUser(new URL(`https://${domain}?code=123&state=abc`))).rejects.toThrowError(
    'The transaction is missing.'
  );
});

test('completeLinkUser - should throw an error when token exchange failed', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn().mockResolvedValue({}),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.completeLinkUser(new URL(`https://${domain}?code=<code_should_fail>`))
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

test('completeLinkUser - should return the appState', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  mockTransactionStore.get.mockResolvedValue({ appState: { foo: '<bar>' } });

  const { appState } = await serverClient.completeLinkUser<{ foo: string }>(new URL(`https://${domain}?code=123`));

  expect(appState!.foo).toBe('<bar>');
});

test('completeLinkUser - should delete stored transaction', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await serverClient.completeLinkUser(new URL(`https://${domain}?code=123`));

  expect(mockTransactionStore.delete).toBeCalled();
});

test('completeUnlinkUser - should throw when no transaction', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(serverClient.completeUnlinkUser(new URL(`https://${domain}?code=123&state=abc`))).rejects.toThrowError(
    'The transaction is missing.'
  );
});

test('completeUnlinkUser - should throw an error when token exchange failed', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn().mockResolvedValue({}),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.completeUnlinkUser(new URL(`https://${domain}?code=<code_should_fail>`))
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

test('completeUnlinkUser - should return the appState', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  mockTransactionStore.get.mockResolvedValue({ appState: { foo: '<bar>' } });

  const { appState } = await serverClient.completeUnlinkUser<{ foo: string }>(new URL(`https://${domain}?code=123`));

  expect(appState!.foo).toBe('<bar>');
});

test('completeUnlinkUser - should delete stored transaction', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    },
  });

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await serverClient.completeUnlinkUser(new URL(`https://${domain}?code=123`));

  expect(mockTransactionStore.delete).toBeCalled();
});

test('loginBackchannel - should store the access token from the token endpoint', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  await serverClient.loginBackchannel({ loginHint: { sub: '<sub>' }, bindingMessage: '<binding_message>' });

  const stateData = mockStateStore.set.mock.calls[0]?.[1];

  expect(stateData.tokenSets.length).toBe(1);
  expect(stateData.tokenSets[0].accessToken).toBe(accessToken);
});

test('loginBackchannel - should store the access token from the token endpoint when passing audience and binding_message', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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
    stateStore: mockStateStore,
  });

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
  });

  const stateData = mockStateStore.set.mock.calls[0]?.[1];

  expect(stateData.tokenSets.length).toBe(1);
  expect(stateData.tokenSets[0].accessToken).toBe(accessTokenWithAudienceAndBindingMessage);
});

test('loginBackchannel - should support RAR', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  const response = await serverClient.loginBackchannel({
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

test('loginBackchannel - should throw an error when bc-authorize failed', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.loginBackchannel({ loginHint: { sub: '<sub>' }, bindingMessage: '<binding_message>' })
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

test('loginBackchannel - should throw an error when token exchange failed', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  await expect(
    serverClient.loginBackchannel({ loginHint: { sub: '<sub>' }, bindingMessage: '<binding_message>' })
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

test('getUser - should return from the cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const user = await serverClient.getUser();

  expect(user).toStrictEqual(stateData.user);
});

test('getUser - should return undefined when nothing in the cache', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  const user = await serverClient.getUser();

  expect(user).toBeUndefined();
});

test('getSession - should return from the cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const sessionData = await serverClient.getSession();

  expect(sessionData!.user).toStrictEqual(stateData.user);
  expect(sessionData!.refreshToken).toStrictEqual(stateData.refreshToken);
  expect(sessionData!.idToken).toStrictEqual(stateData.idToken);
  expect(sessionData!.tokenSets.length).toEqual(stateData.tokenSets.length);
  expect(sessionData!.internal).toBeUndefined();
});

test('getSession - should return undefined when nothing in the cache', async () => {
  const serverClient = new ServerClient({
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
      deleteByLogoutToken: vi.fn(),
    },
  });

  const sessionData = await serverClient.getSession();

  expect(sessionData).toBeUndefined();
});

test('getAccessToken - should throw when nothing in cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  mockStateStore.get.mockResolvedValue(null);

  await expect(serverClient.getAccessToken()).rejects.toThrowError(
    'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
  );
});

test('getAccessToken - should throw when no refresh token but access token expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '',
    tokenSets: [
      {
        audience: '<audience>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessToken()).rejects.toThrowError(
    'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
  );
});

test('getAccessToken - should return from the cache when not expired and no refresh token', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: undefined,
    tokenSets: [
      {
        audience: 'default',
        accessToken: '<access_token>',
        expiresAt: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessToken();

  expect(accessTokenResult.accessToken).toBe('<access_token>');
});

test('getAccessToken - should return from the cache when not expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: 'default',
        accessToken: '<access_token>',
        expiresAt: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessToken();

  expect(accessTokenResult.accessToken).toBe('<access_token>');
});

test('getAccessToken - should return from the cache when not expired and using scopes', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: 'default',
        accessToken: '<access_token>',
        expiresAt: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessToken();

  expect(accessTokenResult.accessToken).toBe('<access_token>');
});

test('getAccessToken - should return from auth0 when access_token expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
      {
        audience: '<another_audience>',
        accessToken: '<another_access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<another_scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessToken();

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenResult.accessToken).toBe(accessToken);
  expect(state.tokenSets.length).toBe(2);
});

test('getAccessToken - should return from auth0 and append to the state when audience differ', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience_2>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessToken();

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenResult.accessToken).toBe(accessToken);
  expect(state.tokenSets.length).toBe(2);
});

test('getAccessToken - should return from auth0 and append to the state when scope differ', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        audience: '<audience>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<scope2>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessToken();

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenResult.accessToken).toBe(accessToken);
  expect(state.tokenSets.length).toBe(2);
});

test('getAccessToken - should throw an error when refresh_token grant failed', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token_should_fail>',
    tokenSets: [
      {
        audience: 'default',
        accessToken: '<access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessToken()).rejects.toThrowError(
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

test('getAccessTokenForConnection - should throw when nothing in cache', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  mockStateStore.get.mockResolvedValue(null);

  await expect(serverClient.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
  );
});

test('getAccessTokenForConnection - should throw when no refresh token', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
  );
});

test('getAccessTokenForConnection - should pass login_hint when calling auth0', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        loginHint: '<login_hint>',
        expiresAt: (Date.now() - 500) / 1000,
        accessToken: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenForConnectionResult = await serverClient.getAccessTokenForConnection({
    connection: '<connection>',
    loginHint: '<login_hint>',
  });

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenForConnectionResult.accessToken).toBe(accessTokenWithLoginHint);
  expect(state.connectionTokenSets.length).toBe(1);
  expect(state.connectionTokenSets[0].accessToken).toBe(accessTokenForConnectionResult.accessToken);
});

test('getAccessTokenForConnection - should return from the cache when not expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        expiresAt: (Date.now() + 500) / 1000,
        accessToken: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });

  expect(accessTokenResult.accessToken).toBe('<access_token_for_connection>');
});

test('getAccessTokenForConnection - should return from the cache when not expired and no refresh token', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: undefined,
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        expiresAt: (Date.now() + 500) / 1000,
        accessToken: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenResult = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });

  expect(accessTokenResult.accessToken).toBe('<access_token_for_connection>');
});

test('getAccessTokenForConnection - should return from auth0 when access_token expired', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        expiresAt: (Date.now() - 500) / 1000,
        accessToken: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenForConnectionResult = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenForConnectionResult.accessToken).toBe(accessToken);
  expect(state.connectionTokenSets.length).toBe(1);
  expect(state.connectionTokenSets[0].accessToken).toBe(accessTokenForConnectionResult.accessToken);
});

test('getAccessTokenForConnection - should return from auth0 append to the state when connection differ', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection_2>',
        expiresAt: (Date.now() - 500) / 1000,
        accessToken: '<access_token_for_connection>',
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  const accessTokenForConnectionResult = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });

  const args = mockStateStore.set.mock.calls[0];
  const state = args?.[1];

  expect(accessTokenForConnectionResult.accessToken).toBe(accessToken);
  expect(state.connectionTokenSets.length).toBe(2);
});

test('getAccessTokenForConnection - should throw an error when refresh_token grant failed', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token_should_fail>',
    tokenSets: [
      {
        audience: '<audience>',
        accessToken: '<access_token>',
        expiresAt: (Date.now() - 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toMatchObject({
    code: 'token_for_connection_error',
    cause: expect.objectContaining({
      error: '<error_code>',
      error_description: '<error_description>',
    }),
  });
});

test('logout - should build the logout url', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const url = await serverClient.logout({
    returnTo: '/test_redirect_uri',
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/logout');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('post_logout_redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.size).toBe(2);
});

test('logout - should clear the cookie with custom cookie options', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const cookieHandlerMock = {
    setCookie: vi.fn(),
    getCookie: vi.fn(),
    getCookies: vi.fn().mockReturnValue({ __a0_session_xyz: 'cookie_value' }),
    deleteCookie: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore: new StatelessStateStore(
      {
        secret: 'abc',
        cookie: {
          name: '__a0_session_xyz',
          sameSite: 'none',
          secure: false,
          path: '/custom_path',
        },
      },
      cookieHandlerMock
    ),
  });
  await serverClient.logout({
    returnTo: '/test_redirect_uri',
  });

  expect(cookieHandlerMock.deleteCookie).toHaveBeenCalledWith(
    '__a0_session_xyz',
    undefined,
    expect.objectContaining({ path: '/custom_path', sameSite: 'none', secure: false })
  );
});

test('handleBackchannelLogout - should throw when no refresh token provided', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await expect(serverClient.handleBackchannelLogout(undefined as any)).rejects.toThrowError('Missing Logout Token');
});
