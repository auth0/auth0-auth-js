import { expect, test, afterAll, afterEach, beforeAll, beforeEach, vi, describe } from 'vitest';
import { ServerClient } from './server-client.js';
import { InvalidConfigurationError, MissingSessionError, MissingTransactionError } from './errors.js';
import { AuthClient, TokenResponse, isMfaRequiredError } from '@auth0/auth0-auth-js';

import * as Auth0AuthJs from '@auth0/auth0-auth-js';

import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';
import { StateData } from './types.js';
import { DefaultStateStore } from './test-utils/default-state-store.js';
import { DefaultTransactionStore } from './test-utils/default-transaction-store.js';
import { StatelessStateStore } from './store/stateless-state-store.js';

type ServerMetadata = Awaited<ReturnType<AuthClient['getServerMetadata']>>;
const asIdTokenClaims = (claims: Record<string, unknown>) =>
  claims as unknown as NonNullable<TokenResponse['claims']>;

const domain = 'auth0.local';
const fakePasskeyCredential = {
  id: 'cred_123',
  rawId: 'cred_123',
  type: 'public-key',
  response: {
    clientDataJSON: 'fake_client_data',
    authenticatorData: 'fake_authenticator_data',
    signature: 'fake_signature',
  },
};
let accessToken: string;
let mtlsAccessToken: string;
let accessTokenWithLoginHint: string;
let accessTokenWithAudienceAndBindingMessage: string;
let lastBackchannelScope: string | null;
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
    lastBackchannelScope = info.get('scope')?.toString() ?? null;

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
    // The passkey (WebAuthn) grant sends application/json; all other grants
    // send application/x-www-form-urlencoded. Both Map and FormData expose
    // `.get()`, so the rest of the handler works against either.
    const info = (request.headers.get('content-type') ?? '').includes('application/json')
      ? new Map(Object.entries((await request.json()) as Record<string, unknown>))
      : await request.formData();

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

  http.post(`https://${domain}/passkey/register`, async () => {
    return HttpResponse.json({
      auth_session: 'auth_session_register_123',
      authn_params_public_key: {
        challenge: 'register_challenge',
        rp: { id: domain, name: 'Test RP' },
        user: { id: 'user_handle_123', name: 'jane@example.com', displayName: 'Jane' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    });
  }),

  http.post(`https://${domain}/passkey/challenge`, async () => {
    return HttpResponse.json({
      auth_session: 'auth_session_challenge_123',
      authn_params_public_key: {
        challenge: 'login_challenge',
        rpId: domain,
      },
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
  lastBackchannelScope = null;
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
    domain: 'auth0.local',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  expect(serverClient).toBeDefined();
});

test('should normalize static domain when provided as a URL', async () => {
  const serverClient = new ServerClient({
    domain: 'https://AUTH0.LOCAL/some/path',
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
});

test('should not create an instance when no stateStore provided', () => {
  expect(
    () =>
      new ServerClient({
        domain: '',
        clientId: '',
        clientSecret: '',
        transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
        //eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any)
  ).toThrowError(`The argument 'stateStore' is required but was not provided.`);
});

test('should not create an instance when no transactionStore provided', () => {
  expect(
    () =>
      new ServerClient({
        domain: '',
        clientId: '',
        clientSecret: '',
        stateStore: new DefaultStateStore({ secret: '<secret>' }),
        //eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any)
  ).toThrowError(`The argument 'transactionStore' is required but was not provided.`);
});

test('should not create an instance when domain is not string or function', () => {
  const createClient = () =>
    new ServerClient({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      domain: 123 as any,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      stateStore: new DefaultStateStore({ secret: '<secret>' }),
      transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    });

  expect(createClient).toThrowError(InvalidConfigurationError);
  expect(createClient).toThrowError('domain must be a string or resolver function');
});

test('authClient - should throw when using a resolver', () => {
  const serverClient = new ServerClient({
    domain: async () => domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  expect(() => serverClient.authClient).toThrowError(InvalidConfigurationError);
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
    discoveryCache: { ttl: 11, maxEntries: 3 },
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

test('startInteractiveLogin - should call domain resolver with storeOptions', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const storeOptions = { request: { headers: { host: 'example.test' } } };

  await serverClient.startInteractiveLogin(
    {
      authorizationParams: {
        redirect_uri: '/test_redirect_uri',
      },
    },
    storeOptions
  );

  expect(domainResolver).toHaveBeenCalledWith(storeOptions);
});

test('startInteractiveLogin - should throw when resolver returns no domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue(null);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await expect(
    serverClient.startInteractiveLogin({
      authorizationParams: {
        redirect_uri: '/test_redirect_uri',
      },
    })
  ).rejects.toThrowError('domainResolver returned no domain');
});

test('startInteractiveLogin - should throw when resolver returns a non-string domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue(123 as unknown as string);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await expect(
    serverClient.startInteractiveLogin({
      authorizationParams: {
        redirect_uri: '/test_redirect_uri',
      },
    })
  ).rejects.toThrowError('domainResolver returned no domain');
});

test('startInteractiveLogin - should include openid scope when using a resolver', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const url = await serverClient.startInteractiveLogin({
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: 'profile',
    },
  });

  expect(url.searchParams.get('scope')).toBe('openid profile');
});

test('startInteractiveLogin - should include openid scope for static domain', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: 'profile',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  expect(url.searchParams.get('scope')).toBe('openid profile');
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
    discoveryCache: { ttl: 12, maxEntries: 4 },
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
  expect(url.searchParams.get('scope')).toBe('openid <scope>');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(6);
});

test('startInteractiveLogin - should always include openid in scope even when custom scope provided', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: 'read:data write:data',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  const scope = url.searchParams.get('scope');
  expect(scope).toContain('openid');
  expect(scope).toContain('read:data');
  expect(scope).toContain('write:data');
  expect(scope).toBe('openid read:data write:data');
});

test('startInteractiveLogin - should not duplicate openid when already present in custom scope', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: 'openid read:data',
    },
  });

  const url = await serverClient.startInteractiveLogin();

  const scope = url.searchParams.get('scope');
  expect(scope).toBe('openid read:data');
  // Verify openid appears only once
  expect(scope?.split(' ').filter((s) => s === 'openid').length).toBe(1);
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
  expect(url.searchParams.get('scope')).toBe('openid <scope>');
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
  expect(url.searchParams.get('scope')).toBe('openid <scope2>');
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

test('startInteractiveLogin - should store domain in transaction', async () => {
  const domainResolver = vi.fn().mockResolvedValue('https://AUTH0.LOCAL');
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: 'openid profile',
    },
    transactionStore: mockTransactionStore,
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
  });

  await serverClient.startInteractiveLogin();

  expect(mockTransactionStore.set).toHaveBeenCalledWith(
    '__a0_tx',
    expect.objectContaining({
      domain,
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

test('startLinkUser - should throw when session domain does not match current domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(
    serverClient.startLinkUser({ connection: '<connection>', connectionScope: '<connection_scope>' })
  ).rejects.toThrowError(MissingSessionError);
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

test('startLinkUser - should build the link user url in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockStateStore.get.mockResolvedValue({
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    domain,
  });

  const linkUrl = new URL(`https://${domain}/authorize?client_id=<client_id>`);
  linkUrl.searchParams.set('requested_connection', '<connection>');
  linkUrl.searchParams.set('requested_connection_scope', '<connection_scope>');
  const linkSpy = vi
    .spyOn(AuthClient.prototype, 'buildLinkUserUrl')
    .mockResolvedValue({ linkUserUrl: linkUrl, codeVerifier: '<code_verifier>' });
  const metadataSpy = vi
    .spyOn(AuthClient.prototype, 'getServerMetadata')
    .mockResolvedValue({ issuer: `https://${domain}/` } as ServerMetadata);

  let linkUserUrl: URL;
  try {
    linkUserUrl = await serverClient.startLinkUser({
      connection: '<connection>',
      connectionScope: '<connection_scope>',
    });
  } finally {
    linkSpy.mockRestore();
    metadataSpy.mockRestore();
  }

  expect(linkUserUrl.host).toBe(domain);
  expect(linkUserUrl.pathname).toBe('/authorize');
  expect(linkUserUrl.searchParams.get('requested_connection')).toBe('<connection>');
  expect(mockTransactionStore.set).toHaveBeenCalled();
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

test('startLinkUser - should use audience from options when provided', async () => {
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
      audience: '<default_audience>',
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
    authorizationParams: {
      audience: '<override_audience>',
    },
  });

  const args = mockTransactionStore.set.mock.calls[0];
  expect(args?.[1]).toMatchObject({ audience: '<override_audience>' });
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

test('startUnlinkUser - should throw when session domain does not match current domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.startUnlinkUser({ connection: '<connection>' })).rejects.toThrowError(MissingSessionError);
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

test('startUnlinkUser - should build the unlink user url in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockStateStore.get.mockResolvedValue({
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    domain,
  });

  const unlinkUrl = new URL(`https://${domain}/authorize?client_id=<client_id>`);
  unlinkUrl.searchParams.set('requested_connection', '<connection>');
  const unlinkSpy = vi
    .spyOn(AuthClient.prototype, 'buildUnlinkUserUrl')
    .mockResolvedValue({ unlinkUserUrl: unlinkUrl, codeVerifier: '<code_verifier>' });
  const metadataSpy = vi
    .spyOn(AuthClient.prototype, 'getServerMetadata')
    .mockResolvedValue({ issuer: `https://${domain}/` } as ServerMetadata);

  let unlinkUserUrl: URL;
  try {
    unlinkUserUrl = await serverClient.startUnlinkUser({
      connection: '<connection>',
    });
  } finally {
    unlinkSpy.mockRestore();
    metadataSpy.mockRestore();
  }

  expect(unlinkUserUrl.host).toBe(domain);
  expect(unlinkUserUrl.pathname).toBe('/authorize');
  expect(unlinkUserUrl.searchParams.get('requested_connection')).toBe('<connection>');
  expect(mockTransactionStore.set).toHaveBeenCalled();
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

test('startUnlinkUser - should use audience from options when provided', async () => {
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
      audience: '<default_audience>',
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
    authorizationParams: {
      audience: '<override_audience>',
    },
  });

  const args = mockTransactionStore.set.mock.calls[0];
  expect(args?.[1]).toMatchObject({ audience: '<override_audience>' });
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

test('completeInteractiveLogin - should fail when id_token iss is missing in resolver mode (handled by underlying SDK)', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await serverClient.startInteractiveLogin();

  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () =>
      HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', false),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
      })
    )
  );

  await expect(serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`))).rejects.toMatchObject({
    code: 'token_by_code_error',
  });
});

test('completeInteractiveLogin - should fail when issuer mismatches in resolver mode (handled by underlying SDK)', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await serverClient.startInteractiveLogin();

  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () =>
      HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', 'https://other-issuer.example/'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
      })
    )
  );

  await expect(serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`))).rejects.toMatchObject({
    code: 'token_by_code_error',
  });
});

test('completeInteractiveLogin - should fail when transaction issuer is missing and id_token issuer mismatches', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
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
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockTransactionStore.get.mockResolvedValue({
    codeVerifier: '<code_verifier>',
    domain,
  });
  mockStateStore.get.mockResolvedValue(undefined);

  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () =>
      HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', 'https://other-issuer.example/'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
      })
    )
  );

  await expect(serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`))).rejects.toMatchObject({
    code: 'token_by_code_error',
  });
});

test('completeInteractiveLogin - should fail when transaction issuer is empty and id_token issuer mismatches', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
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
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockTransactionStore.get.mockResolvedValue({
    codeVerifier: '<code_verifier>',
    domain,
    issuer: '',
  });
  mockStateStore.get.mockResolvedValue(undefined);

  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () =>
      HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', 'https://other-issuer.example/'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
      })
    )
  );

  await expect(serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`))).rejects.toMatchObject({
    code: 'token_by_code_error',
  });
});

test('completeInteractiveLogin - should persist domain from transaction and ignore stale issuer', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
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
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    transactionStore: mockTransactionStore,
    stateStore: mockStateStore,
  });

  mockTransactionStore.get.mockResolvedValue({
    codeVerifier: '<code_verifier>',
    domain,
    issuer: 'https://stale-issuer.example/',
  });
  mockStateStore.get.mockResolvedValue(undefined);

  await serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`));

  expect(mockStateStore.set).toHaveBeenCalledWith(
    '__a0_session',
    expect.objectContaining({
      domain,
    }),
    true,
    undefined
  );
});
test('completeInteractiveLogin - should not enforce issuer validation in static domain mode', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await serverClient.startInteractiveLogin();

  const tokenResponse = new TokenResponse(
    accessToken,
    Math.floor(Date.now() / 1000) + 3600,
    '<id_token>',
    '<refresh_token>',
    '<scope>',
    asIdTokenClaims({ sub: 'user_123' })
  );

  const getTokenByCodeSpy = vi.spyOn(AuthClient.prototype, 'getTokenByCode').mockResolvedValue(tokenResponse);

  try {
    const result = await serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`));

    expect(result.appState).toBeUndefined();
    expect(result.authorizationDetails).toBeUndefined();
  } finally {
    getTokenByCodeSpy.mockRestore();
  }
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

test('loginBackchannel - should use default scopes when no scope provided', async () => {
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

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
  });

  expect(lastBackchannelScope).toBe('openid profile email offline_access');
});

test('loginBackchannel - should always include openid in scope even when custom scope provided', async () => {
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

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    authorizationParams: {
      scope: 'read:data write:data',
    },
  });

  expect(lastBackchannelScope).toBe('openid read:data write:data');
});

test('loginBackchannel - should not duplicate openid when already present in custom scope', async () => {
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

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    authorizationParams: {
      scope: 'openid read:data',
    },
  });

  const scope = lastBackchannelScope;
  expect(scope).toBe('openid read:data');
  // Verify openid appears only once
  expect(scope?.split(' ').filter((s) => s === 'openid').length).toBe(1);
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
      message: 'There was an error when trying to use Client-Initiated Backchannel Authentication.',
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

test('loginBackchannel - should use default scopes when no scope provided', async () => {
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

  const spy = vi.spyOn(serverClient.authClient, 'backchannelAuthentication');

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
  });

  expect(spy).toHaveBeenCalledWith(
    expect.objectContaining({
      authorizationParams: expect.objectContaining({
        scope: 'openid profile email offline_access',
      }),
    })
  );

  spy.mockRestore();
});

test('loginBackchannel - should always include openid in scope even when custom scope provided', async () => {
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

  const spy = vi.spyOn(serverClient.authClient, 'backchannelAuthentication');

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    authorizationParams: {
      scope: 'read:data write:data',
    },
  });

  expect(spy).toHaveBeenCalledWith(
    expect.objectContaining({
      authorizationParams: expect.objectContaining({
        scope: 'openid read:data write:data',
      }),
    })
  );

  spy.mockRestore();
});

test('loginBackchannel - should not duplicate openid when already present in custom scope', async () => {
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

  const spy = vi.spyOn(serverClient.authClient, 'backchannelAuthentication');

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
    authorizationParams: {
      scope: 'openid read:data',
    },
  });

  const callArgs = spy.mock.calls[0]![0];
  const scope = callArgs.authorizationParams?.scope;

  expect(scope).toBe('openid read:data');
  // Verify openid appears only once
  expect(scope?.split(' ').filter((s) => s === 'openid').length).toBe(1);

  spy.mockRestore();
});

test('loginWithCustomTokenExchange - should persist session after successful exchange', async () => {
  const mockStateStore = {
    get: vi.fn().mockResolvedValue(undefined),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: { audience: 'https://api.example.com' },
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  await serverClient.loginWithCustomTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
    audience: 'https://api.example.com',
  });

  expect(mockStateStore.set).toHaveBeenCalledOnce();
  const stateData = mockStateStore.set.mock.calls[0]?.[1];
  expect(stateData.tokenSets.length).toBe(1);
  expect(stateData.tokenSets[0].audience).toBe('https://api.example.com');
  expect(stateData.tokenSets[0].accessToken).toBeDefined();
});

test('loginWithCustomTokenExchange - should use "default" audience when none provided', async () => {
  const mockStateStore = {
    get: vi.fn().mockResolvedValue(undefined),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  await serverClient.loginWithCustomTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
  });

  const stateData = mockStateStore.set.mock.calls[0]?.[1];
  expect(stateData.tokenSets[0].audience).toBe('default');
});

test('loginWithCustomTokenExchange - should persist domain on session', async () => {
  const mockStateStore = {
    get: vi.fn().mockResolvedValue(undefined),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  await serverClient.loginWithCustomTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
  });

  const stateData = mockStateStore.set.mock.calls[0]?.[1];
  expect(stateData.domain).toBe(domain);
});

test('loginWithCustomTokenExchange - should call stateStore.set with removeIfExists=true (session fixation)', async () => {
  const mockStateStore = {
    get: vi.fn().mockResolvedValue(undefined),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  await serverClient.loginWithCustomTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
  });

  // Third arg to stateStore.set is removeIfExists — must be true to prevent session fixation
  expect(mockStateStore.set.mock.calls[0]?.[2]).toBe(true);
});

test('loginWithCustomTokenExchange - should throw when exchange fails', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  await expect(
    serverClient.loginWithCustomTokenExchange({
      subjectToken: '<refresh_token_should_fail>',
      subjectTokenType: 'urn:acme:legacy-token',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      name: 'TokenExchangeError',
      code: 'token_exchange_error',
    })
  );
});

test('loginWithCustomTokenExchange - should allow getAccessToken to return the token after login', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: { audience: 'https://api.example.com' },
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
  });

  await serverClient.loginWithCustomTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
    audience: 'https://api.example.com',
  });

  const tokenSet = await serverClient.getAccessToken();
  expect(tokenSet.accessToken).toBeDefined();
  expect(tokenSet.audience).toBe('https://api.example.com');
});

test('customTokenExchange - should return token response without persisting session', async () => {
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
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  const result = await serverClient.customTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
    audience: 'https://api.example.com',
  });

  expect(result.accessToken).toBeDefined();
  expect(result.expiresAt).toBeGreaterThan(0);
  expect(mockStateStore.set).not.toHaveBeenCalled();
  expect(mockStateStore.get).not.toHaveBeenCalled();
});

test('customTokenExchange - should return act claim when actor token is used', async () => {
  const mockTokenResponse = new TokenResponse('<access_token>', Date.now() / 1000 + 60);
  mockTokenResponse.act = { sub: 'service-account-id' };
  const exchangeSpy = vi.spyOn(AuthClient.prototype, 'exchangeToken').mockResolvedValue(mockTokenResponse);

  try {
    const serverClient = new ServerClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
      stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
    });

    const result = await serverClient.customTokenExchange({
      subjectToken: 'user-token',
      subjectTokenType: 'urn:acme:user-token',
      actorToken: 'service-token',
      actorTokenType: 'urn:acme:service-token',
    });

    expect(result.act).toEqual({ sub: 'service-account-id' });
    expect(exchangeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        actorToken: 'service-token',
        actorTokenType: 'urn:acme:service-token',
      })
    );
  } finally {
    exchangeSpy.mockRestore();
  }
});

test('loginWithCustomTokenExchange - should persist act claim on session user when actor token is used', async () => {
  const idToken = await generateToken(domain, 'user_123', '<client_id>');
  const mockTokenResponse = new TokenResponse('<access_token>', Date.now() / 1000 + 60, idToken);
  mockTokenResponse.claims = { sub: 'user_123', iss: `https://${domain}/`, aud: '<client_id>', iat: 0, exp: 0, act: { sub: 'service-account-id' } };
  mockTokenResponse.act = { sub: 'service-account-id' };
  const exchangeSpy = vi.spyOn(AuthClient.prototype, 'exchangeToken').mockResolvedValue(mockTokenResponse);

  try {
    const serverClient = new ServerClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
      stateStore: new DefaultStateStore({ secret: '<secret>' }),
    });

    await serverClient.loginWithCustomTokenExchange({
      subjectToken: 'user-token',
      subjectTokenType: 'urn:acme:user-token',
      actorToken: 'service-token',
      actorTokenType: 'urn:acme:service-token',
    });

    const session = await serverClient.getSession();
    expect(session?.user?.act).toEqual({ sub: 'service-account-id' });
    expect(exchangeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        actorToken: 'service-token',
        actorTokenType: 'urn:acme:service-token',
      })
    );
  } finally {
    exchangeSpy.mockRestore();
  }
});

test('customTokenExchange - should throw when exchange fails', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  await expect(
    serverClient.customTokenExchange({
      subjectToken: '<refresh_token_should_fail>',
      subjectTokenType: 'urn:acme:legacy-token',
    })
  ).rejects.toThrowError(
    expect.objectContaining({
      name: 'TokenExchangeError',
      code: 'token_exchange_error',
    })
  );
});

test('loginWithCustomTokenExchange - should return authorizationDetails when RAR was used', async () => {
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn().mockResolvedValue(undefined), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () => {
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
        authorization_details: [{ type: 'accepted' }],
      });
    })
  );

  const result = await serverClient.loginWithCustomTokenExchange({
    subjectToken: 'external-token-123',
    subjectTokenType: 'urn:acme:legacy-token',
    extra: { authorization_details: JSON.stringify([{ type: 'accepted' }]) },
  });

  expect(result.authorizationDetails?.[0]!.type).toBe('accepted');
});

test('loginWithCustomTokenExchange - should resolve domain via resolver function', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn().mockResolvedValue(undefined),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  await serverClient.loginWithCustomTokenExchange(
    {
      subjectToken: 'external-token-123',
      subjectTokenType: 'urn:acme:legacy-token',
    },
    { req: 'store-options' } as unknown as never
  );

  expect(domainResolver).toHaveBeenCalledWith({ req: 'store-options' });
  expect(mockStateStore.set).toHaveBeenCalledOnce();
  const stateData = mockStateStore.set.mock.calls[0]?.[1];
  expect(stateData.domain).toBe(domain);
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

test('getUser - should return undefined when session domain does not match', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const user = await serverClient.getUser();

  expect(user).toBeUndefined();
});

test('getUser - should return undefined when session domain is missing in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const user = await serverClient.getUser();

  expect(user).toBeUndefined();
});

test('getUser - should return user for legacy resolver-mode session when user.iss matches resolved domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    user: { sub: '<sub>', iss: `https://${domain}/` },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const user = await serverClient.getUser();

  expect(user).toStrictEqual(stateData.user);
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

test('getSession - should return undefined when session domain does not match', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const sessionData = await serverClient.getSession();

  expect(sessionData).toBeUndefined();
});

test('getSession - should return session for legacy resolver-mode session when user.iss matches resolved domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    user: { sub: '<sub>', iss: `https://${domain}/` },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const sessionData = await serverClient.getSession();

  expect(sessionData).toBeDefined();
  expect(sessionData!.user).toStrictEqual(stateData.user);
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

test('getAccessToken - should throw when nothing in cache in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    'Unable to retrieve access token without a logged in user.'
  );
});

test('getAccessToken - should throw when session domain does not match', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessToken()).rejects.toThrowError(MissingSessionError);
});

test('getAccessToken - should throw when session domain is missing in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessToken()).rejects.toThrowError(MissingSessionError);
});

test('getAccessToken - should return cached token for legacy resolver-mode session when user.iss matches resolved domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    user: { sub: '<sub>', iss: `https://${domain}/` },
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
        expiresAt: 0,
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

test('getAccessToken - should refresh token in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    ],
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const tokenResponse = new TokenResponse(
    accessToken,
    Math.floor(Date.now() / 1000) + 3600,
    '<id_token>',
    '<refresh_token>',
    '<scope>',
    asIdTokenClaims({ sub: 'user_123' })
  );

  const refreshSpy = vi.spyOn(AuthClient.prototype, 'getTokenByRefreshToken').mockResolvedValue(tokenResponse);

  try {
    const accessTokenResult = await serverClient.getAccessToken();

    expect(accessTokenResult.accessToken).toBe(accessToken);
    expect(refreshSpy).toHaveBeenCalled();
    expect(mockStateStore.set).toHaveBeenCalled();
  } finally {
    refreshSpy.mockRestore();
  }
});

test('getAccessToken - should migrate legacy resolver-mode session context from user.iss on refresh', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    user: { sub: '<sub>', iss: `https://${domain}/` },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
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

  const tokenResponse = new TokenResponse(
    accessToken,
    Math.floor(Date.now() / 1000) + 3600,
    '<id_token>',
    '<refresh_token>',
    '<scope>',
    asIdTokenClaims({ sub: 'user_123', iss: `https://${domain}/` })
  );

  const refreshSpy = vi.spyOn(AuthClient.prototype, 'getTokenByRefreshToken').mockResolvedValue(tokenResponse);

  try {
    await serverClient.getAccessToken();

    const persistedState = mockStateStore.set.mock.calls[0]?.[1] as StateData;
    expect(persistedState.domain).toBe(domain);
    expect(refreshSpy).toHaveBeenCalled();
  } finally {
    refreshSpy.mockRestore();
  }
});

test('getAccessToken - should refresh token in static domain', async () => {
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
        expiresAt: 0,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const tokenResponse = new TokenResponse(
    accessToken,
    Math.floor(Date.now() / 1000) + 3600,
    '<id_token>',
    '<refresh_token>',
    '<scope>',
    asIdTokenClaims({ sub: 'user_123' })
  );

  const refreshSpy = vi.spyOn(AuthClient.prototype, 'getTokenByRefreshToken').mockResolvedValue(tokenResponse);

  try {
    const accessTokenResult = await serverClient.getAccessToken();

    expect(accessTokenResult.accessToken).toBe(accessToken);
    expect(refreshSpy).toHaveBeenCalled();
    expect(mockStateStore.set).toHaveBeenCalled();
  } finally {
    refreshSpy.mockRestore();
  }
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
    user: { sub: 'user_123' },
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
    user: { sub: 'user_123' },
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
    user: { sub: 'user_123' },
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
      message: 'The access token has expired and there was an error while trying to refresh it.',
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

test('getAccessTokenForConnection - should throw when nothing in cache in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    'Unable to retrieve an access token for a connection without a logged in user.'
  );
});

test('getAccessTokenForConnection - should throw when session domain does not match', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    MissingSessionError
  );
});

test('getAccessTokenForConnection - should throw when session domain is missing in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await expect(serverClient.getAccessTokenForConnection({ connection: '<connection>' })).rejects.toThrowError(
    MissingSessionError
  );
});

test('getAccessTokenForConnection - should return cached token for legacy resolver-mode session when user.iss matches resolved domain', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    user: { sub: '<sub>', iss: `https://${domain}/` },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        accessToken: '<connection_access_token>',
        expiresAt: (Date.now() + 500) / 1000,
        scope: '<scope>',
      },
    ],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const result = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });
  expect(result.accessToken).toBe('<connection_access_token>');
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

test('getAccessTokenForConnection - should refresh token in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    connectionTokenSets: [],
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const tokenResponse = new TokenResponse(
    accessToken,
    Math.floor(Date.now() / 1000) + 3600,
    '<id_token>',
    '<refresh_token>',
    '<scope>',
    asIdTokenClaims({ sub: 'user_123' })
  );

  const tokenSpy = vi.spyOn(AuthClient.prototype, 'getTokenForConnection').mockResolvedValue(tokenResponse);

  try {
    const tokenSet = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });

    expect(tokenSet.accessToken).toBe(accessToken);
    expect(tokenSpy).toHaveBeenCalled();
    expect(mockStateStore.set).toHaveBeenCalled();
  } finally {
    tokenSpy.mockRestore();
  }
});

test('getAccessTokenForConnection - should refresh token in static domain', async () => {
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
    connectionTokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const tokenResponse = new TokenResponse(
    accessToken,
    Math.floor(Date.now() / 1000) + 3600,
    '<id_token>',
    '<refresh_token>',
    '<scope>',
    asIdTokenClaims({ sub: 'user_123' })
  );

  const tokenSpy = vi.spyOn(AuthClient.prototype, 'getTokenForConnection').mockResolvedValue(tokenResponse);

  try {
    const tokenSet = await serverClient.getAccessTokenForConnection({ connection: '<connection>' });

    expect(tokenSet.accessToken).toBe(accessToken);
    expect(tokenSpy).toHaveBeenCalled();
    expect(mockStateStore.set).toHaveBeenCalled();
  } finally {
    tokenSpy.mockRestore();
  }
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

test('logout - should not delete session when domain does not match', async () => {
  const domainResolver = vi.fn().mockResolvedValue('other.local');
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const otherDomainConfig = {
    issuer: 'https://other.local/',
    authorization_endpoint: 'https://other.local/authorize',
    backchannel_authentication_endpoint: 'https://other.local/custom-authorize',
    token_endpoint: 'https://other.local/custom/token',
    end_session_endpoint: 'https://other.local/logout',
    pushed_authorization_request_endpoint: 'https://other.local/pushed-authorize',
    mtls_endpoint_aliases: {
      token_endpoint: 'https://mtls.other.local/oauth/token',
      userinfo_endpoint: 'https://mtls.other.local/userinfo',
      revocation_endpoint: 'https://mtls.other.local/oauth/revoke',
      pushed_authorization_request_endpoint: 'https://mtls.other.local/oauth/par',
    },
  };

  server.use(
    http.get('https://other.local/.well-known/openid-configuration', () => {
      return HttpResponse.json(otherDomainConfig);
    })
  );

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  const url = await serverClient.logout({ returnTo: '/test_redirect_uri' });

  expect(mockStateStore.delete).not.toHaveBeenCalled();
  expect(url.host).toBe('other.local');
});

test('logout - should return logout url when no session exists in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  mockStateStore.get.mockResolvedValue(null);

  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
    stateStore: mockStateStore,
  });

  const url = await serverClient.logout({ returnTo: '/test_redirect_uri' });

  expect(mockStateStore.delete).not.toHaveBeenCalled();
  expect(url.host).toBe(domain);
});

test('logout - should delete session when domains match in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const serverClient = new ServerClient({
    domain: domainResolver,
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
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  mockStateStore.get.mockResolvedValue(stateData);

  await serverClient.logout({ returnTo: '/test_redirect_uri' });

  expect(mockStateStore.delete).toHaveBeenCalled();
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

  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    domain,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const stateStore = new StatelessStateStore(
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
  );
  vi.spyOn(stateStore, 'get').mockResolvedValue(stateData);

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    stateStore,
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

test('handleBackchannelLogout - should throw when logout token is missing issuer in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await expect(serverClient.handleBackchannelLogout('not-a-jwt')).rejects.toThrowError(
    'Logout token is missing an issuer'
  );
});

test('handleBackchannelLogout - should treat non-string issuer as missing', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: 123 })).toString('base64url');
  const token = `${header}.${payload}.`;

  await expect(serverClient.handleBackchannelLogout(token)).rejects.toThrowError('Logout token is missing an issuer');
});

test('handleBackchannelLogout - should throw when issuer does not match the resolved domain in resolver mode', async () => {
  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const logoutToken = await generateToken('other.example.auth0.com', '<sub>', '<client_id>');
  const verifyLogoutTokenSpy = vi.spyOn(AuthClient.prototype, 'verifyLogoutToken');

  try {
    await expect(serverClient.handleBackchannelLogout(logoutToken)).rejects.toThrowError(
      'Logout token issuer does not match the resolved domain'
    );
  } finally {
    verifyLogoutTokenSpy.mockRestore();
  }

  expect(verifyLogoutTokenSpy).not.toHaveBeenCalled();
});

test('handleBackchannelLogout - should delete session by logout token in static mode', async () => {
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
    stateStore: mockStateStore,
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>');
  const verifyLogoutTokenSpy = vi
    .spyOn(AuthClient.prototype, 'verifyLogoutToken')
    .mockResolvedValue({ sid: '<sid>', sub: '<sub>' });

  try {
    await serverClient.handleBackchannelLogout(logoutToken);
  } finally {
    verifyLogoutTokenSpy.mockRestore();
  }

  expect(mockStateStore.deleteByLogoutToken).toHaveBeenCalledWith({ sid: '<sid>', sub: '<sub>' }, undefined);
});

test('handleBackchannelLogout - should delete session by logout token in resolver mode', async () => {
  const mockStateStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    deleteByLogoutToken: vi.fn(),
  };

  const domainResolver = vi.fn().mockResolvedValue(domain);
  const serverClient = new ServerClient({
    domain: domainResolver,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: mockStateStore,
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  const logoutToken = await generateToken(domain, '<sub>', '<client_id>');
  const verifyLogoutTokenSpy = vi
    .spyOn(AuthClient.prototype, 'verifyLogoutToken')
    .mockResolvedValue({ sid: '<sid>', sub: '<sub>' });

  try {
    await serverClient.handleBackchannelLogout(logoutToken);
  } finally {
    verifyLogoutTokenSpy.mockRestore();
  }

  expect(mockStateStore.deleteByLogoutToken).toHaveBeenCalledWith(
    { sid: '<sid>', sub: '<sub>', iss: `https://${domain}/` },
    undefined
  );
});

test('Telemetry - should include Auth0-Client header with server-js package info by default', async () => {
  let capturedHeader: string | null = null;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, ({ request }) => {
      capturedHeader = request.headers.get('Auth0-Client');
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );

  // Mock the underlying AuthClient to disable caching and ensure the header is captured on every request
  const OriginalAuthClient = Auth0AuthJs.AuthClient;
  const spy = vi.spyOn(Auth0AuthJs, 'AuthClient').mockImplementation((options) => {
    return new OriginalAuthClient({ ...options, discoveryCache: { ttl: 0 } });
  });

  try {
    const serverClient = new ServerClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      stateStore: new DefaultStateStore({ secret: '<secret>' }),
      transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    });

    await serverClient.startInteractiveLogin({
      authorizationParams: { redirect_uri: '/test_redirect_uri' },
    });

    expect(capturedHeader).toBeDefined();
    const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
    expect(decoded.name).toBe('@auth0/auth0-server-js');
    expect(decoded.version).toMatch(/^\d+\.\d+\.\d+/);
  } finally {
    // Restore the underlying AuthClient
    spy.mockRestore();
  }
});

test('Telemetry - should allow custom telemetry name and version', async () => {
  let capturedHeader: string | null = null;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, ({ request }) => {
      capturedHeader = request.headers.get('Auth0-Client');
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );

  // Mock the underlying AuthClient to disable caching and ensure the header is captured on every request
  const OriginalAuthClient = Auth0AuthJs.AuthClient;
  const spy = vi.spyOn(Auth0AuthJs, 'AuthClient').mockImplementation((options) => {
    return new OriginalAuthClient({ ...options, discoveryCache: { ttl: 0 } });
  });

  try {
    const serverClient = new ServerClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      stateStore: new DefaultStateStore({ secret: '<secret>' }),
      transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
      telemetry: {
        name: 'my-custom-server-app',
        version: '3.0.0',
      },
    });

    await serverClient.startInteractiveLogin({
      authorizationParams: { redirect_uri: '/test_redirect_uri' },
    });

    expect(capturedHeader).toBeDefined();
    const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
    expect(decoded.name).toBe('my-custom-server-app');
    expect(decoded.version).toBe('3.0.0');
  } finally {
    // Restore the underlying AuthClient
    spy.mockRestore();
  }
});

test('Telemetry - should not include Auth0-Client header when telemetry is disabled', async () => {
  let capturedHeader: string | null = null;
  server.use(
    http.get(`https://${domain}/.well-known/openid-configuration`, ({ request }) => {
      capturedHeader = request.headers.get('Auth0-Client');
      return HttpResponse.json(mockOpenIdConfiguration);
    })
  );
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
    telemetry: { enabled: false },
  });

  await serverClient.startInteractiveLogin({
    authorizationParams: { redirect_uri: '/test_redirect_uri' },
  });

  expect(capturedHeader).toBeNull();
});

test('Telemetry - should include Auth0-Client header in token requests', async () => {
  let capturedHeader: string | null = null;
  server.use(
    http.post(mockOpenIdConfiguration.backchannel_authentication_endpoint, async ({ request }) => {
      capturedHeader = request.headers.get('Auth0-Client');
      return HttpResponse.json({
        auth_req_id: 'auth_req_123',
        interval: 0.5,
        expires_in: 60,
      });
    })
  );

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
  });

  await serverClient.loginBackchannel({
    bindingMessage: '<binding_message>',
    loginHint: { sub: '<sub>' },
  });

  expect(capturedHeader).toBeDefined();
  const decoded = JSON.parse(Buffer.from(capturedHeader!, 'base64').toString());
  expect(decoded.name).toBe('@auth0/auth0-server-js');
  expect(decoded.version).toMatch(/^\d+\.\d+\.\d+/);
});

test('passkeyRegister - should return the signup challenge and not write to the state store', async () => {
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
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  const result = await serverClient.passkeyRegister({ email: 'jane@example.com', name: 'Jane' });

  expect(result.authSession).toBe('auth_session_register_123');
  expect(result.authnParamsPublicKey.challenge).toBe('register_challenge');
  expect(mockStateStore.set).not.toHaveBeenCalled();
});

test('passkeyChallenge - should return the login challenge and not write to the state store', async () => {
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
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  const result = await serverClient.passkeyChallenge();

  expect(result.authSession).toBe('auth_session_challenge_123');
  expect(result.authnParamsPublicKey.challenge).toBe('login_challenge');
  expect(mockStateStore.set).not.toHaveBeenCalled();
});

test('passkeyGetToken - should exchange the credential and store the access token', async () => {
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
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  await serverClient.passkeyGetToken({
    authSession: 'auth_session_challenge_123',
    credential: fakePasskeyCredential,
  });

  const stateData = mockStateStore.set.mock.calls[0]?.[1];

  expect(stateData.tokenSets.length).toBe(1);
  expect(stateData.tokenSets[0].accessToken).toBe(accessToken);
});

test('passkeyGetToken - should always include openid in a custom scope', async () => {
  let capturedScope: string | null = null;
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
      // Passkey grant sends application/json (see note on the default handler).
      const info = (request.headers.get('content-type') ?? '').includes('application/json')
        ? new Map(Object.entries((await request.json()) as Record<string, unknown>))
        : await request.formData();
      capturedScope = info.get('scope')?.toString() ?? null;
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: capturedScope ?? '<scope>',
      });
    })
  );

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  await serverClient.passkeyGetToken({
    authSession: 'auth_session_challenge_123',
    credential: fakePasskeyCredential,
    scope: 'profile email',
  });

  expect(capturedScope).toBe('openid profile email');
});

test('passkeyChallenge - should throw when the challenge endpoint fails', async () => {
  server.use(
    http.post(`https://${domain}/passkey/challenge`, () => {
      return HttpResponse.json({ error: '<error_code>', error_description: '<error_description>' }, { status: 400 });
    })
  );

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  await expect(serverClient.passkeyChallenge()).rejects.toThrowError();
});

test('passkeyRegister - should throw when the register endpoint fails', async () => {
  server.use(
    http.post(`https://${domain}/passkey/register`, () => {
      return HttpResponse.json({ error: '<error_code>', error_description: '<error_description>' }, { status: 400 });
    })
  );

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  await expect(serverClient.passkeyRegister({ email: 'jane@example.com', name: 'Jane' })).rejects.toThrowError();
});

test('passkeyGetToken - should propagate an mfa_required error and not write to the state store', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () =>
      HttpResponse.json(
        {
          error: 'mfa_required',
          error_description: 'MFA required.',
          mfa_token: '<mfa_token>',
          mfa_requirements: { challenge: [{ type: 'otp' }] },
        },
        { status: 403 }
      )
    )
  );

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
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: mockStateStore,
  });

  const error = await serverClient
    .passkeyGetToken({ authSession: 'auth_session_challenge_123', credential: fakePasskeyCredential })
    .catch((e) => e);

  expect(isMfaRequiredError(error)).toBe(true);
  expect(error.cause.mfa_token).toBe('<mfa_token>');
  expect(mockStateStore.set).not.toHaveBeenCalled();
});

test('passkeyGetToken - should return the authorizationDetails when present in the response', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () =>
      HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>'),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
        authorization_details: [{ type: 'accepted' }],
      })
    )
  );

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  const result = await serverClient.passkeyGetToken({
    authSession: 'auth_session_challenge_123',
    credential: fakePasskeyCredential,
  });

  expect(result.authorizationDetails).toEqual([{ type: 'accepted' }]);
});

test('passkeyGetToken - should forward audience and organization to the grant', async () => {
  let capturedAudience: string | null = null;
  let capturedOrganization: string | null = null;
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
      // Passkey grant sends application/json (see note on the default handler).
      const info = (request.headers.get('content-type') ?? '').includes('application/json')
        ? new Map(Object.entries((await request.json()) as Record<string, unknown>))
        : await request.formData();
      capturedAudience = info.get('audience')?.toString() ?? null;
      capturedOrganization = info.get('organization')?.toString() ?? null;
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', undefined, { org_id: 'org_123' }),
        expires_in: 60,
        token_type: 'Bearer',
        scope: '<scope>',
      });
    })
  );

  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() },
  });

  await serverClient.passkeyGetToken({
    authSession: 'auth_session_challenge_123',
    credential: fakePasskeyCredential,
    audience: 'https://api.example.com',
    organization: 'org_123',
  });

  expect(capturedAudience).toBe('https://api.example.com');
  expect(capturedOrganization).toBe('org_123');
});

describe('passwordless (session layer)', () => {
  const PASSWORDLESS_GRANT = 'http://auth0.com/oauth/grant-type/passwordless/otp';
  const startUrl = `https://${domain}/passwordless/start`;

  let lastStartBody: Record<string, unknown> | null;
  let lastOtpForm: URLSearchParams | null;
  let startCount: number;

  const newServerClient = (extra?: Record<string, unknown>) =>
    new ServerClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      stateStore: new DefaultStateStore({ secret: '<secret>' }),
      transactionStore: new DefaultTransactionStore({ secret: '<secret>' }),
      ...extra,
    });

  // Capture /passwordless/start request bodies.
  const captureStart = (status = 200) =>
    server.use(
      http.post(startUrl, async ({ request }) => {
        startCount += 1;
        lastStartBody = (await request.json()) as Record<string, unknown>;
        return status === 204 ? new HttpResponse(null, { status: 204 }) : HttpResponse.json({}, { status });
      })
    );

  // Capture the OTP grant form posted to the token endpoint.
  const captureOtp = (respond?: (form: URLSearchParams) => Response | Promise<Response>) =>
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const form = new URLSearchParams(await request.text());
        if (form.get('grant_type') === PASSWORDLESS_GRANT) {
          lastOtpForm = form;
          if (respond) {
            return respond(form);
          }
          return HttpResponse.json({
            access_token: accessToken,
            id_token: await generateToken(domain, 'user_123', '<client_id>'),
            expires_in: 86400,
            token_type: 'Bearer',
            scope: form.get('scope') ?? '<scope>',
          });
        }
        return HttpResponse.json({ access_token: accessToken, expires_in: 60, token_type: 'Bearer' });
      })
    );

  beforeEach(() => {
    lastStartBody = null;
    lastOtpForm = null;
    startCount = 0;
  });

  test('FT-1: startPasswordlessEmail delegates to token layer (stateless)', async () => {
    captureStart();
    await newServerClient().startPasswordlessEmail({ email: 'user@example.com', send: 'code' });

    expect(startCount).toBe(1);
    expect(lastStartBody).toMatchObject({ email: 'user@example.com', send: 'code', connection: 'email' });
  });

  test('FT-2: startPasswordlessEmail forwards link options incl authParams (camelCase)', async () => {
    captureStart();
    await newServerClient().startPasswordlessEmail({
      email: 'user@example.com',
      send: 'link',
      authParams: { redirect_uri: 'https://app/cb', scope: 'openid' },
    });

    expect(lastStartBody!.send).toBe('link');
    expect(lastStartBody!.authParams).toMatchObject({ redirect_uri: 'https://app/cb' });
    expect(lastStartBody!).not.toHaveProperty('auth_params');
  });

  test('FT-3: startPasswordlessSms delegates; no delivery_method', async () => {
    captureStart();
    await newServerClient().startPasswordlessSms({ phoneNumber: '+14155550100' });

    expect(lastStartBody).toMatchObject({ phone_number: '+14155550100', connection: 'sms' });
    expect(lastStartBody!).not.toHaveProperty('delivery_method');
  });

  test('FT-4: loginWithPasswordlessEmail exchanges OTP and persists session', async () => {
    captureOtp();
    const serverClient = newServerClient();

    await serverClient.loginWithPasswordlessEmail({
      email: 'user@example.com',
      code: '123456',
      authorizationParams: { scope: 'openid profile' },
    });

    expect(lastOtpForm!.get('grant_type')).toBe(PASSWORDLESS_GRANT);
    expect(lastOtpForm!.get('username')).toBe('user@example.com');
    expect(lastOtpForm!.get('otp')).toBe('123456');
    expect(lastOtpForm!.get('realm')).toBe('email');
    expect(lastOtpForm!.get('scope')).toContain('openid');
    expect((await serverClient.getAccessToken()).accessToken).toBe(accessToken);
  });

  test('FT-5: session retrievable after login', async () => {
    captureOtp();
    const serverClient = newServerClient();

    await serverClient.loginWithPasswordlessEmail({ email: 'user@example.com', code: '123456' });

    expect(await serverClient.getUser()).toBeDefined();
    expect((await serverClient.getAccessToken()).accessToken).toBe(accessToken);
  });

  test('FT-6: ensureOpenId injects openid when caller scope omits it', async () => {
    captureOtp();
    await newServerClient().loginWithPasswordlessEmail({
      email: 'user@example.com',
      code: '123456',
      authorizationParams: { scope: 'profile email' },
    });

    const scope = lastOtpForm!.get('scope')!;
    expect(scope.split(' ')).toContain('openid');
  });

  test('FT-7: mfa_required propagates from token layer, narrowable via isMfaRequiredError', async () => {
    captureOtp(() =>
      HttpResponse.json(
        { error: 'mfa_required', error_description: 'MFA required', mfa_token: 'mt' },
        { status: 403 }
      )
    );

    const error = await newServerClient()
      .loginWithPasswordlessEmail({ email: 'user@example.com', code: '123456' })
      .catch((e) => e);

    expect(error).toBeInstanceOf(Auth0AuthJs.PasswordlessVerifyError);
    expect(Auth0AuthJs.isMfaRequiredError(error)).toBe(true);
    if (Auth0AuthJs.isMfaRequiredError(error)) {
      expect(error.cause.mfa_token).toBe('mt');
    }
  });

  test('FT-8: PasswordlessVerifyError propagates from token layer', async () => {
    captureOtp(() =>
      HttpResponse.json({ error: 'invalid_grant', error_description: 'Invalid code' }, { status: 403 })
    );

    await expect(
      newServerClient().loginWithPasswordlessEmail({ email: 'user@example.com', code: 'wrong' })
    ).rejects.toBeInstanceOf(Auth0AuthJs.PasswordlessVerifyError);
  });

  test('FT-9: loginWithPasswordlessSms exchanges + persists (realm=sms)', async () => {
    captureOtp();
    const serverClient = newServerClient();

    await serverClient.loginWithPasswordlessSms({ phoneNumber: '+14155550100', code: '123456' });

    expect(lastOtpForm!.get('realm')).toBe('sms');
    expect(lastOtpForm!.get('username')).toBe('+14155550100');
    expect((await serverClient.getAccessToken()).accessToken).toBe(accessToken);
  });

  test('FT-10: resolver mode routes to resolved domain for start + login', async () => {
    captureStart();
    captureOtp();
    const domainResolver = vi.fn().mockResolvedValue(domain);
    const serverClient = newServerClient({ domain: domainResolver });

    await serverClient.startPasswordlessEmail({ email: 'user@example.com' }, { ctx: 1 } as never);
    await serverClient.loginWithPasswordlessEmail({ email: 'user@example.com', code: '123456' }, { ctx: 1 } as never);

    expect(domainResolver).toHaveBeenCalled();
    expect(startCount).toBe(1);
    expect(lastOtpForm!.get('realm')).toBe('email');
  });

  test('FT-10b: resolver throwing propagates (no silent session write)', async () => {
    const domainResolver = vi.fn().mockRejectedValue(new Error('resolver boom'));
    const serverClient = newServerClient({ domain: domainResolver });

    await expect(
      serverClient.loginWithPasswordlessEmail({ email: 'user@example.com', code: '123456' }, { ctx: 1 } as never)
    ).rejects.toThrow('resolver boom');
  });

  // Capture the authorization_code grant posted to the token endpoint (magic-link completion).
  let lastCodeForm: URLSearchParams | null = null;
  const captureCodeGrant = (respond?: (form: URLSearchParams) => Response | Promise<Response>) =>
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const form = new URLSearchParams(await request.text());
        lastCodeForm = form;
        if (respond) {
          return respond(form);
        }
        return HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_123', '<client_id>'),
          expires_in: 86400,
          token_type: 'Bearer',
          scope: form.get('scope') ?? '<scope>',
        });
      })
    );

  const mockStores = () => {
    const transactionStore = { get: vi.fn(), set: vi.fn(), delete: vi.fn() };
    const stateStore = { get: vi.fn(), set: vi.fn(), delete: vi.fn(), deleteByLogoutToken: vi.fn() };
    stateStore.get.mockResolvedValue(undefined);
    return { transactionStore, stateStore };
  };

  test('FT-11: startPasswordlessMagicLink sends link + persists state, no codeVerifier', async () => {
    captureStart();
    const { transactionStore, stateStore } = mockStores();
    const serverClient = newServerClient({ transactionStore, stateStore });

    await serverClient.startPasswordlessMagicLink({
      email: 'user@example.com',
      redirectUri: 'https://app.example.com/auth/callback',
      scope: 'profile',
    });

    expect(lastStartBody!.send).toBe('link');
    const authParams = lastStartBody!.authParams as Record<string, unknown>;
    expect(authParams.redirect_uri).toBe('https://app.example.com/auth/callback');
    expect(authParams.response_type).toBe('code');
    expect((authParams.scope as string).split(' ')).toContain('openid');
    expect(authParams.state).toBeTruthy();

    expect(transactionStore.set).toHaveBeenCalledTimes(1);
    const persisted = transactionStore.set.mock.calls[0]![1];
    expect(persisted.state).toBe(authParams.state);
    expect(persisted).not.toHaveProperty('codeVerifier');
  });

  test('FT-12: completePasswordlessMagicLink validates state, exchanges (no PKCE), persists', async () => {
    captureCodeGrant();
    const { transactionStore, stateStore } = mockStores();
    transactionStore.get.mockResolvedValue({ state: 's1', domain });
    const serverClient = newServerClient({ transactionStore, stateStore });

    const result = await serverClient.completePasswordlessMagicLink(
      new URL(`https://${domain}/cb?code=123&state=s1`)
    );

    expect(lastCodeForm!.get('grant_type')).toBe('authorization_code');
    expect(lastCodeForm!.has('code_verifier')).toBe(false);
    expect(stateStore.set).toHaveBeenCalledTimes(1);
    expect(transactionStore.delete).toHaveBeenCalledTimes(1);
    expect(result).toBeDefined();
  });

  test('FT-13: completePasswordlessMagicLink throws MissingTransactionError when no transaction', async () => {
    const { transactionStore, stateStore } = mockStores();
    transactionStore.get.mockResolvedValue(undefined);
    const serverClient = newServerClient({ transactionStore, stateStore });

    await expect(
      serverClient.completePasswordlessMagicLink(new URL(`https://${domain}/cb?code=123&state=s1`))
    ).rejects.toBeInstanceOf(MissingTransactionError);
  });

  test('FT-14: state mismatch throws PasswordlessVerifyError, no exchange, no delete', async () => {
    let exchangeCalled = false;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async () => {
        exchangeCalled = true;
        return HttpResponse.json({ access_token: accessToken, expires_in: 60, token_type: 'Bearer' });
      })
    );
    const { transactionStore, stateStore } = mockStores();
    transactionStore.get.mockResolvedValue({ state: 's1', domain });
    const serverClient = newServerClient({ transactionStore, stateStore });

    await expect(
      serverClient.completePasswordlessMagicLink(new URL(`https://${domain}/cb?code=123&state=tampered`))
    ).rejects.toBeInstanceOf(Auth0AuthJs.PasswordlessVerifyError);
    expect(exchangeCalled).toBe(false);
    expect(transactionStore.delete).not.toHaveBeenCalled();
  });

  test('FT-15: absent state on callback throws PasswordlessVerifyError', async () => {
    const { transactionStore, stateStore } = mockStores();
    transactionStore.get.mockResolvedValue({ state: 's1', domain });
    const serverClient = newServerClient({ transactionStore, stateStore });

    await expect(
      serverClient.completePasswordlessMagicLink(new URL(`https://${domain}/cb?code=123`))
    ).rejects.toBeInstanceOf(Auth0AuthJs.PasswordlessVerifyError);
  });

  test('FT-16: magic-link methods resolve domain in resolver mode', async () => {
    captureStart();
    captureCodeGrant();
    const domainResolver = vi.fn().mockResolvedValue(domain);
    const { transactionStore, stateStore } = mockStores();
    transactionStore.get.mockResolvedValue({ state: 's1', domain });
    const serverClient = newServerClient({ domain: domainResolver, transactionStore, stateStore });

    await serverClient.startPasswordlessMagicLink(
      { email: 'user@example.com', redirectUri: 'https://app/cb' },
      { ctx: 1 } as never
    );
    await serverClient.completePasswordlessMagicLink(new URL(`https://${domain}/cb?code=123&state=s1`), {
      ctx: 1,
    } as never);

    expect(domainResolver).toHaveBeenCalled();
  });

  test('FT-17: startPasswordlessMagicLink ensures openid even when scope omits it', async () => {
    captureStart();
    const { transactionStore, stateStore } = mockStores();
    const serverClient = newServerClient({ transactionStore, stateStore });

    await serverClient.startPasswordlessMagicLink({
      email: 'user@example.com',
      redirectUri: 'https://app/cb',
      scope: 'profile email',
    });

    const authParams = lastStartBody!.authParams as Record<string, unknown>;
    expect((authParams.scope as string).split(' ')).toContain('openid');
  });

  test('FT-18: completeInteractiveLogin still completes a PKCE transaction (regression)', async () => {
    captureCodeGrant();
    const { transactionStore, stateStore } = mockStores();
    // Interactive transaction: carries a codeVerifier (the field stayed required at runtime).
    transactionStore.get.mockResolvedValue({ codeVerifier: '<code_verifier>', domain });
    const serverClient = newServerClient({ transactionStore, stateStore });

    await serverClient.completeInteractiveLogin(new URL(`https://${domain}?code=123`));

    // PKCE path unchanged by the optional-codeVerifier widening: verifier sent on the wire.
    expect(lastCodeForm!.get('code_verifier')).toBe('<code_verifier>');
    expect(stateStore.set).toHaveBeenCalledTimes(1);
    expect(transactionStore.delete).toHaveBeenCalledTimes(1);
  });
});
