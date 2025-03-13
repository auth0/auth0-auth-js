import {
  expect,
  test,
  afterAll,
  beforeAll,
  afterEach,
  vi,
  beforeEach,
} from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './test-utils/tokens.js';
import { ApiAuthClient } from './api-auth-client.js';

const domain = 'auth0.local';
let accessToken: string;
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
  authorization_endpoint: `https://${domain}/authorize`,
  token_endpoint: `https://${domain}/oauth/token`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
  http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
    const info = await request.formData();

    const shouldFailTokenExchange = info.get('code') === '<code_should_fail>';

    return shouldFailTokenExchange
      ? HttpResponse.json(
          { error: '<error_code>', error_description: '<error_description>' },
          { status: 400 }
        )
      : HttpResponse.json({
          access_token: accessToken,
          id_token: await generateToken(domain, 'user_123', '<client_id>'),
          refresh_token: '<refresh_token>',
          expires_in: 60,
          token_type: 'Bearer',
          scope: '<scope>',
          ...(info.get('auth_req_id') === 'auth_req_with_authorization_details'
            ? { authorization_details: [{ type: 'accepted' }] }
            : {}),
        });
  }),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
});

afterEach(() => {
  mockOpenIdConfiguration = {
    issuer: `https://${domain}/`,
    jwks_uri: `https://${domain}/.well-known/jwks.json`,
    authorization_endpoint: `https://${domain}/authorize`,
    token_endpoint: `https://${domain}/oauth/token`,
  };
  server.resetHandlers();
});

test('should not create an instance when no transactionStore provided', () => {
  expect(
    () =>
      new ApiAuthClient({
        domain: '',
        clientId: '',
        clientSecret: '',
        //eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any)
  ).toThrowError(
    `The argument 'transactionStore' is required but was not provided.`
  );
});

test('startLinkUser - should throw when no idToken provided', async () => {
  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await expect(
    apiAuthClient.startLinkUser({
      connection: '<connection>',
      connectionScope: '<connection_scope>',
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any)
  ).rejects.toThrowError(
    `The argument 'idToken' is required but was not provided.`
  );
});

test('startLinkUser - should build the link user url', async () => {
  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
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
  });

  const linkUserUrl = await apiAuthClient.startLinkUser({
    connection: '<connection>',
    connectionScope: '<connection_scope>',
    idToken: '<id_token>',
  });

  expect(linkUserUrl.host).toBe(domain);
  expect(linkUserUrl.pathname).toBe('/authorize');
  expect(linkUserUrl.searchParams.get('client_id')).toBe('<client_id>');
  expect(linkUserUrl.searchParams.get('redirect_uri')).toBe(
    '/test_redirect_uri'
  );
  expect(linkUserUrl.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(linkUserUrl.searchParams.get('audience')).toBe('<audience>');
  expect(linkUserUrl.searchParams.get('response_type')).toBe('code');
  expect(linkUserUrl.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(linkUserUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(linkUserUrl.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(linkUserUrl.searchParams.get('requested_connection')).toBe(
    '<connection>'
  );
  expect(linkUserUrl.searchParams.get('requested_connection_scope')).toBe(
    '<connection_scope>'
  );
  expect(linkUserUrl.searchParams.size).toBe(10);
});

test('startLinkUser - should put appState in transaction store', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
    transactionStore: mockTransactionStore,
  });

  await apiAuthClient.startLinkUser({
    connection: '<connection>',
    connectionScope: '<connection_scope>',
    idToken: '<id_token>',
    appState: {
      returnTo: 'foo',
    },
  });
  expect(mockTransactionStore.set).toHaveBeenCalledWith(
    '__a0_api_tx',
    expect.objectContaining({
      appState: {
        returnTo: 'foo',
      },
    }),
    undefined
  );
});

test('startLinkUser - should put connection in transaction store', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
      foo: '<bar>',
    },
    transactionStore: mockTransactionStore,
  });

  await apiAuthClient.startLinkUser({
    connection: '<connection>',
    connectionScope: '<connection_scope>',
    idToken: '<id_token>',
  });
  expect(mockTransactionStore.set).toHaveBeenCalledWith(
    '__a0_api_tx',
    expect.objectContaining({
      connection: '<connection>',
    }),
    undefined
  );
});

test('completeLinkUser - should throw when no transaction', async () => {
  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await expect(
    apiAuthClient.completeLinkUser(
      new URL(`https://${domain}?code=123&state=abc`)
    )
  ).rejects.toThrowError('The transaction is missing.');
});

test('completeLinkUser - should throw an error when token exchange failed', async () => {
  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: {
      get: vi.fn().mockResolvedValue({}),
      set: vi.fn(),
      delete: vi.fn(),
    },
  });

  await expect(
    apiAuthClient.completeLinkUser(
      new URL(`https://${domain}?code=<code_should_fail>`)
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

test('completeLinkUser - should return the appState', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
  });

  mockTransactionStore.get.mockResolvedValue({ appState: { foo: '<bar>' } });

  const { appState } = await apiAuthClient.completeLinkUser<{ foo: string }>(
    new URL(`https://${domain}?code=123`)
  );

  expect(appState!.foo).toBe('<bar>');
});

test('completeLinkUser - should delete stored transaction', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
  });

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await apiAuthClient.completeLinkUser(new URL(`https://${domain}?code=123`));

  expect(mockTransactionStore.delete).toBeCalled();
});

test('completeLinkUser - should call onUserLinked', async () => {
  const mockTransactionStore = {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
  };

  const mockOnUserLinked = vi.fn();

  const apiAuthClient = new ApiAuthClient({
    domain,
    audience: '<audience>',
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: mockTransactionStore,
    onUserLinked: mockOnUserLinked,
  });

  mockTransactionStore.get.mockResolvedValue({
    connection: '<connection>',
    state: 'xyz',
  });

  await apiAuthClient.completeLinkUser(new URL(`https://${domain}?code=123`));

  expect(mockOnUserLinked).toBeCalledWith(
    'user_123',
    '<connection>',
    '<refresh_token>'
  );
});
