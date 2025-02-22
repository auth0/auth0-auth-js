import { expect, test, afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { Auth0Client } from './auth0-client.js';

import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';

const domain = 'auth0.local';
let accessToken: string;
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.post(mockOpenIdConfiguration.backchannel_authentication_endpoint, () => {
    return HttpResponse.json({
      auth_req_id: 'auth_req_123',
      expires_in: 60,
    });
  }),

  http.post(mockOpenIdConfiguration.token_endpoint, async () => {
    return HttpResponse.json({
      access_token: accessToken,
      id_token: await generateToken(domain, 'user_123', '<client_id>'),
      expires_in: 60,
      token_type: 'Bearer',
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
    authorization_endpoint: `https://${domain}/authorize`,
    backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
    token_endpoint: `https://${domain}/custom/token`,
    end_session_endpoint: `https://${domain}/logout`,
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

test('buildAuthorizationUrl - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await expect(
    auth0Client.buildAuthorizationUrl({
      authorizationParams: {
        redirect_uri: '/test_redirect_uri',
      },
    })
  ).rejects.toThrowError('The client was not initialized. Ensure to call `init()`.');
});

test('buildAuthorizationUrl - should build the authorization url', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();
  const url = await auth0Client.buildAuthorizationUrl({
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
    },
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('client_secret')).toBe('<client_secret>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.size).toBe(6);
});

test('buildAuthorizationUrl - should build the authorization url with audience when provided', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();
  const url = await auth0Client.buildAuthorizationUrl({
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      audience: '<audience>',
    },
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('client_secret')).toBe('<client_secret>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('audience')).toBe('<audience>');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.size).toBe(7);
});

test('buildAuthorizationUrl - should build the authorization url with scope when provided', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();
  const url = await auth0Client.buildAuthorizationUrl({
    authorizationParams: {
      redirect_uri: '/test_redirect_uri',
      scope: '<scope>',
    },
  });

  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('client_secret')).toBe('<client_secret>');
  expect(url.searchParams.get('redirect_uri')).toBe('/test_redirect_uri');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('scope')).toBe('<scope>');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.size).toBe(6);
});

test('handleCallback - should throw when init was not called', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await expect(auth0Client.handleCallback(new URL(`https://${domain}`))).rejects.toThrowError(
    'The client was not initialized. Ensure to call `init()`.'
  );
});

test('handleCallback - should throw when no state query param', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();

  await expect(auth0Client.handleCallback(new URL(`https://${domain}?code=123`))).rejects.toThrowError(
    'The state parameter is missing.'
  );
});

test('handleCallback - should throw when no transaction', async () => {
  const auth0Client = new Auth0Client({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    secret: '<secret>',
  });

  await auth0Client.init();

  await expect(auth0Client.handleCallback(new URL(`https://${domain}?code=123&state=abc`))).rejects.toThrowError(
    'The state parameter is invalid.'
  );
});

test('handleCallback - should throw when state not found in transaction', async () => {
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
    }
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({});

  await expect(auth0Client.handleCallback(new URL(`https://${domain}?code=123&state=abc`))).rejects.toThrowError(
    'The state parameter is invalid.'
  );
});

test('handleCallback - should throw when state mismatch', async () => {
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
    }
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await expect(auth0Client.handleCallback(new URL(`https://${domain}?code=123&state=abc`))).rejects.toThrowError(
    'The state parameter is invalid.'
  );
});

test('handleCallback - should return the access token from the token endpoint', async () => {
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
    }
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  const token = await auth0Client.handleCallback(new URL(`https://${domain}?code=123&state=xyz`));

  expect(token).toBe(accessToken);
});

test('handleCallback - should delete stored transaction', async () => {
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
    }
  });

  await auth0Client.init();

  mockTransactionStore.get.mockResolvedValue({ state: 'xyz' });

  await auth0Client.handleCallback(new URL(`https://${domain}?code=123&state=xyz`));

  expect(mockTransactionStore.delete).toBeCalled();
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
