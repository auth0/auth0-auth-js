import { expect, test, afterAll, afterEach, beforeAll, beforeEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';
import Fastify from 'fastify';
import plugin from './index.js';
import { decrypt, encrypt } from './store/test-utils.js';

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

test('auth/login redirects to authorize', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    secret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/auth/callback');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('state')).toBeDefined();
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(7);
});

test('auth/login should put the appState in the transaction store', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    secret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?returnTo=http://localhost:3000/custom-return',
  });
  const cookieName = '__a0_tx';
  const encryptedCookieValue = res.headers['set-cookie']?.toString().replace(`${cookieName}=`, '').split(';')[0];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cookieValue = encryptedCookieValue && await decrypt(encryptedCookieValue, '<secret>', cookieName) as any;
  
  expect(cookieValue?.appState?.returnTo).toBe('http://localhost:3000/custom-return');
});

test('auth/callback redirects to /', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    secret: '<secret>',
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({ state: 'xyz' }, '<secret>', cookieName);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/callback?code=123&state=xyz`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('auth/callback redirects to returnTo in state', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    secret: '<secret>',
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt(
    { state: 'xyz', appState: { returnTo: 'http://localhost:3000/custom-return' } },
    '<secret>',
    cookieName
  );
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/callback?code=123&state=xyz`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/custom-return');
  expect(url.searchParams.size).toBe(0);
});

test('auth/profile returns user information', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    secret: '<secret>',
  });

  const cookieName = '__a0_session';
  const cookieValue = await encrypt({ user: { sub: '<sub>' } }, '<secret>', cookieName);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/profile`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });

  expect(res.json().sub).toBe('<sub>');
});

test('auth/logout redirects to logout', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    secret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/logout',
  });
  const url = new URL(res.headers['location']?.toString() || '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/logout');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:3000');
  expect(url.searchParams.size).toBe(2);
});
