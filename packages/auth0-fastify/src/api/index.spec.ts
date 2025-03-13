import { expect, test, afterAll, afterEach, beforeAll } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './../test-utils/tokens.js';
import Fastify from 'fastify';
import fastifyAuth0Api from './index.js';
import { decrypt, encrypt } from 'src/encryption.js';

const domain = 'auth0.local';
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
  http.post(mockOpenIdConfiguration.token_endpoint, async () => {
    const accessToken = await generateToken(domain, 'user_123');
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

afterEach(() => {
  mockOpenIdConfiguration = {
    issuer: `https://${domain}/`,
    authorization_endpoint: `https://${domain}/authorize`,
    backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
    token_endpoint: `https://${domain}/custom/token`,
    end_session_endpoint: `https://${domain}/logout`,
    jwks_uri: `https://${domain}/.well-known/jwks.json`,
  };
  server.resetHandlers();
});

test('should return 400 when no token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('No Authorization provided');
});

test('should return 200 when valid token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should return 401 when no issuer in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', undefined, false);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "iss" claim');
});

test('should return 401 when invalid issuer in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', 'https://invalid-issuer.local');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('unexpected "iss" claim value');
});

test('should return 401 when no audience in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "aud" claim');
});

test('should return 401 when no iat in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, false, undefined, {
    scope: 'valid',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "iat" claim');
});

test('should return 401 when no exp in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, false);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "exp" claim');
});

test('should return 401 when invalid audience in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<invalid_audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('unexpected "aud" claim value');
});

test('should throw when no audience configured', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  await expect(
    fastify.inject({
      method: 'GET',
      url: '/test',
    })
  ).rejects.toThrowError('In order to use the Auth0 Api plugin, you must provide an audience.');
});

test('should return 403 when invalid scope in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
    scope: 'invalid',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth({ scopes: 'valid' }),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(403);
  expect(res.json().error).toBe('insufficient_scope');
  expect(res.json().error_description).toBe('Insufficient scopes');
});

test('should return 200 when valid audience in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should return 200 when valid scope in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
    scope: 'valid',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth({ scopes: 'valid' }),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should not register api plugin without clientId when apiAsClient is enabled', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  });

  await expect(
    fastify.inject({
      method: 'GET',
      url: '/test',
    })
  ).rejects.toThrowError("The argument 'clientId' is required but was not provided.");
});

test('should not register api plugin without appBaseUrl when apiAsClient is enabled', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  });

  await expect(
    fastify.inject({
      method: 'GET',
      url: '/test',
    })
  ).rejects.toThrowError("The argument 'appBaseUrl' is required but was not provided.");
});

test('should not register api plugin without apiBaseUrl when apiAsClient is enabled', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      appBaseUrl: 'http://localhost:3000',
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  });

  await expect(
    fastify.inject({
      method: 'GET',
      url: '/test',
    })
  ).rejects.toThrowError("The argument 'apiBaseUrl' is required but was not provided.");
});

test('api/connect/start returns 500 when ticketSecret not configured', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      audience: '<audience_2>',
      mountRoutes: true,
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  const res = await fastify.inject({
    method: 'POST',
    url: '/api/connect/start',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    body: { idToken: '<id_token>' },
  });

  expect(res.statusCode).toBe(500);
  expect(res.json().error).toBe('internal_error');
  expect(res.json().error_description).toBe('ticketSecret is not configured');
});

test('api/connect/start returns a ticket', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  const res = await fastify.inject({
    method: 'POST',
    url: '/api/connect/start',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    body: { idToken: '<id_token>' },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().ticket).toBeTypeOf('string');

  const decodedTicket = await decrypt(res.json().ticket, '<secret>', '');

  expect(decodedTicket.idToken).toBe('<id_token>');
});

test('api/connect returns 400 when ticket not provided', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect?connection=<connection>`,
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('ticket is required');
});

test('api/connect returns 400 when connection not provided', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const ticket = await encrypt({ idToken: '<id_token>' }, '<secret>', '', Date.now() + 500);

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect?ticket=${ticket}`,
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('connection is required');
});

test('api/connect redirects to /authorize', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const ticket = await encrypt({ idToken: '<id_token>' }, '<secret>', '', Date.now() + 500);

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect?ticket=${ticket}&connection=<connection>`,
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3001/api/connect/callback');
  expect(url.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('audience')).toBe('<audience_2>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.size).toBe(9);
});

test('api/connect redirects to authorize when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001/subpath',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const ticket = await encrypt({ idToken: '<id_token>' }, '<secret>', '', Date.now() + 500);

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect?ticket=${ticket}&connection=<connection>`,
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3001/subpath/api/connect/callback');
  expect(url.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('audience')).toBe('<audience_2>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.size).toBe(9);
});

test('api/connect/callback redirects to /', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const cookieName = '__a0_api_tx';
  const cookieValue = JSON.stringify({});
  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect/callback?code=123`,
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

test('api/connect/callback redirects to / when not using a root apiBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000/subpath',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const cookieName = '__a0_api_tx';
  const cookieValue = JSON.stringify({});
  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/subpath');
  expect(url.searchParams.size).toBe(0);
});

test('api/connect/callback redirects to returnTo in state', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const cookieName = '__a0_api_tx';
  const cookieValue = JSON.stringify({ appState: { returnTo: 'http://localhost:3000/custom-return' } });
  const res = await fastify.inject({
    method: 'GET',
    url: `/api/connect/callback?code=123`,
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

test('api/unconnect/start returns 500 when ticketSecret not configured', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      audience: '<audience_2>',
      mountRoutes: true,
      //eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  const res = await fastify.inject({
    method: 'POST',
    url: '/api/unconnect/start',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    body: { idToken: '<id_token>' },
  });

  expect(res.statusCode).toBe(500);
  expect(res.json().error).toBe('internal_error');
  expect(res.json().error_description).toBe('ticketSecret is not configured');
});

test('api/unconnect/start returns a ticket', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  const res = await fastify.inject({
    method: 'POST',
    url: '/api/unconnect/start',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
    body: { idToken: '<id_token>' },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().ticket).toBeTypeOf('string');

  const decodedTicket = await decrypt(res.json().ticket, '<secret>', '');

  expect(decodedTicket.idToken).toBe('<id_token>');
});

test('api/unconnect returns 400 when ticket not provided', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect?connection=<connection>`,
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('ticket is required');
});

test('api/unconnect returns 400 when connection not provided', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      apiBaseUrl: 'http://localhost:3001',
      appBaseUrl: 'http://localhost:3000',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const ticket = await encrypt({ idToken: '<id_token>' }, '<secret>', '', Date.now() + 500);

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect?ticket=${ticket}`,
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('connection is required');
});

test('api/unconnect redirects to /authorize', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const ticket = await encrypt({ idToken: '<id_token>' }, '<secret>', '', Date.now() + 500);

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect?ticket=${ticket}&connection=<connection>`,
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3001/api/unconnect/callback');
  expect(url.searchParams.get('scope')).toBe('openid unlink_account');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('audience')).toBe('<audience_2>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.size).toBe(9);
});

test('api/unconnect redirects to authorize when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001/subpath',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const ticket = await encrypt({ idToken: '<id_token>' }, '<secret>', '', Date.now() + 500);

  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect?ticket=${ticket}&connection=<connection>`,
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3001/subpath/api/unconnect/callback');
  expect(url.searchParams.get('scope')).toBe('openid unlink_account');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('audience')).toBe('<audience_2>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.size).toBe(9);
});

test('api/unconnect/callback redirects to /', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const cookieName = '__a0_api_tx';
  const cookieValue = JSON.stringify({});
  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect/callback?code=123`,
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

test('api/unconnect/callback redirects to / when not using a root apiBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000/subpath',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const cookieName = '__a0_api_tx';
  const cookieValue = JSON.stringify({});
  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/subpath');
  expect(url.searchParams.size).toBe(0);
});

test('api/unconnect/callback redirects to returnTo in state', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    apiAsClient: {
      enabled: true,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
      appBaseUrl: 'http://localhost:3000',
      apiBaseUrl: 'http://localhost:3001',
      ticketSecret: '<secret>',
      audience: '<audience_2>',
      mountRoutes: true,
    },
  });

  const cookieName = '__a0_api_tx';
  const cookieValue = JSON.stringify({ appState: { returnTo: 'http://localhost:3000/custom-return' } });
  const res = await fastify.inject({
    method: 'GET',
    url: `/api/unconnect/callback?code=123`,
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
