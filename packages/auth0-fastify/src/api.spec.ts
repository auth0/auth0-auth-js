import { expect, test, afterAll, afterEach, beforeAll } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './test-utils/tokens.js';
import Fastify from 'fastify';
import fastifyAuth0Api from './api.js';

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

test('should return 401 when no token', async () => {
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

  expect(res.statusCode).toBe(401);
  expect(res.json().message).toBe('No Authorization provided');
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
  expect(res.json().message).toBe('missing required "iss" claim');
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
  expect(res.json().message).toBe('unexpected "iss" claim value');
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
  expect(res.json().message).toBe('missing required "aud" claim');
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
  expect(res.json().message).toBe('missing required "iat" claim');
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
  expect(res.json().message).toBe('missing required "exp" claim');
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
  expect(res.json().message).toBe('unexpected "aud" claim value');
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
  expect(res.json().message).toBe('Insufficient scopes');
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
