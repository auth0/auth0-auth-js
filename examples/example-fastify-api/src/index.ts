import Fastify, { FastifyRequest } from 'fastify';
import fastifyAuth0Api from './auth0.js';
import 'dotenv/config';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0Api, {
  domain: process.env.AUTH0_DOMAIN as string,
  audience: process.env.AUTH0_AUDIENCE as string,
});

fastify.register(() => {
  fastify.get(
    '/api/private',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.sub}`;
    }
  );
});

fastify.register(() => {
  fastify.get(
    '/api/private-scope',
    {
      preHandler: fastify.requireAuth({ scopes: ['read:private'] }),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.sub}`;
    }
  );
});

fastify.register(() => {
  fastify.get('/api/public', async (request: FastifyRequest, reply) => {
    return `Hello world!`;
  });
});

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
