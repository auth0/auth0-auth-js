import Fastify from 'fastify';
import fastifyView from '@fastify/view';
import fastifyAuth0, { Auth0FastifyPluginInstance } from '@auth0/auth0-fastify';
import ejs from 'ejs';

declare module 'fastify' {
  interface FastifyInstance {
    auth0Fastify: Auth0FastifyPluginInstance | undefined;
  }
}

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyView, {
  engine: {
    ejs,
  },
  root: './views',
});

fastify.register(fastifyAuth0, {
  domain: '',
  clientId: '',
  clientSecret: '',
  appBaseUrl: 'http://localhost:3000'
});

fastify.get('/', async (req, reply) => {
  return reply.viewAsync('index.ejs');
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
