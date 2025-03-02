import Fastify from 'fastify';
import fastifyView from '@fastify/view';
import fastifyAuth0 from '@auth0/auth0-fastify';
import ejs from 'ejs';

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
  appBaseUrl: 'http://localhost:3000',
  secret: 'abc',
});

fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('index.ejs', { isLoggedIn: !!user, name: user?.name });
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
