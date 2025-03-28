import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyAuth0 from './auth0.js';
import fastifyCookie from '@fastify/cookie';
import ejs from 'ejs';
import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const fastify = Fastify({
  logger: true,
});

// Fix to use __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename); 

fastify.register(fastifyStatic, {
  root: path.join(__dirname, '../public')
});

fastify.register(fastifyView, {
  engine: {
    ejs: ejs,
  },
  root: './views',
  layout: 'layout.ejs',
});


fastify.register(fastifyCookie);

fastify.register(fastifyAuth0, {
  domain: process.env.AUTH0_DOMAIN as string,
  clientId: process.env.AUTH0_CLIENT_ID as string,
  clientSecret: process.env.AUTH0_CLIENT_SECRET as string,
  appBaseUrl: process.env.APP_BASE_URL as string,
  sessionSecret: process.env.AUTH0_SESSION_SECRET as string,
});


fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('index.ejs', { isLoggedIn: !!user, user: user });
});

async function hasSessionPreHandler(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const session = await fastify.auth0Client!.getSession({ request, reply });

  if (!session) {
    reply.redirect(`/auth/login?returnTo=${request.url}`);
  }
}

fastify.get(
  '/public',
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return reply.viewAsync('public.ejs', {
      isLoggedIn: !!user,
      user,
    });
  }
);

fastify.get(
  '/private',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return reply.viewAsync('private.ejs', {
      isLoggedIn: !!user,
      user,
    });
  }
);

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
