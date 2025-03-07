import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifyView from '@fastify/view';
import fastifyAuth0 from '@auth0/auth0-fastify';
import fastifyAuth0Api from '@auth0/auth0-fastify/api';
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

fastify.register(fastifyAuth0Api, {
  domain: '',
  audience: '',
});

fastify.register(fastifyAuth0, {
  domain: '',
  clientId: '',
  clientSecret: '',
  appBaseUrl: 'http://localhost:3000',
  secret: 'abc',
});

fastify.register(() => {
  fastify.get(
    '/protected-api',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.sub}`;
    }
  );
});

fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('index.ejs', { isLoggedIn: !!user, name: user?.name });
});

async function hasSessionPreHandler(request: FastifyRequest, reply: FastifyReply) {
  const session = await fastify.auth0Client!.getSession({ request, reply });

  if (!session) {
    reply.redirect('/auth/login');
  }
}

fastify.get(
  '/profile',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return reply.viewAsync('profile.ejs', {
      name: user!.name,
    });
  }
);

fastify.get(
  '/connect/google',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const callbackPath = '/connect/callback';
    const redirectUri = new URL(callbackPath, appBaseUrl);
    const linkUserUrl = await fastify.auth0Client!.startLinkUser({ 
      connection: 'google-oauth2',
      connectionScope: 'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.events.readonly',
      authorizationParams: {
        redirect_uri: redirectUri.toString(),
      }
    }, { request, reply });

    reply.redirect(linkUserUrl.href);
  }
);

fastify.get(
  '/connect/callback',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    await fastify.auth0Client!.completeInteractiveLogin(new URL(request.url, appBaseUrl), { request, reply });

    reply.redirect(appBaseUrl);
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
