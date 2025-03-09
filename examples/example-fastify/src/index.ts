import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifyView from '@fastify/view';
import fastifyAuth0 from '@auth0/auth0-fastify';
import fastifyAuth0Api from '@auth0/auth0-fastify/api';
import ejs from 'ejs';
import { decrypt, encrypt } from './encryption.js';

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
  clientId: '',
  clientSecret: '',
});

const appBaseUrl = 'http://localhost:3000';
fastify.register(fastifyAuth0, {
  domain: '',
  clientId: '',
  clientSecret: '',
  appBaseUrl: appBaseUrl,
  sessionSecret: 'abc',
  audience: '',
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

async function hasSessionPreHandler(
  request: FastifyRequest,
  reply: FastifyReply
) {
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
    const linkUserUrl = await fastify.auth0Client!.startLinkUser(
      {
        connection: 'google-oauth2',
        connectionScope:
          'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.events.readonly',
        authorizationParams: {
          redirect_uri: redirectUri.toString(),
        },
      },
      { request, reply }
    );

    reply.redirect(linkUserUrl.href);
  }
);

fastify.get(
  '/connect/callback',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    await fastify.auth0Client!.completeLinkUser(
      new URL(request.url, appBaseUrl),
      { request, reply }
    );

    reply.redirect(appBaseUrl);
  }
);

fastify.register(() => {
  fastify.post(
    '/api/connect/google/start',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request, reply) => {
      // TODO: Avoid any.
      const idToken = (request.body as any).idToken;

      // TODO: Should we ensure the sub is the same in the id token as in the access token?

      const maxAge = 60 * 60; // TODO: change to 2 minutes instead of 60 minutes
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const ticket = await encrypt(
        { idToken },
        '<secret>',
        '<salt>',
        expiration
      );

      reply.send({ ticket });
    }
  );

  fastify.get(
    '/api/connect/google',
    {
      // TODO: Add TicketAuthHandler to ensure the endpoint is only callable using a decryptable ticket.
      // preHandler: hasSessionPreHandler,
    },
    async (request, reply) => {
      // TODO: Avoid any.
      const ticket = (request.query as any).ticket;
      const { idToken } = await decrypt<{ sub: string; idToken: string }>(
        ticket,
        '<secret>',
        '<salt>'
      );
      const callbackPath = '/api/connect/callback';
      const redirectUri = new URL(callbackPath, appBaseUrl);
      const linkUserUrl = await fastify.apiAuthClient!.startLinkUser(
        {
          idToken: idToken,
          connection: 'google-oauth2',
          connectionScope:
            'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.events.readonly',
          authorizationParams: {
            redirect_uri: redirectUri.toString(),
          },
        },
        { request, reply }
      );

      reply.redirect(linkUserUrl.href);
    }
  );

  fastify.get('/api/connect/callback', async (request, reply) => {
    await fastify.apiAuthClient!.completeLinkUser(
      new URL(request.url, appBaseUrl),
      { request, reply }
    );

    reply.redirect(appBaseUrl);
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
