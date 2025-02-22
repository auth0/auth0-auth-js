import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { Auth0Client } from '@auth0/auth0-server-js';
import type { UserClaims } from '@auth0/auth0-server-js';
import type { StoreOptions } from './types.js';
import { CookieTransactionStore } from './store/cookie-transaction-store.js';
import { CookieStateStore } from './store/cookie-state-store.js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

export interface Auth0FastifyPluginInstance {
  getUser: (req: FastifyRequest, reply: FastifyReply) => Promise<UserClaims | undefined>;
  getAccessToken: (req: FastifyRequest, reply: FastifyReply) => Promise<string | undefined>;
}

export interface Auth0FastifyOptions {
  domain: string;
  clientId: string;
  clientSecret: string;
  audience?: string;
  appBaseUrl: string;

  secret: string;
}

export default fp(async function auth0Fastify(fastify: FastifyInstance, options: Auth0FastifyOptions) {
  const callbackPath = '/auth/callback';
  const redirectUri = new URL(callbackPath, options.appBaseUrl);

  const auth0Client = new Auth0Client<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationParams: {
      audience: options.audience,
      redirect_uri: redirectUri.toString(),
    },
    transactionStore: new CookieTransactionStore({ secret: options.secret }),
    stateStore: new CookieStateStore({
      secret: options.secret,
    }),
  });

  if (!fastify.hasReplyDecorator('cookie')) {
    fastify.register(import('@fastify/cookie'));
  }

  await auth0Client.init();

  fastify.get('/auth/login', async (request, reply) => {
    const authorizationUrl = await auth0Client.buildAuthorizationUrl({ request, reply });

    reply.redirect(authorizationUrl.href);
  });

  fastify.get('/auth/callback', async (request, reply) => {
    const token = await auth0Client.handleCallback(new URL(request.url, options.appBaseUrl), { request, reply });

    // Temporarily logging the token to verify everything works
    console.log(`AccessToken: ${token}`);

    reply.redirect(options.appBaseUrl);
  });

  fastify.get('/auth/logout', async (request, reply) => {
    const returnTo = options.appBaseUrl;
    const logoutUrl = await auth0Client.buildLogoutUrl({ returnTo: returnTo.toString() }, { request, reply });

    reply.redirect(logoutUrl.href);
  });

  const getUser = async (request: FastifyRequest, reply: FastifyReply) => {
    return await auth0Client.getUser({ request, reply });
  };

  const getAccessToken = async (request: FastifyRequest, reply: FastifyReply) => {
    return await auth0Client.getAccessToken({ request, reply });
  };

  const decoration = {
    getUser,
    getAccessToken,
  };

  const name = 'auth0Fastify';

  fastify.decorate(name, decoration);
});
