import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { Auth0Client } from '@auth0/auth0-server-js';
import type { TransactionStore, UserClaims } from '@auth0/auth0-server-js';
import type { StoreOptions } from './types.js';
import { CookieTransactionStore } from './store/cookie-transaction-store.js';
import { CookieStateStore } from './store/cookie-state-store.js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

export interface Auth0FastifyPluginInstance {
  getUser: (req: FastifyRequest, reply: FastifyReply) => Promise<UserClaims | undefined>;
}

export interface Auth0FastifyOptions {
  domain: string;
  clientId: string;
  clientSecret: string;
  appBaseUrl: string;

  transactionStore?: TransactionStore<StoreOptions>;
}

export default fp(async function auth0Fastify(fastify: FastifyInstance, options: Auth0FastifyOptions) {
  const auth0Client = new Auth0Client<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    transactionStore: options.transactionStore ?? new CookieTransactionStore(),
    stateStore: new CookieStateStore(),
  });

  if (!fastify.hasReplyDecorator('cookie')) {
    fastify.register(import('@fastify/cookie'));
  }

  await auth0Client.init();

  fastify.get('/auth/login', async (request, reply) => {
    const callbackPath = '/auth/callback';
    const redirectUri = new URL(callbackPath, options.appBaseUrl);
    const authorizationUrl = await auth0Client.buildAuthorizationUrl(
      {
        authorizationParams: {
          redirect_uri: redirectUri.toString(),
        },
      },
      { request, reply }
    );

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

  const decoration = {
    getUser,
  };

  const name = 'auth0Fastify';

  fastify.decorate(name, decoration);
});
