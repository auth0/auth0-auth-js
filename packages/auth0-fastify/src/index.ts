import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Auth0Client } from '@auth0/auth0-server-js';
import type { StoreOptions } from './types.js';
import { CookieTransactionStore } from './store/cookie-transaction-store.js';
import { CookieStateStore } from './store/cookie-state-store.js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

declare module 'fastify' {
  interface FastifyInstance {
    auth0Client: Auth0Client<StoreOptions> | undefined;
  }
}

export interface Auth0FastifyOptions {
  domain: string;
  clientId: string;
  clientSecret: string;
  audience?: string;
  appBaseUrl: string;

  secret: string;
  pushedAuthorizationRequests?: boolean;
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
    const authorizationUrl = await auth0Client.buildAuthorizationUrl(
      { pushedAuthorizationRequests: options.pushedAuthorizationRequests },
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

  fastify.get('/auth/profile', async (request, reply) => {
    const user = await auth0Client.getUser({ request, reply });

    reply.send(user);
  });

  fastify.get('/auth/logout', async (request, reply) => {
    const returnTo = options.appBaseUrl;
    const logoutUrl = await auth0Client.buildLogoutUrl({ returnTo: returnTo.toString() }, { request, reply });

    reply.redirect(logoutUrl.href);
  });

  fastify.decorate('auth0Client', auth0Client);
});
