import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { Auth0Client } from '@auth0/auth0-server-js';
import type { SessionStore, StoreOptions } from './types.js';
import { CookieTransactionStore } from './store/cookie-transaction-store.js';
import { StatelessStateStore } from './store/stateless-state-store.js';
import { StatefulStateStore } from './store/stateful-state-store.js';

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
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  audience?: string;
  appBaseUrl: string;

  secret: string;
  pushedAuthorizationRequests?: boolean;

  sessionStore?: SessionStore;
}

export default fp(async function auth0Fastify(fastify: FastifyInstance, options: Auth0FastifyOptions) {
  const callbackPath = '/auth/callback';
  const redirectUri = new URL(callbackPath, options.appBaseUrl);

  const auth0Client = new Auth0Client<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    clientAssertionSigningKey: options.clientAssertionSigningKey,
    clientAssertionSigningAlg: options.clientAssertionSigningAlg,
    authorizationParams: {
      audience: options.audience,
      redirect_uri: redirectUri.toString(),
    },
    transactionStore: new CookieTransactionStore({ secret: options.secret }),
    stateStore: options.sessionStore ? new StatefulStateStore({
      secret: options.secret,
      store: options.sessionStore,
    }) : new StatelessStateStore({
      secret: options.secret,
    }),
  });

  if (!fastify.hasReplyDecorator('cookie')) {
    fastify.register(import('@fastify/cookie'));
  }

  fastify.get(
    '/auth/login',
    async (
      request: FastifyRequest<{
        Querystring: { returnTo?: string };
      }>,
      reply
    ) => {
      const returnTo = request.query.returnTo;
      const authorizationUrl = await auth0Client.startInteractiveLogin(
        { pushedAuthorizationRequests: options.pushedAuthorizationRequests, appState: { returnTo } },
        { request, reply }
      );

      reply.redirect(authorizationUrl.href);
    }
  );

  fastify.get('/auth/callback', async (request, reply) => {
    const { appState } = await auth0Client.completeInteractiveLogin<{ returnTo: string } | undefined>(
      new URL(request.url, options.appBaseUrl),
      { request, reply }
    );

    reply.redirect(appState?.returnTo ?? options.appBaseUrl);
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

  fastify.post(
    '/auth/backchannel-logout',
    async (
      request: FastifyRequest<{
        Body: { logout_token?: string };
      }>,
      reply
    ) => {
      const logoutToken = request.body.logout_token;

      if (!logoutToken) {
        reply.code(400).send('Missing `logout_token` in the request body.');

        return;
      }

      try {
        await auth0Client.handleBackchannelLogout(logoutToken, { request, reply });
        reply.code(204).send(null);
      } catch (e) {
        reply.code(400).send((e as Error).message);
      }
    }
  );

  fastify.decorate('auth0Client', auth0Client);
});
