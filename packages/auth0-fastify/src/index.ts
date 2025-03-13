import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { ServerClient } from '@auth0/auth0-server-js';
import type { SessionConfiguration, SessionStore, StoreOptions } from './types.js';
import { CookieTransactionStore } from './store/cookie-transaction-store.js';
import { StatelessStateStore } from './store/stateless-state-store.js';
import { StatefulStateStore } from './store/stateful-state-store.js';
import { createRouteUrl, toSafeRedirect } from './utils.js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

declare module 'fastify' {
  interface FastifyInstance {
    auth0Client: ServerClient<StoreOptions> | undefined;
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

  pushedAuthorizationRequests?: boolean;

  sessionSecret: string;
  sessionStore?: SessionStore;
  sessionConfiguration?: SessionConfiguration;
  /**
   * Whether to mount the default routes for login, logout, callback and profile.
   * Defaults to true.
   */
  mountRoutes?: boolean;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
}

export default fp(async function auth0Fastify(fastify: FastifyInstance, options: Auth0FastifyOptions) {
  const callbackPath = '/auth/callback';
  const redirectUri = createRouteUrl(callbackPath, options.appBaseUrl);

  const auth0Client = new ServerClient<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    clientAssertionSigningKey: options.clientAssertionSigningKey,
    clientAssertionSigningAlg: options.clientAssertionSigningAlg,
    authorizationParams: {
      audience: options.audience,
      redirect_uri: redirectUri.toString(),
    },
    transactionStore: new CookieTransactionStore(),
    stateStore: options.sessionStore
      ? new StatefulStateStore({
          ...options.sessionConfiguration,
          secret: options.sessionSecret,
          store: options.sessionStore,
        })
      : new StatelessStateStore({
          ...options.sessionConfiguration,
          secret: options.sessionSecret,
        }),
    stateIdentifier: options.sessionConfiguration?.cookie?.name,
    customFetch: options.customFetch,
  });

  if (!fastify.hasReplyDecorator('cookie')) {
    fastify.register(import('@fastify/cookie'));
  }

  const shouldMountRoutes = options.mountRoutes ?? true;

  if (shouldMountRoutes) {
    fastify.get(
      '/auth/login',
      async (
        request: FastifyRequest<{
          Querystring: { returnTo?: string };
        }>,
        reply
      ) => {
        const dangerousReturnTo = request.query.returnTo;
        const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', options.appBaseUrl);

        const authorizationUrl = await auth0Client.startInteractiveLogin(
          { pushedAuthorizationRequests: options.pushedAuthorizationRequests, appState: { returnTo: sanitizedReturnTo } },
          { request, reply }
        );

        reply.redirect(authorizationUrl.href);
      }
    );

    fastify.get('/auth/callback', async (request, reply) => {
      const { appState } = await auth0Client.completeInteractiveLogin<{ returnTo: string } | undefined>(
        createRouteUrl(request.url, options.appBaseUrl),
        { request, reply }
      );

      reply.redirect(appState?.returnTo ?? options.appBaseUrl);
    });

    fastify.get('/auth/logout', async (request, reply) => {
      const returnTo = options.appBaseUrl;
      const logoutUrl = await auth0Client.logout({ returnTo: returnTo.toString() }, { request, reply });

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

    fastify.get(
      '/auth/connect',
      async (
        request: FastifyRequest<{
          Querystring: { connection: string; connectionScope: string; returnTo?: string };
        }>,
        reply
      ) => {
        const { connection, connectionScope, returnTo } = request.query;
        const dangerousReturnTo = returnTo;

        if (!connection) {
          return reply.code(400).send({
            error: 'invalid_request',
            error_description: 'connection is not set',
          });
        }

        const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', options.appBaseUrl);
        const callbackPath = '/auth/connect/callback';
        const redirectUri = createRouteUrl(callbackPath, options.appBaseUrl);
        const linkUserUrl = await fastify.auth0Client!.startLinkUser(
          {
            connection: connection,
            connectionScope: connectionScope,
            authorizationParams: {
              redirect_uri: redirectUri.toString(),
            },
            appState: {
              returnTo: sanitizedReturnTo,
            },
          },
          { request, reply }
        );

        reply.redirect(linkUserUrl.href);
      }
    );

    fastify.get('/auth/connect/callback', async (request, reply) => {
      const { appState } = await fastify.auth0Client!.completeLinkUser<{ returnTo: string }>(
        createRouteUrl(request.url, options.appBaseUrl),
        {
          request,
          reply,
        }
      );

      reply.redirect(appState?.returnTo ?? options.appBaseUrl);
    });
  }

  fastify.decorate('auth0Client', auth0Client);
});
