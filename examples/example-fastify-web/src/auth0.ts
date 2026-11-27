import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import {
  ServerClient,
  CookieTransactionStore,
  StatelessStateStore,
} from '@auth0/auth0-server-js';
import type { StoreOptions } from './types.js';
import { FastifyCookieHandler } from './store/fastify-cookie-handler.js';

declare module 'fastify' {
  interface FastifyInstance {
    auth0Client: ServerClient<StoreOptions> | undefined;
  }
}

export interface Auth0FastifyOptions {
  domain: string;
  clientId: string;
  clientSecret: string;
  appBaseUrl: string;
  sessionSecret: string;
}

export default fp(async function auth0Fastify(
  fastify: FastifyInstance,
  options: Auth0FastifyOptions
) {
  const callbackPath = '/auth/callback';
  const redirectUri = new URL(callbackPath, options.appBaseUrl);

  const auth0Client = new ServerClient<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationParams: {
      redirect_uri: redirectUri.toString(),
    },
    transactionStore: new CookieTransactionStore(
      {
        secret: options.sessionSecret,
      },
      new FastifyCookieHandler()
    ),
    stateStore: new StatelessStateStore(
      {
        secret: options.sessionSecret,
      },
      new FastifyCookieHandler()
    ),
  });

  fastify.get(
    '/auth/login',
    async (
      request: FastifyRequest<{
        Querystring: { returnTo?: string };
      }>,
      reply
    ) => {
      const authorizationUrl = await auth0Client.startInteractiveLogin(
        {
          appState: { returnTo: options.appBaseUrl },
        },
        { request, reply }
      );

      reply.redirect(authorizationUrl.href);
    }
  );

  fastify.get('/auth/callback', async (request, reply) => {
    const { appState } = await auth0Client.completeInteractiveLogin<
      { returnTo: string } | undefined
    >(new URL(request.url, options.appBaseUrl), { request, reply });

    reply.redirect(appState?.returnTo ?? options.appBaseUrl);
  });

  // With a hint, Auth0 ends the session without asking the user, and any site can make the browser call this GET
  // route. logout() sends no hint by default; this route only asks for one on a top-level navigation by the user (a
  // link click or a typed URL), not for an <img> or <iframe>, even from this site. Every other request gets the
  // confirmation page, where Auth0 shows one (RP-Initiated Logout enabled, not /v2/logout). A POST route with CSRF
  // protection doesn't need this. See `Skipping the logout confirmation prompt` in the auth0-server-js EXAMPLES.md.
  fastify.get('/auth/logout', async (request, reply) => {
    const fetchSite = request.headers['sec-fetch-site'];
    const userNavigation =
      (fetchSite === 'same-origin' || fetchSite === 'none') &&
      request.headers['sec-fetch-mode'] === 'navigate' &&
      request.headers['sec-fetch-dest'] === 'document';
    const hint = userNavigation ? 'id_token_hint' : 'none';
    const returnTo = options.appBaseUrl;
    const logoutUrl = await auth0Client.logout(
      { returnTo: returnTo.toString(), hint },
      { request, reply }
    );

    reply.redirect(logoutUrl.href);
  });

  fastify.decorate('auth0Client', auth0Client);
});
