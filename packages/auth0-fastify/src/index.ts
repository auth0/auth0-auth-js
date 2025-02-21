import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Auth0Client, TransactionStore } from '@auth0/auth0-server-js';
import { CookieTransactionStore, StoreOptions } from './store/cookie-transaction-store.js';

export type { StoreOptions } from './store/cookie-transaction-store.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

// Temporarily empty, will be changed later.
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface Auth0FastifyPluginInstance {}

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

  fastify.get('/auth/logout', async (req, reply) => {
    const returnTo = options.appBaseUrl;
    const logoutUrl = await auth0Client.buildLogoutUrl({ returnTo: returnTo.toString() });

    reply.redirect(logoutUrl.href);
  });
});
