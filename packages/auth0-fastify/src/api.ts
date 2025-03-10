import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { ApiClient, MissingRequiredArgumentError } from '@auth0/auth0-auth-js';
import { ApiClient as ApiAuthClient } from '@auth0/auth0-api-js';
import { CookieTransactionStore } from './store/cookie-transaction-store.js';
import { StoreOptions } from './types.js';
import { decrypt, encrypt } from './encryption.js';
import { createRouteUrl } from './utils.js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

interface AuthRouteOptions {
  scopes?: string | string[];
}

declare module 'fastify' {
  interface FastifyInstance {
    apiAuthClient: ApiAuthClient<StoreOptions> | undefined;
    requireAuth: (opts?: AuthRouteOptions) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    user: Token;
  }
}

export interface Auth0FastifyApiOptions {
  domain: string;
  audience: string;
  clientId?: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  sessionSecret?: string;
  appBaseUrl?: string;
  apiAsClient?: boolean;
  mountConnectRoutes?: boolean;
  onRefreshTokenReceived?: (sub: string, refreshToken: string) => void;
}

export interface Token {
  sub?: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
}

function validateScopes(token: Token, requiredScopes: string | string[]): boolean {
  const scopes = Array.isArray(requiredScopes) ? requiredScopes : [requiredScopes];

  // Extract token scopes (handling different formats)
  let tokenScopes: string[] = [];

  if (token.scope) {
    tokenScopes = typeof token.scope === 'string' ? token.scope.split(' ') : token.scope;
  }

  // All required scopes must be present
  return scopes.every((required) => tokenScopes.includes(required));
}
async function auth0FastifApi(fastify: FastifyInstance, options: Auth0FastifyApiOptions) {
  if (!options.audience) {
    throw new Error('In order to use the Auth0 Api plugin, you must provide an audience.');
  }

  const apiClient = new ApiClient({
    domain: options.domain,
    audience: options.audience,
  });

  const replyWithError = (reply: FastifyReply, statusCode: number, error: string, errorDescription: string) => {
    return reply
      .code(statusCode)
      .header(
        'WWW-Authenticate',
        `Bearer error="${error.replaceAll('"', '\\"')}", error_description="${errorDescription.replaceAll('"', '\\"')}"`
      )
      .send({
        error: error,
        error_description: errorDescription,
      });
  };

  fastify.decorate('requireAuth', function (opts: AuthRouteOptions = {}) {
    return async function (request: FastifyRequest, reply: FastifyReply) {
      const accessToken = getToken(request);

      if (!accessToken) {
        return replyWithError(reply, 400, 'invalid_request', 'No Authorization provided');
      }

      try {
        const token: Token = await apiClient.verifyAccessToken({ accessToken });
        if (opts.scopes && !validateScopes(token, opts.scopes)) {
          return replyWithError(reply, 403, 'insufficient_scope', 'Insufficient scopes');
        }

        request['user'] = token;
      } catch (error) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if ((error as any).code === 'verify_access_token_error') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          return replyWithError(reply, 401, 'invalid_token', (error as any).message);
        }

        return replyWithError(reply, 401, 'invalid_token', 'Invalid token');
      }
    };
  });

  const runApiAsClient = 'apiAsClient' in options && options.apiAsClient === true;

  // If we are running the Api as a client, we need to:
  //  - ensure the required options are provided
  //  - create an instance of the ApiAuthClient
  //  - decorate the fastify instance with the ApiAuthClient
  //  - mount the connect routes if opted-in
  if (runApiAsClient) {
    if (!options.clientId) {
      throw new MissingRequiredArgumentError('clientId');
    }

    if (!options.appBaseUrl) {
      throw new MissingRequiredArgumentError('appBaseUrl');
    }

    if (!options.sessionSecret) {
      throw new MissingRequiredArgumentError('sessionSecret');
    }

    const apiAuthClient = new ApiAuthClient({
      domain: options.domain,
      audience: options.audience,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      transactionStore: new CookieTransactionStore({ secret: options.sessionSecret }),
      onRefreshTokenReceived: options.onRefreshTokenReceived,
    });

    fastify.decorate('apiAuthClient', apiAuthClient);

    if (options.mountConnectRoutes) {
      fastify.post(
        '/api/connect/start',
        {
          preHandler: fastify.requireAuth(),
        },
        async (request, reply) => {
          // TODO: Avoid any.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const idToken = (request.body as any).idToken;

          const maxAgeMinutes = 5;
          const maxAge = 60 * maxAgeMinutes;
          const expiration = Math.floor(Date.now() / 1000 + maxAge);
          const ticket = await encrypt({ idToken }, '<secret>', '<salt>', expiration);

          reply.send({ ticket });
        }
      );

      fastify.get(
        '/api/connect',
        async (request: FastifyRequest<{ Querystring: { ticket: string; connection: string; connectionScope: string } }>, reply) => {
          const { ticket, connection, connectionScope } = request.query;

          if (!ticket) {
            return reply.code(401).send({
              error: 'invalid_request',
              error_description: 'ticket is not set',
            });
          }

          if (!connection) {
            return reply.code(400).send({
              error: 'invalid_request',
              error_description: 'connection is not set',
            });
          }

          const { idToken } = await decrypt<{ sub: string; idToken: string }>(ticket, '<secret>', '<salt>');
          const callbackPath = '/api/connect/callback';
          const redirectUri = createRouteUrl(callbackPath, options.appBaseUrl!);
          const linkUserUrl = await fastify.apiAuthClient!.startLinkUser(
            {
              idToken: idToken,
              connection: connection,
              connectionScope: connectionScope,
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
        if (!options.appBaseUrl) {
          return reply.code(500).send({
            error: 'internal_error',
            error_description: 'appBaseUrl is not set',
          });
        }

        await fastify.apiAuthClient!.completeLinkUser(createRouteUrl(request.url, options.appBaseUrl), { request, reply });

        reply.redirect(options.appBaseUrl);
      });
    }
  }
}

export default fp(auth0FastifApi);

function getToken(request: FastifyRequest): string | undefined {
  const parts = request.headers.authorization?.split(' ');

  return parts?.length === 2 && parts[0]?.toLowerCase() === 'bearer' ? parts[1] : undefined;
}
