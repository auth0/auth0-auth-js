import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { ApiClient, getToken, InvalidRequestError } from '@auth0/auth0-api-js';
import { replyWithError } from './utils.js';
import { Auth0FastifyApiOptions, AuthRouteOptions, Token } from './types.js';

function validateScopes(token: Token, requiredScopes: string[]): boolean {
  let tokenScopes: string[] = [];

  if (token.scope) {
    tokenScopes =
      typeof token.scope === 'string' ? token.scope.split(' ') : token.scope;
  }

  return requiredScopes.every((required) => tokenScopes.includes(required));
}

/**
 * Extending the Fastify types to include the requireAuth method and the user property
 */
declare module 'fastify' {
  // We expose the requireAuth method to the `FastifyInstance`, so we can do `fastify.requireAuth()` to use it.
  interface FastifyInstance {
    requireAuth: (
      opts?: AuthRouteOptions
    ) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  // We expose the user property to the `FastifyRequest`, so we can do `request.user` to access the user's information extracted from the token.
  interface FastifyRequest {
    user: Token;
  }
}

/**
 * Registering the Auth0 Fastify API plugin
 * @param fastify The fastify instance
 * @param options Options used to configure the Plugin
 */
async function auth0FastifApi(
  fastify: FastifyInstance,
  options: Auth0FastifyApiOptions
) {
  // 1. Create an instance of ApiClient and pass it the configuration
  const apiClient = new ApiClient({
    domain: options.domain,
    audience: options.audience,
  });

  // 2. Decorate the FastifyInstance with the requireAuth method.
  // This method is used to attach to our endoint handlers to require a JWT
  // with the expected claims.
  fastify.decorate('requireAuth', function (opts: AuthRouteOptions = {}) {
    return async function (request: FastifyRequest, reply: FastifyReply) {
      let accessToken: string;
      try {
        accessToken = getToken(request.headers);
      } catch (error) {
        if (error instanceof InvalidRequestError) {
          return replyWithError(reply, 400, 'invalid_request', error.message);
        }

        // This should never happen, but just in case.
        return replyWithError(reply, 400, 'invalid_request', 'Bad request');
      }

      try {
        // By default, `verifyAccessToken` will validate the token's signature,
        // expiration, audience and issuer. If the token is invalid, it will throw an error.
        //
        // When custom claims need to be validated, they can be passed to `verifyAccessToken`.
        // const token = await apiClient.verifyAccessToken({ accessToken, requiredClaims: ['foo'] });
        const token = await apiClient.verifyAccessToken({ accessToken });

        // 3. Verify scopes if they are provided in the options.
        if (opts.scopes && !validateScopes(token, opts.scopes)) {
          return replyWithError(
            reply,
            403,
            'insufficient_scope',
            'Insufficient scopes'
          );
        }

        request['user'] = token;
      } catch (error) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if ((error as any).code === 'verify_access_token_error') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          return replyWithError(
            reply,
            401,
            'invalid_token',
            (error as any).message
          );
        }

        return replyWithError(reply, 401, 'invalid_token', 'Invalid token');
      }
    };
  });
}

export default fp(auth0FastifApi);
