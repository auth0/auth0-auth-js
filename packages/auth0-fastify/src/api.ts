import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { ApiClient } from '@auth0/auth0-auth-js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

interface AuthRouteOptions {
  scopes?: string | string[];
}

declare module 'fastify' {
  interface FastifyInstance {
    requireAuth: (opts?: AuthRouteOptions) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    user: Token;
  }
}

export interface Auth0FastifyApiOptions {
  domain: string;
  audience: string;
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

export default fp(async function auth0FastifApi(fastify: FastifyInstance, options: Auth0FastifyApiOptions) {
  if (!options.audience) {
    throw new Error('In order to use the Auth0 Api plugin, you must provide an audience.');
  }

  const apiClient = new ApiClient({
    domain: options.domain,
    audience: options.audience,
  });

  const replyWithError = (reply: FastifyReply, statusCode: number, error: string, errorDescription: string) => {
    return reply.code(statusCode).header('WWW-Authenticate', `Bearer error="${error.replaceAll('"', '\\"')}", error_description="${errorDescription.replaceAll('"', '\\"')}"`).send({
      error: error,
      error_description: errorDescription,
    });
  }

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
});

function getToken(request: FastifyRequest): string | undefined {
  const parts = request.headers.authorization?.split(' ')

  return parts?.length === 2 && parts[0]?.toLowerCase() === 'bearer' ? parts[1] : undefined;
}
