import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import fastifyJwt from '@fastify/jwt';
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
}

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: { id: number } // payload type is used for signing and verifying
    user: Token;
  }
}

export interface Auth0FastifyJwtOptions {
  domain: string;
  audience: string;
}

interface Token {
  sub: string;
  scope: string | string[];
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

export default fp(async function auth0FastifJwt(fastify: FastifyInstance, options: Auth0FastifyJwtOptions) {
  if (!options.audience) {
    throw new Error('In order to use the Auth0 JWT plugin, you must provide an audience.');
  }

  const authClient = new ApiClient({
    domain: options.domain,
    audience: options.audience,
  });

  fastify.register(fastifyJwt, {
    decode: { complete: true },
    // TODO: Add types for token
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    secret: async (_: FastifyRequest, token: any) => {
      return await authClient.getKeyForToken(token);
    },
    verify: {
      algorithms: ['RS256'],
      allowedIss: [`https://${options.domain}/`],
      allowedAud: options.audience ? [options.audience] : undefined,
      requiredClaims: ['iss', 'aud', 'iat', 'exp', 'sub'],
    },
  });

  fastify.decorate('requireAuth', function (opts: AuthRouteOptions = {}) {
    return async function (request: FastifyRequest, reply: FastifyReply) {
      await request.jwtVerify();

      const token = request.user;

      if (opts.scopes && !validateScopes(token, opts.scopes)) {
        return reply.code(403).send({
          error: 'Forbidden',
          message: 'Insufficient scopes',
        });
      }
    };
  });
});
