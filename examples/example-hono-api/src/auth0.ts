import type { Context } from 'hono';
import { env } from 'hono/adapter';
import type { MiddlewareHandler } from 'hono/types';
import { ApiClient } from '@auth0/auth0-api-js';
import { HTTPException } from 'hono/http-exception';
import { JWTPayload } from 'jose';

export type JwtEnv = {
  Variables: {
    jwtPayload: JWTPayload
  }
};

export const jwt = (
  options?: {
    auth0_domain: string;
    auth0_audience: string;
  },
): MiddlewareHandler => {

  let apiClient: ApiClient | null = null;

  return async function jwt(ctx, next) {

    // 1. Create an instance of ApiClient and pass it the configuration
    if (!apiClient) {
      const auth0Env = env(ctx);
      const { auth0_domain, auth0_audience } = options || {
        auth0_domain: auth0Env.AUTH0_DOMAIN,
        auth0_audience: auth0Env.AUTH0_AUDIENCE,
      };
      if (!auth0_domain || auth0_domain.length === 0) {
        throw new Error('JWT auth middleware requires options "auth0_domain"');
      }
      if (!auth0_audience || auth0_audience.length === 0) {
        throw new Error('JWT auth middleware requires options "auth0_audience"');
      }

      apiClient = new ApiClient({
        domain: auth0_domain,
        audience: auth0_audience,
      });
    }

    const credentials = ctx.req.raw.headers.get('Authorization');
    if (!credentials) {
      const errDescription = 'No Authorization header included in request';
      throw new HTTPException(401, {
        message: errDescription,
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_request',
          errDescription,
        }),
      });
    }

    const parts = credentials.split(/\s+/);
    if (parts.length !== 2) {
      const errDescription = 'Invalid Authorization header structure';
      throw new HTTPException(401, {
        message: errDescription,
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_request',
          errDescription,
        }),
      });
    }

    if (parts[0] !== 'Bearer') {
      const errDescription =
        'Invalid authorization header (only Bearer tokens are supported)';
      throw new HTTPException(401, {
        message: errDescription,
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_request',
          errDescription: errDescription,
        }),
      });
    }

    const accessToken = parts[1];
    if (!accessToken || accessToken.length === 0) {
      const errDescription = 'No token included in request';
      throw new HTTPException(401, {
        message: errDescription,
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_request',
          errDescription,
        }),
      });
    }

    try {
      const jwtPayload = await apiClient.verifyAccessToken({ accessToken });

      ctx.set('jwtPayload', jwtPayload);

      await next();
    } catch (cause) {
      console.trace(cause);

      throw new HTTPException(401, {
        message: 'Unauthorized',
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_token',
          statusText: 'Unauthorized',
          errDescription: 'Token verification failure',
        }),
        cause,
      });
    }

  };
};

function unauthorizedResponse(opts: {
  ctx: Context;
  error: string;
  errDescription: string;
  statusText?: string;
}) {
  return new Response('Unauthorized', {
    status: 401,
    statusText: opts.statusText,
    headers: {
      'WWW-Authenticate': `Bearer realm="${opts.ctx.req.url}",error="${opts.error}",error_description="${opts.errDescription}"`,
    },
  });
}

export function requireScope(scope: string | string[]): MiddlewareHandler {

  return async function requireScope(ctx, next) {
    const payload = ctx.var.jwtPayload as JWTPayload;

    if (!payload.scope) {
      throw new HTTPException(403, {
        message: 'Forbidden',
        res: unauthorizedResponse({
          ctx,
          error: 'insufficient_scope',
          errDescription: `Missing required scope: ${scope}`,
        }),
      });
    }

    const payload_scopes = Array.isArray(payload.scope)
      ? payload.scope
      : (payload.scope as string).split(' ');

    const required_scopes = Array.isArray(scope)
      ? scope
      : (scope as string).split(' ');

    for (const scope of required_scopes) {
      if (!payload_scopes.includes(scope)) {
        throw new HTTPException(403, {
          message: 'Forbidden',
          res: unauthorizedResponse({
            ctx,
            error: 'insufficient_scope',
            errDescription: `Missing required scope: ${scope}`,
          }),
        });
      }
    }

    await next();
  };
}
