import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request, response, Response } from 'express';
import { PROTECTED_KEY } from './decorators/protected.decorator.js';
import { ApiClient, getToken, InvalidRequestError } from '@auth0/auth0-api-js';
import {
  AUTH0_API_CLIENT,
  AUTH0_JWT_MODULE_OPTIONS,
} from './auth0-jwt.types.js';
import type {
  Auth0JwtModuleOptions,
  Auth0ProtectedMetadata,
} from './auth0-jwt.types.js';

function validateScopes(token: any, requiredScopes: string[]): boolean {
  let tokenScopes: string[] = [];

  if (token.scope) {
    tokenScopes =
      typeof token.scope === 'string' ? token.scope.split(' ') : token.scope;
  }

  return requiredScopes.every((required) => tokenScopes.includes(required));
}

export const replyWithError = (
  response: Response,
  statusCode: number,
  error: string,
  errorDescription: string
) => {
  response.status(statusCode).send({
    error: error,
    error_description: errorDescription,
  });

  return false;
};

@Injectable()
export class Auth0JwtGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(AUTH0_JWT_MODULE_OPTIONS)
    private readonly options: Auth0JwtModuleOptions,
    @Inject(AUTH0_API_CLIENT)
    private readonly apiClient: ApiClient
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const protectedMetadata =
      this.reflector.getAllAndOverride<Auth0ProtectedMetadata>(PROTECTED_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);

    if (!protectedMetadata) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse() as Response;

    let accessToken: string;
    try {
      accessToken = getToken(request.headers);
    } catch (error) {
      if (error instanceof InvalidRequestError) {
        throw new InvalidRequestError(error.message);
      }

      // This should never happen, but just in case.
      throw new InvalidRequestError('Bad Request');
    }

    try {
      const payload = await this.apiClient.verifyAccessToken({
        accessToken,
        requiredClaims: this.options.requiredClaims,
      });

      if (
        protectedMetadata.scopes &&
        !validateScopes(payload, protectedMetadata.scopes)
      ) {
        return replyWithError(
          response,
          403,
          'insufficient_scope',
          'Insufficient scopes'
        );
      }

      request['user'] = payload;
    } catch (e) {
      if ((e as any).code === 'verify_access_token_error') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return replyWithError(
          response,
          401,
          'invalid_token',
          (e as any).message
        );
      }

      return replyWithError(response, 401, 'invalid_token', 'Invalid token');
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
