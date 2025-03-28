import { DynamicModule, Module } from '@nestjs/common';
import {
  AUTH0_API_CLIENT,
  Auth0JwtModuleOptions,
  AUTH0_JWT_MODULE_OPTIONS,
} from './auth0-jwt.types.js';
import { ApiClient } from '@auth0/auth0-api-js';
import { Auth0JwtGuard } from './auth0-jwt.guard.js';
import { APP_GUARD } from '@nestjs/core';

export function createJwtProvider(options: Auth0JwtModuleOptions): any[] {
  return [
    { provide: AUTH0_JWT_MODULE_OPTIONS, useValue: options },
    {
      provide: AUTH0_API_CLIENT,
      useValue: new ApiClient({
        domain: options.domain,
        audience: options.audience,
      }),
    },
    {
      provide: APP_GUARD,
      useClass: Auth0JwtGuard,
    },
  ];
}

@Module({})
export class Auth0JwtModule {
  static register(options: Auth0JwtModuleOptions): DynamicModule {
    return {
      module: Auth0JwtModule,
      global: true,
      providers: createJwtProvider(options),
    };
  }
}
