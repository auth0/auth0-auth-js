import { Module } from '@nestjs/common';
import { Auth0JwtModule } from './auth0-jwt/auth0-jwt.module.js';
import { PrivateModule } from './private/private.module.js';
import { PublicModule } from './public/public.module.js';
import { PrivateScopeModule } from './private-scope/private-scope.module.js';

@Module({
  imports: [
    Auth0JwtModule.register({
      domain: process.env.AUTH0_DOMAIN as string,
      audience: process.env.AUTH0_AUDIENCE as string,
    }),
    PublicModule,
    PrivateModule,
    PrivateScopeModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
