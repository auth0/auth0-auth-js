import { Controller, Get, Request } from '@nestjs/common';
import { Protected } from '../auth0-jwt/decorators/protected.decorator.js';

@Controller('api/private-scope')
export class PrivateScopeController {
  @Protected({ scopes: ['read:private'] })
  @Get()
  getPrivate(@Request() request: any) {
    return `Hello, ${request.user.sub}`;
  }
}
