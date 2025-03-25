import { Controller, Get, Request } from '@nestjs/common';
import { Protected } from '../auth0-jwt/decorators/protected.decorator.js';

@Controller('api/private')
export class PrivateController {
  @Protected()
  @Get()
  getPrivate(@Request() request: any) {
    return `Hello, ${request.user.sub}`;
  }
}
