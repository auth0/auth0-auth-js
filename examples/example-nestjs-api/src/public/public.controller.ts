import { Controller, Get, Request } from '@nestjs/common';

@Controller('api/public')
export class PublicController {
  @Get()
  getPublic(@Request() req: any) {
    return 'Hello world';
  }
}
