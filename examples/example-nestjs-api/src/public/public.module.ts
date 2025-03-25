import { Module } from '@nestjs/common';
import { PublicController } from './public.controller.js';

@Module({
  controllers: [PublicController],
})
export class PublicModule {}
