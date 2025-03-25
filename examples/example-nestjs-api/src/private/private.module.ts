import { Module } from '@nestjs/common';
import { PrivateController } from './private.controller.js';

@Module({
  controllers: [PrivateController],
})
export class PrivateModule {}
