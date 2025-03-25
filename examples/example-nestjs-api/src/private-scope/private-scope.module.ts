import { Module } from '@nestjs/common';
import { PrivateScopeController } from './private-scope.controller.js';

@Module({
  controllers: [PrivateScopeController],
})
export class PrivateScopeModule {}
