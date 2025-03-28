import { FastifyReply, FastifyRequest } from 'fastify';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

export interface SessionConfiguration {
  rolling?: boolean;
  absoluteDuration?: number;
  inactivityDuration?: number;
}
