import { FastifyReply, FastifyRequest } from 'fastify';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}
