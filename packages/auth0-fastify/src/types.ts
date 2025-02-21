import type { FastifyReply, FastifyRequest } from "fastify";

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}