import { FastifyReply } from 'fastify';

export const replyWithError = (
  reply: FastifyReply,
  statusCode: number,
  error: string,
  errorDescription: string
) => {
  return reply.code(statusCode).send({
    error: error,
    error_description: errorDescription,
  });
};
