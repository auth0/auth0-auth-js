import { FastifyReply, FastifyRequest } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';
import { TransactionStore, TransactionData } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

export class CookieTransactionStore implements TransactionStore<StoreOptions> {
  async set(identifier: string, transactionData: TransactionData, options?: StoreOptions): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };

    // Temporarily unencrypted, will encrypt in a follow-up commit.
    options.reply.setCookie(identifier, JSON.stringify(transactionData), cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookie = options.request.cookies[identifier];

    if (cookie) {
      return JSON.parse(cookie);
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    options?.reply.clearCookie(identifier);
  }
}
