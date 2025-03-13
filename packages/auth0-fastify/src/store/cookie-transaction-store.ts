import { CookieSerializeOptions } from '@fastify/cookie';
import { TransactionData, TransactionStore } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import { StoreOptions } from '../types.js';

export class CookieTransactionStore implements TransactionStore<StoreOptions> {
  async set(
    identifier: string,
    transactionData: TransactionData,
    removeIfExists?: boolean,
    options?: StoreOptions
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    
    options.reply.setCookie(identifier, JSON.stringify(transactionData), cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieValue = options.request.cookies[identifier];

    if (cookieValue) {
      return JSON.parse(cookieValue) as TransactionData;
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
