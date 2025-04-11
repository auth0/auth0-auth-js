import type { TransactionData, TransactionStore } from '@auth0/auth0-server-js';
import type { StoreOptions } from '../types.js';
import { setCookie, deleteCookie, getCookie } from 'h3';
import type { CookieSerializeOptions } from 'cookie-es';

export class CookieTransactionStore implements TransactionStore<StoreOptions> {
  async set(
    identifier: string,
    transactionData: TransactionData,
    removeIfExists?: boolean,
    options?: StoreOptions
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    
    setCookie(options.event, identifier, JSON.stringify(transactionData), cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const cookieValue = getCookie(options.event, identifier);

    if (cookieValue) {
      return JSON.parse(cookieValue) as TransactionData;
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    deleteCookie(options.event, identifier);
  }
}
