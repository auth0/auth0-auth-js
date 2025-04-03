import { CookieSerializeOptions } from '@fastify/cookie';
import { TransactionData, AbstractTransactionStore } from '@auth0/auth0-server-js';
import { StoreOptions } from '../types.js';

export class CookieTransactionStore extends AbstractTransactionStore<StoreOptions> {
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
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(identifier, transactionData, expiration);
    
    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const cookieValue = options.request.cookies[identifier];

    if (cookieValue) {
      return await this.decrypt(identifier, cookieValue);
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    options?.reply.clearCookie(identifier);
  }
}