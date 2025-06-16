import { MissingStoreOptionsError } from './../errors.js';
import type { EncryptedStoreOptions, TransactionData } from './../types.js';
import { AbstractTransactionStore } from './abstract-transaction-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

export class CookieTransactionStore<TStoreOptions> extends AbstractTransactionStore<TStoreOptions> {
  readonly #cookieHandler: CookieHandler<TStoreOptions>;

  constructor(options: EncryptedStoreOptions, cookieHandler: CookieHandler<TStoreOptions>) {
    super(options);
    this.#cookieHandler = cookieHandler;
  }

  async set(
    identifier: string,
    transactionData: TransactionData,
    removeIfExists?: boolean,
    options?: TStoreOptions
  ): Promise<void> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }
    
    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(identifier, transactionData, expiration);

    this.#cookieHandler.setCookie(identifier, encryptedStateData, cookieOpts, options);
  }

  async get(identifier: string, options?: TStoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieValue = this.#cookieHandler.getCookie(identifier, options);

    if (cookieValue) {
      return await this.decrypt(identifier, cookieValue);
    }
  }

  async delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    this.#cookieHandler.deleteCookie(identifier, options);
  }
}
