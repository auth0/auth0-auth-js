import type { TransactionData, TransactionStore } from './../types.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

export class CookieTransactionStore<TStoreOptions> implements TransactionStore<TStoreOptions> {
  readonly #cookieHandler: CookieHandler<TStoreOptions>;

  constructor(cookieHandler: CookieHandler<TStoreOptions>) {
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
      throw new Error('StoreOptions not provided');
    }

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', secure: true, maxAge };

    this.#cookieHandler.setCookie(options, identifier, JSON.stringify(transactionData), cookieOpts);
  }

  async get(identifier: string, options?: TStoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const cookieValue = this.#cookieHandler.getCookie(options, identifier);

    if (cookieValue) {
      return JSON.parse(cookieValue) as TransactionData;
    }
  }

  async delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    this.#cookieHandler.deleteCookie(options, identifier);
  }
}
