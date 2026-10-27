import type { EncryptedStoreOptions, TransactionData } from './../types.js';
import { AbstractTransactionStore } from './abstract-transaction-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

/**
 * The lifetime of a transaction cookie, in seconds. Also the most an entry with its own `expiresAt` gets.
 */
const TRANSACTION_MAX_AGE = 60 * 60;

/**
 * An entry that carries its own `expiresAt` (a passkey transaction, which lives only as long as the
 * Auth0 auth session) gets a cookie that expires with it, never later than the usual lifetime.
 */
const getMaxAge = (transactionData: TransactionData): number => {
  const { expiresAt } = transactionData;

  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
    return TRANSACTION_MAX_AGE;
  }

  // At least one second: a `Max-Age` of 0 would delete the cookie instead of setting it.
  return Math.min(Math.max(Math.ceil(expiresAt - Date.now() / 1000), 1), TRANSACTION_MAX_AGE);
};

/**
 * Transaction store that keeps the encrypted transaction data in a cookie, using the given `CookieHandler`.
 *
 * @category Session Stores & Cookies
 */
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
    const maxAge = getMaxAge(transactionData);
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(identifier, transactionData, expiration);

    this.#cookieHandler.setCookie(identifier, encryptedStateData, cookieOpts, options);
  }

  async get(identifier: string, options?: TStoreOptions): Promise<TransactionData | undefined> {
    const cookieValue = this.#cookieHandler.getCookie(identifier, options);

    if (cookieValue) {
      return await this.decrypt(identifier, cookieValue);
    }
  }

  async delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    this.#cookieHandler.deleteCookie(identifier, options);
  }
}
