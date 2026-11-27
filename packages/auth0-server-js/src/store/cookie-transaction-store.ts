import { InvalidConfigurationError } from './../errors.js';
import type { EncryptedStoreOptions, TransactionData } from './../types.js';
import { AbstractTransactionStore } from './abstract-transaction-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

/**
 * The default lifetime of a transaction cookie, in seconds.
 */
const TRANSACTION_MAX_AGE = 60 * 60;

/**
 * An entry that carries its own `expiresAt` (a passkey transaction, which lives only as long as the
 * Auth0 auth session) gets a cookie that expires with it, never later than the configured lifetime.
 */
const getMaxAge = (transactionData: TransactionData, lifetime: number): number => {
  const { expiresAt } = transactionData;

  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
    return lifetime;
  }

  // At least one second: a `Max-Age` of 0 would delete the cookie instead of setting it.
  return Math.min(Math.max(Math.ceil(expiresAt - Date.now() / 1000), 1), lifetime);
};

/**
 * Options for the transaction cookie, which holds the encrypted transaction (PKCE code verifier, state)
 * between the login redirect and the callback.
 *
 * @category Configuration
 */
export interface TransactionCookieOptions {
  /**
   * The sameSite attribute of the transaction cookie.
   *
   * Default: `lax`, which lets the cookie arrive on the redirect back from Auth0. Use `none` (with
   * `secure: true`, which the constructor enforces) for `response_mode=form_post`, where Auth0 posts to the callback cross-site.
   * `strict` keeps the cookie off that cross-site redirect, so the callback cannot find the transaction.
   */
  sameSite?: 'strict' | 'lax' | 'none';
  /**
   * The secure attribute of the transaction cookie.
   *
   * Default: not set. Set it to `true` whenever the application is served over HTTPS.
   */
  secure?: boolean;
  /**
   * The path attribute of the transaction cookie.
   *
   * Default: `/`.
   */
  path?: string;
  /**
   * The domain attribute of the transaction cookie.
   *
   * Default: not set, so the cookie applies only to the current host.
   */
  domain?: string;
  /**
   * The lifetime of the transaction cookie, in seconds. Also the most an entry with its own `expiresAt` gets.
   *
   * Default: `3600` (1 hour).
   */
  maxAge?: number;
}

/**
 * @category Configuration
 */
export interface CookieTransactionStoreOptions extends EncryptedStoreOptions {
  /**
   * Options for the transaction cookie.
   */
  cookie?: TransactionCookieOptions;
}

/**
 * Transaction store that keeps the encrypted transaction data in a cookie, using the given `CookieHandler`.
 *
 * @category Session Stores & Cookies
 */
export class CookieTransactionStore<TStoreOptions> extends AbstractTransactionStore<TStoreOptions> {
  readonly #cookieHandler: CookieHandler<TStoreOptions>;
  readonly #cookieOptions: Omit<CookieSerializeOptions, 'maxAge'>;
  readonly #maxAge: number;

  constructor(options: CookieTransactionStoreOptions, cookieHandler: CookieHandler<TStoreOptions>) {
    super(options);
    this.#cookieHandler = cookieHandler;

    const cookie = options.cookie;

    // A `Max-Age` of 0 or less would delete the cookie instead of setting it.
    if (cookie?.maxAge !== undefined && !(Number.isFinite(cookie.maxAge) && cookie.maxAge > 0)) {
      throw new InvalidConfigurationError('The transaction cookie maxAge must be a positive number of seconds.');
    }

    // Browsers drop a `SameSite=None` cookie that is not `Secure`, which would fail the login only at the callback.
    if (cookie?.sameSite === 'none' && cookie.secure !== true) {
      throw new InvalidConfigurationError("The transaction cookie requires secure: true when sameSite is 'none'.");
    }

    this.#maxAge = cookie?.maxAge ?? TRANSACTION_MAX_AGE;
    this.#cookieOptions = {
      httpOnly: true,
      sameSite: cookie?.sameSite ?? 'lax',
      path: cookie?.path ?? '/',
      ...(cookie?.secure !== undefined && { secure: cookie.secure }),
      ...(cookie?.domain !== undefined && { domain: cookie.domain }),
    };
  }

  async set(
    identifier: string,
    transactionData: TransactionData,
    removeIfExists?: boolean,
    options?: TStoreOptions
  ): Promise<void> {
    const maxAge = getMaxAge(transactionData, this.#maxAge);
    const cookieOpts: CookieSerializeOptions = { ...this.#cookieOptions, maxAge };
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
    // Browsers clear a cookie only when the deletion's attributes match the ones it was set with.
    this.#cookieHandler.deleteCookie(identifier, options, this.#cookieOptions);
  }
}
