import type { EncryptedStoreOptions, TransactionData } from './../types.js';
import { AbstractTransactionStore } from './abstract-transaction-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';
import { GENERATED_STATE_LENGTH, isGeneratedState } from '../utils.js';

/**
 * The lifetime of a transaction cookie, in seconds. Also the most an entry with its own `expiresAt` gets.
 */
const TRANSACTION_MAX_AGE = 60 * 60;

/**
 * The most bytes the state-scoped transaction cookies of one `transactionIdentifier` may take together on a
 * request, as `name=value`. With `enableParallelTransactions`, every login start adds one, and abandoned or failed
 * logins leave theirs until they expire, which can push the `Cookie` header past server limits (`431`). One cookie
 * is about 500 to 600 bytes, so this leaves room for about six logins in flight. Same limit as nextjs-auth0.
 */
const MAX_TRANSACTION_COOKIE_BYTES = 3500;

const cookieBytes = (name: string, value: string) => new TextEncoder().encode(`${name}=${value}`).length;

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

    await this.#evictOldestTransactionCookies(identifier, encryptedStateData, options);
    this.#cookieHandler.setCookie(identifier, encryptedStateData, cookieOpts, options);
  }

  /**
   * With `enableParallelTransactions`, the identifier is `${transactionIdentifier}${state}`. Before such a cookie is
   * written, deletes the oldest cookies of the same `transactionIdentifier` until all of them, the new one included,
   * stay under {@link MAX_TRANSACTION_COOKIE_BYTES}. Other cookies, and the one being written, are never touched.
   * A new cookie that is over the limit on its own is still written, as in nextjs-auth0, and all its siblings
   * are deleted, so the `Cookie` header stays bounded.
   */
  async #evictOldestTransactionCookies(identifier: string, value: string, options?: TStoreOptions): Promise<void> {
    const prefix = identifier.slice(0, -GENERATED_STATE_LENGTH);
    if (!prefix || !isGeneratedState(identifier.slice(prefix.length))) {
      return;
    }

    const siblings = Object.entries(this.#cookieHandler.getCookies(options) ?? {}).filter(
      ([name]) => name !== identifier && name.startsWith(prefix) && isGeneratedState(name.slice(prefix.length))
    );
    const projected = siblings.reduce((sum, [name, v]) => sum + cookieBytes(name, v), cookieBytes(identifier, value));
    if (projected < MAX_TRANSACTION_COOKIE_BYTES) {
      return;
    }

    // Oldest first, by the expiry inside each cookie: they all get the same lifetime, so it orders them by age.
    // A cookie that can't be read (expired, or written with another secret) can't be completed, so it goes first.
    const withExpiry = await Promise.all(
      siblings.map(async ([name, v]) => {
        const data = await this.decrypt<{ exp?: number }>(name, v).catch(() => undefined);
        return { name, bytes: cookieBytes(name, v), exp: typeof data?.exp === 'number' ? data.exp : 0 };
      })
    );
    withExpiry.sort((a, b) => a.exp - b.exp);

    let freed = 0;
    for (const cookie of withExpiry) {
      if (projected - freed < MAX_TRANSACTION_COOKIE_BYTES) {
        break;
      }
      this.#cookieHandler.deleteCookie(cookie.name, options);
      freed += cookie.bytes;
    }
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
