import { errors } from 'jose';
import { InvalidConfigurationError } from '../errors.js';
import type { CookieHandler, CookieSerializeOptions } from '../store/cookie-handler.js';
import type { EncryptedStoreOptions } from '../types.js';
import { AbstractPoppyGuestStore } from './abstract-poppy-guest-store.js';
import type { PoppyGuestData } from './types.js';

/**
 * Cookie chunk size, the same as `StatelessStateStore`. The encrypted guest holds an access token, so the value can be
 * larger than the 4 KB that a browser allows for a single cookie.
 */
const CHUNK_SIZE = 3072;

/**
 * The number in the name of a chunk, as `set` writes it: a whole number with no leading zero.
 */
const CHUNK_NUMBER = /^(?:0|[1-9]\d*)$/;

/**
 * Cookie attributes for the guest cookie.
 *
 * This is your application's own cookie on your own domain.
 *
 * @beta
 * @category Session Stores & Cookies
 */
export interface PoppyGuestCookieOptions {
  /**
   * The sameSite attribute of the guest cookie.
   *
   * Default: `lax`. `lax` is enough: this cookie is only read by your own server, on requests to your own site.
   */
  sameSite?: 'strict' | 'lax' | 'none';
  /**
   * The secure attribute of the guest cookie.
   *
   * Default: `true`. Set it to `false` only for local development over plain HTTP.
   */
  secure?: boolean;
  /**
   * The path attribute of the guest cookie.
   *
   * Default: `/`.
   */
  path?: string;
}

/**
 * Options for `StatelessPoppyGuestStore`.
 *
 * @beta
 * @category Session Stores & Cookies
 */
export interface StatelessPoppyGuestStoreOptions extends EncryptedStoreOptions {
  /**
   * The options for the guest cookie.
   */
  cookie?: PoppyGuestCookieOptions;
}

/**
 * Stateless guest store.
 *
 * Keeps the whole guest in an encrypted, `HttpOnly` cookie on your application's domain, chunked across several
 * cookies when needed, so it needs no server-side storage. Pass it as `guestStore` in the `poppy` option of the
 * `ServerClient`.
 *
 * The cookie ends when the guest does. Its `Max-Age` and the expiry inside the encrypted value are both the
 * `expiresAt` of the guest. There is no lifetime option on purpose: a setting that is longer would keep a guest on your
 * website after the agent's Poppy Session has ended. A guest that is already past its `expiresAt` is not stored.
 *
 * @example
 * ```typescript
 * const serverClient = new ServerClient({
 *   domain: '<AUTH0_DOMAIN>',
 *   clientId: '<AUTH0_CLIENT_ID>',
 *   clientSecret: '<AUTH0_CLIENT_SECRET>',
 *   transactionStore: new CookieTransactionStore({ secret }, cookieHandler),
 *   stateStore: new StatelessStateStore({ secret }, cookieHandler),
 *   poppy: {
 *     config: poppyConfig,
 *     guestStore: new StatelessPoppyGuestStore({ secret }, cookieHandler),
 *   },
 * });
 * ```
 *
 * @beta
 * @category Session Stores & Cookies
 */
export class StatelessPoppyGuestStore<TStoreOptions> extends AbstractPoppyGuestStore<TStoreOptions> {
  readonly #cookieOptions: PoppyGuestCookieOptions | undefined;
  readonly #cookieHandler: CookieHandler<TStoreOptions>;

  constructor(options: StatelessPoppyGuestStoreOptions, cookieHandler: CookieHandler<TStoreOptions>) {
    super(options);

    this.#cookieOptions = options.cookie;
    this.#cookieHandler = cookieHandler;
  }

  // Every write replaces the whole guest, and there is no server-side id to renew, so `removeIfExists` is not used.
  async set(
    identifier: string,
    data: PoppyGuestData,
    removeIfExists?: boolean,
    options?: TStoreOptions
  ): Promise<void> {
    // The cookie lasts until the guest's deadline and not a second longer: the browser must not keep a guest after the
    // agent's Poppy Session is over. The time is taken in whole seconds, so that `Max-Age` is a whole number.
    const maxAge = data.expiresAt - Math.floor(Date.now() / 1000);

    // The guest is already past its deadline, so there is nothing worth storing. Clear whatever is there instead of
    // writing a cookie that ends at once.
    if (maxAge <= 0) {
      await this.delete(identifier, options);
      return;
    }

    const cookieOpts = this.#getCookieOptions({ maxAge });
    const encryptedData = await this.encrypt(identifier, data, data.expiresAt);

    const chunkCount = Math.ceil(encryptedData.length / CHUNK_SIZE);
    const chunks = [...Array(chunkCount).keys()].map((i) => ({
      value: encryptedData.substring(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE),
      name: `${identifier}.${i}`,
    }));

    chunks.forEach((chunk) => {
      this.#cookieHandler.setCookie(chunk.name, chunk.value, cookieOpts, options);
    });

    // A shorter value than last time leaves stale trailing chunks behind, which would corrupt the value on the next
    // read. They are cleared with the plain cookie attributes, not with `cookieOpts`: a `Max-Age` on a cookie that is
    // being removed is contradictory, and some frameworks set their own expiry for a clear.
    this.#getCookieKeys(identifier, options)
      .filter((key) => !chunks.some((chunk) => chunk.name === key))
      .forEach((key) => {
        this.#cookieHandler.deleteCookie(key, options, this.#getCookieOptions());
      });
  }

  async get(identifier: string, options?: TStoreOptions): Promise<PoppyGuestData | undefined> {
    const encryptedData = this.#getCookieKeys(identifier, options)
      .map((key) => ({
        // The number is what follows the identifier and its dot. An identifier may hold a dot of its own.
        index: parseInt(key.slice(identifier.length + 1), 10),
        value: this.#cookieHandler.getCookie(key, options),
      }))
      .sort((a, b) => a.index - b.index)
      .map((item) => item.value)
      .join('');

    if (encryptedData) {
      try {
        return await this.decrypt<PoppyGuestData>(identifier, encryptedData);
      } catch (error) {
        // Two failures are thrown. An expired value: the guest was real, and the reads of the `poppy` client tell this
        // class from the others and delete the guest. And a secret that cannot decrypt (`InvalidConfigurationError`):
        // that is a mistake in the app and not a cookie that someone forged, so it fails on the first read and does not
        // hide as no guest.
        if (error instanceof errors.JWTExpired || error instanceof InvalidConfigurationError) {
          throw error;
        }

        // The visitor sets this cookie, and so can another site on the same domain, so its value can be anything.
        // `decrypt` turns only two kinds of failure into `undefined`. A forged header can make it throw others: no
        // `kid`, an `enc` or an `alg` that jose does not take, and more. A value that cannot be opened is no guest,
        // whatever way it fails, and it must not become an error for the app.
        return undefined;
      }
    }
  }

  async delete(identifier: string, options?: TStoreOptions): Promise<void> {
    for (const key of this.#getCookieKeys(identifier, options)) {
      this.#cookieHandler.deleteCookie(key, options, this.#getCookieOptions());
    }
  }

  // The names of the cookies that hold the guest: the identifier, a dot and the number of the chunk, exactly as `set`
  // writes them. Any other name is not a chunk, even when it starts with the identifier or holds it. The cookie of
  // another store, of another app on the same domain, or one that a visitor made must neither be read as the guest nor
  // be deleted with it. The identifier is compared as text. It is never turned into a pattern.
  #getCookieKeys(identifier: string, options?: TStoreOptions): string[] {
    const prefix = `${identifier}.`;

    return Object.keys(this.#cookieHandler.getCookies(options)).filter(
      (key) => key.startsWith(prefix) && CHUNK_NUMBER.test(key.slice(prefix.length))
    );
  }

  #getCookieOptions(partial?: Partial<CookieSerializeOptions>): CookieSerializeOptions {
    return {
      httpOnly: true,
      sameSite: this.#cookieOptions?.sameSite ?? 'lax',
      path: this.#cookieOptions?.path ?? '/',
      secure: this.#cookieOptions?.secure ?? true,
      ...partial,
    };
  }
}
