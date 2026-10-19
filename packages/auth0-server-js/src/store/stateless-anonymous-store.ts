import type { AnonymousStateData, EncryptedStoreOptions } from '../types.js';
import { AbstractAnonymousStore } from './abstract-anonymous-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

/**
 * Default lifetime of an anonymous session, in seconds (30 days).
 *
 * Matches the Auth0 default for `sessions.anonymous.lifetime_in_minutes`. Override it with
 * {@link StatelessAnonymousStoreOptions.sessionTokenLifetime} when your tenant is configured
 * differently.
 */
export const DEFAULT_ANONYMOUS_SESSION_LIFETIME = 60 * 60 * 24 * 30;

/**
 * Cookie chunk size, matching `StatelessStateStore`. The encrypted payload holds the
 * anonymous session token plus one access token per audience, which can exceed the 4 KB a
 * browser allows for a single cookie.
 */
const CHUNK_SIZE = 3072;

/**
 * Cookie attributes for the anonymous session cookie.
 *
 * This is your application's own cookie on your own domain. It is not the `auth0_anon`
 * cookie, which Auth0 sets on the Auth0 domain and controls itself.
 */
export interface AnonymousCookieOptions {
  /**
   * The sameSite attribute of the anonymous session cookie.
   *
   * Default: `lax`. `lax` is enough: this cookie is only ever read by your own server on
   * requests to your own site.
   */
  sameSite?: 'strict' | 'lax' | 'none';
  /**
   * The secure attribute of the anonymous session cookie.
   *
   * Default: `true`. Set it to `false` only for local development over plain HTTP.
   */
  secure?: boolean;
  /**
   * The path attribute of the anonymous session cookie.
   *
   * Default: `/`.
   */
  path?: string;
}

export interface StatelessAnonymousStoreOptions extends EncryptedStoreOptions {
  /**
   * Lifetime of an anonymous session in seconds, used to work out the cookie's `Max-Age`.
   *
   * Default: 30 days, matching the Auth0 default. This should match
   * `sessions.anonymous.lifetime_in_minutes` on your tenant. It is only a client-side
   * bound: Auth0 is the authority on when the anonymous session token stops working, and a
   * request made after that point fails with `AnonymousSessionExpiredError` regardless of
   * what is configured here.
   */
  sessionTokenLifetime?: number;
  /**
   * The options for the anonymous session cookie.
   */
  cookie?: AnonymousCookieOptions;
}

/**
 * Stateless anonymous session store.
 *
 * Keeps the whole anonymous session in an encrypted, `HttpOnly` cookie on your application's
 * domain, chunked across several cookies when needed, so it needs no server-side storage.
 * Pass it as `anonymousStore` on the `ServerClient`, alongside `StatelessStateStore`.
 *
 * The cookie's `Max-Age` is anchored to the moment the anonymous session was created, so
 * renewing an access token does not extend it. Auth0 never reissues an anonymous session
 * token, so a rolling expiry here would keep a 30-day session alive forever.
 *
 * @example
 * ```typescript
 * const serverClient = new ServerClient({
 *   domain: '<AUTH0_DOMAIN>',
 *   clientId: '<AUTH0_CLIENT_ID>',
 *   clientSecret: '<AUTH0_CLIENT_SECRET>',
 *   transactionStore: new CookieTransactionStore({ secret }, cookieHandler),
 *   stateStore: new StatelessStateStore({ secret }, cookieHandler),
 *   anonymousStore: new StatelessAnonymousStore({ secret }, cookieHandler),
 * });
 * ```
 */
export class StatelessAnonymousStore<TStoreOptions> extends AbstractAnonymousStore<TStoreOptions> {
  readonly #cookieOptions: AnonymousCookieOptions | undefined;
  readonly #cookieHandler: CookieHandler<TStoreOptions>;
  readonly #sessionTokenLifetime: number;

  constructor(options: StatelessAnonymousStoreOptions, cookieHandler: CookieHandler<TStoreOptions>) {
    super(options);

    this.#cookieOptions = options.cookie;
    this.#cookieHandler = cookieHandler;
    this.#sessionTokenLifetime = options.sessionTokenLifetime ?? DEFAULT_ANONYMOUS_SESSION_LIFETIME;
  }

  async set(
    identifier: string,
    anonymousStateData: AnonymousStateData,
    removeIfExists?: boolean,
    options?: TStoreOptions
  ): Promise<void> {
    const expiration = this.#getExpiration(anonymousStateData);
    const maxAge = expiration - Math.floor(Date.now() / 1000);

    // The anonymous session is already past its lifetime, so there is nothing worth
    // storing. Clear whatever is there instead of writing a cookie that expires instantly.
    if (maxAge <= 0) {
      await this.delete(identifier, options);
      return;
    }

    const cookieOpts = this.#getCookieOptions({ maxAge });
    const encryptedStateData = await this.encrypt(identifier, anonymousStateData, expiration);

    const chunkCount = Math.ceil(encryptedStateData.length / CHUNK_SIZE);
    const chunks = [...Array(chunkCount).keys()].map((i) => ({
      value: encryptedStateData.substring(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE),
      name: `${identifier}.${i}`,
    }));

    chunks.forEach((chunk) => {
      this.#cookieHandler.setCookie(chunk.name, chunk.value, cookieOpts, options);
    });

    // A shorter payload than last time leaves stale trailing chunks behind, which would
    // corrupt the value on the next read. Cleared with the plain cookie attributes, not with
    // `cookieOpts`: a `Max-Age` on a cookie that is being removed is contradictory, and some
    // frameworks set their own expiry for a clear.
    const existingCookieKeys = this.#getCookieKeys(identifier, options);
    existingCookieKeys
      .filter((key) => !chunks.some((chunk) => chunk.name === key))
      .forEach((key) => {
        this.#cookieHandler.deleteCookie(key, options, this.#getCookieOptions());
      });
  }

  async get(identifier: string, options?: TStoreOptions): Promise<AnonymousStateData | undefined> {
    const cookieKeys = this.#getCookieKeys(identifier, options);
    const encryptedStateData = cookieKeys
      .map((key) => ({
        index: parseInt(key.split('.')[1] as string, 10),
        value: this.#cookieHandler.getCookie(key, options),
      }))
      .sort((a, b) => a.index - b.index)
      .map((item) => item.value)
      .join('');

    if (encryptedStateData) {
      return await this.decrypt(identifier, encryptedStateData);
    }
  }

  async delete(identifier: string, options?: TStoreOptions): Promise<void> {
    const cookieKeys = this.#getCookieKeys(identifier, options);
    for (const key of cookieKeys) {
      this.#cookieHandler.deleteCookie(key, options, this.#getCookieOptions());
    }
  }

  /**
   * Absolute expiry of the anonymous session, in Unix seconds.
   *
   * Prefers the value Auth0 reports. `sessionTokenExpiresAt` is not populated yet, because
   * `auth0-auth-js` does not surface `session_expires_in` from the token response; until it
   * does, this falls back to the configured lifetime measured from creation.
   */
  #getExpiration(anonymousStateData: AnonymousStateData): number {
    return anonymousStateData.sessionTokenExpiresAt ?? anonymousStateData.createdAt + this.#sessionTokenLifetime;
  }

  #getCookieKeys(identifier: string, options?: TStoreOptions): string[] {
    return Object.keys(this.#cookieHandler.getCookies(options)).filter((key) => key.startsWith(identifier));
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
