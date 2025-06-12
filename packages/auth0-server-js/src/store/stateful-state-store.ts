import type {
  EncryptedStoreOptions,
  LogoutTokenClaims,
  SessionConfiguration,
  SessionCookieOptions,
  SessionStore,
  StateData,
} from '../types.js';
import { AbstractSessionStore } from './abstract-session-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

export interface StatefulStateStoreOptions<TStoreOptions> extends EncryptedStoreOptions {
  store: SessionStore<TStoreOptions>;
}

const generateId = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

export class StatefulStateStore<TStoreOptions> extends AbstractSessionStore<TStoreOptions> {
  readonly #store: SessionStore<TStoreOptions>;
  readonly #cookieOptions: SessionCookieOptions | undefined;
  readonly #cookieHandler: CookieHandler<TStoreOptions>;

  constructor(
    options: StatefulStateStoreOptions<TStoreOptions> & SessionConfiguration,
    cookieHandler: CookieHandler<TStoreOptions>
  ) {
    super(options);

    this.#store = options.store;
    this.#cookieOptions = options.cookie;
    this.#cookieHandler = cookieHandler;
  }

  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: TStoreOptions | undefined
  ): Promise<void> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    let sessionId = await this.getSessionId(identifier, options);

    // if this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session ID to prevent session fixation.
    if (sessionId && removeIfExists) {
      await this.#store.delete(sessionId);
      sessionId = generateId();
    }

    sessionId ??= generateId();

    const maxAge = this.calculateMaxAge(stateData.internal.createdAt);
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: this.#cookieOptions?.sameSite ?? 'lax',
      path: '/',
      secure: this.#cookieOptions?.secure,
      maxAge,
    };
    const expiration = Date.now() / 1000 + maxAge;
    const encryptedStateData = await this.encrypt<{ id: string }>(
      identifier,
      {
        id: sessionId,
      },
      expiration
    );

    await this.#store.set(sessionId, stateData);

    this.#cookieHandler.setCookie(options, identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: TStoreOptions | undefined): Promise<StateData | undefined> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const sessionId = await this.getSessionId(identifier, options);

    if (sessionId) {
      const stateData = await this.#store.get(sessionId);

      // If we have a session cookie, but no `stateData`, we should remove the cookie.
      if (!stateData) {
        this.#cookieHandler.deleteCookie(options, identifier);
      }

      return stateData;
    }
  }

  async delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const sessionId = await this.getSessionId(identifier, options);

    if (sessionId) {
      await this.#store.delete(sessionId);
    }

    this.#cookieHandler.deleteCookie(options, identifier);
  }

  private async getSessionId(identifier: string, options: TStoreOptions) {
    const cookieValue = this.#cookieHandler.getCookie(options, identifier);
    if (cookieValue) {
      const sessionCookie = await this.decrypt<{ id: string }>(identifier, cookieValue);
      return sessionCookie.id;
    }
  }

  deleteByLogoutToken(claims: LogoutTokenClaims, options?: TStoreOptions | undefined): Promise<void> {
    return this.#store.deleteByLogoutToken(claims, options);
  }
}
