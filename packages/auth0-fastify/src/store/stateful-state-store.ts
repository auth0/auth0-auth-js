import type { CookieSerializeOptions } from '@fastify/cookie';
import { AbstractStateStore, EncryptedStoreOptions, LogoutTokenClaims, StateData } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import type { SessionStore, StoreOptions } from '../types.js';

export interface StatefulStateStoreOptions extends EncryptedStoreOptions {
  store: SessionStore;
}

const generateId = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

export class StatefulStateStore extends AbstractStateStore<StoreOptions> {
  readonly #options: StatefulStateStoreOptions;

  constructor(options: StatefulStateStoreOptions) {
    super(options);

    this.#options = options;
  }

  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: StoreOptions | undefined
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    let sessionId = await this.getSessionId(identifier, options);

    // if this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session ID to prevent session fixation.
    if (sessionId && removeIfExists) {
      await this.#options.store.delete(sessionId);
      sessionId = generateId();
    }

    if (!sessionId) {
      sessionId = generateId();
    }

    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };
    const encryptedStateData = await this.encrypt<{ id: string }>(identifier, {
      id: sessionId,
    });

    await this.#options.store.set(sessionId, stateData);

    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions | undefined): Promise<StateData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const sessionId = await this.getSessionId(identifier, options);

    if (sessionId) {
      const stateData = await this.#options.store.get(sessionId);

      // If we have a session cookie, but no `stateData`, we should remove the cookie.
      if (!stateData) {
        options?.reply.clearCookie(identifier);
      }

      return stateData;
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const sessionId = await this.getSessionId(identifier, options);

    if (sessionId) {
      await this.#options.store.delete(sessionId);
    }

    options?.reply.clearCookie(identifier);
  }

  private async getSessionId(identifier: string, options: StoreOptions) {
    const cookieValue = options.request.cookies[identifier];
    if (cookieValue) {
      const sessionCookie = await this.decrypt<{ id: string }>(identifier, cookieValue);
      return sessionCookie.id;
    }
  }

  deleteByLogoutToken(claims: LogoutTokenClaims, options?: StoreOptions | undefined): Promise<void> {
    return this.#options.store.deleteByLogoutToken(claims, options);
  }
}
