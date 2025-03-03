import type { CookieSerializeOptions } from '@fastify/cookie';
import { BackchannelLogoutError, EncryptedStoreOptions, StateData } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import type { SessionConfiguration, SessionCookieOptions, StoreOptions } from '../types.js';
import { AbstractSessionStore } from './abstract-session-store.js';

export class StatelessStateStore extends AbstractSessionStore {
  readonly #cookieOptions: SessionCookieOptions | undefined;

  constructor(options: SessionConfiguration & EncryptedStoreOptions) {
    super(options);

    this.#cookieOptions = options.cookie;
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

    const maxAge = this.calculateMaxAge(stateData.internal.createdAt);
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: this.#cookieOptions?.sameSite ?? 'lax',
      path: '/',
      secure: this.#cookieOptions?.secure ?? 'auto',
      maxAge,
    };
    const expiration = (Date.now() / 1000) + maxAge;
    const encryptedStateData = await this.encrypt(identifier, stateData, expiration);

    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions | undefined): Promise<StateData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const encryptedStateData = options.request.cookies[identifier];
    if (encryptedStateData) {
      return (await this.decrypt(identifier, encryptedStateData)) as StateData;
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    options?.reply.clearCookie(identifier);
  }

  deleteByLogoutToken(): Promise<void> {
    throw new BackchannelLogoutError(
      'Backchannel logout is not available when using Stateless Storage. Use Stateful Storage by providing a `sessionStore`'
    );
  }
}
