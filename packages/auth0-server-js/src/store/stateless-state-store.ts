import { MissingStoreOptionsError } from 'src/errors.js';
import type { EncryptedStoreOptions, StateData } from './../types.js';
import { AbstractSessionStore } from './abstract-session-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

export class StatelessStateStore<TStoreOptions> extends AbstractSessionStore<TStoreOptions> {
  readonly #cookieHandler: CookieHandler<TStoreOptions>;

  constructor(options: EncryptedStoreOptions, cookieHandler: CookieHandler<TStoreOptions>) {
    super(options);

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
      throw new MissingStoreOptionsError();
    }

    const maxAge = this.calculateMaxAge(stateData.internal.createdAt);
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: true,
      maxAge,
    };
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(identifier, stateData, expiration);

    const chunkSize = 3072;
    const chunkCount = Math.ceil(encryptedStateData.length / chunkSize);
    const chunks = [...Array(chunkCount).keys()].map((i) => ({
      value: encryptedStateData.substring(i * chunkSize, (i + 1) * chunkSize),
      name: `${identifier}.${i}`,
    }));

    chunks.forEach((chunk) => {
      this.#cookieHandler.setCookie(options, chunk.name, chunk.value, cookieOpts);
    });

    const existingCookieKeys = this.getCookieKeys(identifier, options);
    const cookieKeysToRemove = existingCookieKeys.filter((key) => !chunks.some((chunk) => chunk.name === key));
    cookieKeysToRemove.forEach((key) => {
      this.#cookieHandler.deleteCookie(options, key);
    });
  }

  async get(identifier: string, options?: TStoreOptions | undefined): Promise<StateData | undefined> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieKeys = this.getCookieKeys(identifier, options);
    const encryptedStateData = cookieKeys
      .map((key) => ({
        index: parseInt(key.split('.')[1] as string, 10),
        value: this.#cookieHandler.getCookie(options, key),
      }))
      .sort((a, b) => a.index - b.index)
      .map((item) => item.value)
      .join('');

    if (encryptedStateData) {
      return await this.decrypt(identifier, encryptedStateData);
    }
  }

  async delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    // We can not handle cookies when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieKeys = this.getCookieKeys(identifier, options);
    for (const key of cookieKeys) {
      this.#cookieHandler.deleteCookie(options, key);
    }
  }

  deleteByLogoutToken(): Promise<void> {
    throw new Error(
      'Backchannel logout is not available when using Stateless Storage. Use Stateful Storage by providing a `sessionStore`'
    );
  }

  private getCookieKeys(identifier: string, options: TStoreOptions): string[] {
    return Object.keys(this.#cookieHandler.getCookies(options)).filter((key) => key.startsWith(identifier));
  }
}
