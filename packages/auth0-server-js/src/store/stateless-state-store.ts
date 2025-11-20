import type { EncryptedStoreOptions, SessionConfiguration, SessionCookieOptions, StateData } from '../types.js';
import { AbstractSessionStore } from './abstract-session-store.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

export class StatelessStateStore<TStoreOptions> extends AbstractSessionStore<TStoreOptions> {
  readonly #cookieOptions: SessionCookieOptions | undefined;
  readonly #cookieHandler: CookieHandler<TStoreOptions>;

  constructor(options: SessionConfiguration & EncryptedStoreOptions, cookieHandler: CookieHandler<TStoreOptions>) {
    super(options);

    this.#cookieOptions = options.cookie;
    this.#cookieHandler = cookieHandler;
  }

  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: TStoreOptions | undefined
  ): Promise<void> {
    const maxAge = this.calculateMaxAge(stateData.internal.createdAt);
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: this.#cookieOptions?.sameSite ?? 'lax',
      path: '/',
      secure: this.#cookieOptions?.secure ?? true,
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

    for (const chunk of chunks) {
      await this.#cookieHandler.setCookie(chunk.name, chunk.value, cookieOpts, options);
    }

    const existingCookieKeys = await this.getCookieKeys(identifier, options);
    const cookieKeysToRemove = existingCookieKeys.filter((key) => !chunks.some((chunk) => chunk.name === key));
    for (const key of cookieKeysToRemove) {
      await this.#cookieHandler.deleteCookie(key, options);
    }
  }

  async get(identifier: string, options?: TStoreOptions | undefined): Promise<StateData | undefined> {
    const cookieKeys = await this.getCookieKeys(identifier, options);
    const chunks = await Promise.all(
      cookieKeys.map(async (key) => ({
        index: parseInt(key.split('.')[1] as string, 10),
        value: await this.#cookieHandler.getCookie(key, options),
      }))
    );
    const encryptedStateData = chunks
      .sort((a, b) => a.index - b.index)
      .map((item) => item.value)
      .join('');

    if (encryptedStateData) {
      return await this.decrypt(identifier, encryptedStateData);
    }
  }

  async delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    const cookieKeys = await this.getCookieKeys(identifier, options);
    for (const key of cookieKeys) {
      await this.#cookieHandler.deleteCookie(key, options);
    }
  }

  deleteByLogoutToken(): Promise<void> {
    throw new Error(
      'Backchannel logout is not available when using Stateless Storage. Use Stateful Storage by providing a `sessionStore`'
    );
  }

  private async getCookieKeys(identifier: string, options?: TStoreOptions): Promise<string[]> {
    const cookies = await this.#cookieHandler.getCookies(options);
    return Object.keys(cookies).filter((key) => key.startsWith(identifier));
  }
}
