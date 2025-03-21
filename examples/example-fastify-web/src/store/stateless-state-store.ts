import type { CookieSerializeOptions } from '@fastify/cookie';
import {
  BackchannelLogoutError,
  EncryptedStoreOptions,
  StateData,
} from '@auth0/auth0-server-js';
import type { StoreOptions } from '../types.js';
import { AbstractSessionStore } from './abstract-session-store.js';

export class StatelessStateStore extends AbstractSessionStore {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }

  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: StoreOptions | undefined
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const maxAge = this.calculateMaxAge(stateData.internal.createdAt);
    const cookieOpts: CookieSerializeOptions = {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: 'auto',
      maxAge,
    };
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encryptedStateData = await this.encrypt(
      identifier,
      stateData,
      expiration
    );

    const chunkSize = 3072;
    const chunkCount = Math.ceil(encryptedStateData.length / chunkSize);
    const chunks = [...Array(chunkCount).keys()].map((i) => ({
      value: encryptedStateData.substring(i * chunkSize, (i + 1) * chunkSize),
      name: `${identifier}.${i}`,
    }));

    chunks.forEach((chunk) => {
      options.reply.setCookie(chunk.name, chunk.value, cookieOpts);
    });

    const existingCookieKeys = this.getCookieKeys(identifier, options);
    const cookieKeysToRemove = existingCookieKeys.filter(
      (key) => !chunks.some((chunk) => chunk.name === key)
    );
    cookieKeysToRemove.forEach((key) => {
      options.reply.clearCookie(key);
    });
  }

  async get(
    identifier: string,
    options?: StoreOptions | undefined
  ): Promise<StateData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const cookieKeys = this.getCookieKeys(identifier, options);
    const encryptedStateData = cookieKeys
      .map((key) => ({
        index: parseInt(key.split('.')[1] as string, 10),
        value: options.request.cookies[key],
      }))
      .sort((a, b) => a.index - b.index)
      .map((item) => item.value)
      .join('');

    if (encryptedStateData) {
      return (await this.decrypt(identifier, encryptedStateData)) as StateData;
    }
  }

  async delete(
    identifier: string,
    options?: StoreOptions | undefined
  ): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new Error('StoreOptions not provided');
    }

    const cookieKeys = this.getCookieKeys(identifier, options);
    for (const key of cookieKeys) {
      options?.reply.clearCookie(key);
    }
  }

  deleteByLogoutToken(): Promise<void> {
    throw new BackchannelLogoutError(
      'Backchannel logout is not available when using Stateless Storage. Use Stateful Storage by providing a `sessionStore`'
    );
  }

  private getCookieKeys(identifier: string, options: StoreOptions): string[] {
    return Object.keys(options.request.cookies).filter((key) =>
      key.startsWith(identifier)
    );
  }
}
