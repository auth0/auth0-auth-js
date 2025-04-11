import type { CookieSerializeOptions } from 'cookie-es';
import type {
  EncryptedStoreOptions,
  StateData,
} from '@auth0/auth0-server-js';
import type { StoreOptions } from '../types.js';
import { AbstractSessionStore } from './abstract-session-store.js';

import { setCookie, deleteCookie } from 'h3';

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
      secure: true,
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
      setCookie(options.event, chunk.name, chunk.value, cookieOpts);
    });

    const existingCookieKeys = this.getCookieKeys(identifier, options);
    const cookieKeysToRemove = existingCookieKeys.filter(
      (key) => !chunks.some((chunk) => chunk.name === key)
    );
    cookieKeysToRemove.forEach((key) => {
      deleteCookie(options.event, key);
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
        value: getCookie(options.event, key),
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
      deleteCookie(options.event, key);
    }
  }

  deleteByLogoutToken(): Promise<void> {
    throw new Error(
      'Backchannel logout is not available when using Stateless Storage. Use Stateful Storage by providing a `sessionStore`'
    );
  }

  private getCookieKeys(identifier: string, options: StoreOptions): string[] {
    return Object.keys(this.getAllCookies(options)).filter((key) =>
      key.startsWith(identifier)
    );
  }

  private getAllCookies(options: StoreOptions) {
    const cookieHeader = getHeader(options.event, 'Cookie');

    if (!cookieHeader) {
      return {};
    }

    const cookies: { [key: string]: string } = {};
    const cookiePairs = cookieHeader.split(';');

    cookiePairs.forEach((pair) => {
      const [name, value] = pair.trim().split('=');
      if (name) {
        cookies[decodeURIComponent(name)] = decodeURIComponent(value || '');
      }
    });

    return cookies;
  }
}
