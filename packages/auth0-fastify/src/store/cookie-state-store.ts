import type { CookieSerializeOptions } from '@fastify/cookie';
import { AbstractEncryptedStateStore } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import type { StoreOptions } from '../types.js';

export class CookieStateStore extends AbstractEncryptedStateStore<StoreOptions> {
  async onSet(identifier: string, encryptedStateData: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };

    options.reply.setCookie(identifier, encryptedStateData, cookieOpts);
  }

  async onGet(identifier: string, options?: StoreOptions | undefined): Promise<string | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    return options.request.cookies[identifier];
  }

  async onDelete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    options?.reply.clearCookie(identifier);
  }
}
