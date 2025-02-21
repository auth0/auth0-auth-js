import type { CookieSerializeOptions } from '@fastify/cookie';
import type { StateStore, StateData } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import type { StoreOptions } from '../types.js';

export class CookieStateStore implements StateStore<StoreOptions> {
  async set(identifier: string, stateData: StateData, options?: StoreOptions): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };

    // Temporarily unencrypted, will encrypt in a follow-up commit.
    options.reply.setCookie(identifier, JSON.stringify(stateData), cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<StateData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookie = options.request.cookies[identifier];

    if (cookie) {
      return JSON.parse(cookie);
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    options?.reply.clearCookie(identifier);
  }
}
