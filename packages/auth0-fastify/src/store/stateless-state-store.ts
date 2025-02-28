import type { CookieSerializeOptions } from '@fastify/cookie';
import { AbstractStateStore, BackchannelLogoutError, StateData } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import type { StoreOptions } from '../types.js';

export class StatelessStateStore extends AbstractStateStore<StoreOptions> {
  
  async set(identifier: string, stateData: StateData, removeIfExists?: boolean, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/' };
    const encryptedStateData = await this.encrypt(identifier, stateData);

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
    throw new BackchannelLogoutError('Backchannel logout is not available when using Stateless Storage. Use Stateful Storage by providing a `sessionStore`');
  }
}
