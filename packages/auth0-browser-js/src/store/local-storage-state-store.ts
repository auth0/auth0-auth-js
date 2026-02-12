import type { StateData, LogoutTokenClaims } from '../types.js';
import { AbstractStateStore } from './abstract-state-store.js';
import { EncryptedStoreOptions } from './abstract-store.js';

/**
 * A state store implementation that stores encrypted state in localStorage.
 */
export class LocalStorageStateStore extends AbstractStateStore {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }

  async set(identifier: string, state: StateData, removeIfExists?: boolean): Promise<void> {
    if (removeIfExists) {
      await this.delete(identifier);
    }

    const expiration = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60); // 7 days
    const encryptedState = await this.encrypt(identifier, state, expiration);

    localStorage.setItem(identifier, encryptedState);
  }

  async get(identifier: string): Promise<StateData | undefined> {
    const encryptedState = localStorage.getItem(identifier);

    if (!encryptedState) {
      return undefined;
    }

    try {
      return await this.decrypt<StateData>(identifier, encryptedState);
    } catch {
      // If decryption fails (e.g., expired or tampered), remove the item
      await this.delete(identifier);
      return undefined;
    }
  }

  async delete(identifier: string): Promise<void> {
    localStorage.removeItem(identifier);
  }

  async deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void> {
    const state = await this.get('__a0_session');

    if (!state) {
      return;
    }

    // Check if the logout token matches the session
    if (
      (claims.sid && state.internal.sid === claims.sid) ||
      (claims.sub && state.user?.sub === claims.sub)
    ) {
      await this.delete('__a0_session');
    }
  }
}
