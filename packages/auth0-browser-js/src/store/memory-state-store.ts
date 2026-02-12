import type { StateData, LogoutTokenClaims, StateStore } from '../types.js';

/**
 * A state store implementation that stores state in memory.
 * Data is cleared when the page is reloaded.
 * Does not encrypt data since it's never persisted.
 */
export class MemoryStateStore implements StateStore {
  #storage: Map<string, StateData> = new Map();

  async set(identifier: string, state: StateData, removeIfExists?: boolean): Promise<void> {
    if (removeIfExists) {
      await this.delete(identifier);
    }

    this.#storage.set(identifier, state);
  }

  async get(identifier: string): Promise<StateData | undefined> {
    return this.#storage.get(identifier);
  }

  async delete(identifier: string): Promise<void> {
    this.#storage.delete(identifier);
  }

  async deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void> {
    const state = await this.get('__a0_session');

    if (!state) {
      return;
    }

    if (claims.sid && state.internal.sid === claims.sid) {
      await this.delete('__a0_session');
    }

    if (claims.sub && state.user?.sub === claims.sub) {
      await this.delete('__a0_session');
    }
  }
}
