import { StateData, AbstractStateStore, LogoutTokenClaims } from '@auth0/auth0-web-js';

export class MemorySessionStore extends AbstractStateStore {
  private store: Map<string, StateData> = new Map();

  async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
  ): Promise<void> {
    this.store.set(identifier, stateData);
  }

  async get(identifier: string): Promise<StateData | undefined> {
    return this.store.get(identifier);
  }

  async delete(identifier: string): Promise<void> {
    this.store.delete(identifier);
  }

  async deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void> {
  }
}
