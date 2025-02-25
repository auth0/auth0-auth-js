import { StateData } from '../types.js';
import { AbstractStateStore } from './abstract-state-store.js';

/**
 * Default, in-memory, Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export class DefaultStateStore extends AbstractStateStore {
  data = new Map<string, string>();

  delete(identifier: string): Promise<void> {
    this.data.delete(identifier);

    return Promise.resolve();
  }

  async set(identifier: string, value: StateData): Promise<void> {
    const encryptedValue = await this.encrypt(identifier, value);
    this.data.set(identifier, encryptedValue);
  }

  async get(identifier: string): Promise<StateData | undefined> {
    const encryptedValue = this.data.get(identifier);

    if (encryptedValue) {
      return (await this.decrypt(identifier, encryptedValue)) as StateData;
    }
  }

  deleteByLogoutToken(): Promise<void> {
    throw new Error('Method not implemented.');
  }
}
