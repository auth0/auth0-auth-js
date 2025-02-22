import { AbstractEncryptedStateStore } from './encrypted-state-store.js';

/**
 * Default, in-memory, Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export class DefaultStateStore extends AbstractEncryptedStateStore {
  data = new Map<string, string>();

  onDelete(identifier: string): Promise<void> {
    this.data.delete(identifier);

    return Promise.resolve();
  }
  onSet(identifier: string, value: string): Promise<void> {
    this.data.set(identifier, value);

    return Promise.resolve();
  }
  onGet(identifier: string): Promise<string | undefined> {
    return Promise.resolve(this.data.get(identifier));
  }
}
