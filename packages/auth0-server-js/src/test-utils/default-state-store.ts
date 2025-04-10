import { EncryptedStoreOptions, StateData } from '../types.js';
import { AbstractStateStore } from './../store/abstract-state-store.js';

/**
 * Default, in-memory, Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export class DefaultStateStore extends AbstractStateStore {
  readonly #data = new Map<string, string>();
  readonly #absoluteDuration: number;

  constructor(options: EncryptedStoreOptions & { absoluteDuration?: number }) {
    super(options);
    this.#absoluteDuration = options.absoluteDuration ?? 60 * 60 * 24 * 3;
  }

  delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);

    return Promise.resolve();
  }

  async set(identifier: string, value: StateData): Promise<void> {
    const expiration = Math.floor((Date.now() / 1000) + this.#absoluteDuration);
    const encryptedValue = await this.encrypt(identifier, value, expiration);
    this.#data.set(identifier, encryptedValue);
  }

  async get(identifier: string): Promise<StateData | undefined> {
    const encryptedValue = this.#data.get(identifier);

    if (encryptedValue) {
      return await this.decrypt(identifier, encryptedValue);
    }
  }

  deleteByLogoutToken(): Promise<void> {
    throw new Error('Method not implemented.');
  }
}
