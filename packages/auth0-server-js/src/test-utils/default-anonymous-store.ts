import { AnonymousStateData, EncryptedStoreOptions } from '../types.js';
import { AbstractAnonymousStore } from './../store/abstract-anonymous-store.js';

/**
 * Default, in-memory, Encrypted JWT Anonymous Session Store, using the 'A256CBC-HS512'
 * encryption algorithm.
 */
export class DefaultAnonymousStore extends AbstractAnonymousStore {
  readonly #data = new Map<string, string>();
  readonly #sessionTokenLifetime: number;

  constructor(options: EncryptedStoreOptions & { sessionTokenLifetime?: number }) {
    super(options);
    this.#sessionTokenLifetime = options.sessionTokenLifetime ?? 60 * 60 * 24 * 30;
  }

  delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);

    return Promise.resolve();
  }

  async set(identifier: string, value: AnonymousStateData): Promise<void> {
    const expiration = value.sessionTokenExpiresAt ?? value.createdAt + this.#sessionTokenLifetime;
    const encryptedValue = await this.encrypt(identifier, value, expiration);
    this.#data.set(identifier, encryptedValue);
  }

  async get(identifier: string): Promise<AnonymousStateData | undefined> {
    const encryptedValue = this.#data.get(identifier);

    if (encryptedValue) {
      return await this.decrypt(identifier, encryptedValue);
    }
  }
}
