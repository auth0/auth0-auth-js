import { EncryptedStoreOptions, TransactionData } from '../types.js';
import { AbstractTransactionStore } from './../store/abstract-transaction-store.js';

/**
 * Default, in-memory, transaction store.
 */
export class DefaultTransactionStore extends AbstractTransactionStore {
  readonly #data = new Map<string, string>();

  constructor(options: EncryptedStoreOptions) {
    super(options);
  }

  delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);

    return Promise.resolve();
  }

  async set(identifier: string, value: TransactionData): Promise<void> {
    const absoluteDuration = 60 * 60;
    const expiration = Math.floor(Date.now() / 1000 + absoluteDuration);
    const encryptedValue = await this.encrypt(identifier, value, expiration);
    this.#data.set(identifier, encryptedValue);
  }

  async get(identifier: string): Promise<TransactionData | undefined> {
    const encryptedValue = this.#data.get(identifier);

    if (encryptedValue) {
      return await this.decrypt(identifier, encryptedValue);
    }
  }
}
