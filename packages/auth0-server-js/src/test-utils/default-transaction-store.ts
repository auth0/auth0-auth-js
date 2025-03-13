import { TransactionData, TransactionStore } from '../types.js';

/**
 * Default, in-memory, transaction store.
 */
export class DefaultTransactionStore implements TransactionStore {
  readonly #data = new Map<string, TransactionData>();

  delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);

    return Promise.resolve();
  }

  async set(identifier: string, value: TransactionData): Promise<void> {
    this.#data.set(identifier, value);
  }

  async get(identifier: string): Promise<TransactionData | undefined> {
    const value = this.#data.get(identifier);

    return value;
  }
}
