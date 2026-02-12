import type { TransactionData, TransactionStore } from '../types.js';

/**
 * A transaction store implementation that stores transaction data in memory.
 * Data is cleared when the page is reloaded.
 * Does not encrypt data since it's never persisted.
 */
export class MemoryTransactionStore implements TransactionStore {
  #storage: Map<string, TransactionData> = new Map();

  async set(identifier: string, transaction: TransactionData, removeIfExists?: boolean): Promise<void> {
    if (removeIfExists) {
      await this.delete(identifier);
    }

    this.#storage.set(identifier, transaction);
  }

  async get(identifier: string): Promise<TransactionData | undefined> {
    return this.#storage.get(identifier);
  }

  async delete(identifier: string): Promise<void> {
    this.#storage.delete(identifier);
  }
}
