import { TransactionData, TransactionStore } from '../types.js';

/**
 * Default, in-memory, transaction store.
 */
export class DefaultTransactionStore implements TransactionStore {
  data = new Map<string, TransactionData>();

  delete(identifier: string): Promise<void> {
    this.data.delete(identifier);

    return Promise.resolve();
  }
  set(identifier: string, transactionData: TransactionData): Promise<void> {
    this.data.set(identifier, transactionData);

    return Promise.resolve();
  }
  get(identifier: string): Promise<TransactionData | undefined> {
    return Promise.resolve(this.data.get(identifier));
  }
}
