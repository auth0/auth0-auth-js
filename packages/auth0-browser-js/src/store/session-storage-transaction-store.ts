import type { TransactionData } from '../types.js';
import { AbstractTransactionStore } from './abstract-transaction-store.js';
import { EncryptedStoreOptions } from './abstract-store.js';

/**
 * A transaction store implementation that stores encrypted transaction data in sessionStorage.
 * Data is cleared when the browser tab/window is closed.
 */
export class SessionStorageTransactionStore extends AbstractTransactionStore {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }

  async set(identifier: string, transaction: TransactionData, removeIfExists?: boolean): Promise<void> {
    if (removeIfExists) {
      await this.delete(identifier);
    }

    const expiration = Math.floor(Date.now() / 1000) + (10 * 60); // 10 minutes
    const encryptedTransaction = await this.encrypt(identifier, transaction, expiration);

    sessionStorage.setItem(identifier, encryptedTransaction);
  }

  async get(identifier: string): Promise<TransactionData | undefined> {
    const encryptedTransaction = sessionStorage.getItem(identifier);

    if (!encryptedTransaction) {
      return undefined;
    }

    try {
      return await this.decrypt<TransactionData>(identifier, encryptedTransaction);
    } catch {
      // If decryption fails (e.g., expired or tampered), remove the item
      await this.delete(identifier);
      return undefined;
    }
  }

  async delete(identifier: string): Promise<void> {
    sessionStorage.removeItem(identifier);
  }
}
