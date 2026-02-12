import type { TransactionData, TransactionStore } from '../types.js';
import { AbstractStore, EncryptedStoreOptions } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT Transaction Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractTransactionStore extends AbstractStore<TransactionData> implements TransactionStore {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }
}
