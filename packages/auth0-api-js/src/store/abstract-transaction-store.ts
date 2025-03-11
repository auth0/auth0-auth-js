import type { EncryptedStoreOptions, TransactionData, TransactionStore } from '../types.js';
import { AbstractStore } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT Transaction Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractTransactionStore<TStoreOptions = unknown> extends AbstractStore<TransactionData, TStoreOptions> implements TransactionStore<TStoreOptions> {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }
}