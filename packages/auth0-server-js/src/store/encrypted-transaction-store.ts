import type { EncryptedStoreOptions, TransactionData } from '../types.js';
import { AbstractEncryptedStore } from './abstract-encrypted-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT Transaction Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractEncryptedTransactionStore<TStoreOptions = unknown> extends AbstractEncryptedStore<TransactionData, TStoreOptions> {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }
}
