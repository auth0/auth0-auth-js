import type { TransactionData, TransactionStore } from '../types.js';
import { AbstractStore } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT Transaction Store
 */
export abstract class AbstractTransactionStore<TStoreOptions = unknown> extends AbstractStore<TransactionData, TStoreOptions> implements TransactionStore<TStoreOptions> {
  constructor() {
    super();
  }
}