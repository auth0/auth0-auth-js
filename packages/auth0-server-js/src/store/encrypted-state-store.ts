import type { StateData, EncryptedStoreOptions } from '../types.js';
import { AbstractEncryptedStore } from './abstract-encrypted-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractEncryptedStateStore<TStoreOptions = unknown> extends AbstractEncryptedStore<StateData, TStoreOptions> {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }
}
