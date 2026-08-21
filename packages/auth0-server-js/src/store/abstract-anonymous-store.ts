import type { AnonymousStateData, AnonymousStore, EncryptedStoreOptions } from '../types.js';
import { AbstractStore } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT Anonymous Session Store,
 * using the 'A256CBC-HS512' encryption algorithm.
 *
 * Extend this when you want the SDK's encryption but your own persistence (Redis, a
 * database, and so on). For the cookie-backed default, use `StatelessAnonymousStore`.
 */
export abstract class AbstractAnonymousStore<TStoreOptions = unknown>
  extends AbstractStore<AnonymousStateData, TStoreOptions>
  implements AnonymousStore<TStoreOptions>
{
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }
}
