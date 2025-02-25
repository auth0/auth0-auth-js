import type { StateData, EncryptedStoreOptions, StateStore, LogoutTokenClaims } from '../types.js';
import { AbstractStore } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractStateStore<TStoreOptions = unknown> extends AbstractStore<StateData, TStoreOptions> implements StateStore<TStoreOptions> {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }

  abstract deleteByLogoutToken(claims: LogoutTokenClaims, options?: TStoreOptions | undefined): Promise<void>;
}