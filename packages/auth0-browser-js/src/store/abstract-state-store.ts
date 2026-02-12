import type { StateData, StateStore, LogoutTokenClaims } from '../types.js';
import { AbstractStore, EncryptedStoreOptions } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractStateStore extends AbstractStore<StateData> implements StateStore {
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }

  abstract deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void>;
}
