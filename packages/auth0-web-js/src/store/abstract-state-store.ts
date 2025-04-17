import type { StateData, StateStore, LogoutTokenClaims } from '../types.js';
import { AbstractStore } from './abstract-store.js';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store
 */
export abstract class AbstractStateStore<TStoreOptions = unknown> extends AbstractStore<StateData, TStoreOptions> implements StateStore<TStoreOptions> {
  constructor() {
    super();
  }

  abstract deleteByLogoutToken(claims: LogoutTokenClaims, options?: TStoreOptions | undefined): Promise<void>;
}