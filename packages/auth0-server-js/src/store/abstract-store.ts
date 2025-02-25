import type { EncryptedStoreOptions, AbstractDataStore } from '../types.js';
import { encrypt, decrypt } from '../encryption/index.js';
import { JWTPayload } from 'jose';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractStore<TData extends JWTPayload, TStoreOptions = unknown> implements AbstractDataStore<TData, TStoreOptions>
{
  protected readonly options: EncryptedStoreOptions;

  constructor(options: EncryptedStoreOptions) {
    this.options = options;
  }

  abstract set(identifier: string, state: TData, removeIfExists?: boolean, options?: TStoreOptions | undefined): Promise<void>;
  abstract get(identifier: string, options?: TStoreOptions | undefined): Promise<TData | undefined>;
  abstract delete(identifier: string, options?: TStoreOptions | undefined): Promise<void>;

  protected async encrypt<TData extends JWTPayload>(identifier: string, stateData: TData) {
    return await encrypt(stateData, this.options.secret, identifier);
  }

  protected async decrypt<TData>(identifier: string, encryptedStateData: string) {
    return await decrypt(encryptedStateData, this.options.secret, identifier) as TData;
  }
}
