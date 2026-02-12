import type { AbstractDataStore } from '../types.js';
import { encrypt, decrypt } from '../encryption/index.js';
import { JWTPayload } from 'jose';

export interface EncryptedStoreOptions {
  secret: string;
}

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractStore<TData extends JWTPayload> implements AbstractDataStore<TData>
{
  protected readonly options: EncryptedStoreOptions;

  constructor(options: EncryptedStoreOptions) {
    this.options = options;
  }

  abstract set(identifier: string, state: TData, removeIfExists?: boolean): Promise<void>;
  abstract get(identifier: string): Promise<TData | undefined>;
  abstract delete(identifier: string): Promise<void>;

  protected async encrypt<TData extends JWTPayload>(identifier: string, stateData: TData, expiration: number) {
    return await encrypt(stateData, this.options.secret, identifier, expiration);
  }

  protected async decrypt<TData>(identifier: string, encryptedStateData: string) {
    return await decrypt(encryptedStateData, this.options.secret, identifier) as TData;
  }
}
