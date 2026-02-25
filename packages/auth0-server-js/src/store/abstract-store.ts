import type { EncryptedStoreOptions, AbstractDataStore } from '../types.js';
import { encrypt, decrypt, isDecryptionError } from '../encryption/index.js';
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

  protected async encrypt<TData extends JWTPayload>(identifier: string, stateData: TData, expiration: number) {
    return await encrypt(stateData, this.options.secret, identifier, expiration);
  }

  protected async decrypt<TData>(identifier: string, encryptedStateData: string) {
    try {
      return (await decrypt(encryptedStateData, this.options.secret, identifier)) as TData;
    } catch (e: unknown){
      // When the error is a decryption failure, we want to ignore it and return undefined, as this likely means the session has expired or the data is invalid.
      if (isDecryptionError(e)) {
        return;
      }

      throw e;
    }
  }
}
