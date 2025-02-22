import type { EncryptedStoreOptions, AbstractDataStore } from '../types.js';
import { encrypt, decrypt } from '../encryption/index.js';
import { JWTPayload } from 'jose';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store, using the 'A256CBC-HS512' encryption algorithm.
 */
export abstract class AbstractEncryptedStore<TData extends JWTPayload, TStoreOptions = unknown>
  implements AbstractDataStore<TData, TStoreOptions>
{
  protected readonly options: EncryptedStoreOptions;

  constructor(options: EncryptedStoreOptions) {
    this.options = options;
  }

  /**
   * Encrypt and store the transaction data.
   * @param identifier The identifier of the transaction data, used as the persistency identifier.
   * @param stateData The data to be stored
   * @param options Additional store options, can be useful when you need access to the Request / Response or other framework-specific integrations.
   * @returns A promise, resolving when the transaction data was stored succesfully.
   */
  async set(identifier: string, stateData: TData, options?: TStoreOptions | undefined): Promise<void> {
    const encryptedStateData = await encrypt(stateData, this.options.secret, identifier);

    return this.onSet(identifier, encryptedStateData, options);
  }

  /**
   * Decrypt and retrieve the stored transaction data.
   * @param identifier The identifier of the transaction data, used as the persistency identifier.
   * @param options Additional store options, can be useful when you need access to the Request / Response or other framework-specific integrations.
   * @returns A promisem, resolving to the decrypted transaction data, or undefined of no transaction data was found.
   */
  async get(identifier: string, options?: TStoreOptions | undefined): Promise<TData | undefined> {
    const encryptedStateData = await this.onGet(identifier, options);

    if (encryptedStateData) {
      return decrypt(encryptedStateData, this.options.secret, identifier);
    }
  }

  /**
   * Delete the stored state data.
   * @param identifier The identifier of the state data, used as the persistency identifier.
   * @param options Additional store options, can be useful when you need access to the Request / Response or other framework-specific integrations.
   * @returns A promise, resolving when the state data was deleted succesfully.
   */
  delete(identifier: string, options?: TStoreOptions | undefined): Promise<void> {
    return this.onDelete(identifier, options);
  }

  abstract onSet(identifier: string, encryptedStateData: string, options?: TStoreOptions | undefined): Promise<void>;
  abstract onGet(identifier: string, options?: TStoreOptions | undefined): Promise<string | undefined>;
  abstract onDelete(identifier: string, options?: TStoreOptions | undefined): Promise<void>;
}
