import type { EncryptedStoreOptions, AbstractDataStore } from '../types.js';
import { encrypt, decrypt } from '../encryption/index.js';
import { JWTPayload, errors } from 'jose';

/**
 * Type guard to determine if an error should be ignored as a session expiration or invalid session, based on the type of error thrown during decryption.
 * We want to ignore decryption failures and invalid JWE format errors, as these likely indicate an expired or tampered session. However, we do NOT want to ignore claim validation errors (like expiration), as these indicate a valid token that has simply expired.
 * @param e - The error thrown during decryption
 * @returns True if the error should be ignored (session expiration/invalid), false otherwise
 */
function shouldIgnoreSession(e: unknown): e is Error {
  // Only catch encryption-related errors (decryption failures, invalid JWE format)
  // Do NOT catch claim validation errors (expiration, etc.)
  return e instanceof errors.JWEDecryptionFailed || e instanceof errors.JWEInvalid;
}

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
      // When the error indicates a decryption failure, we want to ignore it and return undefined, as this likely means the session has expired or the data is invalid.
      if (shouldIgnoreSession(e)) {
        return;
      }

      throw e;
    }
  }
}
