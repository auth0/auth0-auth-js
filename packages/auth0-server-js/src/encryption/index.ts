import { EncryptJWT, jwtDecrypt, errors } from 'jose';
import type { JWTPayload } from 'jose';
import { InvalidConfigurationError } from '../errors.js';

const ENC = 'A256CBC-HS512';
const ALG = 'dir';
const DIGEST = 'SHA-256';
const BIT_LENGTH = 512;
const HKDF_INFO = 'derived cookie encryption secret';

let encoder: TextEncoder | undefined;

/**
 * Type guard to determine if an error is a decryption-related error.
 * Decryption errors (JWEDecryptionFailed, JWEInvalid) indicate issues with the encryption key or data format.
 * These are distinct from claim validation errors (like expiration), which indicate a valid token with invalid claims.
 * @param e - The error thrown during decryption
 * @returns True if the error is a decryption error, false otherwise
 */
export function isDecryptionError(e: unknown): e is Error {
  return e instanceof errors.JWEDecryptionFailed || e instanceof errors.JWEInvalid;
}

async function deriveEncryptionSecret(secret: string, salt: string, kid: string) {
  encoder ||= new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits']);

  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: DIGEST,
        info: encoder.encode(HKDF_INFO),
        salt: encoder.encode(`${salt}${kid}`),
      } as HkdfParams,
      key,
      BIT_LENGTH
    )
  );
}

/**
 * Encrypts a payload using the provided secret and salt, with an expiration time.
 * @param payload The payload to encrypt.
 * @param secret The secret to use for encryption.
 * @param salt The salt to use for encryption.
 * @param expiration The expiration time for the encrypted payload.
 * @returns The encrypted payload.
 */
async function _encrypt(payload: JWTPayload, secret: string, salt: string, expiration: number) {
  const kid = crypto.randomUUID();
  const encryptionSecret = await deriveEncryptionSecret(secret, salt, kid);

  return await new EncryptJWT(payload)
    .setProtectedHeader({ enc: ENC, alg: ALG, kid: kid })
    .setExpirationTime(expiration)
    .encrypt(encryptionSecret);
}

/**
 * Encrypts a payload using the provided secret and salt, with an expiration time.
 * The secret can be a single string or an array of strings for secret rotation support.
 * When using an array of secrets, only the first one is used for encryption (all secrets are tried for decryption).
 * @param payload The payload to encrypt.
 * @param secret The secret(s) to use for encryption. Can be a single string or an array of strings for secret rotation support.
 * @param salt The salt to use for encryption.
 * @param expiration The expiration time for the encrypted payload.
 * @returns The encrypted payload.
 */
export async function encrypt(payload: JWTPayload, secret: string | string[], salt: string, expiration: number) {
  if (typeof secret === 'string') {
    return await _encrypt(payload, secret, salt, expiration);
  } else {
    // For encryption, we only use the newest secret, as the old secrets are only used for backward compatibility during decryption.
    const [newSecret] = secret;

    if (!newSecret) {
      throw new InvalidConfigurationError('At least one secret must be provided');
    }

    return await _encrypt(payload, newSecret, salt, expiration);
  }
}

/**
 * Decrypts an encrypted payload using the provided secret(s) and salt.
 * @param value The encrypted payload to decrypt.
 * @param secret The secret to use for decryption.
 * @param salt The salt to use for decryption.
 * @returns The decrypted payload.
 */
export async function _decrypt<T>(value: string, secret: string, salt: string) {
  const res = await jwtDecrypt<T>(
    value,
    async (protectedHeader) => {
      // This error shouldn't happen, as we always set a kid.
      // However, leaving this here as a safety net.
      if (!protectedHeader.kid) {
        throw new Error('Missing "kid" in JWE header');
      }

      return await deriveEncryptionSecret(secret, salt, protectedHeader.kid);
    },
    { clockTolerance: 15 }
  );
  return res.payload;
}

/**
 * Decrypts an encrypted payload using the provided secret(s) and salt.
 * The secret can be a single string or an array of strings for secret rotation support.
 * When using an array of secrets, the function will try to decrypt with each secret in order until it succeeds or exhausts all options.
 * Only decryption-related errors (JWEDecryptionFailed, JWEInvalid) will trigger fallback to old secrets.
 * Other errors (like expiration) will be thrown immediately.
 * @param value The encrypted payload to decrypt.
 * @param secret The secret(s) to use for decryption. Can be a single string or an array of strings for secret rotation support.
 * @param salt The salt to use for decryption.
 * @returns The decrypted payload.
 */
export async function decrypt<T>(value: string, secret: string | string[], salt: string) {
  if (typeof secret === 'string') {
    return await _decrypt<T>(value, secret, salt);
  } else {
    const [newSecret, ...oldSecrets] = secret;

    if (!newSecret) {
      throw new InvalidConfigurationError('At least one secret must be provided');
    }

    let firstError: Error | undefined;

    try {
      return await _decrypt<T>(value, newSecret, salt);
    } catch (err) {
      firstError = err as Error;

      // Only try old secrets if this is a decryption-related error
      // Other errors (like expiration) should be thrown immediately
      if (!isDecryptionError(err)) {
        throw firstError;
      }

      for (const oldSecret of oldSecrets) {
        try {
          return await _decrypt(value, oldSecret, salt);
        } catch (fallbackErr) {
          // Only ignore decryption errors with old secrets and continue trying with the next one
          // If it's a different type of error, throw it
          if (!isDecryptionError(fallbackErr)) {
            throw fallbackErr;
          }
        }
      }

      // If we've exhausted all secrets and still can't decrypt, throw the original error.
      throw firstError;
    }
  }
}
