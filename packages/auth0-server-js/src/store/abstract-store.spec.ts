import { expect, test } from 'vitest';
import { AbstractStore } from './abstract-store.js';
import { encrypt } from './../test-utils/encryption.js';
import type { JWTPayload } from 'jose';
import { errors } from 'jose';
import { InvalidConfigurationError } from '../errors.js';

interface TestData extends JWTPayload {
  foo: string;
}

/**
 * Concrete implementation of AbstractStore for testing purposes
 */
class TestStore extends AbstractStore<TestData> {
  private storage = new Map<string, string>();

  async set(identifier: string, state: TestData): Promise<void> {
    const encrypted = await this.encrypt(identifier, state, Date.now() / 1000 + 3600);
    this.storage.set(identifier, encrypted);
  }

  async get(identifier: string): Promise<TestData | undefined> {
    const encrypted = this.storage.get(identifier);
    if (!encrypted) {
      return undefined;
    }
    return await this.decrypt<TestData>(identifier, encrypted);
  }

  async delete(identifier: string): Promise<void> {
    this.storage.delete(identifier);
  }

  // Expose decrypt method for testing
  public async testDecrypt(identifier: string, encryptedData: string): Promise<TestData | undefined> {
    return await this.decrypt<TestData>(identifier, encryptedData);
  }
}

test('decrypt - should return undefined when decryption fails with wrong secret', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with a different secret
  const encrypted = await encrypt(data, '<different-secret>', identifier, Date.now() / 1000 + 3600);

  // Decrypt should return undefined instead of throwing
  const result = await store.testDecrypt(identifier, encrypted);
  expect(result).toBeUndefined();
});

test('decrypt - should throw when token is expired', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with expiration in the past (beyond clock tolerance of 15 seconds)
  const encrypted = await encrypt(data, '<secret>', identifier, Date.now() / 1000 - 20);

  // Decrypt should throw for claim validation errors like expiration
  await expect(store.testDecrypt(identifier, encrypted)).rejects.toThrow();
});

test('decrypt - should return undefined when encrypted data is invalid', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';

  // Invalid encrypted data
  const result = await store.testDecrypt(identifier, 'invalid-encrypted-data');
  expect(result).toBeUndefined();
});

test('decrypt - should return undefined when encrypted data is corrupted', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt properly
  const encrypted = await encrypt(data, '<secret>', identifier, Date.now() / 1000 + 3600);

  // Corrupt the encrypted data
  const corrupted = encrypted.slice(0, -10) + 'corrupted';

  // Decrypt should return undefined instead of throwing
  const result = await store.testDecrypt(identifier, corrupted);
  expect(result).toBeUndefined();
});

test('decrypt - should return undefined when wrong identifier is used', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const data = { foo: 'bar' };

  // Encrypt with one identifier
  const encrypted = await encrypt(data, '<secret>', '<identifier-1>', Date.now() / 1000 + 3600);

  // Try to decrypt with a different identifier (salt mismatch)
  const result = await store.testDecrypt('<identifier-2>', encrypted);
  expect(result).toBeUndefined();
});

test('decrypt - should successfully decrypt valid encrypted data', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt properly
  const encrypted = await encrypt(data, '<secret>', identifier, Date.now() / 1000 + 3600);

  // Decrypt should succeed
  const result = await store.testDecrypt(identifier, encrypted);
  expect(result).toStrictEqual(expect.objectContaining(data));
});

test('get - should return undefined when stored data cannot be decrypted', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Store data encrypted with one secret
  await store.set(identifier, data);

  // Create a new store instance with a different secret
  const storeWithDifferentSecret = new TestStore({ secret: '<different-secret>' });

  // Manually set the encrypted data in the new store (simulating secret rotation)
  const encrypted = await encrypt(data, '<secret>', identifier, Date.now() / 1000 + 3600);
  await storeWithDifferentSecret.set(identifier, data);

  // Override the storage with old encrypted data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (storeWithDifferentSecret as any).storage.set(identifier, encrypted);

  // Get should return undefined instead of throwing
  const result = await storeWithDifferentSecret.get(identifier);
  expect(result).toBeUndefined();
});

test('decrypt - should catch JWEDecryptionFailed and return undefined', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with a different secret to trigger JWEDecryptionFailed
  const encrypted = await encrypt(data, '<different-secret>', identifier, Date.now() / 1000 + 3600);

  // This should catch JWEDecryptionFailed and return undefined
  const result = await store.testDecrypt(identifier, encrypted);
  expect(result).toBeUndefined();
});

test('decrypt - should catch JWEInvalid and return undefined', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';

  // Invalid JWE format should trigger JWEInvalid
  const result = await store.testDecrypt(identifier, 'not-a-valid-jwe');
  expect(result).toBeUndefined();
});

test('decrypt - should throw JWTExpired without catching it', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with expiration in the past to trigger JWTExpired
  const encrypted = await encrypt(data, '<secret>', identifier, Date.now() / 1000 - 20);

  // Should throw JWTExpired (not catch it)
  await expect(store.testDecrypt(identifier, encrypted)).rejects.toThrow(errors.JWTExpired);
});

// Secret rotation tests

test('decrypt with secret rotation - should successfully decrypt data encrypted with old secret', async () => {
  const oldSecret = 'old-secret';
  const newSecret = 'new-secret';
  const store = new TestStore({ secret: [newSecret, oldSecret] });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with the old secret (simulating existing data before rotation)
  const encrypted = await encrypt(data, oldSecret, identifier, Date.now() / 1000 + 3600);

  // Should successfully decrypt by falling back to old secret
  const result = await store.testDecrypt(identifier, encrypted);
  expect(result).toStrictEqual(expect.objectContaining(data));
});

test('decrypt with secret rotation - should return undefined when none of the secrets work', async () => {
  const store = new TestStore({ secret: ['secret-1', 'secret-2', 'secret-3'] });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with a completely different secret not in the rotation array
  const encrypted = await encrypt(data, 'wrong-secret', identifier, Date.now() / 1000 + 3600);

  // Should return undefined as this is a decryption failure
  const result = await store.testDecrypt(identifier, encrypted);
  expect(result).toBeUndefined();
});

test('decrypt with secret rotation - should throw JWTExpired without trying old secrets', async () => {
  const oldSecret = 'old-secret';
  const newSecret = 'new-secret';
  const store = new TestStore({ secret: [newSecret, oldSecret] });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with the new secret but with expiration in the past
  const encrypted = await encrypt(data, newSecret, identifier, Date.now() / 1000 - 20);

  // Should throw JWTExpired immediately without trying old secrets
  await expect(store.testDecrypt(identifier, encrypted)).rejects.toThrow(errors.JWTExpired);
});

test('decrypt with secret rotation - should return undefined for corrupted data even with multiple secrets', async () => {
  const store = new TestStore({ secret: ['secret-1', 'secret-2'] });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt properly with first secret
  const encrypted = await encrypt(data, 'secret-1', identifier, Date.now() / 1000 + 3600);

  // Corrupt the encrypted data
  const corrupted = encrypted.slice(0, -10) + 'corrupted';

  // Should return undefined instead of throwing
  const result = await store.testDecrypt(identifier, corrupted);
  expect(result).toBeUndefined();
});

test('get with secret rotation - should successfully retrieve data encrypted with old secret', async () => {
  const oldSecret = 'old-secret';
  const newSecret = 'new-secret';
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Simulate a scenario where data was encrypted with old secret
  const encryptedWithOldSecret = await encrypt(data, oldSecret, identifier, Date.now() / 1000 + 3600);

  // Create store with secret rotation (new secret first, old secret as fallback)
  const store = new TestStore({ secret: [newSecret, oldSecret] });

  // Manually set the encrypted data (simulating existing data before rotation)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (store as any).storage.set(identifier, encryptedWithOldSecret);

  // Should successfully retrieve and decrypt using old secret
  const result = await store.get(identifier);
  expect(result).toStrictEqual(expect.objectContaining(data));
});

test('encrypt - should throw InvalidConfigurationError when secret array is empty', async () => {
  const store = new TestStore({ secret: [] });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Should throw InvalidConfigurationError when trying to encrypt with empty secret array
  await expect(store.set(identifier, data)).rejects.toThrow(InvalidConfigurationError);
  await expect(store.set(identifier, data)).rejects.toThrow('At least one secret must be provided');
});

test('decrypt - should throw InvalidConfigurationError when secret array is empty', async () => {
  const store = new TestStore({ secret: [] });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt data with a valid secret first
  const encrypted = await encrypt(data, 'valid-secret', identifier, Date.now() / 1000 + 3600);

  // Should throw InvalidConfigurationError when trying to decrypt with empty secret array
  await expect(store.testDecrypt(identifier, encrypted)).rejects.toThrow(InvalidConfigurationError);
  await expect(store.testDecrypt(identifier, encrypted)).rejects.toThrow('At least one secret must be provided');
});
