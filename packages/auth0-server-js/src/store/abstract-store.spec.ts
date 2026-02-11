import { expect, test } from 'vitest';
import { AbstractStore } from './abstract-store.js';
import { encrypt } from './../test-utils/encryption.js';
import type { JWTPayload } from 'jose';

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

test('decrypt - should return undefined when token is expired', async () => {
  const store = new TestStore({ secret: '<secret>' });
  const identifier = '<identifier>';
  const data = { foo: 'bar' };

  // Encrypt with expiration in the past (beyond clock tolerance of 15 seconds)
  const encrypted = await encrypt(data, '<secret>', identifier, Date.now() / 1000 - 20);

  // Decrypt should return undefined instead of throwing
  const result = await store.testDecrypt(identifier, encrypted);
  expect(result).toBeUndefined();
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
  (storeWithDifferentSecret as any).storage.set(identifier, encrypted);

  // Get should return undefined instead of throwing
  const result = await storeWithDifferentSecret.get(identifier);
  expect(result).toBeUndefined();
});
