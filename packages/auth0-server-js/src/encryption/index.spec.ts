import { expect, test } from 'vitest';
import { decrypt, encrypt } from './index.js';

test('should fail decrypting when expiration in the past and has passed the clock tolerance', async () => {
    const secret = '<secret>';
    const salt = '<salt>';
    const encrypted = await encrypt({ foo: 'bar' }, secret, salt, (Date.now() / 1000) - 16);

    await expect(decrypt(encrypted, secret, salt)).rejects.toThrowError('"exp" claim timestamp check failed');
});

test('should decrypt succesfully when expiration in the past and has not passed the clock tolerance', async () => {
    const secret = '<secret>';
    const salt = '<salt>';
    const encrypted = await encrypt({ foo: 'bar' }, secret, salt, (Date.now() / 1000) - 14);
    const value = await decrypt(encrypted, secret, salt);
    expect(value).toStrictEqual(expect.objectContaining({ foo: 'bar' }));
});

test('should decrypt succesfully when expiration in the future', async () => {
    const secret = '<secret>';
    const salt = '<salt>';
    const encrypted = await encrypt({ foo: 'bar' }, secret, salt, (Date.now() / 1000) + 14);
    const value = await decrypt(encrypted, secret, salt);
    expect(value).toStrictEqual(expect.objectContaining({ foo: 'bar' }));
});

// Secret rotation tests

test('should encrypt and decrypt with single secret string', async () => {
    const secret = 'my-secret-key';
    const salt = '<salt>';
    const payload = { foo: 'bar', user: { sub: 'user123' } };

    const encrypted = await encrypt(payload, secret, salt, (Date.now() / 1000) + 3600);
    const decrypted = await decrypt(encrypted, secret, salt);

    expect(decrypted).toStrictEqual(expect.objectContaining(payload));
});

test('should encrypt with newest secret when using array', async () => {
    const oldSecret = 'old-secret';
    const newSecret = 'new-secret';
    const secrets = [newSecret, oldSecret];
    const salt = '<salt>';
    const payload = { foo: 'bar' };

    const encrypted = await encrypt(payload, secrets, salt, (Date.now() / 1000) + 3600);
    const decrypted = await decrypt(encrypted, newSecret, salt);

    expect(decrypted).toStrictEqual(expect.objectContaining(payload));
});

test('should decrypt data encrypted with newest secret', async () => {
    const newSecret = 'new-secret';
    const oldSecret = 'old-secret';
    const salt = '<salt>';
    const payload = { foo: 'bar', baz: 123 };

    // Encrypt with the new secret directly
    const encrypted = await encrypt(payload, newSecret, salt, (Date.now() / 1000) + 3600);

    // Should decrypt successfully using array with new secret first
    const decrypted = await decrypt(encrypted, [newSecret, oldSecret], salt);

    expect(decrypted).toStrictEqual(expect.objectContaining(payload));
});

test('should fall back to old secret when decryption with new secret fails', async () => {
    const newSecret = 'new-secret';
    const oldSecret = 'old-secret';
    const salt = '<salt>';
    const payload = { foo: 'bar', user: 'testuser' };

    // Encrypt with the old secret
    const encrypted = await encrypt(payload, oldSecret, salt, (Date.now() / 1000) + 3600);

    // Should decrypt successfully by falling back to old secret
    const decrypted = await decrypt(encrypted, [newSecret, oldSecret], salt);

    expect(decrypted).toStrictEqual(expect.objectContaining(payload));
});

test('should try multiple old secrets in order', async () => {
    const newestSecret = 'newest-secret';
    const middleSecret = 'middle-secret';
    const oldestSecret = 'oldest-secret';
    const salt = '<salt>';
    const payload = { data: 'test-data', count: 42 };

    // Encrypt with the oldest secret
    const encrypted = await encrypt(payload, oldestSecret, salt, (Date.now() / 1000) + 3600);

    // Should decrypt successfully by trying all secrets
    const decrypted = await decrypt(encrypted, [newestSecret, middleSecret, oldestSecret], salt);

    expect(decrypted).toStrictEqual(expect.objectContaining(payload));
});

test('should throw error when none of the secrets can decrypt', async () => {
    const salt = '<salt>';
    const payload = { foo: 'bar' };

    // Encrypt with a different secret that's not in the array
    const encrypted = await encrypt(payload, 'wrong-secret', salt, (Date.now() / 1000) + 3600);

    // Should fail to decrypt with any of the secrets
    await expect(decrypt(encrypted, ['secret1', 'secret2', 'secret3'], salt)).rejects.toThrow();
});

test('should support secret rotation workflow', async () => {
    const oldSecret = 'old-secret';
    const newSecret = 'new-secret';
    const salt = '<salt>';
    const payload = { user: { sub: 'user123' }, session: 'abc' };

    // Step 1: Encrypt data with old secret (simulating existing data)
    const encryptedWithOldSecret = await encrypt(payload, oldSecret, salt, (Date.now() / 1000) + 3600);

    // Step 2: Rotate to new secret, keeping old secret for backward compatibility
    // Should still be able to decrypt old data encrypted with old secret
    const retrieved = await decrypt(encryptedWithOldSecret, [newSecret, oldSecret], salt);
    expect(retrieved).toStrictEqual(expect.objectContaining(payload));

    // Step 3: New writes use new secret
    const encryptedWithNewSecret = await encrypt(payload, [newSecret, oldSecret], salt, (Date.now() / 1000) + 3600);

    // Should be able to decrypt newly written data
    const retrievedNew = await decrypt(encryptedWithNewSecret, [newSecret, oldSecret], salt);
    expect(retrievedNew).toStrictEqual(expect.objectContaining(payload));

    // Step 4: Verify new data was encrypted with new secret (can decrypt with only new secret)
    const finalRetrieved = await decrypt(encryptedWithNewSecret, newSecret, salt);
    expect(finalRetrieved).toStrictEqual(expect.objectContaining(payload));

    // Step 5: After all old sessions expire, data with only new secret cannot decrypt old data
    await expect(decrypt(encryptedWithOldSecret, newSecret, salt)).rejects.toThrow();
});

test('should handle single secret in array format', async () => {
    const secret = ['only-secret'];
    const salt = '<salt>';
    const payload = { test: 'value' };

    const encrypted = await encrypt(payload, secret, salt, (Date.now() / 1000) + 3600);
    const decrypted = await decrypt(encrypted, secret, salt);

    expect(decrypted).toStrictEqual(expect.objectContaining(payload));
});

test('should throw error when empty array of secrets is provided for encryption', async () => {
    const salt = '<salt>';
    const payload = { foo: 'bar' };

    await expect(encrypt(payload, [], salt, (Date.now() / 1000) + 3600))
        .rejects.toThrow('At least one secret must be provided');
});

test('should throw error when empty array of secrets is provided for decryption', async () => {
    const salt = '<salt>';

    await expect(decrypt('encrypted-data', [], salt))
        .rejects.toThrow('At least one secret must be provided');
});

test('should not try old secrets when token is expired', async () => {
    const newSecret = 'new-secret';
    const oldSecret = 'old-secret';
    const salt = '<salt>';
    const payload = { foo: 'bar' };

    // Encrypt with the new secret but with expiration in the past
    const encrypted = await encrypt(payload, newSecret, salt, (Date.now() / 1000) - 3600);

    // Should throw expiration error immediately without trying old secrets
    await expect(decrypt(encrypted, [newSecret, oldSecret], salt))
        .rejects.toThrow('"exp" claim timestamp check failed');
});

test('should try old secrets only for decryption failures, not expiration', async () => {
    const newSecret = 'new-secret';
    const oldSecret = 'old-secret';
    const salt = '<salt>';
    const payload = { data: 'test' };

    // Encrypt with old secret with valid expiration
    const encryptedWithOldSecret = await encrypt(payload, oldSecret, salt, (Date.now() / 1000) + 3600);

    // Should decrypt successfully by trying old secret (decryption failure triggers fallback)
    const decrypted = await decrypt(encryptedWithOldSecret, [newSecret, oldSecret], salt);
    expect(decrypted).toStrictEqual(expect.objectContaining(payload));

    // Now encrypt with new secret but with expiration in the past
    const expiredEncrypted = await encrypt(payload, newSecret, salt, (Date.now() / 1000) - 3600);

    // Should throw expiration error immediately, even though old secret is available
    await expect(decrypt(expiredEncrypted, [newSecret, oldSecret], salt))
        .rejects.toThrow('"exp" claim timestamp check failed');
});
