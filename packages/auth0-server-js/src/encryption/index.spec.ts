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
