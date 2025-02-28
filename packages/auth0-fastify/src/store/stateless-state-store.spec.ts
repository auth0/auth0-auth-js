import { expect, test, vi } from 'vitest';
import { StatelessStateStore } from './stateless-state-store.js';
import type { StoreOptions } from '../types.js';
import { decrypt, encrypt } from './test-utils.js';

test('get - should throw when no storeOptions provided', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });

  await expect(store.get('<identifier>')).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('get - should read cookie from request', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });
  const cookieValue = { state: '<state>' };
  const storeOptions = {
    request: {
      cookies: {
        '<identifier>': await encrypt(cookieValue, '<secret>', '<identifier>'),
      },
    },
    reply: {
      setCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  const value = await store.get('<identifier>', storeOptions);
  expect(value).toStrictEqual(cookieValue);
});

test('set - should throw when no storeOptions provided', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });

  await expect(
    store.set('<identifier>', {
      user: { sub: '<sub>' },
      idToken: '<id_token>',
      refreshToken: '<refresh_token>',
      tokenSets: [],
      internal: { sid: '<sid>', createdAt: 1 },
    })
  ).rejects.toThrowError('The store options are missing, making it impossible to interact with the store.');
});

test('set - should call reply to set the cookie', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });
  const cookieValue = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() / 1000 },
  };
  const setCookieMock = vi.fn();
  const storeOptions = {
    request: {},
    reply: {
      setCookie: setCookieMock,
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, false, storeOptions);

  const args = setCookieMock.mock.calls[0];
  const encryptedCookieValue = args![1];
  const decryptedCookieValue = await decrypt(encryptedCookieValue, '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>');
  expect(decryptedCookieValue).toStrictEqual(cookieValue);
  expect(args![2]).toMatchObject(
    expect.objectContaining({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 86400
    })
  );
});

test('delete - should throw when no storeOptions provided', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });

  await expect(store.delete('<identifier>')).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('delete - should call reply to clear the cookie', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });
  const storeOptions = {
    request: {},
    reply: {
      clearCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.delete('<identifier>', storeOptions);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledWith('<identifier>');
});
