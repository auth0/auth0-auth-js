import { expect, test, vi } from 'vitest';
import { CookieTransactionStore, StoreOptions } from './cookie-transaction-store.js';

test('get - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore();

  await expect(store.get('<identifier>')).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('get - should read cookie from request', async () => {
  const store = new CookieTransactionStore();
  const cookieValue = { state: '<state>' };
  const storeOptions = {
    request: {
      cookies: {
        '<identifier>': JSON.stringify(cookieValue),
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
  const store = new CookieTransactionStore();

  await expect(store.set('<identifier>', { state: '<state>>' })).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('set - should call reply to set the cookie', async () => {
  const store = new CookieTransactionStore();
  const cookieValue = { state: '<state>' };
  const storeOptions = {
    request: {},
    reply: {
      setCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, storeOptions);
  expect(storeOptions.reply.setCookie).toHaveBeenCalledWith(
    '<identifier>',
    JSON.stringify(cookieValue),
    expect.objectContaining({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
    })
  );
});

test('delete - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore();

  await expect(store.delete('<identifier>')).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('delete - should call reply to clear the cookie', async () => {
  const store = new CookieTransactionStore();
  const storeOptions = {
    request: {},
    reply: {
      clearCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.delete('<identifier>', storeOptions);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledWith('<identifier>');
});
