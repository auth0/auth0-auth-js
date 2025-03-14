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
        '<identifier>': await encrypt(cookieValue, '<secret>', '<identifier>', Date.now() / 1000),
      },
    },
    reply: {
      setCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  const value = await store.get('<identifier>', storeOptions);
  expect(value).toStrictEqual(expect.objectContaining(cookieValue));
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
    request: {
      cookies: {}
    },
    reply: {
      setCookie: setCookieMock,
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, false, storeOptions);

  const args = setCookieMock.mock.calls[0];
  const encryptedCookieValue = args![1];
  const decryptedCookieValue = await decrypt(encryptedCookieValue, '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>.0');
  expect(decryptedCookieValue).toStrictEqual(expect.objectContaining(cookieValue));
  expect(args![2]).toMatchObject(
    expect.objectContaining({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 86400
    })
  );
});

test('set - should call reply to set the cookie with chunks', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });
  const cookieValue = {
    user: { sub: '<sub>' },
    idToken: '<id_token>'.repeat(175), // Increase the cookie size
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() / 1000 },
    foo: 'bar'.repeat(100)
  };
  const setCookieMock = vi.fn();
  const storeOptions = {
    request: {
      cookies: {}
    },
    reply: {
      setCookie: setCookieMock,
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, false, storeOptions);

  const args = setCookieMock.mock.calls[0];
  const args2 = setCookieMock.mock.calls[1];
  const encryptedCookieValue = args![1];
  const encryptedCookieValue2 = args2![1];
  const decryptedCookieValue = await decrypt(encryptedCookieValue + encryptedCookieValue2, '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>.0');
  expect(args2![0]).toBe('<identifier>.1');
  expect(decryptedCookieValue).toStrictEqual(expect.objectContaining(cookieValue));
  expect(args![2]).toMatchObject(
    expect.objectContaining({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 86400
    })
  );
});

test('set - should remove unexisting cookie chunks', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' });
  const cookieValue = {
    user: { sub: '<sub>' },
    idToken: '<id_token>'.repeat(175), // Increase the cookie size
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() / 1000 },
    foo: 'bar'.repeat(100)
  };
  const storeOptions = {
    request: {
      cookies: {
        '<identifier>.0': 'existing',
        '<identifier>.1': 'existing',
        '<identifier>.2': 'existing',
        '<identifier>.3': 'existing',
      }
    },
    reply: {
      setCookie: vi.fn(),
      clearCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, false, storeOptions);

  expect(storeOptions.reply.clearCookie).toHaveBeenCalledTimes(2);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledTimes(2);
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(1, '<identifier>.2');
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(2, '<identifier>.3');
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
    request: {
      cookies: {
        '<identifier>.0': 'existing',
        '<identifier>.1': 'existing',
      }
    },
    reply: {
      clearCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.delete('<identifier>', storeOptions);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledTimes(2);
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(1, '<identifier>.0');
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(2, '<identifier>.1');
});
