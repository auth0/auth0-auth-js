import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { CookieTransactionStore } from './cookie-transaction-store.js';
import { decrypt, encrypt } from './../test-utils/encryption.js';
import { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';
import type { TransactionData } from '../types.js';

export interface StoreOptions {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  request: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  reply: any;
}

export class TestCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, storeOptions?: StoreOptions): void {
    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    storeOptions.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    return storeOptions.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    return storeOptions.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions): void {
    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    storeOptions.reply.clearCookie(name);
  }
}

test('get - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.get('<identifier>')).rejects.toThrowError('StoreOptions not provided');
});

test('get - should read cookie from request', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());
  const cookieValue = { codeVerifier: '<code_verifier>' };
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
  const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.set('<identifier>', { codeVerifier: '<code_verifier>' })).rejects.toThrowError(
    'StoreOptions not provided'
  );
});

test('set - should call reply to set the cookie', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());
  const cookieValue = { codeVerifier: '<code_verifier>' };
  const setCookieMock = vi.fn();
  const storeOptions = {
    request: {},
    reply: {
      setCookie: setCookieMock,
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, false, storeOptions);

  const args = setCookieMock.mock.calls[0];
  const retrievedCookieValue = await decrypt(args![1], '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>');
  expect(retrievedCookieValue).toStrictEqual(expect.objectContaining(cookieValue));
  expect(args![2]).toMatchObject(
    expect.objectContaining({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 3600,
    })
  );
});

describe('set - with an expiresAt', () => {
  const setWith = async (expiresAt: unknown) => {
    const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());
    const setCookieMock = vi.fn();
    const storeOptions = { request: {}, reply: { setCookie: setCookieMock } } as unknown as StoreOptions;

    await store.set('<identifier>', { kind: 'passkey', expiresAt } as TransactionData, false, storeOptions);

    const [, value, options] = setCookieMock.mock.calls[0]!;
    const decrypted = await decrypt<{ exp: number }>(value, '<secret>', '<identifier>');
    return { maxAge: options.maxAge, exp: decrypted.exp };
  };

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-16T10:00:00.400Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const now = () => Math.floor(Date.now() / 1000);

  test('expires the cookie and the encrypted value at expiresAt', async () => {
    const { maxAge, exp } = await setWith(now() + 60);

    expect(maxAge).toBe(60);
    expect(exp).toBe(now() + 60);
  });

  test('rounds a partial second up', async () => {
    const { maxAge } = await setWith(Date.now() / 1000 + 899.5);

    expect(maxAge).toBe(900);
  });

  test('never keeps the cookie longer than an hour', async () => {
    const { maxAge, exp } = await setWith(now() + 7200);

    expect(maxAge).toBe(3600);
    expect(exp).toBe(now() + 3600);
  });

  test('keeps the cookie for at least a second when expiresAt has passed', async () => {
    const { maxAge } = await setWith(now() - 10);

    expect(maxAge).toBe(1);
  });

  test.each([undefined, '60', Number.NaN, Number.POSITIVE_INFINITY])('uses an hour when expiresAt is %s', async (expiresAt) => {
    const { maxAge, exp } = await setWith(expiresAt);

    expect(maxAge).toBe(3600);
    expect(exp).toBe(now() + 3600);
  });
});

test('delete - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.delete('<identifier>')).rejects.toThrowError('StoreOptions not provided');
});

test('delete - should call reply to clear the cookie', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = {
    request: {},
    reply: {
      clearCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.delete('<identifier>', storeOptions);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledWith('<identifier>');
});
