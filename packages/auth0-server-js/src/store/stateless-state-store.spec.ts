import { expect, test, vi } from 'vitest';
import { StatelessStateStore } from './stateless-state-store.js';
import { decrypt, encrypt } from './../test-utils/encryption.js';
import { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';
import type { StateData } from '../types.js';

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
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.get('<identifier>')).rejects.toThrowError('StoreOptions not provided');
});

test('get - should read cookie from request', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());
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
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(
    store.set('<identifier>', {
      user: { sub: '<sub>' },
      idToken: '<id_token>',
      refreshToken: '<refresh_token>',
      tokenSets: [],
      internal: { sid: '<sid>', createdAt: 1 },
    })
  ).rejects.toThrowError('StoreOptions not provided');
});

test('set - should call reply to set the cookie', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());
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
      cookies: {},
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
      maxAge: 86400,
    })
  );
});

test('set - should call reply to set the cookie with chunks', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());
  const cookieValue = {
    user: { sub: '<sub>' },
    idToken: '<id_token>'.repeat(175), // Increase the cookie size
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() / 1000 },
    foo: 'bar'.repeat(100),
  };
  const setCookieMock = vi.fn();
  const storeOptions = {
    request: {
      cookies: {},
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
      maxAge: 86400,
    })
  );
});

test('set - should remove unexisting cookie chunks', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());
  const cookieValue = {
    user: { sub: '<sub>' },
    idToken: '<id_token>'.repeat(175), // Increase the cookie size
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Date.now() / 1000 },
    foo: 'bar'.repeat(100),
  };
  const storeOptions = {
    request: {
      cookies: {
        '<identifier>.0': 'existing',
        '<identifier>.1': 'existing',
        '<identifier>.2': 'existing',
        '<identifier>.3': 'existing',
      },
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
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.delete('<identifier>')).rejects.toThrowError('StoreOptions not provided');
});

test('delete - should call reply to clear the cookie', async () => {
  const store = new StatelessStateStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = {
    request: {
      cookies: {
        '<identifier>.0': 'existing',
        '<identifier>.1': 'existing',
      },
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

test('set - caps the cookie maxAge at sessionExpiresAt when the ceiling is sooner than idle/absolute', async () => {
  const store = new StatelessStateStore(
    {
      secret: '<secret>',
      rolling: true,
      absoluteDuration: 60 * 60 * 24 * 3,
      inactivityDuration: 60 * 60 * 24 * 1,
    },
    new TestCookieHandler()
  );

  const setCookie = vi.fn();
  const storeOptions = {
    request: { cookies: {} },
    reply: { setCookie },
  } as unknown as StoreOptions;

  const now = Math.floor(Date.now() / 1000);
  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    sessionExpiresAt: now + 100, // ceiling much sooner than the multi-day idle/absolute defaults
    internal: { sid: '<sid>', createdAt: now },
  };

  await store.set('__a0_session', stateData, false, storeOptions);

  // TestCookieHandler forwards options as the 3rd arg to reply.setCookie(name, value, options).
  const maxAges = setCookie.mock.calls
    .map((call) => (call[2] as CookieSerializeOptions | undefined)?.maxAge)
    .filter((v): v is number => typeof v === 'number');

  expect(maxAges.length).toBeGreaterThan(0);
  expect(Math.max(...maxAges)).toBeLessThanOrEqual(101); // capped at the ~100s ceiling, not days
});

test('set - caps the cookie maxAge at sessionExpiresAt in non-rolling mode', async () => {
  const store = new StatelessStateStore(
    {
      secret: '<secret>',
      rolling: false,
      absoluteDuration: 60 * 60 * 24 * 3,
    },
    new TestCookieHandler()
  );

  const setCookie = vi.fn();
  const storeOptions = {
    request: { cookies: {} },
    reply: { setCookie },
  } as unknown as StoreOptions;

  const now = Math.floor(Date.now() / 1000);
  const stateData: StateData = {
    user: { sub: '<sub>' },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    sessionExpiresAt: now + 100, // ceiling much sooner than the 3-day absolute duration
    internal: { sid: '<sid>', createdAt: now },
  };

  await store.set('__a0_session', stateData, false, storeOptions);

  // TestCookieHandler forwards options as the 3rd arg to reply.setCookie(name, value, options).
  const maxAges = setCookie.mock.calls
    .map((call) => (call[2] as CookieSerializeOptions | undefined)?.maxAge)
    .filter((v): v is number => typeof v === 'number');

  expect(maxAges.length).toBeGreaterThan(0);
  expect(Math.max(...maxAges)).toBeLessThanOrEqual(101); // capped at the ~100s ceiling, not the 3-day absolute
});
