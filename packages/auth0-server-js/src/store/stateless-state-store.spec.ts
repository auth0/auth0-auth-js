import { describe, expect, test, vi } from 'vitest';
import { StatelessStateStore } from './stateless-state-store.js';
import { decrypt, encrypt } from './../test-utils/encryption.js';
import { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';

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

export class AsyncCookieHandler implements CookieHandler<StoreOptions> {
  async setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    storeOptions?: StoreOptions
  ): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 150));

    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    storeOptions.reply.setCookie(name, value, options || {});
  }

  async getCookie(name: string, storeOptions?: StoreOptions): Promise<string | undefined> {
    await new Promise((resolve) => setTimeout(resolve, 150));

    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    return storeOptions.request.cookies?.[name];
  }

  async getCookies(storeOptions?: StoreOptions): Promise<Record<string, string>> {
    await new Promise((resolve) => setTimeout(resolve, 150));

    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    return storeOptions.request.cookies as Record<string, string>;
  }

  async deleteCookie(name: string, storeOptions?: StoreOptions): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 150));

    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    storeOptions.reply.clearCookie(name);
  }
}

[
  { name: 'SyncCookieHandler', handler: new TestCookieHandler() },
  { name: 'AsyncCookieHandler', handler: new AsyncCookieHandler() },
].forEach(({ name, handler }) => {
  describe(`StatelessStateStore with ${name}`, () => {
    test('get - should throw when no storeOptions provided', async () => {
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);

      await expect(store.get('<identifier>')).rejects.toThrowError('StoreOptions not provided');
    });

    test('get - should read cookie from request', async () => {
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);
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
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);

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
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);
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
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);
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
      const decryptedCookieValue = await decrypt(
        encryptedCookieValue + encryptedCookieValue2,
        '<secret>',
        '<identifier>'
      );

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
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);
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
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);

      await expect(store.delete('<identifier>')).rejects.toThrowError('StoreOptions not provided');
    });

    test('delete - should call reply to clear the cookie', async () => {
      const store = new StatelessStateStore({ secret: '<secret>' }, handler);
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
  });
});
