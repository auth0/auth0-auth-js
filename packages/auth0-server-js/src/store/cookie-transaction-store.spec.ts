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

    await store.set('<identifier>', { expiresAt } as TransactionData, false, storeOptions);

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

describe('set - caps the state-scoped transaction cookies', () => {
  const secret = '<secret>';
  const MAX_BYTES = 3500;
  const bytes = (name: string, value: string) => new TextEncoder().encode(`${name}=${value}`).length;

  // `count` sibling login cookies, oldest first, plus cookies that are not siblings and must never be touched.
  const setup = async (count: number, { garbageOldest = false } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const cookies: Record<string, string> = {
      __a0_tx: await encrypt({ codeVerifier: 'fixed' }, secret, '__a0_tx', now + 3600),
      __a0_passkey_tx: await encrypt({ authSession: 'p' }, secret, '__a0_passkey_tx', now + 60),
      __a0_session: 'session-value',
      '__a0_txnot-a-uuid': 'other-value',
    };
    const siblings: string[] = [];
    for (let i = 0; i < count; i++) {
      const name = `__a0_tx${crypto.randomUUID()}`;
      cookies[name] =
        garbageOldest && i === 0
          ? 'not-a-jwe'
          : await encrypt({ codeVerifier: 'v'.repeat(43), state: name.slice(7) }, secret, name, now + 600 + i);
      siblings.push(name);
    }
    const storeOptions = { request: { cookies }, reply: { setCookie: vi.fn(), clearCookie: vi.fn() } };
    return { cookies, siblings, storeOptions };
  };

  test('deletes the oldest siblings, and only as many as needed to stay under the limit', async () => {
    const { cookies, siblings, storeOptions } = await setup(10);
    const store = new CookieTransactionStore({ secret }, new TestCookieHandler());
    const newName = `__a0_tx${crypto.randomUUID()}`;

    await store.set(newName, { codeVerifier: 'v'.repeat(43), state: newName.slice(7) }, false, storeOptions);

    const written = storeOptions.reply.setCookie.mock.calls[0]!;
    expect(written[0]).toBe(newName);
    const cleared = storeOptions.reply.clearCookie.mock.calls.map(([name]) => name);
    expect(cleared.length).toBeGreaterThan(0);
    expect(cleared).toEqual(siblings.slice(0, cleared.length));

    const total = (names: string[]) => names.reduce((sum, name) => sum + bytes(name, cookies[name]!), 0);
    const newBytes = bytes(newName, written[1]);
    const kept = siblings.filter((name) => !cleared.includes(name));
    expect(total(kept) + newBytes).toBeLessThan(MAX_BYTES);
    // One fewer deletion would still be over the limit.
    expect(total([...kept, cleared.at(-1)!]) + newBytes).toBeGreaterThanOrEqual(MAX_BYTES);
  });

  test('never deletes cookies that are not state-scoped siblings, nor the one being written', async () => {
    const { storeOptions } = await setup(12);
    const store = new CookieTransactionStore({ secret }, new TestCookieHandler());
    const newName = `__a0_tx${crypto.randomUUID()}`;

    await store.set(newName, { state: newName.slice(7) }, false, storeOptions);

    const cleared = storeOptions.reply.clearCookie.mock.calls.map(([name]) => name);
    for (const name of ['__a0_tx', '__a0_passkey_tx', '__a0_session', '__a0_txnot-a-uuid', newName]) {
      expect(cleared).not.toContain(name);
    }
  });

  test('deletes nothing under the limit, or for an identifier that is not state-scoped', async () => {
    const few = await setup(2);
    const store = new CookieTransactionStore({ secret }, new TestCookieHandler());
    const newName = `__a0_tx${crypto.randomUUID()}`;
    await store.set(newName, { state: newName.slice(7) }, false, few.storeOptions);
    expect(few.storeOptions.reply.clearCookie).not.toHaveBeenCalled();

    const many = await setup(12);
    await store.set('__a0_tx', { codeVerifier: 'fixed' }, false, many.storeOptions);
    expect(many.storeOptions.reply.clearCookie).not.toHaveBeenCalled();
  });

  test('deletes a sibling that cannot be read first', async () => {
    const { siblings, storeOptions } = await setup(10, { garbageOldest: true });
    const store = new CookieTransactionStore({ secret }, new TestCookieHandler());
    const newName = `__a0_tx${crypto.randomUUID()}`;

    await store.set(newName, { state: newName.slice(7) }, false, storeOptions);

    expect(storeOptions.reply.clearCookie.mock.calls[0]![0]).toBe(siblings[0]);
  });
});
