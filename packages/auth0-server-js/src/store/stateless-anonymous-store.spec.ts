import { expect, test, vi } from 'vitest';
import { StatelessAnonymousStore, DEFAULT_ANONYMOUS_SESSION_LIFETIME } from './stateless-anonymous-store.js';
import { decrypt } from './../test-utils/encryption.js';
import type { CookieHandler, CookieSerializeOptions } from './cookie-handler.js';
import type { AnonymousStateData } from '../types.js';

interface StoreOptions {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  request: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  reply: any;
}

/**
 * Forwards the cookie options on both `setCookie` and `deleteCookie`, so the tests can
 * assert the attributes used to clear a cookie as well as the ones used to write it.
 */
class TestCookieHandler implements CookieHandler<StoreOptions> {
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

    return (storeOptions.request.cookies ?? {}) as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions, options?: CookieSerializeOptions): void {
    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    storeOptions.reply.clearCookie(name, options || {});
  }
}

const identifier = '__a0_anon';
const now = () => Math.floor(Date.now() / 1000);

const makeStoreOptions = (cookies: Record<string, string> = {}) =>
  ({
    request: { cookies },
    reply: { setCookie: vi.fn(), clearCookie: vi.fn() },
  }) as unknown as StoreOptions;

const stateData = (overrides: Partial<AnonymousStateData> = {}): AnonymousStateData => ({
  sessionToken: '<session_token>',
  createdAt: now(),
  tokenSets: [
    {
      audience: 'https://api.example.com',
      accessToken: '<access_token>',
      scope: undefined,
      expiresAt: now() + 7200,
    },
  ],
  domain: 'auth0.local',
  ...overrides,
});

/** Turns the cookies written by `set` into the cookies a follow-up request would carry. */
const cookiesFromSet = (storeOptions: StoreOptions): Record<string, string> =>
  Object.fromEntries(storeOptions.reply.setCookie.mock.calls.map((call: unknown[]) => [call[0], call[1]]));

const maxAgesFromSet = (storeOptions: StoreOptions): number[] =>
  storeOptions.reply.setCookie.mock.calls
    .map((call: unknown[]) => (call[2] as CookieSerializeOptions | undefined)?.maxAge)
    .filter((value: unknown): value is number => typeof value === 'number');

test('get - should throw when no storeOptions provided', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.get(identifier)).rejects.toThrowError('StoreOptions not provided');
});

test('set - should throw when no storeOptions provided', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.set(identifier, stateData())).rejects.toThrowError('StoreOptions not provided');
});

test('delete - should throw when no storeOptions provided', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());

  await expect(store.delete(identifier)).rejects.toThrowError('StoreOptions not provided');
});

test('set - writes an encrypted, HttpOnly cookie and get reads it back', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions();
  const data = stateData();

  await store.set(identifier, data, false, storeOptions);

  const args = storeOptions.reply.setCookie.mock.calls[0];
  expect(args[0]).toBe(`${identifier}.0`);
  expect(await decrypt(args[1], '<secret>', identifier)).toStrictEqual(expect.objectContaining(data));
  expect(args[2]).toMatchObject({
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: true,
  });

  const readStoreOptions = makeStoreOptions(cookiesFromSet(storeOptions));
  expect(await store.get(identifier, readStoreOptions)).toStrictEqual(expect.objectContaining(data));
});

test('get - returns undefined when there is no cookie', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());

  expect(await store.get(identifier, makeStoreOptions())).toBeUndefined();
});

test('set - uses the default 30 day lifetime, measured from createdAt', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions();

  await store.set(identifier, stateData(), false, storeOptions);

  const maxAge = maxAgesFromSet(storeOptions)[0]!;
  expect(maxAge).toBeGreaterThan(DEFAULT_ANONYMOUS_SESSION_LIFETIME - 5);
  expect(maxAge).toBeLessThanOrEqual(DEFAULT_ANONYMOUS_SESSION_LIFETIME);
});

test('set - anchors maxAge to createdAt, so renewing an access token never extends the cookie', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const createdAt = now() - 60 * 60 * 24 * 10; // created 10 days ago

  const first = makeStoreOptions();
  await store.set(identifier, stateData({ createdAt }), false, first);

  // A renewal writes the same session again, with a fresh access token.
  const second = makeStoreOptions(cookiesFromSet(first));
  await store.set(
    identifier,
    stateData({
      createdAt,
      tokenSets: [{ audience: 'default', accessToken: '<new>', scope: undefined, expiresAt: now() + 7200 }],
    }),
    false,
    second
  );

  const remaining = DEFAULT_ANONYMOUS_SESSION_LIFETIME - 60 * 60 * 24 * 10;
  for (const maxAge of [maxAgesFromSet(first)[0]!, maxAgesFromSet(second)[0]!]) {
    expect(maxAge).toBeGreaterThan(remaining - 5);
    expect(maxAge).toBeLessThanOrEqual(remaining);
  }
});

test('set - honours a custom sessionTokenLifetime', async () => {
  const store = new StatelessAnonymousStore(
    { secret: '<secret>', sessionTokenLifetime: 60 * 60 },
    new TestCookieHandler()
  );
  const storeOptions = makeStoreOptions();

  await store.set(identifier, stateData(), false, storeOptions);

  const maxAge = maxAgesFromSet(storeOptions)[0]!;
  expect(maxAge).toBeGreaterThan(60 * 60 - 5);
  expect(maxAge).toBeLessThanOrEqual(60 * 60);
});

test('set - prefers sessionTokenExpiresAt over the configured lifetime', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions();

  await store.set(identifier, stateData({ sessionTokenExpiresAt: now() + 100 }), false, storeOptions);

  const maxAge = maxAgesFromSet(storeOptions)[0]!;
  expect(maxAge).toBeGreaterThan(95);
  expect(maxAge).toBeLessThanOrEqual(100);
});

test('set - clears the cookies instead of writing an already expired session', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions({ [`${identifier}.0`]: 'existing' });

  // Driven through `createdAt`, which is the path this is reachable by: the anonymous session
  // was created longer ago than its configured lifetime, so there is nothing left to store.
  await store.set(
    identifier,
    stateData({ createdAt: now() - DEFAULT_ANONYMOUS_SESSION_LIFETIME - 10 }),
    false,
    storeOptions
  );

  expect(storeOptions.reply.setCookie).not.toHaveBeenCalled();
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledWith(`${identifier}.0`, expect.any(Object));
});

test('set - chunks a payload that does not fit in a single cookie', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions();
  const data = stateData({
    tokenSets: [...Array(20).keys()].map((i) => ({
      audience: `https://api.${i}.example.com`,
      accessToken: '<access_token>'.repeat(20),
      scope: 'read:articles',
      expiresAt: now() + 7200,
    })),
  });

  await store.set(identifier, data, false, storeOptions);

  const calls = storeOptions.reply.setCookie.mock.calls;
  expect(calls.length).toBeGreaterThan(1);
  expect(calls.map((call: unknown[]) => call[0])).toStrictEqual(
    [...Array(calls.length).keys()].map((i) => `${identifier}.${i}`)
  );
  for (const call of calls) {
    expect((call[1] as string).length).toBeLessThanOrEqual(3072);
  }

  // The chunks recombine into the original value, in cookie order.
  const readStoreOptions = makeStoreOptions(cookiesFromSet(storeOptions));
  expect(await store.get(identifier, readStoreOptions)).toStrictEqual(expect.objectContaining(data));
});

test('get - recombines chunks that arrive out of order', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions();
  const data = stateData({
    tokenSets: [...Array(20).keys()].map((i) => ({
      audience: `https://api.${i}.example.com`,
      accessToken: '<access_token>'.repeat(20),
      scope: undefined,
      expiresAt: now() + 7200,
    })),
  });

  await store.set(identifier, data, false, storeOptions);

  const written = cookiesFromSet(storeOptions);
  expect(Object.keys(written).length).toBeGreaterThan(1);
  const reversed = Object.fromEntries(Object.entries(written).reverse());

  expect(await store.get(identifier, makeStoreOptions(reversed))).toStrictEqual(expect.objectContaining(data));
});

test('set - removes stale trailing chunks left by a larger payload', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions({
    [`${identifier}.0`]: 'existing',
    [`${identifier}.1`]: 'existing',
    [`${identifier}.2`]: 'existing',
  });

  await store.set(identifier, stateData(), false, storeOptions);

  expect(storeOptions.reply.setCookie).toHaveBeenCalledTimes(1);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledTimes(2);
  // Cleared with the plain attributes, not with the `Max-Age` used for the cookie that is
  // being written: a lifetime on a cookie that is going away is contradictory.
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(1, `${identifier}.1`, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: true,
  });
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(2, `${identifier}.2`, expect.any(Object));
});

test('delete - clears every chunk with the cookie attributes', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions({
    [`${identifier}.0`]: 'existing',
    [`${identifier}.1`]: 'existing',
  });

  await store.delete(identifier, storeOptions);

  expect(storeOptions.reply.clearCookie).toHaveBeenCalledTimes(2);
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(1, `${identifier}.0`, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: true,
  });
  expect(storeOptions.reply.clearCookie).toHaveBeenNthCalledWith(2, `${identifier}.1`, expect.any(Object));
});

test('delete - is a no-op when there is nothing stored', async () => {
  const store = new StatelessAnonymousStore({ secret: '<secret>' }, new TestCookieHandler());
  const storeOptions = makeStoreOptions();

  await store.delete(identifier, storeOptions);

  expect(storeOptions.reply.clearCookie).not.toHaveBeenCalled();
});

test('set - applies the cookie option overrides', async () => {
  const store = new StatelessAnonymousStore(
    { secret: '<secret>', cookie: { sameSite: 'strict', secure: false, path: '/app' } },
    new TestCookieHandler()
  );
  const storeOptions = makeStoreOptions();

  await store.set(identifier, stateData(), false, storeOptions);

  expect(storeOptions.reply.setCookie.mock.calls[0][2]).toMatchObject({
    httpOnly: true,
    sameSite: 'strict',
    path: '/app',
    secure: false,
  });
});

test('set - keeps the cookie HttpOnly, so the browser can never read the session token', async () => {
  const store = new StatelessAnonymousStore(
    // `httpOnly` is not part of `AnonymousCookieOptions`, so there is no way to turn it off.
    { secret: '<secret>', cookie: { sameSite: 'none' } },
    new TestCookieHandler()
  );
  const storeOptions = makeStoreOptions();

  await store.set(identifier, stateData(), false, storeOptions);

  expect(storeOptions.reply.setCookie.mock.calls[0][2]).toMatchObject({ httpOnly: true, sameSite: 'none' });
});
