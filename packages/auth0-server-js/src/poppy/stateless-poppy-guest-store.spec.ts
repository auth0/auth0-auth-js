import { decodeProtectedHeader, errors } from 'jose';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Mock } from 'vitest';
import { InvalidConfigurationError } from '../errors.js';
import type { CookieHandler, CookieSerializeOptions } from '../store/cookie-handler.js';
import { decrypt, encrypt } from '../test-utils/encryption.js';
import { AGENT_ID, CIMD_URL, FORGED_GUEST_COOKIES, GUEST_SUB, SESSION_ID, USER_ID } from '../test-utils/poppy.js';
import { AbstractPoppyGuestStore } from './abstract-poppy-guest-store.js';
import { POPPY_GUEST_IDENTIFIER } from './constants.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';
import type { StatelessPoppyGuestStoreOptions } from './stateless-poppy-guest-store.js';
import type { PoppyGuestData, PoppyGuestStore, PoppyOptions } from './types.js';

type SetCookie = (name: string, value: string, options: CookieSerializeOptions) => void;
type ClearCookie = (name: string, options: CookieSerializeOptions) => void;

// What a framework gives the store for one request: the cookies that the browser sent, and a reply that records the
// cookies that the store writes and clears.
interface StoreOptions {
  request: { cookies: Record<string, string> };
  reply: { setCookie: Mock<SetCookie>; clearCookie: Mock<ClearCookie> };
}

function requireStoreOptions(storeOptions: StoreOptions | undefined): StoreOptions {
  if (!storeOptions) {
    throw new Error('StoreOptions not provided');
  }

  return storeOptions;
}

// Passes the cookie options on, for both `setCookie` and `deleteCookie`, so a test can check the attributes that clear
// a cookie as well as the ones that write it. It throws without store options, so a store that drops them fails.
class TestCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, storeOptions?: StoreOptions): void {
    requireStoreOptions(storeOptions).reply.setCookie(name, value, options ?? {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    return requireStoreOptions(storeOptions).request.cookies[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    return requireStoreOptions(storeOptions).request.cookies;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions, options?: CookieSerializeOptions): void {
    requireStoreOptions(storeOptions).reply.clearCookie(name, options ?? {});
  }
}

const SECRET = '<secret>';
const OLD_SECRET = 'old-secret-that-is-at-least-32-chars';
const NEW_SECRET = 'new-secret-that-is-at-least-32-chars';

const identifier = POPPY_GUEST_IDENTIFIER;

// The attributes that clear a cookie: the defaults, and no Max-Age.
const plainAttributes = { httpOnly: true, sameSite: 'lax', path: '/', secure: true } as const;

const now = () => Math.floor(Date.now() / 1000);

const guestData = (overrides: Partial<PoppyGuestData> = {}): PoppyGuestData => ({
  sub: GUEST_SUB,
  poppy: { sessionId: SESSION_ID, userId: USER_ID, agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } },
  tokenSets: [
    {
      audience: 'https://zepto.example/api',
      accessToken: '<access_token>',
      scope: 'orders:read',
      expiresAt: now() + 3600,
    },
  ],
  createdAt: now(),
  expiresAt: now() + 3600,
  ...overrides,
});

// A guest whose access token has `length` characters, for values that do not fit in one cookie.
const guestWithAccessToken = (length: number): PoppyGuestData => {
  const data = guestData();

  return { ...data, tokenSets: [{ ...data.tokenSets[0]!, accessToken: 'x'.repeat(length) }] };
};

const makeStore = (options: Partial<StatelessPoppyGuestStoreOptions> = {}) =>
  new StatelessPoppyGuestStore({ secret: SECRET, ...options }, new TestCookieHandler());

const makeStoreOptions = (cookies: Record<string, string> = {}): StoreOptions => ({
  request: { cookies },
  reply: { setCookie: vi.fn<SetCookie>(), clearCookie: vi.fn<ClearCookie>() },
});

// Turns the cookies that `set` wrote into the cookies that the next request carries.
const cookiesFromSet = (storeOptions: StoreOptions): Record<string, string> =>
  Object.fromEntries(storeOptions.reply.setCookie.mock.calls.map(([name, value]) => [name, value]));

// What `get` returns for a stored guest: the data, and the `exp` claim of the encrypted value.
const asRead = (data: PoppyGuestData) => ({ ...data, exp: data.expiresAt });

beforeEach(() => {
  // The clock is not on a whole second, so a Max-Age that is not rounded down shows up as a fraction.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-11-10T10:00:00.400Z'));
});

afterEach(() => {
  vi.useRealTimers();
});

test('set - writes one encrypted, HttpOnly cookie that ends at the deadline of the guest', async () => {
  const storeOptions = makeStoreOptions();

  await makeStore().set(identifier, guestData({ expiresAt: now() + 3600 }), false, storeOptions);

  expect(storeOptions.reply.setCookie).toHaveBeenCalledTimes(1);
  const [name, value, attributes] = storeOptions.reply.setCookie.mock.calls[0]!;
  expect(name).toBe('__a0_poppy.0');
  expect(attributes).toStrictEqual({ httpOnly: true, sameSite: 'lax', path: '/', secure: true, maxAge: 3600 });
  // The value is a JWE under the algorithm that the other stores use.
  expect(decodeProtectedHeader(value)).toMatchObject({ alg: 'dir', enc: 'A256CBC-HS512' });
});

test('get - reads back what set wrote', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestData();

  await store.set(identifier, data, false, written);

  expect(await store.get(identifier, makeStoreOptions(cookiesFromSet(written)))).toStrictEqual(asRead(data));
});

test.each([1, 90, 3600, 86_400])('set - sets Max-Age to the time left until expiresAt (%i s)', async (secondsLeft) => {
  const storeOptions = makeStoreOptions();

  await makeStore().set(identifier, guestData({ expiresAt: now() + secondsLeft }), false, storeOptions);

  expect(storeOptions.reply.setCookie.mock.calls[0]![2].maxAge).toBe(secondsLeft);
});

test.each([90, 3600, 86_400])(
  'set - sets the expiry in the encrypted value to expiresAt (%i s away)',
  async (secondsLeft) => {
    const storeOptions = makeStoreOptions();
    const expiresAt = now() + secondsLeft;

    await makeStore().set(identifier, guestData({ expiresAt }), false, storeOptions);

    const value = storeOptions.reply.setCookie.mock.calls[0]![1];
    expect((await decrypt<{ exp: number }>(value, SECRET, identifier)).exp).toBe(expiresAt);
  }
);

test.each([
  { when: 'now', secondsAway: 0 },
  { when: 'a second ago', secondsAway: -1 },
  { when: 'an hour ago', secondsAway: -3600 },
])('set - writes nothing and clears every chunk when expiresAt is $when', async ({ secondsAway }) => {
  const storeOptions = makeStoreOptions({ [`${identifier}.0`]: 'existing', [`${identifier}.1`]: 'existing' });

  await makeStore().set(identifier, guestData({ expiresAt: now() + secondsAway }), false, storeOptions);

  expect(storeOptions.reply.setCookie).not.toHaveBeenCalled();
  expect(storeOptions.reply.clearCookie.mock.calls).toStrictEqual([
    [`${identifier}.0`, plainAttributes],
    [`${identifier}.1`, plainAttributes],
  ]);
});

test('set - splits a value that does not fit in one cookie into chunks of 3072 characters', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestWithAccessToken(10 * 1024);

  await store.set(identifier, data, false, written);

  const calls = written.reply.setCookie.mock.calls;
  expect(calls.length).toBeGreaterThan(1);
  expect(calls.map(([name]) => name)).toStrictEqual(calls.map((_, i) => `${identifier}.${i}`));
  const values = calls.map(([, value]) => value);
  for (const value of values.slice(0, -1)) {
    expect(value).toHaveLength(3072);
  }
  expect(values[values.length - 1]!.length).toBeGreaterThan(0);
  expect(values[values.length - 1]!.length).toBeLessThanOrEqual(3072);
  // Every chunk ends at the same deadline.
  for (const [, , attributes] of calls) {
    expect(attributes).toStrictEqual({ ...plainAttributes, maxAge: 3600 });
  }

  expect(await store.get(identifier, makeStoreOptions(cookiesFromSet(written)))).toStrictEqual(asRead(data));
});

test('get - puts chunks that arrive out of order back together', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestWithAccessToken(10 * 1024);

  await store.set(identifier, data, false, written);

  const cookies = cookiesFromSet(written);
  expect(Object.keys(cookies).length).toBeGreaterThan(1);
  const reversed = Object.fromEntries(Object.entries(cookies).reverse());

  expect(await store.get(identifier, makeStoreOptions(reversed))).toStrictEqual(asRead(data));
});

test('get - puts more than ten chunks back in numeric order, not in the order of their names', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestWithAccessToken(30 * 1024);

  await store.set(identifier, data, false, written);

  const cookies = cookiesFromSet(written);
  // By name, `.10` comes before `.2`. A store that did not sort by number would join the chunks in that order.
  expect(Object.keys(cookies).length).toBeGreaterThan(10);
  const byName = Object.fromEntries(Object.entries(cookies).sort(([a], [b]) => (a < b ? -1 : 1)));

  expect(await store.get(identifier, makeStoreOptions(byName))).toStrictEqual(asRead(data));
});

test('set - clears stale trailing chunks that a larger value left behind, with the plain attributes', async () => {
  const storeOptions = makeStoreOptions({
    [`${identifier}.0`]: 'existing',
    [`${identifier}.1`]: 'existing',
    '__a0_session.0': 'other',
    [`${identifier}.2`]: 'existing',
  });

  await makeStore().set(identifier, guestData(), false, storeOptions);

  expect(storeOptions.reply.setCookie).toHaveBeenCalledTimes(1);
  // No Max-Age here: a lifetime on a cookie that is going away is contradictory. The cookie of another store stays.
  expect(storeOptions.reply.clearCookie.mock.calls).toStrictEqual([
    [`${identifier}.1`, plainAttributes],
    [`${identifier}.2`, plainAttributes],
  ]);
});

test('set - clears only the stale chunks of the guest, and leaves the cookies that only look like them', async () => {
  const storeOptions = makeStoreOptions({
    ...lookAlikeCookies(),
    [`${identifier}.0`]: 'existing',
    [`${identifier}.1`]: 'existing',
    [`${identifier}.2`]: 'existing',
  });

  await makeStore().set(identifier, guestData(), false, storeOptions);

  expect(storeOptions.reply.setCookie).toHaveBeenCalledTimes(1);
  expect(storeOptions.reply.clearCookie.mock.calls).toStrictEqual([
    [`${identifier}.1`, plainAttributes],
    [`${identifier}.2`, plainAttributes],
  ]);
});

test('set - does not clear a chunk that it has just written', async () => {
  const storeOptions = makeStoreOptions({ [`${identifier}.0`]: 'existing' });

  await makeStore().set(identifier, guestData(), false, storeOptions);

  expect(storeOptions.reply.setCookie).toHaveBeenCalledTimes(1);
  expect(storeOptions.reply.clearCookie).not.toHaveBeenCalled();
});

test('get - returns undefined when there is no cookie', async () => {
  expect(await makeStore().get(identifier, makeStoreOptions())).toBeUndefined();
});

test('get - reads the guest when the request also carries the cookies of other stores', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestData();

  await store.set(identifier, data, false, written);

  const cookies = { '__a0_session.0': 'other', ...cookiesFromSet(written), '__a0_anon.0': 'other', theme: 'dark' };
  expect(await store.get(identifier, makeStoreOptions(cookies))).toStrictEqual(asRead(data));
});

// Cookie names that only look like the chunks of the guest. They can come from another store that has a longer
// identifier, from another app on the same domain, or from a visitor. A name is a chunk of the guest only when it is
// the identifier, a dot and the number of the chunk, as `set` writes it. Nothing else is read as the guest, or deleted
// with it.
const LOOK_ALIKES = [
  '__a0_poppy_x.0', // another name that starts with the identifier
  '__a0_poppy_session.0', // a state identifier that starts with it
  'x__a0_poppy.0', // the identifier at the end of another name
  'other.__a0_poppy.1', // the identifier in the middle of another name
  '__a0_poppy', // no chunk number
  '__a0_poppy.', // an empty chunk number
  '__a0_poppy.x', // not a number
  '__a0_poppy.1a', // a number with more after it
  '__a0_poppy.0.1', // more than one number
  '__a0_poppy.01', // a number that `set` never writes
];

const lookAlikeCookies = (): Record<string, string> => Object.fromEntries(LOOK_ALIKES.map((name) => [name, 'other']));

test('get - reads the guest when other cookies only look like its chunks', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestData();

  await store.set(identifier, data, false, written);

  const cookies = { ...lookAlikeCookies(), ...cookiesFromSet(written) };
  expect(await store.get(identifier, makeStoreOptions(cookies))).toStrictEqual(asRead(data));
});

test('get - reads a guest of several chunks when other cookies only look like its chunks', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestWithAccessToken(10 * 1024);

  await store.set(identifier, data, false, written);

  const chunks = cookiesFromSet(written);
  expect(Object.keys(chunks).length).toBeGreaterThan(1);
  expect(await store.get(identifier, makeStoreOptions({ ...lookAlikeCookies(), ...chunks }))).toStrictEqual(
    asRead(data)
  );
});

test('get - returns undefined when the request has only cookies that look like the chunks', async () => {
  expect(await makeStore().get(identifier, makeStoreOptions(lookAlikeCookies()))).toBeUndefined();
});

test('get - returns undefined for a request with only a chunk that is not the first, as before', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  await store.set(identifier, guestWithAccessToken(10 * 1024), false, written);
  const [, ...rest] = Object.entries(cookiesFromSet(written));

  // A chunk is missing, so the value cannot be opened. It is still no guest, and not an error.
  expect(await store.get(identifier, makeStoreOptions(Object.fromEntries(rest)))).toBeUndefined();
});

test('get - returns undefined for a value that is not a valid guest cookie', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  await store.set(identifier, guestData(), false, written);
  const valid = cookiesFromSet(written)[`${identifier}.0`]!;
  // The last characters of a JWE are its authentication tag, so changing them fails the check.
  const tampered = `${valid.slice(0, -4)}${valid.endsWith('AAAA') ? 'BBBB' : 'AAAA'}`;

  for (const value of ['not-a-jwe', tampered]) {
    expect(await store.get(identifier, makeStoreOptions({ [`${identifier}.0`]: value }))).toBeUndefined();
  }
});

// The visitor sets this cookie, and so can another site on the same domain, so its value can be anything. jose refuses
// these values in ways that `decrypt` of the abstract store does not turn into `undefined`: a plain Error,
// JOSENotSupported, a TypeError and more. A forged cookie is no guest. It must not become an error for the app.
test.each(FORGED_GUEST_COOKIES)('get - returns undefined for a forged cookie: $name', async ({ value }) => {
  const storeOptions = makeStoreOptions({ [`${identifier}.0`]: value });

  expect(await makeStore().get(identifier, storeOptions)).toBeUndefined();
});

// A secret that cannot decrypt is a mistake in the app, and not a cookie that someone forged. It is thrown, so it
// fails on the first read of a guest and does not hide as no guest. An empty list of secrets is one that `decrypt`
// refuses with `InvalidConfigurationError`, before it looks at the cookie.
test('get - throws InvalidConfigurationError when the secret cannot decrypt, and does not hide it as no guest', async () => {
  const written = makeStoreOptions();
  await makeStore().set(identifier, guestData(), false, written);
  const cookies = makeStoreOptions(cookiesFromSet(written));

  await expect(makeStore({ secret: [] }).get(identifier, cookies)).rejects.toBeInstanceOf(InvalidConfigurationError);
  await expect(makeStore({ secret: [] }).get(identifier, cookies)).rejects.toThrowError(
    'At least one secret must be provided'
  );
});

test.each(FORGED_GUEST_COOKIES)(
  'get - reads a forged cookie as no guest with a good secret, and reports the bad secret with the same cookie: $name',
  async ({ value }) => {
    const storeOptions = makeStoreOptions({ [`${identifier}.0`]: value });

    expect(await makeStore().get(identifier, storeOptions)).toBeUndefined();
    await expect(makeStore({ secret: [] }).get(identifier, storeOptions)).rejects.toBeInstanceOf(
      InvalidConfigurationError
    );
  }
);

test('get - returns undefined when there is no cookie, also with a secret that cannot decrypt', async () => {
  // There is nothing to decrypt, so the secret is not used.
  expect(await makeStore({ secret: [] }).get(identifier, makeStoreOptions())).toBeUndefined();
});

// `JWTExpired` is the one failure of the value itself that `get` throws: the guest was real, and the reads of the poppy
// client tell this class from the others and delete the guest. Another claim that fails is not an expiry, so it is no
// guest.
test('get - throws JWTExpired when the encrypted value is more than 15 seconds past its expiry', async () => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestData({ expiresAt: now() + 60 });
  await store.set(identifier, data, false, written);
  const cookies = makeStoreOptions(cookiesFromSet(written));

  // Decryption allows 15 seconds of difference between clocks, so the value still opens 10 seconds after its expiry.
  vi.setSystemTime((data.expiresAt + 10) * 1000);
  expect(await store.get(identifier, cookies)).toStrictEqual(asRead(data));

  vi.setSystemTime((data.expiresAt + 16) * 1000);
  await expect(store.get(identifier, cookies)).rejects.toBeInstanceOf(errors.JWTExpired);
});

test('get - returns undefined for a value that is not valid yet, as only JWTExpired is thrown', async () => {
  const data = guestData();
  // `nbf` is an hour away. It is a claim that fails and it is not an expiry.
  const notYet = await encrypt({ ...data, nbf: now() + 3600 }, SECRET, identifier, data.expiresAt);

  expect(await makeStore().get(identifier, makeStoreOptions({ [`${identifier}.0`]: notYet }))).toBeUndefined();
});

test('delete - clears every chunk with the plain attributes, and leaves other cookies alone', async () => {
  const storeOptions = makeStoreOptions({
    [`${identifier}.0`]: 'existing',
    '__a0_session.0': 'other',
    [`${identifier}.1`]: 'existing',
    '__a0_anon.0': 'other',
    theme: 'dark',
  });

  await makeStore().delete(identifier, storeOptions);

  expect(storeOptions.reply.clearCookie.mock.calls).toStrictEqual([
    [`${identifier}.0`, plainAttributes],
    [`${identifier}.1`, plainAttributes],
  ]);
});

test('delete - clears only the chunks of the guest, and leaves the cookies that only look like them', async () => {
  const storeOptions = makeStoreOptions({
    ...lookAlikeCookies(),
    [`${identifier}.0`]: 'existing',
    [`${identifier}.1`]: 'existing',
    [`${identifier}.12`]: 'existing',
  });

  await makeStore().delete(identifier, storeOptions);

  expect(storeOptions.reply.clearCookie.mock.calls).toStrictEqual([
    [`${identifier}.0`, plainAttributes],
    [`${identifier}.1`, plainAttributes],
    [`${identifier}.12`, plainAttributes],
  ]);
});

test('delete - does nothing when the request has only cookies that look like the chunks', async () => {
  const storeOptions = makeStoreOptions(lookAlikeCookies());

  await makeStore().delete(identifier, storeOptions);

  expect(storeOptions.reply.clearCookie).not.toHaveBeenCalled();
});

test('delete - does nothing when there is nothing stored', async () => {
  const storeOptions = makeStoreOptions();

  await makeStore().delete(identifier, storeOptions);

  expect(storeOptions.reply.clearCookie).not.toHaveBeenCalled();
});

// The identifier is a name and not a pattern. A character that a pattern would treat as special matches only itself.
test.each([
  { identifier: 'guest.v2', lookAlike: 'guestXv2.0' },
  { identifier: 'guest+', lookAlike: 'guestt.0' },
  { identifier: 'guest(1)', lookAlike: 'guest1.0' },
])('an identifier like $identifier matches only its own chunks', async ({ identifier: custom, lookAlike }) => {
  const store = makeStore();
  const written = makeStoreOptions();
  const data = guestWithAccessToken(10 * 1024);

  await store.set(custom, data, false, written);

  // The chunks arrive in reverse order, so they are put back together by their numbers, also when the identifier holds
  // a dot.
  const chunks = Object.entries(cookiesFromSet(written));
  expect(chunks.length).toBeGreaterThan(1);
  const cookies = { ...Object.fromEntries(chunks.reverse()), [lookAlike]: 'other' };
  expect(await store.get(custom, makeStoreOptions(cookies))).toStrictEqual(asRead(data));

  const deleted = makeStoreOptions(cookies);
  await store.delete(custom, deleted);
  expect(deleted.reply.clearCookie.mock.calls.map(([name]) => name).sort()).toStrictEqual(
    chunks.map(([name]) => name).sort()
  );
});

test('set - applies the cookie option overrides', async () => {
  const storeOptions = makeStoreOptions();

  await makeStore({ cookie: { sameSite: 'strict', secure: false, path: '/shop' } }).set(
    identifier,
    guestData(),
    false,
    storeOptions
  );

  expect(storeOptions.reply.setCookie.mock.calls[0]![2]).toStrictEqual({
    httpOnly: true,
    sameSite: 'strict',
    path: '/shop',
    secure: false,
    maxAge: 3600,
  });
});

test('set - keeps the defaults for the cookie options that are not overridden', async () => {
  const storeOptions = makeStoreOptions();

  // The usual case for local development over plain HTTP.
  await makeStore({ cookie: { secure: false } }).set(identifier, guestData(), false, storeOptions);

  expect(storeOptions.reply.setCookie.mock.calls[0]![2]).toStrictEqual({
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: false,
    maxAge: 3600,
  });
});

// A browser removes a cookie only when the path (and the other attributes) match the ones it was set with.
test('set and delete - clear cookies with the cookie option overrides', async () => {
  const store = makeStore({ cookie: { sameSite: 'strict', secure: false, path: '/shop' } });
  const overrides = { httpOnly: true, sameSite: 'strict', path: '/shop', secure: false };
  const stale = makeStoreOptions({ [`${identifier}.0`]: 'existing', [`${identifier}.1`]: 'existing' });
  const deleted = makeStoreOptions({ [`${identifier}.0`]: 'existing', [`${identifier}.1`]: 'existing' });

  await store.set(identifier, guestData(), false, stale);
  await store.delete(identifier, deleted);

  expect(stale.reply.clearCookie.mock.calls).toStrictEqual([[`${identifier}.1`, overrides]]);
  expect(deleted.reply.clearCookie.mock.calls).toStrictEqual([
    [`${identifier}.0`, overrides],
    [`${identifier}.1`, overrides],
  ]);
});

test('set - keeps the cookie HttpOnly, so the browser can never read the guest', async () => {
  const storeOptions = makeStoreOptions();
  // `httpOnly` is not part of `PoppyGuestCookieOptions`, so a typed caller cannot turn it off. A caller that is not
  // typed cannot either.
  // @ts-expect-error `httpOnly` is not a cookie option of the guest store.
  const store = makeStore({ cookie: { httpOnly: false, sameSite: 'none' } });

  await store.set(identifier, guestData(), false, storeOptions);

  expect(storeOptions.reply.setCookie.mock.calls[0]![2]).toMatchObject({ httpOnly: true, sameSite: 'none' });
});

test('get - reads a value that was written with an old secret, after the secret is rotated', async () => {
  const written = makeStoreOptions();
  const data = guestData();

  await makeStore({ secret: OLD_SECRET }).set(identifier, data, false, written);

  const rotated = makeStore({ secret: [NEW_SECRET, OLD_SECRET] });
  expect(await rotated.get(identifier, makeStoreOptions(cookiesFromSet(written)))).toStrictEqual(asRead(data));
});

test('set - writes with the newest secret', async () => {
  const written = makeStoreOptions();
  const data = guestData();

  await makeStore({ secret: [NEW_SECRET, OLD_SECRET] }).set(identifier, data, false, written);

  const cookies = makeStoreOptions(cookiesFromSet(written));
  expect(await makeStore({ secret: NEW_SECRET }).get(identifier, cookies)).toStrictEqual(asRead(data));
  expect(await makeStore({ secret: OLD_SECRET }).get(identifier, cookies)).toBeUndefined();
});

test('get - returns undefined for a value encrypted for another store, as the identifier salts the key', async () => {
  const data = guestData();
  const forGuest = await encrypt(data, SECRET, identifier, data.expiresAt);
  const forAnonymous = await encrypt(data, SECRET, '__a0_anon', data.expiresAt);

  // The same secret and the same data: only the identifier that the value was encrypted for differs.
  expect(await makeStore().get(identifier, makeStoreOptions({ [`${identifier}.0`]: forGuest }))).toStrictEqual(
    asRead(data)
  );
  expect(await makeStore().get(identifier, makeStoreOptions({ [`${identifier}.0`]: forAnonymous }))).toBeUndefined();
});

test('is accepted as the guestStore of the poppy option', () => {
  // The assignment is the test: `npm run typecheck` fails when the store does not fit.
  const guestStore: PoppyOptions<StoreOptions>['guestStore'] = makeStore();

  expect(guestStore).toBeInstanceOf(AbstractPoppyGuestStore);
});

// A custom store: the SDK's encryption, and a Map in place of cookies.
class MapGuestStore extends AbstractPoppyGuestStore {
  readonly values = new Map<string, string>();

  async set(identifier: string, data: PoppyGuestData): Promise<void> {
    this.values.set(identifier, await this.encrypt(identifier, data, data.expiresAt));
  }

  async get(identifier: string): Promise<PoppyGuestData | undefined> {
    const value = this.values.get(identifier);

    if (value) {
      return await this.decrypt<PoppyGuestData>(identifier, value);
    }
  }

  async delete(identifier: string): Promise<void> {
    this.values.delete(identifier);
  }
}

test('AbstractPoppyGuestStore - a subclass round-trips a guest through this.encrypt and this.decrypt', async () => {
  const store: PoppyGuestStore = new MapGuestStore({ secret: SECRET });
  const data = guestData();

  await store.set(identifier, data);

  expect(await store.get(identifier)).toStrictEqual(asRead(data));

  await store.delete(identifier);

  expect(await store.get(identifier)).toBeUndefined();
});

test('AbstractPoppyGuestStore - a subclass keeps the guest encrypted under its secret', async () => {
  const store = new MapGuestStore({ secret: SECRET });
  const data = guestData();

  await store.set(identifier, data);

  const value = store.values.get(identifier)!;
  expect(decodeProtectedHeader(value)).toMatchObject({ alg: 'dir', enc: 'A256CBC-HS512' });
  expect((await decrypt<{ exp: number }>(value, SECRET, identifier)).exp).toBe(data.expiresAt);

  // The same value under another secret is not a guest.
  const other = new MapGuestStore({ secret: OLD_SECRET });
  other.values.set(identifier, value);
  expect(await other.get(identifier)).toBeUndefined();
});
