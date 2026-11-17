import { EnterpriseConnectNotSupportedError, TokenByRefreshTokenError } from '@auth0/auth0-auth-js';
import { errors } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { InvalidConfigurationError, MissingSessionError, SessionExpiredError } from '../errors.js';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import { StatelessAnonymousStore } from '../store/stateless-anonymous-store.js';
import { StatelessStateStore } from '../store/stateless-state-store.js';
import {
  BrowserCookieHandler,
  CIMD_URL,
  FORGED_GUEST_COOKIES,
  GUEST_SUB,
  OTHER_SESSION_ID,
  POPPY_CLIENT_ID,
  POPPY_DOMAIN,
  POPPY_ISSUER,
  SESSION_ID,
  SESSION_KEY,
  USER_ID,
  agentAct,
  agentActClaim,
  agentContext,
  agentIdToken,
  createPoppyConfig,
  guestRecord,
} from '../test-utils/poppy.js';
import type { AgentIdTokenOptions, Browser } from '../test-utils/poppy.js';
import type { StateData } from '../types.js';
import { ANONYMOUS_USER_PROFILE } from './constants.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';
import type { PoppyGuestData, PoppyGuestStore } from './types.js';

// These tests run the whole website. A fake Auth0 answers the code exchange with a signed ID token, and one Map (the
// browser) holds the cookies of every store, so a test can see what each read leaves behind.

const SECRET = '<secret>';
const TRANSACTION_ID = '__a0_tx';
const STATE_ID = '__a0_session';
const GUEST_ID = '__a0_poppy';
// The cookie that holds the guest: with the defaults (Secure, Path=/) the store gives it the `__Host-` prefix.
const GUEST_COOKIE = '__Host-a0_poppy';
const CALLBACK = new URL('https://zepto.example/auth/callback?code=c1');
const ANA = 'auth0|ana';
const HUMAN = { kind: 'human' };

// What the fake Auth0 answers with. A test sets them for each login.
let idToken: string | undefined;
let expiresIn = 3600;
// The path of every request that reached the fake Auth0. A read that must stay local leaves this list empty.
const requests: string[] = [];

const server = setupServer(
  http.get(`https://${POPPY_DOMAIN}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: POPPY_ISSUER,
      authorization_endpoint: `https://${POPPY_DOMAIN}/authorize`,
      token_endpoint: `https://${POPPY_DOMAIN}/oauth/token`,
      // As the real tenant: RP-Initiated Logout is on, so a normal logout goes to the OIDC logout endpoint.
      end_session_endpoint: `https://${POPPY_DOMAIN}/oidc/logout`,
    })
  ),
  http.post(`https://${POPPY_DOMAIN}/oauth/token`, () =>
    HttpResponse.json({
      ...(idToken !== undefined && { id_token: idToken }),
      access_token: 'at_join',
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope: 'openid profile',
      // A refresh token is always there, so a check that a session has none means something.
      refresh_token: 'rt_join',
    })
  )
);

server.events.on('request:start', ({ request }) => {
  requests.push(new URL(request.url).pathname);
});

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

beforeEach(() => {
  idToken = undefined;
  expiresIn = 3600;
  requests.length = 0;
  // Only the clock is fake. The time has a fraction of a second, as the real time has.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-11-10T10:00:00.400Z'));
});

afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});

const now = () => Math.floor(Date.now() / 1000);

// Moves the clock on.
const later = (seconds: number) => vi.setSystemTime(Date.now() + seconds * 1000);

// Sets the clock to a whole second, in Unix seconds.
const setClock = (unixSeconds: number) => vi.setSystemTime(unixSeconds * 1000);

// A website with one browser. `poppy: false` leaves the `poppy` option out.
interface App {
  browser: Browser;
  client: ServerClient<Browser>;
  transactionStore: CookieTransactionStore<Browser>;
  stateStore: StatelessStateStore<Browser>;
  guestStore: PoppyGuestStore<Browser>;
}

interface AppOptions {
  poppy?: boolean;
  /** The guest store. Default: `StatelessPoppyGuestStore`. */
  guestStore?: PoppyGuestStore<Browser>;
  /** The browser. Default: a new one. */
  browser?: Browser;
}

function createApp(options: AppOptions = {}): App {
  const browser: Browser = options.browser ?? new Map();
  const cookies = new BrowserCookieHandler();
  const transactionStore = new CookieTransactionStore<Browser>({ secret: SECRET }, cookies);
  const stateStore = new StatelessStateStore<Browser>({ secret: SECRET }, cookies);
  const guestStore = options.guestStore ?? new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, cookies);

  const client = new ServerClient<Browser>({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 0 },
    transactionStore,
    stateStore,
    anonymousStore: new StatelessAnonymousStore<Browser>({ secret: SECRET }, cookies),
    poppy: options.poppy === false ? undefined : { config: createPoppyConfig(), guestStore },
  });

  return { browser, client, transactionStore, stateStore, guestStore };
}

// The browser comes back from Auth0 with a code, and the token endpoint answers with an ID token made from `token`.
async function login(app: App, token: AgentIdTokenOptions = {}) {
  idToken = await agentIdToken(token);
  await app.transactionStore.set(TRANSACTION_ID, { codeVerifier: 'cv', domain: POPPY_DOMAIN }, false, app.browser);

  return app.client.completeInteractiveLogin(CALLBACK, app.browser);
}

// A guest has a guest `sub` and the anonymous user profile.
const joinAsGuest = (app: App, sessionId = SESSION_ID, act = agentAct({ poppy_sid: sessionId })) =>
  login(app, { sub: GUEST_SUB, subProfile: ANONYMOUS_USER_PROFILE, act });

const joinSignedIn = (app: App, sub = ANA, sessionId = SESSION_ID, act = agentAct({ poppy_sid: sessionId })) =>
  login(app, { sub, act });

// What a customer's own login leaves in the state store.
function ownLogin(sub: string): StateData {
  const at = now();

  return {
    user: { sub, iss: POPPY_ISSUER, name: 'Own Login', email: 'old@zepto.example' },
    idToken: 'old.id.token',
    refreshToken: 'rt_old',
    tokenSets: [{ audience: 'default', accessToken: 'at_old', scope: 'openid profile email', expiresAt: at + 600 }],
    domain: POPPY_DOMAIN,
    internal: { sid: 'old_sid', createdAt: at },
  };
}

const seedOwnLogin = (app: App, sub = ANA) => app.stateStore.set(STATE_ID, ownLogin(sub), false, app.browser);

const stateOf = (app: App) => app.stateStore.get(STATE_ID, app.browser);

// The deadline T of a guest, from the store, and of a signed-in agent, from the state store.
const guestDeadline = async (app: App) => (await app.guestStore.get(GUEST_ID, app.browser))!.expiresAt;
const sessionDeadline = async (app: App) => (await stateOf(app))!.sessionExpiresAt!;

// The raw cookies of one store, by name. A read that leaves a store alone leaves equal lists.
const cookiesOf = (app: App, name: string): Array<[string, string]> =>
  [...app.browser]
    .filter(([cookie]) => cookie.startsWith(name))
    .map(([cookie, { value }]): [string, string] => [cookie, value])
    .sort(([a], [b]) => a.localeCompare(b));

// A guest store of the app's own, which answers `get` with `record`.
function customGuestStore(record?: unknown) {
  return {
    get: vi.fn(async () => record as PoppyGuestData | undefined),
    set: vi.fn(async () => {}),
    delete: vi.fn(async () => {}),
  };
}

describe('poppy.getContext | who makes the request', () => {
  test('a browser with no cookies is human', async () => {
    const app = createApp();

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
  });

  test("a browser with a person's own session is human", async () => {
    const app = createApp();
    await seedOwnLogin(app);

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
  });

  test('a person who logged in normally is human, even when the act has no Poppy Session', async () => {
    const app = createApp();
    await login(app, { sub: ANA, act: { sub: CIMD_URL } });

    expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
  });

  test('after a guest join, the context is the guest and has the key of the Session', async () => {
    const app = createApp();
    await joinAsGuest(app);

    const context = await app.client.poppy.getContext(app.browser);

    expect(context).toStrictEqual(agentContext('guest'));
    expect(context).toHaveProperty('key', SESSION_KEY);
  });

  test('after a signed-in join, the context is signed_in and has the same key', async () => {
    const app = createApp();
    await joinSignedIn(app);

    const context = await app.client.poppy.getContext(app.browser);

    expect(context).toStrictEqual(agentContext('signed_in'));
    expect(context).toHaveProperty('key', SESSION_KEY);
  });

  // The agent of the Session has no id inside its Personal Agent. `toStrictEqual` fails on a member that is there with
  // the value `undefined`.
  const withoutAgentId = agentAct({ poppy_agent_id: undefined });

  test.each(['guest', 'signed_in'] as const)('an agent with no poppy_agent_id: %s', async (state) => {
    const app = createApp();
    await (state === 'guest'
      ? joinAsGuest(app, SESSION_ID, withoutAgentId)
      : joinSignedIn(app, ANA, SESSION_ID, withoutAgentId));

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(
      agentContext(state, { act: { sub: CIMD_URL, poppy_sid: SESSION_ID, poppy_user_id: USER_ID } })
    );
  });

  // A guest and a user session never coexist: the join of a guest ends the session of the browser, a person's too.
  test('a guest join over the own login of a person gives the guest and no user', async () => {
    const app = createApp();
    await seedOwnLogin(app);
    expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    await joinAsGuest(app);

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest'));
    expect(await app.client.getUser(app.browser)).toBeUndefined();
  });

  test('a guest join over an agent session of another Session gives the guest and no user', async () => {
    const app = createApp();
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    await joinAsGuest(app, SESSION_ID);

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest'));
    expect(await app.client.getUser(app.browser)).toBeUndefined();
  });
});

describe('poppy.getContext | the guest ends 30 seconds before its deadline', () => {
  // The leeway is the one that the ceiling of any session has: the guest is gone from 30 seconds before the deadline.
  test.each([
    { before: 31, gone: false },
    { before: 30, gone: true },
    { before: 29, gone: true },
  ])('at the deadline minus $before seconds, the guest is gone: $gone', async ({ before, gone }) => {
    const app = createApp();
    await joinAsGuest(app);
    const guestCookies = cookiesOf(app, GUEST_COOKIE);
    expect(guestCookies).not.toEqual([]);
    setClock((await guestDeadline(app)) - before);

    const context = await app.client.poppy.getContext(app.browser);

    expect(context).toStrictEqual(gone ? HUMAN : agentContext('guest'));
    // A guest that is gone has its cookies deleted. A guest that is not gone is left as it was.
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual(gone ? [] : guestCookies);
  });

  test('the access token of a guest is gone too, and the cookies are deleted', async () => {
    const app = createApp();
    await joinAsGuest(app);
    setClock((await guestDeadline(app)) - 29);

    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });

  // A browser drops a cookie at its Max-Age, but a client can send a copy of it later. Ten seconds after the deadline
  // the encrypted value still opens, because decryption allows 15 seconds of difference between clocks: the guest store
  // gives the guest back. Sixteen seconds after, the store throws `JWTExpired`. Neither may reach the app.
  describe.each([
    { seconds: 10, storeThrows: false },
    { seconds: 16, storeThrows: true },
  ])('the cookies are copied and put back $seconds seconds after the deadline', ({ seconds, storeThrows }) => {
    async function replay() {
      const app = createApp();
      await joinAsGuest(app);
      const deadline = await guestDeadline(app);
      const copies = [...app.browser].filter(([name]) => name.startsWith(GUEST_COOKIE));
      expect(copies).not.toEqual([]);

      // The browser has dropped the cookies. The copies come back later.
      copies.forEach(([name]) => app.browser.delete(name));
      expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
      setClock(deadline + seconds);
      copies.forEach(([name, cookie]) => app.browser.set(name, cookie));
      expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);

      // This is the state that the test is about: the store itself does not refuse the copy at 10 seconds.
      if (storeThrows) {
        await expect(app.guestStore.get(GUEST_ID, app.browser)).rejects.toBeInstanceOf(errors.JWTExpired);
      } else {
        await expect(app.guestStore.get(GUEST_ID, app.browser)).resolves.toMatchObject({ expiresAt: deadline });
      }

      return app;
    }

    test('getContext gives human, deletes the cookies and does not throw', async () => {
      const app = await replay();

      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    });

    test('getGuestAccessToken gives undefined, deletes the cookies and does not throw', async () => {
      const app = await replay();

      expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
      expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    });
  });
});

describe('poppy.getContext | a guest record that lacks a member', () => {
  const withoutMember = (member: keyof PoppyGuestData): PoppyGuestData => {
    const record: Partial<PoppyGuestData> = guestRecord();
    delete record[member];

    return record as PoppyGuestData;
  };

  const withAct = (act: unknown): PoppyGuestData => guestRecord({ act: act as PoppyGuestData['act'] });
  const actWithout = (member: string) => {
    const act: Record<string, unknown> = agentAct();
    delete act[member];

    return act;
  };

  const badRecords: Array<{ name: string; record: () => unknown }> = [
    { name: 'no expiresAt', record: () => withoutMember('expiresAt') },
    { name: 'an expiresAt that is a string', record: () => guestRecord({ expiresAt: String(now() + 3600) as never }) },
    { name: 'an expiresAt that is null', record: () => guestRecord({ expiresAt: null as never }) },
    // These two never end, because the check of the ceiling is false for them.
    { name: 'an expiresAt that is NaN', record: () => guestRecord({ expiresAt: NaN }) },
    { name: 'an expiresAt that is Infinity', record: () => guestRecord({ expiresAt: Infinity }) },
    { name: 'no sub', record: () => withoutMember('sub') },
    { name: 'a sub that is a number', record: () => guestRecord({ sub: 7 as never }) },
    { name: 'no act member', record: () => withoutMember('act') },
    { name: 'an act that is null', record: () => withAct(null) },
    { name: 'an act that is a string', record: () => withAct(CIMD_URL) },
    { name: 'an act with no sub', record: () => withAct(actWithout('sub')) },
    { name: 'an act whose sub is a number', record: () => withAct(agentAct({ sub: 7 })) },
    { name: 'an act with no poppy_sid', record: () => withAct(actWithout('poppy_sid')) },
    { name: 'an act whose poppy_sid is a number', record: () => withAct(agentAct({ poppy_sid: 42 })) },
    { name: 'an act with no poppy_user_id', record: () => withAct(actWithout('poppy_user_id')) },
    { name: 'an act whose poppy_user_id is undefined', record: () => withAct(agentAct({ poppy_user_id: undefined })) },
  ];

  test('a custom store with a complete record gives the guest, and deletes nothing', async () => {
    const store = customGuestStore(guestRecord());
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest'));
    expect(store.get).toHaveBeenCalledWith(GUEST_ID, app.browser);
    expect(store.delete).not.toHaveBeenCalled();
  });

  test.each(badRecords)('getContext gives human and deletes the guest for $name', async ({ record }) => {
    const store = customGuestStore(record());
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
    expect(store.delete).toHaveBeenCalledTimes(1);
    expect(store.delete).toHaveBeenCalledWith(GUEST_ID, app.browser);
  });

  test.each(badRecords)('getGuestAccessToken gives undefined and deletes it for $name', async ({ record }) => {
    const store = customGuestStore(record());
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    expect(store.delete).toHaveBeenCalledTimes(1);
    expect(store.delete).toHaveBeenCalledWith(GUEST_ID, app.browser);
  });

  // The act is kept whole, with the members that this package does not know. The other members of the record are not in
  // the context, and neither is a `sub_profile` that is not a string.
  test('the context of a guest from a custom store has the whole act, and no other member of the record', async () => {
    const act = agentActClaim({ client_id: 'web_app_client', extension: { tags: ['a'] } });
    const record = { ...guestRecord({ act }), refresh_token: 'rt_secret', extra: 'x' };
    const app = createApp({ guestStore: customGuestStore(record) });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest', { act }));
  });

  test('the context of a guest from a custom store has no sub_profile that is not a string', async () => {
    const record = guestRecord({ sub_profile: ['urn:auth0:anonymous_user'] as never });
    const app = createApp({ guestStore: customGuestStore(record) });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(
      agentContext('guest', { sub_profile: undefined })
    );
  });

  test('a guest store with no guest gives human, and nothing is deleted', async () => {
    const store = customGuestStore(undefined);
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    expect(store.delete).not.toHaveBeenCalled();
  });

  test('a custom store with a guest past its deadline gives human and deletes the guest', async () => {
    const store = customGuestStore(guestRecord({ expiresAt: now() + 29 }));
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
    expect(store.delete).toHaveBeenCalledTimes(1);
  });

  // A store that is down must not turn a visitor into a person, so the error reaches the app and nothing is deleted.
  test('any other error of the guest store goes to the app, and nothing is deleted', async () => {
    const store = customGuestStore();
    store.get.mockRejectedValue(new Error('guest store is down'));
    const app = createApp({ guestStore: store });

    await expect(app.client.poppy.getContext(app.browser)).rejects.toThrow('guest store is down');
    await expect(app.client.poppy.getGuestAccessToken(app.browser)).rejects.toThrow('guest store is down');
    expect(store.delete).not.toHaveBeenCalled();
  });

  test('a guest store that reports JWTExpired gives human, and the guest is deleted', async () => {
    const store = customGuestStore();
    store.get.mockRejectedValue(new errors.JWTExpired('"exp" claim timestamp check failed', {}));
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
    expect(store.delete).toHaveBeenCalledTimes(1);
    expect(store.delete).toHaveBeenCalledWith(GUEST_ID, app.browser);
  });

  // A guest that has ended, or that is not valid, is deleted when it is read. It is already read as absent, so a store
  // that fails to delete it must not turn the read into an error. A guest that stays behind cannot outlive its
  // deadline, because every read of it checks that.
  describe('a guest store whose delete fails', () => {
    type Store = ReturnType<typeof customGuestStore>;

    const endedGuests: Array<{ name: string; arrange: (store: Store) => void }> = [
      {
        name: 'a guest past its deadline',
        arrange: (store) => store.get.mockResolvedValue(guestRecord({ expiresAt: now() + 29 })),
      },
      {
        name: 'a record that lacks a member',
        arrange: (store) => store.get.mockResolvedValue(guestRecord({ expiresAt: NaN })),
      },
      {
        name: 'an encrypted value that has ended',
        arrange: (store) =>
          store.get.mockRejectedValue(new errors.JWTExpired('"exp" claim timestamp check failed', {})),
      },
    ];

    const storeFor = ({ arrange }: { arrange: (store: Store) => void }): Store => {
      const store = customGuestStore();
      arrange(store);
      store.delete.mockRejectedValue(new Error('guest store is down'));

      return store;
    };

    test.each(endedGuests)('getContext gives human for $name, and the delete is tried', async (ended) => {
      const store = storeFor(ended);
      const app = createApp({ guestStore: store });

      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect(store.delete).toHaveBeenCalledTimes(1);
      expect(store.delete).toHaveBeenCalledWith(GUEST_ID, app.browser);
    });

    test.each(endedGuests)('getGuestAccessToken gives undefined for $name, and the delete is tried', async (ended) => {
      const store = storeFor(ended);
      const app = createApp({ guestStore: store });

      expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
      expect(store.delete).toHaveBeenCalledTimes(1);
    });

    test('the error of get still reaches the app, and delete is not tried', async () => {
      const store = customGuestStore();
      store.get.mockRejectedValue(new Error('guest store is down'));
      store.delete.mockRejectedValue(new Error('delete is down'));
      const app = createApp({ guestStore: store });

      await expect(app.client.poppy.getContext(app.browser)).rejects.toThrow('guest store is down');
      await expect(app.client.poppy.getGuestAccessToken(app.browser)).rejects.toThrow('guest store is down');
      expect(store.delete).not.toHaveBeenCalled();
    });
  });
});

// The visitor sets the guest cookie, and so can another site on the same domain. A value that cannot be opened is no
// guest, and the request is the request of a person. It must never be an error for the app.
describe('poppy.getContext | a forged guest cookie', () => {
  describe.each(FORGED_GUEST_COOKIES)('$name', ({ value }) => {
    const forge = (app: App) => app.browser.set(`${GUEST_COOKIE}.0`, { value });

    test('getContext gives human, getGuestAccessToken gives undefined, and nothing throws', async () => {
      const app = createApp();
      forge(app);

      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    });

    test('a person with a session of their own is still that person', async () => {
      const app = createApp();
      await seedOwnLogin(app);
      forge(app);

      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    });

    test('a later guest join replaces the cookie, and the guest works', async () => {
      const app = createApp();
      forge(app);

      await joinAsGuest(app);

      expect(app.browser.get(`${GUEST_COOKIE}.0`)?.value).not.toBe(value);
      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest'));
      expect(await app.client.poppy.getGuestAccessToken(app.browser)).toMatchObject({ accessToken: 'at_join' });
    });
  });
});

describe('poppy.getContext | a signed-in agent', () => {
  test('31 seconds before the deadline the agent is still signed in', async () => {
    const app = createApp();
    await joinSignedIn(app);
    setClock((await sessionDeadline(app)) - 31);

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('signed_in'));
  });

  test('29 seconds before the deadline the context is human, and the session is gone', async () => {
    const app = createApp();
    await joinSignedIn(app);
    setClock((await sessionDeadline(app)) - 29);

    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });

  // The usual path stores the `act` as the token has it, so a session from before the `poppy` option can hold one that
  // is not a Poppy Session. Reading it must not throw.
  describe.each([
    { name: 'a poppy_sid that is a number', act: { sub: CIMD_URL, poppy_sid: 42 } },
    { name: 'a poppy_sid that is a list', act: agentAct({ poppy_sid: [SESSION_ID] }) },
    { name: 'no act.sub', act: agentAct({ sub: undefined }) },
    { name: 'no poppy_user_id', act: agentAct({ poppy_user_id: undefined }) },
  ])('a session that the usual path stored with $name', ({ act }) => {
    test('is human, and the session stays', async () => {
      // An app without the `poppy` option stores the `act` as the token has it.
      const legacy = createApp({ poppy: false });
      await login(legacy, { sub: ANA, act });
      expect((await legacy.client.getUser(legacy.browser))?.act).toStrictEqual(JSON.parse(JSON.stringify(act)));

      // The same browser, now with the option.
      const app = createApp({ browser: legacy.browser });

      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    });
  });
});

describe('poppy.getGuestAccessToken | the access token of the join', () => {
  test('gives the first token set of the guest, and sends no request to Auth0', async () => {
    const app = createApp();
    await joinAsGuest(app);
    const at = now();
    requests.length = 0;

    const tokenSet = await app.client.poppy.getGuestAccessToken(app.browser);

    expect(tokenSet).toStrictEqual({
      audience: 'default',
      accessToken: 'at_join',
      scope: 'openid profile',
      expiresAt: at + 3600,
    });
    expect(requests).toEqual([]);
  });

  test('gives a token that is a copy, so a change by the app does not reach the store', async () => {
    const record = guestRecord();
    const store = customGuestStore(record);
    const app = createApp({ guestStore: store });

    const tokenSet = await app.client.poppy.getGuestAccessToken(app.browser);
    tokenSet!.accessToken = 'changed';

    expect(record.tokenSets[0]?.accessToken).toBe('at_custom');
  });

  test('gives undefined from the second the token ends, while the guest is still there', async () => {
    // The token ends in 10 minutes, and the guest in an hour.
    expiresIn = 600;
    const app = createApp();
    await joinAsGuest(app);
    const tokenSet = (await app.client.poppy.getGuestAccessToken(app.browser))!;
    requests.length = 0;

    setClock(tokenSet.expiresAt - 1);
    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toStrictEqual(tokenSet);

    setClock(tokenSet.expiresAt);
    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();

    setClock(tokenSet.expiresAt + 1);
    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    // The guest is still there. Only its token has ended, and the token is not renewed.
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest'));
    expect(requests).toEqual([]);
  });

  test('gives undefined when there is no guest', async () => {
    const app = createApp();

    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    expect(requests).toEqual([]);
  });

  test('gives undefined for a signed-in agent, who has a user session and no guest', async () => {
    const app = createApp();
    await joinSignedIn(app);

    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
  });

  // The guest is still a guest, so getContext reads it. It has no token to give.
  test.each([
    { name: 'an empty list', tokenSets: [] },
    { name: 'no list', tokenSets: undefined },
    { name: 'a list with null in it', tokenSets: [null] },
  ])('gives undefined for a guest whose token sets are $name', async ({ tokenSets }) => {
    const store = customGuestStore(guestRecord({ tokenSets: tokenSets as never }));
    const app = createApp({ guestStore: store });

    expect(await app.client.poppy.getGuestAccessToken(app.browser)).toBeUndefined();
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('guest'));
    expect(store.delete).not.toHaveBeenCalled();
  });
});

describe('existing methods | a guest and a signed-in agent', () => {
  test('a guest is not a user: no session, user or anonymous session, and no access token', async () => {
    const app = createApp();
    await joinAsGuest(app);

    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect(await app.client.anonymous.getSession(app.browser)).toBeUndefined();
    await expect(app.client.getAccessToken({}, app.browser)).rejects.toBeInstanceOf(TokenByRefreshTokenError);
  });

  test('the access token of a signed-in agent is the one of the join, and it is never refreshed', async () => {
    expiresIn = 600;
    const app = createApp();
    await joinSignedIn(app);
    const at = now();
    requests.length = 0;

    expect(await app.client.getAccessToken({}, app.browser)).toStrictEqual({
      audience: 'default',
      accessToken: 'at_join',
      scope: 'openid profile',
      expiresAt: at + 600,
    });
    // The session has no refresh token, so there is nothing to revoke.
    await expect(app.client.revokeRefreshToken({}, app.browser)).rejects.toBeInstanceOf(MissingSessionError);

    later(601);
    await expect(app.client.getAccessToken({}, app.browser)).rejects.toBeInstanceOf(TokenByRefreshTokenError);
    expect(requests).toEqual([]);
  });

  test('29 seconds before the deadline the access token fails, and the session is deleted', async () => {
    expiresIn = 600;
    const app = createApp();
    await joinSignedIn(app);
    setClock((await sessionDeadline(app)) - 29);
    requests.length = 0;

    await expect(app.client.getAccessToken({}, app.browser)).rejects.toBeInstanceOf(SessionExpiredError);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(requests).toEqual([]);
  });
});

describe('logout | the guest', () => {
  const returnTo = 'https://zepto.example/';

  // The URL of a guest: `/v2/logout`, because the OIDC logout endpoint looks the user up and fails for a guest.
  const expectGuestLogoutUrl = (url: URL) => {
    expect(url.origin).toBe(POPPY_ISSUER.slice(0, -1));
    expect(url.pathname).toBe('/v2/logout');
    expect(url.searchParams.get('returnTo')).toBe(returnTo);
    expect(url.searchParams.get('client_id')).toBe(POPPY_CLIENT_ID);
  };

  // The URL of everybody else: the end session endpoint that the tenant advertises.
  const expectOidcLogoutUrl = (url: URL) => {
    expect(url.origin).toBe(POPPY_ISSUER.slice(0, -1));
    expect(url.pathname).toBe('/oidc/logout');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe(returnTo);
  };

  // The join of a guest ended the login of the person, so there is a guest and no user session to delete.
  test('logout deletes the guest cookies of a guest that replaced the login of a person', async () => {
    const app = createApp();
    await seedOwnLogin(app);
    await joinAsGuest(app);
    expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);

    const url = await app.client.logout({ returnTo }, app.browser);

    expectGuestLogoutUrl(url);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
  });

  test('logout deletes the guest of a visitor who has no user session', async () => {
    const app = createApp();
    await joinAsGuest(app);

    const url = await app.client.logout({ returnTo }, app.browser);

    expectGuestLogoutUrl(url);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });

  test('the logout of a guest keeps `federated` and does not discover the tenant', async () => {
    const app = createApp();
    await joinAsGuest(app);
    requests.length = 0;

    const url = await app.client.logout({ returnTo, federated: true }, app.browser);

    expectGuestLogoutUrl(url);
    expect(url.searchParams.has('federated')).toBe(true);
    expect(requests).toEqual([]);
  });

  test('logout deletes the cookies of a signed-in agent, and its URL is the OIDC one', async () => {
    const app = createApp();
    await joinSignedIn(app);

    const url = await app.client.logout({ returnTo }, app.browser);

    expectOidcLogoutUrl(url);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
  });

  test('the logout of a person with no guest uses the end session endpoint of the tenant', async () => {
    const app = createApp();
    await seedOwnLogin(app);

    const url = await app.client.logout({ returnTo }, app.browser);

    expectOidcLogoutUrl(url);
  });

  test('a guest store whose delete rejects does not stop the logout', async () => {
    const store = customGuestStore(guestRecord());
    store.delete.mockRejectedValue(new Error('guest store is down'));
    const app = createApp({ guestStore: store });
    await seedOwnLogin(app);

    const url = await app.client.logout({ returnTo }, app.browser);

    expectGuestLogoutUrl(url);
    expect(store.delete).toHaveBeenCalledWith(GUEST_ID, app.browser);
    // The user session is gone too: the failure of the guest store does not come first.
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });

  test('a state store whose delete rejects does not leave the guest behind', async () => {
    const app = createApp();
    await joinAsGuest(app);
    expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);
    vi.spyOn(app.stateStore, 'delete').mockRejectedValue(new Error('state store is down'));

    await expect(app.client.logout({ returnTo }, app.browser)).rejects.toThrow('state store is down');

    // The logout failed, and the guest is gone anyway: it was dropped before the state store was used.
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });

  test('a guest store whose get rejects reads as no guest, and the logout goes on', async () => {
    const store = customGuestStore();
    store.get.mockRejectedValue(new Error('guest store is down'));
    const app = createApp({ guestStore: store });
    await seedOwnLogin(app);

    const url = await app.client.logout({ returnTo }, app.browser);

    expectOidcLogoutUrl(url);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });

  test('without the poppy option, logout leaves a cookie of that name alone', async () => {
    const app = createApp({ poppy: false });
    app.browser.set(`${GUEST_COOKIE}.0`, { value: 'not-ours' });

    await app.client.logout({ returnTo }, app.browser);

    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([[`${GUEST_COOKIE}.0`, 'not-ours']]);
  });
});

describe('Enterprise Connect | the poppy option', () => {
  const CONFLICT = 'Invalid poppy configuration: poppy cannot be combined with enterpriseConnect.';

  // Enterprise Connect has no state store. The transaction store is the only store it needs.
  const enterpriseConnectOptions = () => ({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    transactionStore: new CookieTransactionStore<Browser>({ secret: SECRET }, new BrowserCookieHandler()),
    enterpriseConnect: true as const,
  });

  const poppyOption = () => ({
    config: createPoppyConfig(),
    guestStore: new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, new BrowserCookieHandler()),
  });

  // The Enterprise Connect callback returns before the Poppy hook. A guest token would reach the app as a user there.
  test('is refused at construction, even when the option is valid', () => {
    const construct = () => new ServerClient({ ...enterpriseConnectOptions(), poppy: poppyOption() });

    expect(construct).toThrowError(InvalidConfigurationError);
    expect(construct).toThrowError(CONFLICT);
  });

  test('is refused with this message first, even when the option is not valid', () => {
    const invalid = { ...poppyOption(), config: {} as never };
    const construct = () => new ServerClient({ ...enterpriseConnectOptions(), poppy: invalid });

    expect(construct).toThrowError(CONFLICT);
  });

  test('enterpriseConnect without the poppy option is built as before, and blocks the poppy getter', () => {
    const serverClient = new ServerClient(enterpriseConnectOptions());

    expect(() => serverClient.poppy).toThrowError(EnterpriseConnectNotSupportedError);
  });
});
