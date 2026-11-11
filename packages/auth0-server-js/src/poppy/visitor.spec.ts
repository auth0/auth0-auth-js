import { errors } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, expectTypeOf, test, vi } from 'vitest';
import { InvalidConfigurationError } from '../errors.js';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import { StatelessAnonymousStore } from '../store/stateless-anonymous-store.js';
import { StatelessStateStore } from '../store/stateless-state-store.js';
import {
  AGENT_ID,
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
  agentIdToken,
  createPoppyConfig,
} from '../test-utils/poppy.js';
import type { AgentIdTokenOptions, Browser } from '../test-utils/poppy.js';
import type { AnonymousSessionData, AnonymousStateData, StateData, UserClaims } from '../types.js';
import { ANONYMOUS_USER_PROFILE } from './constants.js';
import type { ServerPoppyClient } from './server-poppy-client.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';
import type { PoppyAgentContext, PoppyGuestData, PoppyGuestStore, PoppyVisitor } from './types.js';

// These tests run the whole website. A fake Auth0 answers the code exchange with a signed ID token, and one Map (the
// browser) holds the cookies of every store, so a test can see what each read leaves behind.

const SECRET = '<secret>';
const TRANSACTION_ID = '__a0_tx';
const STATE_ID = '__a0_session';
const GUEST_ID = '__a0_poppy';
const ANONYMOUS_ID = '__a0_anon';
const CALLBACK = new URL('https://zepto.example/auth/callback?code=c1');
const ANA = 'auth0|ana';
const ANON_SUB = 'anon@2f1c1b7e';
const NONE = { kind: 'none' };
const HUMAN = { kind: 'human' };

// What the fake Auth0 answers with. A test sets the ID token for each login.
let idToken: string | undefined;
// The path of every request that reached the fake Auth0. A read that must stay local leaves this list empty.
const requests: string[] = [];

const server = setupServer(
  http.get(`https://${POPPY_DOMAIN}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: POPPY_ISSUER,
      authorization_endpoint: `https://${POPPY_DOMAIN}/authorize`,
      token_endpoint: `https://${POPPY_DOMAIN}/oauth/token`,
    })
  ),
  http.post(`https://${POPPY_DOMAIN}/oauth/token`, () =>
    HttpResponse.json({
      ...(idToken !== undefined && { id_token: idToken }),
      access_token: 'at_join',
      token_type: 'Bearer',
      expires_in: 3600,
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

// Sets the clock to a whole second, in Unix seconds.
const setClock = (unixSeconds: number) => vi.setSystemTime(unixSeconds * 1000);

// A website with one browser.
interface App {
  browser: Browser;
  client: ServerClient<Browser>;
  transactionStore: CookieTransactionStore<Browser>;
  stateStore: StatelessStateStore<Browser>;
  guestStore: PoppyGuestStore<Browser>;
  // The store of anonymous sessions. The website reads it only when the app was made with `anonymous: true`. A test can
  // still write to it, to leave a cookie that a website with no anonymous store cannot read.
  anonymousStore: StatelessAnonymousStore<Browser>;
}

interface AppOptions {
  /** Whether the website has an anonymous store. Default: `false`. */
  anonymous?: boolean;
  /** The guest store. Default: `StatelessPoppyGuestStore`. */
  guestStore?: PoppyGuestStore<Browser>;
  /** The browser. Default: a new one. */
  browser?: Browser;
  /** `false` leaves the `poppy` option out. */
  poppy?: boolean;
}

function createApp(options: AppOptions = {}): App {
  const browser: Browser = options.browser ?? new Map();
  const cookies = new BrowserCookieHandler();
  const transactionStore = new CookieTransactionStore<Browser>({ secret: SECRET }, cookies);
  const stateStore = new StatelessStateStore<Browser>({ secret: SECRET }, cookies);
  const guestStore = options.guestStore ?? new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, cookies);
  const anonymousStore = new StatelessAnonymousStore<Browser>({ secret: SECRET }, cookies);

  const client = new ServerClient<Browser>({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 0 },
    transactionStore,
    stateStore,
    anonymousStore: options.anonymous ? anonymousStore : undefined,
    poppy: options.poppy === false ? undefined : { config: createPoppyConfig(), guestStore },
  });

  return { browser, client, transactionStore, stateStore, guestStore, anonymousStore };
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

// What a customer's own login leaves in the state store: a user, and no agent.
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

// A session that has no user, as a flow with no ID token leaves.
const seedSessionWithoutUser = (app: App) =>
  app.stateStore.set(STATE_ID, { ...ownLogin(ANA), user: undefined }, false, app.browser);

// A regular anonymous session, as the anonymous store keeps it.
function anonymousSession(): AnonymousStateData {
  const at = now();

  return {
    sub: ANON_SUB,
    sessionToken: '<session_token>',
    metadata: { campaign: 'summer' },
    createdAt: at,
    tokenSets: [
      { audience: 'https://api.zepto.example', accessToken: 'at_anon', scope: 'cart:read', expiresAt: at + 3600 },
    ],
  };
}

const seedAnonymous = (app: App) => app.anonymousStore.set(ANONYMOUS_ID, anonymousSession(), false, app.browser);

const stateOf = (app: App) => app.stateStore.get(STATE_ID, app.browser);

// The deadline T of a guest, from the store, and of a signed-in agent, from the state store.
const guestDeadline = async (app: App) => (await app.guestStore.get(GUEST_ID, app.browser))!.expiresAt;
const sessionDeadline = async (app: App) => (await stateOf(app))!.sessionExpiresAt!;

// The raw cookies of one store, by name. A read that leaves a store alone leaves equal lists. An empty name gives every
// cookie of the browser.
const cookiesOf = (app: App, name: string): Array<[string, string]> =>
  [...app.browser]
    .filter(([cookie]) => cookie.startsWith(name))
    .map(([cookie, { value }]): [string, string] => [cookie, value])
    .sort(([a], [b]) => a.localeCompare(b));

const agentContext = (state: 'signed_out' | 'signed_in') => ({
  kind: 'agent',
  state,
  sessionId: SESSION_ID,
  userId: USER_ID,
  agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
  key: SESSION_KEY,
});

const GUEST_VISITOR = { kind: 'guest', poppy: agentContext('signed_out') };

const visitorOf = (app: App) => app.client.poppy.getVisitor(app.browser);

// Fails the test when the visitor is another kind. When it is the kind that was asked for, it gives the visitor that
// kind as its type, so the test can read the members of that kind.
function expectKind<K extends PoppyVisitor['kind']>(
  visitor: PoppyVisitor,
  kind: K
): Extract<PoppyVisitor, { kind: K }> {
  expect(visitor.kind).toBe(kind);

  return visitor as Extract<PoppyVisitor, { kind: K }>;
}

// A guest store of the app's own, which answers `get` with `record`.
function customGuestStore(record?: unknown) {
  return {
    get: vi.fn(async () => record as PoppyGuestData | undefined),
    set: vi.fn(async () => {}),
    delete: vi.fn(async () => {}),
  };
}

// A guest as the SDK writes it, with a deadline an hour away.
function guestRecord(overrides: Partial<PoppyGuestData> = {}): PoppyGuestData {
  const at = now();

  return {
    sub: GUEST_SUB,
    poppy: { sessionId: SESSION_ID, userId: USER_ID, agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } },
    tokenSets: [{ audience: 'default', accessToken: 'at_custom', scope: 'openid profile', expiresAt: at + 600 }],
    createdAt: at,
    expiresAt: at + 3600,
    ...overrides,
  };
}

// Spies that call through, on the three stores that the website can read.
const spiesOn = (app: App) => ({
  guest: vi.spyOn(app.guestStore, 'get'),
  state: vi.spyOn(app.stateStore, 'get'),
  anonymous: vi.spyOn(app.anonymousStore, 'get'),
});

// How often each store was read: the guest store, the state store and the anonymous store.
const readsOf = (spies: ReturnType<typeof spiesOn>) =>
  [spies.guest, spies.state, spies.anonymous].map((spy) => spy.mock.calls.length);

describe('poppy.getVisitor | who is behind the request', () => {
  test.each([
    { name: 'with an anonymous store', anonymous: true },
    { name: 'without an anonymous store', anonymous: false },
  ])('1: a browser with no cookies is none, $name', async ({ anonymous }) => {
    const app = createApp({ anonymous });

    expect(await visitorOf(app)).toStrictEqual(NONE);
  });

  test.each([
    { name: 'a login with no act claim', act: null },
    { name: 'a login whose act holds no Poppy Session', act: { sub: 'support@zepto.example' } },
  ])('2: $name is a user, and the visitor has no poppy key at all', async ({ act }) => {
    const app = createApp();
    await login(app, { sub: ANA, act });

    const visitor = await visitorOf(app);

    // `poppy: undefined` would be a key too, so the keys are listed.
    expect(Object.keys(visitor)).toEqual(['kind', 'user']);
    expect(expectKind(visitor, 'user').user.sub).toBe(ANA);
    expect(expectKind(visitor, 'user').user).toStrictEqual(await app.client.getUser(app.browser));
  });

  test("2: a session that the app's own code wrote is a user too", async () => {
    const app = createApp();
    await seedOwnLogin(app);

    const visitor = await visitorOf(app);

    expect(Object.keys(visitor)).toEqual(['kind', 'user']);
    expect(expectKind(visitor, 'user').user).toMatchObject({ sub: ANA, name: 'Own Login' });
  });

  test('3: a regular anonymous session is anonymous, with what anonymous.getSession gives', async () => {
    const app = createApp({ anonymous: true });
    await seedAnonymous(app);

    const visitor = await visitorOf(app);

    expect(visitor).toStrictEqual({ kind: 'anonymous', anonymous: await app.client.anonymous.getSession(app.browser) });
    const { anonymous } = expectKind(visitor, 'anonymous');
    expect(anonymous.sub).toBe(ANON_SUB);
    expect(anonymous.tokenSets).toHaveLength(1);
    // The session token stays inside the SDK.
    expect(anonymous).not.toHaveProperty('sessionToken');
  });

  test('4: a guest join is a guest with the signed_out context and the key of the Session', async () => {
    const app = createApp();
    await joinAsGuest(app);

    const visitor = await visitorOf(app);

    expect(visitor).toStrictEqual(GUEST_VISITOR);
    const { poppy } = expectKind(visitor, 'guest');
    expect(poppy.state).toBe('signed_out');
    expect(poppy.key).toBe(SESSION_KEY);
    // A guest is never a user.
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
  });

  test('5: a signed-in join is a user whose act holds the Session, with the signed_in context', async () => {
    const app = createApp();
    await joinSignedIn(app);

    const { user, poppy } = expectKind(await visitorOf(app), 'user');

    expect(user.sub).toBe(ANA);
    expect(user.act?.poppy_sid).toBe(SESSION_ID);
    expect(poppy).toStrictEqual(agentContext('signed_in'));
    expect(poppy?.state).toBe('signed_in');
    expect(poppy?.key).toBe(SESSION_KEY);
    expect(user).toStrictEqual(await app.client.getUser(app.browser));
  });

  // The agent of the Session has no id inside its Personal Agent. `toStrictEqual` fails on a member that is there with
  // the value `undefined`.
  test.each(['guest', 'user'] as const)('an agent with no poppy_agent_id: %s', async (kind) => {
    const app = createApp();
    const act = agentAct({ poppy_agent_id: undefined });
    await (kind === 'guest' ? joinAsGuest(app, SESSION_ID, act) : joinSignedIn(app, ANA, SESSION_ID, act));

    const { poppy } = expectKind(await visitorOf(app), kind);

    expect(poppy).toStrictEqual({
      ...agentContext(kind === 'guest' ? 'signed_out' : 'signed_in'),
      agent: { cimdUrl: CIMD_URL },
    });
  });

  test('a session that has no user is skipped: none', async () => {
    const app = createApp();
    await seedSessionWithoutUser(app);
    // The session is there, and it has no user.
    expect(await app.client.getSession(app.browser)).toBeDefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();

    expect(await visitorOf(app)).toStrictEqual(NONE);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
  });

  test('a session that has no user is skipped: with a regular anonymous session, anonymous', async () => {
    const app = createApp({ anonymous: true });
    await seedSessionWithoutUser(app);
    await seedAnonymous(app);

    expect(expectKind(await visitorOf(app), 'anonymous').anonymous.sub).toBe(ANON_SUB);
  });
});

describe('poppy.getVisitor | the order: a guest, then a user, then an anonymous session', () => {
  test('6: a guest next to the own login of a person is the guest, and getUser is still ana', async () => {
    const app = createApp({ anonymous: true });
    await seedOwnLogin(app);
    await joinAsGuest(app);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
    expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
  });

  // A guest join ends an agent session of the browser, so the SDK never leaves a guest next to one. The guest is written
  // straight into its store here, to show which of the two is read first. The own login has no agent in it, so only a
  // session that holds an agent shows that.
  test('6: an agent session, then a guest of another Session, is the guest', async () => {
    const app = createApp({ anonymous: true });
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    await app.guestStore.set(GUEST_ID, guestRecord(), false, app.browser);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(OTHER_SESSION_ID);
  });

  test('6: a guest join over an agent session of another Session is the guest, and there is no user', async () => {
    const app = createApp({ anonymous: true });
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    await joinAsGuest(app, SESSION_ID);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
  });

  test('6: a guest next to a regular anonymous session is the guest', async () => {
    const app = createApp({ anonymous: true });
    await seedAnonymous(app);
    await joinAsGuest(app);
    // The join leaves the anonymous session alone, so both are there.
    const anonymous = await app.client.anonymous.getSession(app.browser);
    expect(anonymous?.sub).toBe(ANON_SUB);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
    expect(await app.client.anonymous.getSession(app.browser)).toStrictEqual(anonymous);
  });

  test('6: a user next to a regular anonymous session is the user', async () => {
    const app = createApp({ anonymous: true });
    // A login clears the anonymous session, so the anonymous session is made after the login.
    await seedOwnLogin(app);
    await seedAnonymous(app);
    expect((await app.client.anonymous.getSession(app.browser))?.sub).toBe(ANON_SUB);

    const visitor = await visitorOf(app);

    expect(Object.keys(visitor)).toEqual(['kind', 'user']);
    expect(expectKind(visitor, 'user').user.sub).toBe(ANA);
  });

  test('6: a signed-in agent next to a regular anonymous session is the user, with the agent', async () => {
    const app = createApp({ anonymous: true });
    await joinSignedIn(app);
    await seedAnonymous(app);

    const { user, poppy } = expectKind(await visitorOf(app), 'user');

    expect(user.act?.poppy_sid).toBe(SESSION_ID);
    expect(poppy).toStrictEqual(agentContext('signed_in'));
  });

  test('6: a guest, a user and a regular anonymous session together are the guest', async () => {
    const app = createApp({ anonymous: true });
    await seedOwnLogin(app);
    await seedAnonymous(app);
    await joinAsGuest(app);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
  });
});

describe('poppy.getVisitor | a website with no anonymous store', () => {
  test('7: there is no anonymous branch and nothing throws', async () => {
    const app = createApp({ anonymous: false });
    // The getter throws, so the method must not call it to find out.
    expect(() => app.client.anonymous).toThrowError(InvalidConfigurationError);

    expect(await visitorOf(app)).toStrictEqual(NONE);
  });

  test('7: a cookie of an anonymous session that the website cannot read is not a visitor', async () => {
    const app = createApp({ anonymous: false });
    await seedAnonymous(app);
    expect(cookiesOf(app, ANONYMOUS_ID)).not.toEqual([]);

    expect(await visitorOf(app)).toStrictEqual(NONE);
  });

  test('7: a user is a user', async () => {
    const app = createApp({ anonymous: false });
    await seedOwnLogin(app);

    expect(expectKind(await visitorOf(app), 'user').user.sub).toBe(ANA);
  });

  test('7: a signed-in agent is a user with the agent', async () => {
    const app = createApp({ anonymous: false });
    await joinSignedIn(app);

    expect(expectKind(await visitorOf(app), 'user').poppy).toStrictEqual(agentContext('signed_in'));
  });

  test('7: a guest is a guest', async () => {
    const app = createApp({ anonymous: false });
    await joinAsGuest(app);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
  });

  test('7: a guest next to a user is the guest', async () => {
    const app = createApp({ anonymous: false });
    await seedOwnLogin(app);
    await joinAsGuest(app);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);
  });
});

describe('poppy.getVisitor | a guest and a signed-in agent end 30 seconds before their deadline', () => {
  describe.each([
    { before: 31, gone: false },
    { before: 30, gone: true },
    { before: 29, gone: true },
  ])('8: at the deadline minus $before seconds, the Session is gone: $gone', ({ before, gone }) => {
    test('a guest', async () => {
      const app = createApp();
      await joinAsGuest(app);
      const guestCookies = cookiesOf(app, GUEST_ID);
      expect(guestCookies).not.toEqual([]);
      setClock((await guestDeadline(app)) - before);

      expect(await visitorOf(app)).toStrictEqual(gone ? NONE : GUEST_VISITOR);
      // A guest that is gone has its cookies deleted. A guest that is not gone is left as it was.
      expect(cookiesOf(app, GUEST_ID)).toEqual(gone ? [] : guestCookies);
    });

    test('a signed-in agent', async () => {
      const app = createApp();
      await joinSignedIn(app);
      const sessionCookies = cookiesOf(app, STATE_ID);
      expect(sessionCookies).not.toEqual([]);
      setClock((await sessionDeadline(app)) - before);

      const visitor = await visitorOf(app);

      expect(visitor.kind).toBe(gone ? 'none' : 'user');
      // A session that is gone has its cookies deleted. A session that is not gone is left as it was.
      expect(cookiesOf(app, STATE_ID)).toEqual(gone ? [] : sessionCookies);
      expect(Boolean(await app.client.getSession(app.browser))).toBe(!gone);
    });
  });

  test('8: with a regular anonymous session, a guest that has ended falls through to anonymous', async () => {
    const app = createApp({ anonymous: true });
    await joinAsGuest(app);
    await seedAnonymous(app);
    const anonymousCookies = cookiesOf(app, ANONYMOUS_ID);
    setClock((await guestDeadline(app)) - 29);

    expect(expectKind(await visitorOf(app), 'anonymous').anonymous.sub).toBe(ANON_SUB);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymousCookies);
  });

  test('8: with a regular anonymous session, a signed-in agent that has ended falls through to anonymous', async () => {
    const app = createApp({ anonymous: true });
    await joinSignedIn(app);
    await seedAnonymous(app);
    const anonymousCookies = cookiesOf(app, ANONYMOUS_ID);
    setClock((await sessionDeadline(app)) - 29);

    expect(expectKind(await visitorOf(app), 'anonymous').anonymous.sub).toBe(ANON_SUB);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymousCookies);
  });

  // The guest is read as absent, so the next step is the user session, and the person comes back.
  test('8: a guest that has ended gives the own login of the person back', async () => {
    const app = createApp({ anonymous: true });
    await seedOwnLogin(app);
    await seedAnonymous(app);
    await joinAsGuest(app);
    setClock((await guestDeadline(app)) - 29);

    const visitor = await visitorOf(app);

    expect(Object.keys(visitor)).toEqual(['kind', 'user']);
    expect(expectKind(visitor, 'user').user.sub).toBe(ANA);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
  });

  // The SDK never leaves a guest next to an agent session, so the guest is written straight into its store.
  test('8: a guest that has ended gives a signed-in agent of another Session back', async () => {
    const app = createApp();
    // The Session of the signed-in agent ends in about two hours, and the Session of the guest ends in one.
    const act = agentAct({ poppy_sid: OTHER_SESSION_ID, poppy_session_exp: now() + 7000 });
    await joinSignedIn(app, ANA, OTHER_SESSION_ID, act);
    await app.guestStore.set(GUEST_ID, guestRecord(), false, app.browser);
    setClock((await guestDeadline(app)) - 29);

    const { poppy } = expectKind(await visitorOf(app), 'user');

    expect(poppy?.state).toBe('signed_in');
    expect(poppy?.sessionId).toBe(OTHER_SESSION_ID);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
  });
});

describe.each([
  { seconds: 10, storeThrows: false },
  { seconds: 16, storeThrows: true },
])(
  'poppy.getVisitor | 9: the guest cookies are copied and put back $seconds seconds after the deadline',
  ({ seconds, storeThrows }) => {
    // A browser drops a cookie at its Max-Age, but a client can send a copy of it later. Ten seconds after the deadline
    // the encrypted value still opens, because decryption allows 15 seconds of difference between clocks: the guest
    // store gives the guest back. Sixteen seconds after, the store throws `JWTExpired`. Neither may reach the app.
    async function replay(options: AppOptions = {}) {
      const app = createApp(options);
      await joinAsGuest(app);
      if (options.anonymous) {
        await seedAnonymous(app);
      }
      const deadline = await guestDeadline(app);
      const copies = [...app.browser].filter(([name]) => name.startsWith(GUEST_ID));
      expect(copies).not.toEqual([]);

      // The browser has dropped the cookies. The copies come back later.
      copies.forEach(([name]) => app.browser.delete(name));
      expect(cookiesOf(app, GUEST_ID)).toEqual([]);
      setClock(deadline + seconds);
      copies.forEach(([name, cookie]) => app.browser.set(name, cookie));
      expect(cookiesOf(app, GUEST_ID)).not.toEqual([]);

      // This is the state that the test is about: the store itself does not refuse the copy at 10 seconds.
      if (storeThrows) {
        await expect(app.guestStore.get(GUEST_ID, app.browser)).rejects.toBeInstanceOf(errors.JWTExpired);
      } else {
        await expect(app.guestStore.get(GUEST_ID, app.browser)).resolves.toMatchObject({ expiresAt: deadline });
      }

      return app;
    }

    test('getVisitor gives none, deletes the cookies and does not throw', async () => {
      const app = await replay();

      expect(await visitorOf(app)).toStrictEqual(NONE);
      expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    });

    test('with a regular anonymous session, getVisitor gives anonymous', async () => {
      const app = await replay({ anonymous: true });

      expect(expectKind(await visitorOf(app), 'anonymous').anonymous.sub).toBe(ANON_SUB);
      expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    });
  }
);

// The visitor sets the guest cookie, and so can another site on the same domain. A value that cannot be opened is no
// guest. It must never be an error for the app, and it must not hide the rest of the visitor.
describe('poppy.getVisitor | a forged guest cookie', () => {
  describe.each(FORGED_GUEST_COOKIES)('$name', ({ value }) => {
    const forge = (app: App) => app.browser.set(`${GUEST_ID}.0`, { value });

    test('is no guest: none, and nothing throws', async () => {
      const app = createApp({ anonymous: true });
      forge(app);

      expect(await visitorOf(app)).toStrictEqual(NONE);
    });

    test('a person with a session of their own is still that person', async () => {
      const app = createApp({ anonymous: true });
      await seedOwnLogin(app);
      forge(app);

      expect(expectKind(await visitorOf(app), 'user').user.sub).toBe(ANA);
    });
  });
});

// A client can send any cookie under any name. The guest and the user session are encrypted with the name of their
// store as the salt, so the value of one does not open in the other. This is checked from the outside: the cookie of a
// guest, sent under the name of the user session, is no session and no user.
describe('getSession | a guest cookie that is copied to the name of the user session', () => {
  async function appWithCopiedGuest() {
    const app = createApp();
    await joinAsGuest(app);

    const guestCookies = [...app.browser].filter(([name]) => name.startsWith(`${GUEST_ID}.`));
    expect(guestCookies).not.toEqual([]);
    guestCookies.forEach(([name, cookie]) => app.browser.set(name.replace(GUEST_ID, STATE_ID), cookie));

    return app;
  }

  test('gives no session and no user', async () => {
    const app = await appWithCopiedGuest();

    // The copy is there, and it is a good guest cookie: the guest store opens the same value. So the name of the store
    // is the only thing that keeps it from opening as a session.
    const valuesOf = (name: string) => cookiesOf(app, name).map(([, value]) => value);
    expect(valuesOf(STATE_ID)).not.toEqual([]);
    expect(valuesOf(STATE_ID)).toEqual(valuesOf(GUEST_ID));
    await expect(app.guestStore.get(GUEST_ID, app.browser)).resolves.toMatchObject({ sub: GUEST_SUB });

    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect(await stateOf(app)).toBeUndefined();
  });
});

describe('poppy.getVisitor | a session that the usual path stored', () => {
  // The usual path stores the `act` as the token has it, so a session from before the `poppy` option can hold one that
  // is not a Poppy Session. Reading it must not throw: it is a plain user, as `getContext()` reads it.
  describe.each([
    { name: 'a poppy_sid that is a number', act: { sub: CIMD_URL, poppy_sid: 42 } },
    { name: 'a poppy_sid that is a list', act: agentAct({ poppy_sid: [SESSION_ID] }) },
    { name: 'no act.sub', act: agentAct({ sub: undefined }) },
    { name: 'no poppy_user_id', act: agentAct({ poppy_user_id: undefined }) },
  ])('with $name', ({ act }) => {
    test('is a plain user, and the session stays', async () => {
      // An app without the `poppy` option stores the `act` as the token has it.
      const legacy = createApp({ poppy: false });
      await login(legacy, { sub: ANA, act });
      expect((await legacy.client.getUser(legacy.browser))?.act).toStrictEqual(JSON.parse(JSON.stringify(act)));

      // The same browser, now with the option.
      const app = createApp({ browser: legacy.browser });

      const visitor = await visitorOf(app);

      expect(Object.keys(visitor)).toEqual(['kind', 'user']);
      expect(expectKind(visitor, 'user').user.sub).toBe(ANA);
      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    });
  });
});

describe('poppy.getVisitor | the agent of a returned poppy', () => {
  // The context is built from the record again on every read, as in `getContext()`. A change by the app must not reach
  // the store, and a record from a custom store must not add members to what the app sees.
  test('is a new object, so a change by the app does not reach the guest store', async () => {
    const record = guestRecord();
    const app = createApp({ guestStore: customGuestStore(record) });

    const first = expectKind(await visitorOf(app), 'guest');
    first.poppy.agent.cimdUrl = 'https://changed.example/agent.json';
    delete first.poppy.agent.poppyAgentId;

    expect(record.poppy.agent).toStrictEqual({ cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID });
    expect(expectKind(await visitorOf(app), 'guest').poppy).toStrictEqual(agentContext('signed_out'));
  });

  test('has the cimdUrl and a poppyAgentId that is a string, and no other member of the record', async () => {
    const agent = { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID, extra: 'x' };
    const app = createApp({ guestStore: customGuestStore(guestRecord({ poppy: { ...guestRecord().poppy, agent } })) });

    expect(expectKind(await visitorOf(app), 'guest').poppy.agent).toStrictEqual({
      cimdUrl: CIMD_URL,
      poppyAgentId: AGENT_ID,
    });
  });
});

describe('poppy.getVisitor | each store is read at most once', () => {
  // Every situation a website meets, with what one call reads in it. `reads` lists how often the guest store, the state
  // store and the anonymous store are read. The order decides it: nothing is read after a guest, and the anonymous
  // store is read only when there is no guest and no user. `context` is what `getContext()` says about the situation.
  const situations: Array<{
    name: string;
    kind: PoppyVisitor['kind'];
    context: Record<string, unknown>;
    reads: [guest: number, state: number, anonymous: number];
    setup: (app: App) => Promise<unknown>;
  }> = [
    { name: 'nobody', kind: 'none', context: HUMAN, reads: [1, 1, 1], setup: async () => {} },
    { name: 'a regular anonymous session', kind: 'anonymous', context: HUMAN, reads: [1, 1, 1], setup: seedAnonymous },
    { name: "a person's own login", kind: 'user', context: HUMAN, reads: [1, 1, 0], setup: (app) => seedOwnLogin(app) },
    {
      name: 'a signed-in agent',
      kind: 'user',
      context: agentContext('signed_in'),
      reads: [1, 1, 0],
      setup: (app) => joinSignedIn(app),
    },
    {
      name: 'a guest',
      kind: 'guest',
      context: agentContext('signed_out'),
      reads: [1, 0, 0],
      setup: (app) => joinAsGuest(app),
    },
  ];

  describe.each(situations)('10: $name', ({ kind, context, reads, setup }) => {
    async function appInSituation() {
      const app = createApp({ anonymous: true });
      await setup(app);

      return app;
    }

    test('one call of getVisitor reads each store once, or not at all when the order stops before it', async () => {
      const app = await appInSituation();
      const spies = spiesOn(app);

      const visitor = await visitorOf(app);

      expect(visitor.kind).toBe(kind);
      expect(readsOf(spies)).toEqual(reads);
    });

    test('getContext after it still says what it said before', async () => {
      const app = await appInSituation();

      await visitorOf(app);

      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(context);
    });

    test('getContext reads the guest store and the state store as often, and never the anonymous store', async () => {
      const app = await appInSituation();
      const spies = spiesOn(app);

      await app.client.poppy.getContext(app.browser);

      const [guest, state] = reads;
      expect(readsOf(spies)).toEqual([guest, state, 0]);
    });

    test('a read changes no cookie and sends no request to Auth0', async () => {
      const app = await appInSituation();
      const cookies = cookiesOf(app, '');
      requests.length = 0;

      await visitorOf(app);

      expect(cookiesOf(app, '')).toEqual(cookies);
      expect(requests).toEqual([]);
    });
  });

  test('a custom guest store is read once, with the options of the call, and nothing else is read', async () => {
    const store = customGuestStore(guestRecord());
    const app = createApp({ anonymous: true, guestStore: store });
    const { state, anonymous } = spiesOn(app);

    expect(await visitorOf(app)).toStrictEqual(GUEST_VISITOR);

    expect(store.get).toHaveBeenCalledTimes(1);
    expect(store.get).toHaveBeenCalledWith(GUEST_ID, app.browser);
    expect(store.delete).not.toHaveBeenCalled();
    expect(state).not.toHaveBeenCalled();
    expect(anonymous).not.toHaveBeenCalled();
  });
});

describe('poppy.getVisitor | a store that fails', () => {
  // A store that is down must not turn a visitor into another kind of visitor, so the error reaches the app and the
  // stores after it are not read.
  test('a guest store that is down: the error reaches the app, nothing else is read, nothing is deleted', async () => {
    const store = customGuestStore();
    store.get.mockRejectedValue(new Error('guest store is down'));
    const app = createApp({ anonymous: true, guestStore: store });
    await seedOwnLogin(app);
    await seedAnonymous(app);
    const { state, anonymous } = spiesOn(app);

    await expect(visitorOf(app)).rejects.toThrow('guest store is down');

    expect(store.delete).not.toHaveBeenCalled();
    expect(state).not.toHaveBeenCalled();
    expect(anonymous).not.toHaveBeenCalled();
  });

  // A guest that has ended is deleted when it is read, and it is already read as absent. A store that fails to delete
  // it must not turn the read into an error, and the next step is made.
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

    test.each(endedGuests)('gives none for $name, and the delete is tried', async (ended) => {
      const store = storeFor(ended);
      const app = createApp({ guestStore: store });

      expect(await visitorOf(app)).toStrictEqual(NONE);
      expect(store.delete).toHaveBeenCalledTimes(1);
      expect(store.delete).toHaveBeenCalledWith(GUEST_ID, app.browser);
    });

    test.each(endedGuests)('gives the person, and then the regular anonymous session, after $name', async (ended) => {
      const userApp = createApp({ anonymous: true, guestStore: storeFor(ended) });
      await seedOwnLogin(userApp);
      const anonymousApp = createApp({ anonymous: true, guestStore: storeFor(ended) });
      await seedAnonymous(anonymousApp);

      expect(expectKind(await visitorOf(userApp), 'user').user.sub).toBe(ANA);
      expect(expectKind(await visitorOf(anonymousApp), 'anonymous').anonymous.sub).toBe(ANON_SUB);
    });
  });

  test('a state store that is down: the error reaches the app, and the anonymous store is not read', async () => {
    const app = createApp({ anonymous: true });
    await seedAnonymous(app);
    const { state, anonymous } = spiesOn(app);
    state.mockRejectedValue(new Error('state store is down'));

    await expect(visitorOf(app)).rejects.toThrow('state store is down');

    expect(anonymous).not.toHaveBeenCalled();
  });

  test('an anonymous store that is down: the error reaches the app', async () => {
    const app = createApp({ anonymous: true });
    spiesOn(app).anonymous.mockRejectedValue(new Error('anonymous store is down'));

    await expect(visitorOf(app)).rejects.toThrow('anonymous store is down');
  });

  test('an anonymous store that is down is not read when a guest or a user is found first', async () => {
    const guestApp = createApp({ anonymous: true });
    await joinAsGuest(guestApp);
    const userApp = createApp({ anonymous: true });
    await seedOwnLogin(userApp);
    spiesOn(guestApp).anonymous.mockRejectedValue(new Error('anonymous store is down'));
    spiesOn(userApp).anonymous.mockRejectedValue(new Error('anonymous store is down'));

    expect(await visitorOf(guestApp)).toStrictEqual(GUEST_VISITOR);
    expect(expectKind(await visitorOf(userApp), 'user').user.sub).toBe(ANA);
  });
});

describe('PoppyVisitor | the type', () => {
  // An app that handles every kind of visitor. It compiles only while all four kinds are here: when a later version adds
  // a kind, `visitor` in the default branch is no longer `never`, and the build of an app like this one stops.
  function describeVisitor(visitor: PoppyVisitor): string {
    switch (visitor.kind) {
      case 'none':
        return 'nobody';
      case 'anonymous':
        return `anonymous ${visitor.anonymous.sub}`;
      case 'user':
        return visitor.poppy ? `agent ${visitor.poppy.key} for ${visitor.user.sub}` : `user ${visitor.user.sub}`;
      case 'guest':
        return `guest ${visitor.poppy.key}`;
      default: {
        const unreachable: never = visitor;

        return unreachable;
      }
    }
  }

  // The same app with no case for a guest. The check of the default branch must fail here, and `@ts-expect-error` makes
  // `npm run typecheck` fail when it does not.
  function describeWithoutGuest(visitor: PoppyVisitor): string {
    switch (visitor.kind) {
      case 'none':
      case 'anonymous':
      case 'user':
        return visitor.kind;
      default: {
        // @ts-expect-error The guest is not handled, so `visitor` is the guest here and not `never`.
        const unreachable: never = visitor;

        return unreachable;
      }
    }
  }

  // Types have no runtime value: `npm run typecheck` checks these.
  test('11: kind is one of four, and each kind has its members', () => {
    expectTypeOf<PoppyVisitor['kind']>().toEqualTypeOf<'none' | 'anonymous' | 'user' | 'guest'>();
    expectTypeOf<Extract<PoppyVisitor, { kind: 'none' }>>().toEqualTypeOf<{ kind: 'none' }>();
    expectTypeOf<Extract<PoppyVisitor, { kind: 'anonymous' }>['anonymous']>().toEqualTypeOf<AnonymousSessionData>();
    expectTypeOf<Extract<PoppyVisitor, { kind: 'user' }>['user']>().toEqualTypeOf<UserClaims>();
    expectTypeOf<Extract<PoppyVisitor, { kind: 'user' }>['poppy']>().toEqualTypeOf<PoppyAgentContext | undefined>();
    expectTypeOf<Extract<PoppyVisitor, { kind: 'guest' }>['poppy']>().toEqualTypeOf<PoppyAgentContext>();
    expectTypeOf<ServerPoppyClient<Browser>['getVisitor']>().toEqualTypeOf<
      (storeOptions?: Browser) => Promise<PoppyVisitor>
    >();
  });

  test('11: a switch on kind with a never check in default handles every kind of visitor', async () => {
    const nobody = createApp({ anonymous: true });
    const anonymous = createApp({ anonymous: true });
    await seedAnonymous(anonymous);
    const user = createApp({ anonymous: true });
    await seedOwnLogin(user);
    const agent = createApp({ anonymous: true });
    await joinSignedIn(agent);
    const guest = createApp({ anonymous: true });
    await joinAsGuest(guest);

    expect(describeVisitor(await visitorOf(nobody))).toBe('nobody');
    expect(describeVisitor(await visitorOf(anonymous))).toBe(`anonymous ${ANON_SUB}`);
    expect(describeVisitor(await visitorOf(user))).toBe(`user ${ANA}`);
    expect(describeVisitor(await visitorOf(agent))).toBe(`agent ${SESSION_KEY} for ${ANA}`);
    expect(describeVisitor(await visitorOf(guest))).toBe(`guest ${SESSION_KEY}`);
    // The version with no case for a guest compiles only with the `@ts-expect-error` above. At run time it is a function
    // like any other.
    expect(describeWithoutGuest({ kind: 'none' })).toBe('none');
  });
});
