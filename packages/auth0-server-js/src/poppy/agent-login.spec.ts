import { TokenByRefreshTokenError, TokenResponse } from '@auth0/auth0-auth-js';
import type { IDTokenClaims } from '@auth0/auth0-auth-js';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { InvalidPoppySessionError, SessionExpiredError } from '../errors.js';
import { TokenByCodeError } from '../index.js';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import { StatefulStateStore } from '../store/stateful-state-store.js';
import { StatelessAnonymousStore } from '../store/stateless-anonymous-store.js';
import { StatelessStateStore } from '../store/stateless-state-store.js';
import {
  AGENT_ID,
  BrowserCookieHandler,
  CIMD_URL,
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
import type { SessionStore, StateData, StateStore } from '../types.js';
import { completeAgentLogin } from './agent-login.js';
import { ANONYMOUS_USER_PROFILE } from './constants.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';
import type { PoppyGuestData, PoppyGuestStore } from './types.js';

// These tests run the whole callback. A fake Auth0 answers the code exchange with a signed ID token, and one Map (the
// browser) holds the cookies of every store, so a test can see what a login leaves behind in each of them.

const SECRET = '<secret>';
const TRANSACTION_ID = '__a0_tx';
const STATE_ID = '__a0_session';
const GUEST_ID = '__a0_poppy';
const ANONYMOUS_ID = '__a0_anon';
const CALLBACK = new URL('https://zepto.example/auth/callback?code=c1');
const ANA = 'auth0|ana';
const BOB = 'auth0|bob';

// The ID token and the authorization details that the token endpoint answers with. A test sets them for each login.
let idToken: string | undefined;
let authorizationDetails: Array<Record<string, unknown>> | undefined;

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
      ...(authorizationDetails !== undefined && { authorization_details: authorizationDetails }),
    })
  )
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

beforeEach(() => {
  idToken = undefined;
  authorizationDetails = undefined;
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

// A website with one browser. `poppy: false` leaves the `poppy` option out.
interface App {
  browser: Browser;
  client: ServerClient<Browser>;
  transactionStore: CookieTransactionStore<Browser>;
  stateStore: StateStore<Browser>;
  guestStore: PoppyGuestStore<Browser>;
  anonymousStore: StatelessAnonymousStore<Browser>;
}

interface AppOptions {
  poppy?: boolean;
  agentSessionMaxAge?: number;
  clearAnonymousSessionOnLogin?: boolean;
  /** The state store. Default: `StatelessStateStore`. */
  stateStore?: (cookies: BrowserCookieHandler) => StateStore<Browser>;
  /** The guest store. Default: `StatelessPoppyGuestStore`. */
  guestStore?: PoppyGuestStore<Browser>;
}

function createApp(options: AppOptions = {}): App {
  const browser: Browser = new Map();
  const cookies = new BrowserCookieHandler();
  const transactionStore = new CookieTransactionStore<Browser>({ secret: SECRET }, cookies);
  const stateStore = options.stateStore?.(cookies) ?? new StatelessStateStore<Browser>({ secret: SECRET }, cookies);
  const guestStore = options.guestStore ?? new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, cookies);
  const anonymousStore = new StatelessAnonymousStore<Browser>({ secret: SECRET }, cookies);

  const client = new ServerClient<Browser>({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 0 },
    transactionStore,
    stateStore,
    anonymousStore,
    clearAnonymousSessionOnLogin: options.clearAnonymousSessionOnLogin,
    poppy:
      options.poppy === false
        ? undefined
        : { config: createPoppyConfig(), guestStore, agentSessionMaxAge: options.agentSessionMaxAge },
  });

  return { browser, client, transactionStore, stateStore, guestStore, anonymousStore };
}

// The browser comes back from Auth0 with a code, and the token endpoint answers with an ID token made from `token`.
async function login(app: App, token: AgentIdTokenOptions = {}, options: { url?: URL; appState?: unknown } = {}) {
  idToken = await agentIdToken(token);
  await app.transactionStore.set(
    TRANSACTION_ID,
    { codeVerifier: 'cv', domain: POPPY_DOMAIN, ...(options.appState !== undefined && { appState: options.appState }) },
    false,
    app.browser
  );

  return app.client.completeInteractiveLogin(options.url ?? CALLBACK, app.browser);
}

type Kind = 'guest' | 'signed-in';
const KINDS: Kind[] = ['guest', 'signed-in'];

// The ID token of a join. A guest has a guest `sub` and the anonymous user profile. `more` replaces any member.
const joinToken = (kind: Kind, more: AgentIdTokenOptions = {}): AgentIdTokenOptions =>
  kind === 'guest' ? { sub: GUEST_SUB, subProfile: ANONYMOUS_USER_PROFILE, ...more } : { sub: ANA, ...more };

const joinAs = (app: App, kind: Kind, more?: AgentIdTokenOptions, options?: { appState?: unknown }) =>
  login(app, joinToken(kind, more), options);

const joinAsGuest = (app: App, sessionId = SESSION_ID) =>
  joinAs(app, 'guest', { act: agentAct({ poppy_sid: sessionId }) });

const joinSignedIn = (app: App, sub = ANA, sessionId = SESSION_ID) =>
  login(app, { sub, act: agentAct({ poppy_sid: sessionId }) });

// A normal login: the ID token has no `act`.
const loginNormally = (app: App, sub = ANA) => login(app, { sub, act: null });

// What a customer's own login leaves in the state store: a refresh token, two token sets and a connection token.
function ownLogin(sub: string): StateData {
  const at = now();

  return {
    user: { sub, iss: POPPY_ISSUER, name: 'Own Login', email: 'old@zepto.example' },
    idToken: 'old.id.token',
    refreshToken: 'rt_old',
    tokenSets: [
      { audience: 'default', accessToken: 'at_old_default', scope: 'openid profile email', expiresAt: at + 600 },
      { audience: 'https://zepto.example/api', accessToken: 'at_old_api', scope: 'orders:read', expiresAt: at + 600 },
    ],
    connectionTokenSets: [
      { connection: 'google-oauth2', accessToken: 'ct_old', scope: undefined, expiresAt: at + 600 },
    ],
    domain: POPPY_DOMAIN,
    internal: { sid: 'old_sid', createdAt: at },
  };
}

const seedOwnLogin = (app: App, sub = ANA) => app.stateStore.set(STATE_ID, ownLogin(sub), false, app.browser);

// A guest of an earlier join, written straight into the guest store, so that a test does not depend on the code that it
// tests to set up its browser.
function seedGuest(app: App, sessionId = OTHER_SESSION_ID) {
  const at = now();

  return app.guestStore.set(
    GUEST_ID,
    {
      sub: GUEST_SUB,
      poppy: { sessionId, userId: USER_ID, agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } },
      tokenSets: [{ audience: 'default', accessToken: 'at_old_guest', scope: 'openid profile', expiresAt: at + 600 }],
      createdAt: at,
      expiresAt: at + 3600,
    },
    false,
    app.browser
  );
}

const seedAnonymousSession = (app: App) =>
  app.anonymousStore.set(
    ANONYMOUS_ID,
    {
      sessionToken: '<anon_session_token>',
      sub: 'anon@2f1c1b7e',
      createdAt: now(),
      tokenSets: [],
      domain: POPPY_DOMAIN,
    },
    false,
    app.browser
  );

const stateOf = (app: App) => app.stateStore.get(STATE_ID, app.browser);

// The guest as the store gives it back. The store adds an `exp` member, the expiry of the encrypted value, and it is
// left out here.
async function guestOf(app: App): Promise<PoppyGuestData | undefined> {
  const guest = await app.guestStore.get(GUEST_ID, app.browser);

  if (guest === undefined) {
    return undefined;
  }

  const record = { ...guest };
  delete record.exp;

  return record;
}

// The raw cookies of one store, by name. Every write encrypts with a new key, so a store that is written again gets new
// values: equal lists mean that the store was not touched.
const cookiesOf = (app: App, name: string): Array<[string, string]> =>
  [...app.browser]
    .filter(([cookie]) => cookie.startsWith(name))
    .map(([cookie, { value }]): [string, string] => [cookie, value])
    .sort(([a], [b]) => a.localeCompare(b));

// Every cookie of the browser except the transaction. Equal snapshots mean that nothing was added, changed or removed.
const snapshot = (app: App): Record<string, string> =>
  Object.fromEntries(
    [...app.browser]
      .filter(([name]) => name !== TRANSACTION_ID)
      .map(([name, { value }]): [string, string] => [name, value])
  );

const maxAgeOf = (app: App, name: string) => app.browser.get(`${name}.0`)?.options?.maxAge;

const agentContext = (state: 'signed_out' | 'signed_in') => ({
  kind: 'agent',
  state,
  sessionId: SESSION_ID,
  userId: USER_ID,
  agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
  key: SESSION_KEY,
});

// A session made from the tokens of the join only. Nothing of an earlier login is kept: not the user, a token set, a
// connection token or a refresh token. The session ends at the deadline.
function expectFreshAgentSession(
  state: StateData | undefined,
  expected: { sub: string; sessionId: string; at: number }
): void {
  const { at } = expected;

  expect(state).toBeDefined();
  expect(state?.user?.sub).toBe(expected.sub);
  expect(state?.user?.act?.poppy_sid).toBe(expected.sessionId);
  expect(state?.user).not.toHaveProperty('email');
  expect(state?.user).not.toHaveProperty('name');
  expect(state?.refreshToken).toBeUndefined();
  expect(state?.tokenSets).toStrictEqual([
    { audience: 'default', accessToken: 'at_join', scope: 'openid profile', expiresAt: at + 3600 },
  ]);
  expect(state).not.toHaveProperty('connectionTokenSets');
  // The Session ends in an hour. That is earlier than the ID token (2 hours) and the longest session (2 hours).
  expect(state?.sessionExpiresAt).toBe(at + 3600);
  expect(state?.domain).toBe(POPPY_DOMAIN);
  expect(state?.internal.createdAt).toBe(at);
}

function expectGuest(guest: PoppyGuestData | undefined, expected: { sessionId: string; at: number }): void {
  const { at } = expected;

  // `toStrictEqual`: a refresh token, an ID token or any member that is not named here would fail it.
  expect(guest).toStrictEqual({
    sub: GUEST_SUB,
    poppy: {
      sessionId: expected.sessionId,
      userId: USER_ID,
      agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
    },
    tokenSets: [{ audience: 'default', accessToken: 'at_join', scope: 'openid profile', expiresAt: at + 3600 }],
    createdAt: at,
    expiresAt: at + 3600,
  });
}

// A browser that holds all three: the customer's own login, a guest of another Session, and an anonymous session.
async function appWithEverything(options?: AppOptions): Promise<App> {
  const app = createApp(options);
  await seedAnonymousSession(app);
  await seedOwnLogin(app);
  await seedGuest(app, OTHER_SESSION_ID);

  // A refusal test would pass for nothing if one of the stores were empty.
  expect(cookiesOf(app, STATE_ID)).not.toEqual([]);
  expect(cookiesOf(app, GUEST_ID)).not.toEqual([]);
  expect(cookiesOf(app, ANONYMOUS_ID)).not.toEqual([]);

  return app;
}

// A login that is refused changes nothing, and the transaction, which the code exchange has spent, is gone.
function expectNothingWritten(app: App, before: Record<string, string>): void {
  expect(snapshot(app)).toEqual(before);
  expect(cookiesOf(app, TRANSACTION_ID)).toEqual([]);
}

describe('completeInteractiveLogin | what an agent join leaves in the stores', () => {
  // U is the user session, G the guest, and A the anonymous session.

  test('1: a guest joins a browser with no login. G is written, there is no U, and A stays', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    const guestSet = vi.spyOn(app.guestStore, 'set');
    const stateStoreWrites = [vi.spyOn(app.stateStore, 'set'), vi.spyOn(app.stateStore, 'delete')];
    const at = now();

    const result = await joinAsGuest(app);

    expect(result.poppy).toStrictEqual(agentContext('signed_out'));
    // The guest is never a user: the state store is not written or cleared. It is read, to look for an agent session.
    stateStoreWrites.forEach((call) => expect(call).not.toHaveBeenCalled());
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(guestSet).toHaveBeenCalledWith(GUEST_ID, expect.any(Object), false, app.browser);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
    expect(cookiesOf(app, TRANSACTION_ID)).toEqual([]);
  });

  test('2: a signed-in agent joins a browser with no login. U is fresh, there is no G, and A is cleared', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    const at = now();

    const result = await joinSignedIn(app);

    expect(result.poppy).toStrictEqual(agentContext('signed_in'));
    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(SESSION_ID);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    expect(cookiesOf(app, TRANSACTION_ID)).toEqual([]);
  });

  test('2: the anonymous session stays with clearAnonymousSessionOnLogin: false', async () => {
    const app = createApp({ clearAnonymousSessionOnLogin: false });
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);

    const result = await joinSignedIn(app);

    expect(result.poppy?.state).toBe('signed_in');
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  test('3: a guest joins a browser with a customer login. U is unchanged, G is written, and A stays', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedOwnLogin(app);
    const own = cookiesOf(app, STATE_ID);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    const at = now();

    const result = await joinAsGuest(app);

    expect(result.poppy).toStrictEqual(agentContext('signed_out'));
    expect(cookiesOf(app, STATE_ID)).toEqual(own);
    expect(await app.client.getSession(app.browser)).toMatchObject({ refreshToken: 'rt_old' });
    expect((await app.client.getSession(app.browser))?.tokenSets).toHaveLength(2);
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  // A rejoin without an access token ends the sign-in of a Session. The guest replaces an agent session of the browser,
  // whatever Session that one belongs to.
  test.each([
    { name: 'of another Session', earlier: OTHER_SESSION_ID },
    { name: 'of the same Session', earlier: SESSION_ID },
  ])('4: a guest joins a browser with an agent session $name, so U is deleted, G is written, and A stays', async ({ earlier }) => {
    const app = createApp();
    await joinSignedIn(app, ANA, earlier);
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    // The premise: the agent is signed in before the guest joins.
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(earlier);
    later(60);
    const at = now();

    const result = await joinAsGuest(app, SESSION_ID);

    expect(result.poppy).toStrictEqual(agentContext('signed_out'));
    // The agent is not signed in any more, for any reader of the session.
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    await expect(app.client.getAccessToken({}, app.browser)).rejects.toBeInstanceOf(TokenByRefreshTokenError);
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  test('5: a guest joins a browser with a guest of another Session. G is replaced, and A stays', async () => {
    const app = createApp();
    await seedGuest(app, OTHER_SESSION_ID);
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    later(60);
    const at = now();

    const result = await joinAsGuest(app, SESSION_ID);

    expect(result.poppy).toStrictEqual(agentContext('signed_out'));
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  test('6: a signed-in agent joins a browser with a guest. U is fresh, G is deleted, and A is cleared', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedGuest(app, SESSION_ID);
    later(60);
    const at = now();

    const result = await joinSignedIn(app);

    expect(result.poppy).toStrictEqual(agentContext('signed_in'));
    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('7: a signed-in agent joins over a login of the same user. U is fresh, with nothing old', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedOwnLogin(app, ANA);
    later(600);
    const at = now();
    const stateSet = vi.spyOn(app.stateStore, 'set');

    await joinSignedIn(app, ANA);

    // No `rt_old`, no old token sets, no old user claims, and a new `internal.createdAt`.
    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    // The session id of a stateful store is renewed only when the store is told that this is a new login.
    expect(stateSet).toHaveBeenCalledTimes(1);
    expect(stateSet).toHaveBeenCalledWith(
      STATE_ID,
      expect.objectContaining({ sessionExpiresAt: at + 3600 }),
      true,
      app.browser
    );
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('8: a signed-in agent joins over an agent session of the same user. U is fresh, with the new one', async () => {
    const app = createApp();
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    await seedAnonymousSession(app);
    later(600);
    const at = now();

    await joinSignedIn(app, ANA, SESSION_ID);

    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(SESSION_ID);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('9: a signed-in agent joins over a login of another user. U is fresh for the new user', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedOwnLogin(app, BOB);
    later(600);
    const at = now();

    await joinSignedIn(app, ANA);

    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('10: a normal login by the same user replaces an agent session. U is fresh, with no act', async () => {
    const app = createApp();
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    await seedAnonymousSession(app);
    later(600);
    const at = now();

    const result = await loginNormally(app, ANA);

    expect(result).not.toHaveProperty('poppy');
    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.user).not.toHaveProperty('act');
    // The refresh token of this login is kept, as it is for any login, and there is no ceiling.
    expect(state?.refreshToken).toBe('rt_join');
    expect(state?.sessionExpiresAt).toBeUndefined();
    expect(state?.tokenSets).toStrictEqual([
      { audience: 'default', accessToken: 'at_join', scope: 'openid profile', expiresAt: at + 3600 },
    ]);
    expect(state?.internal.createdAt).toBe(at);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('11: a normal login in a browser with a guest takes the usual path. G stays, and A is cleared', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedGuest(app, SESSION_ID);
    const guest = cookiesOf(app, GUEST_ID);
    later(60);
    const at = now();

    const result = await loginNormally(app, ANA);

    expect(result).not.toHaveProperty('poppy');
    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.refreshToken).toBe('rt_join');
    expect(state?.sessionExpiresAt).toBeUndefined();
    expect(state?.internal.createdAt).toBe(at);
    expect(cookiesOf(app, GUEST_ID)).toEqual(guest);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });
});

describe('completeInteractiveLogin | when a store fails', () => {
  test('a failed write of the session leaves no guest behind, and no session', async () => {
    const app = createApp();
    await seedGuest(app, SESSION_ID);
    vi.spyOn(app.stateStore, 'set').mockRejectedValueOnce(new Error('state store is down'));

    await expect(joinSignedIn(app)).rejects.toThrow('state store is down');

    // The guest is dropped before the session is written. The visitor has neither, and can join again.
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });

  test('a failing anonymous store does not fail a signed-in join', async () => {
    const app = createApp();
    const anonymousDelete = vi
      .spyOn(app.anonymousStore, 'delete')
      .mockRejectedValue(new Error('anonymous store is down'));

    const result = await joinSignedIn(app);

    expect(anonymousDelete).toHaveBeenCalledWith(ANONYMOUS_ID, app.browser);
    expect(result.poppy?.state).toBe('signed_in');
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(SESSION_ID);
  });
});

describe('completeInteractiveLogin | a guest join over a session of the browser', () => {
  test('keeps the own login of a person, even when its act is not a Poppy Session', async () => {
    const app = createApp();
    // The member that marks a Poppy Session is `poppy_sid`. An `act` without it is the customer's own.
    await app.stateStore.set(
      STATE_ID,
      { ...ownLogin(ANA), user: { sub: ANA, iss: POPPY_ISSUER, act: { sub: CIMD_URL } } },
      false,
      app.browser
    );
    const own = cookiesOf(app, STATE_ID);
    const stateDelete = vi.spyOn(app.stateStore, 'delete');

    await joinAsGuest(app);

    expect(stateDelete).not.toHaveBeenCalled();
    expect(cookiesOf(app, STATE_ID)).toEqual(own);
    expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    expect((await guestOf(app))?.poppy.sessionId).toBe(SESSION_ID);
  });

  describe('when a store fails', () => {
    // An agent session of the browser, so that the guest join has a session to end.
    async function appWithAgentSession(): Promise<App> {
      const app = createApp();
      await joinSignedIn(app, ANA, OTHER_SESSION_ID);

      return app;
    }

    test('a failing delete of the agent session reaches the app, and no guest is written', async () => {
      const app = await appWithAgentSession();
      const agentSession = cookiesOf(app, STATE_ID);
      const guestSet = vi.spyOn(app.guestStore, 'set');
      vi.spyOn(app.stateStore, 'delete').mockRejectedValueOnce(new Error('state store is down'));

      await expect(joinAsGuest(app, SESSION_ID)).rejects.toThrow('state store is down');

      // Nothing is half done: the agent session is as it was, and there is no guest next to it.
      expect(guestSet).not.toHaveBeenCalled();
      expect(cookiesOf(app, GUEST_ID)).toEqual([]);
      expect(cookiesOf(app, STATE_ID)).toEqual(agentSession);
    });

    test('a failing read of the state store reaches the app, and no guest is written', async () => {
      const app = await appWithAgentSession();
      const agentSession = cookiesOf(app, STATE_ID);
      const guestSet = vi.spyOn(app.guestStore, 'set');
      const stateDelete = vi.spyOn(app.stateStore, 'delete');
      vi.spyOn(app.stateStore, 'get').mockRejectedValueOnce(new Error('state store is down'));

      // A store that fails is never read as empty: that would leave the agent signed in.
      await expect(joinAsGuest(app, SESSION_ID)).rejects.toThrow('state store is down');

      expect(guestSet).not.toHaveBeenCalled();
      expect(stateDelete).not.toHaveBeenCalled();
      expect(cookiesOf(app, GUEST_ID)).toEqual([]);
      expect(cookiesOf(app, STATE_ID)).toEqual(agentSession);
    });

    test('a failing write of the guest leaves the visitor with neither', async () => {
      const app = await appWithAgentSession();
      vi.spyOn(app.guestStore, 'set').mockRejectedValueOnce(new Error('guest store is down'));

      await expect(joinAsGuest(app, SESSION_ID)).rejects.toThrow('guest store is down');

      // The agent session goes first, as the guest goes first in a signed-in join. The visitor can join again.
      expect(cookiesOf(app, STATE_ID)).toEqual([]);
      expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    });
  });

  // The agent session is ended only once the join is accepted.
  describe('that is refused', () => {
    const refusals = [
      {
        name: 'the Session has ended',
        act: () => agentAct({ poppy_session_exp: now() - 1 }),
        error: SessionExpiredError,
      },
      { name: 'the Session is not well formed', act: () => agentAct({ poppy_sid: 42 }), error: InvalidPoppySessionError },
    ];

    test.each(refusals)('leaves the agent session as it was when $name', async ({ act, error }) => {
      const app = createApp();
      await joinSignedIn(app, ANA, OTHER_SESSION_ID);
      await seedAnonymousSession(app);
      const before = snapshot(app);

      const thrown = await joinAs(app, 'guest', { act: act() }).catch((e: unknown) => e);

      expect(thrown).toBeInstanceOf(error);
      expectNothingWritten(app, before);
    });
  });
});

describe('completeInteractiveLogin | the result of an agent join', () => {
  test.each(KINDS)('returns the appState and the authorization details next to poppy for a %s', async (kind) => {
    authorizationDetails = [{ type: 'order_status' }];
    const app = createApp();

    const result = await joinAs(app, kind, {}, { appState: { returnTo: '/cart' } });

    expect(result.appState).toEqual({ returnTo: '/cart' });
    expect(result.authorizationDetails).toEqual([{ type: 'order_status' }]);
    expect(result.poppy).toStrictEqual(agentContext(kind === 'guest' ? 'signed_out' : 'signed_in'));
  });

  test('has no poppy member for a normal login', async () => {
    const app = createApp();

    const result = await loginNormally(app);

    expect(result).not.toHaveProperty('poppy');
  });
});

// A guest store of the app's own may keep the object it is given, and give the same object back. The contract allows
// it. The cookie store writes text, so it cannot show an object that is shared.
class ObjectGuestStore implements PoppyGuestStore<Browser> {
  readonly records = new Map<string, PoppyGuestData>();

  async set(identifier: string, data: PoppyGuestData) {
    this.records.set(identifier, data);
  }

  async get(identifier: string) {
    return this.records.get(identifier);
  }

  async delete(identifier: string) {
    this.records.delete(identifier);
  }
}

describe('completeInteractiveLogin | the agent in the result of a guest join', () => {
  test('is a new object, so a change by the app does not reach the guest that the store keeps', async () => {
    const guestStore = new ObjectGuestStore();
    const app = createApp({ guestStore });

    const result = await joinAsGuest(app);

    const kept = guestStore.records.get(GUEST_ID)!;
    const agent = result.poppy!.agent;
    expect(agent).not.toBe(kept.poppy.agent);
    expect(agent).toStrictEqual({ cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID });
    expect(agent).toStrictEqual(kept.poppy.agent);

    // The app changes what it was given. The guest keeps the agent of the Session, and so keeps its key.
    agent.cimdUrl = 'https://evil.example/agent.json';
    delete agent.poppyAgentId;
    expect(kept.poppy.agent).toStrictEqual({ cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID });
  });
});

describe('completeInteractiveLogin | who is a guest', () => {
  const signals = [
    { name: 'a sub that starts with anon_poppy@ and no sub_profile', token: { sub: GUEST_SUB } },
    {
      name: 'a sub that starts with anon_poppy@ and the anonymous user profile',
      token: { sub: GUEST_SUB, subProfile: 'urn:auth0:anonymous_user' },
    },
    { name: 'the anonymous user profile alone', token: { sub: ANA, subProfile: 'urn:auth0:anonymous_user' } },
  ];

  test.each(signals)('is a guest with $name', async ({ token }) => {
    const app = createApp();
    const at = now();

    const result = await login(app, { act: agentAct(), ...token });

    expect(result.poppy).toStrictEqual(agentContext('signed_out'));
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await guestOf(app)).toMatchObject({ sub: token.sub, poppy: { sessionId: SESSION_ID }, createdAt: at });
  });

  test('is signed in with neither signal', async () => {
    const app = createApp();

    const result = await login(app, { sub: ANA, act: agentAct() });

    expect(result.poppy).toStrictEqual(agentContext('signed_in'));
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
  });
});

describe('completeInteractiveLogin | the deadline of an agent session', () => {
  interface Source {
    name: string;
    app?: AppOptions;
    token: (at: number) => AgentIdTokenOptions;
    seconds: number;
  }

  // Each source is the earliest of the four, so the deadline must be that one.
  const sources: Source[] = [
    { name: 'agentSessionMaxAge', app: { agentSessionMaxAge: 600 }, token: () => ({}), seconds: 600 },
    { name: 'the exp of the ID token', token: (at) => ({ exp: at + 1800 }), seconds: 1800 },
    {
      name: 'poppy_session_exp',
      token: (at) => ({ act: agentAct({ poppy_session_exp: at + 2400 }) }),
      seconds: 2400,
    },
    // A time with a fraction is rounded down, to the earlier second, and it is still a bound. Without it the website
    // would live until the next bound, up to the longest session.
    {
      name: 'poppy_session_exp with a fraction, rounded down',
      token: (at) => ({ act: agentAct({ poppy_session_exp: at + 2400.9 }) }),
      seconds: 2400,
    },
    { name: 'session_expiry', token: (at) => ({ claims: { session_expiry: at + 3000 } }), seconds: 3000 },
  ];

  describe.each(KINDS)('for a %s', (kind) => {
    test.each(sources)('ends at $name when that is the earliest', async ({ app: options, token, seconds }) => {
      const app = createApp(options);
      const at = now();

      await joinAs(app, kind, token(at));

      const deadline = kind === 'guest' ? (await guestOf(app))?.expiresAt : (await stateOf(app))?.sessionExpiresAt;
      expect(deadline).toBe(at + seconds);
    });
  });

  test('the cookies of a guest and of a signed-in agent end with the deadline', async () => {
    const guestApp = createApp({ agentSessionMaxAge: 600 });
    const signedInApp = createApp({ agentSessionMaxAge: 600 });

    await joinAsGuest(guestApp);
    await joinSignedIn(signedInApp);

    expect(maxAgeOf(guestApp, GUEST_ID)).toBe(600);
    expect(maxAgeOf(signedInApp, STATE_ID)).toBe(600);
  });

  test('a signed-in session is gone 30 seconds before the deadline, as any session with a ceiling is', async () => {
    const app = createApp({ agentSessionMaxAge: 600 });
    await joinSignedIn(app);

    later(569);
    expect(await app.client.getSession(app.browser)).toBeDefined();

    later(1);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });
});

describe('completeInteractiveLogin | an agent session that has already ended', () => {
  const cases: Array<{ name: string; token: (at: number) => AgentIdTokenOptions }> = [
    { name: 'poppy_session_exp is in the past', token: (at) => ({ act: agentAct({ poppy_session_exp: at - 1 }) }) },
    // A fraction is rounded down, as the `exp` of the ID token is, and a time that rounds down to 0 is in the past.
    { name: 'poppy_session_exp rounds down to 0', token: () => ({ act: agentAct({ poppy_session_exp: 0.5 }) }) },
    // The code exchange accepts an ID token that ended less than 30 seconds ago, so this one reaches the check.
    { name: 'the exp of the ID token is in the past', token: (at) => ({ exp: at - 10 }) },
    // The deadline is judged with the leeway of 30 seconds, as the ceiling of any session is.
    { name: 'the deadline is 30 seconds away', token: (at) => ({ act: agentAct({ poppy_session_exp: at + 30 }) }) },
    { name: 'session_expiry is in the past', token: (at) => ({ claims: { session_expiry: at - 1 } }) },
  ];

  describe.each(KINDS)('for a %s', (kind) => {
    test.each(cases)('is refused when $name, and nothing is written', async ({ token }) => {
      const app = await appWithEverything();
      const before = snapshot(app);

      const error = await joinAs(app, kind, token(now())).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(SessionExpiredError);
      expect((error as Error).message).toBe(
        'The agent session has already ended; refusing to create an already-expired session.'
      );
      expectNothingWritten(app, before);
    });
  });

  test('is accepted when the deadline is 31 seconds away', async () => {
    const app = createApp();
    const at = now();

    await joinAs(app, 'guest', { act: agentAct({ poppy_session_exp: at + 31 }) });

    expect((await guestOf(app))?.expiresAt).toBe(at + 31);
  });
});

describe('completeInteractiveLogin | a Poppy Session that is not well formed', () => {
  const cases = [
    { name: 'no act.sub', act: () => agentAct({ sub: undefined }), member: 'act.sub' as const },
    { name: 'a poppy_sid that is a number', act: () => agentAct({ poppy_sid: 42 }), member: 'act.poppy_sid' as const },
  ];

  describe.each(KINDS)('for a %s', (kind) => {
    test.each(cases)('is refused with $name, and nothing is written', async ({ act, member }) => {
      const app = await appWithEverything();
      const before = snapshot(app);

      const error = await joinAs(app, kind, { act: act() }).catch((e: unknown) => e);

      // It is not taken for a normal login either: that would write a user session.
      expect(error).toBeInstanceOf(InvalidPoppySessionError);
      expect((error as Error).message).toBe(new InvalidPoppySessionError(member).message);
      expectNothingWritten(app, before);
    });
  });
});

describe('completeInteractiveLogin | a token that looks like a guest but holds no Poppy Session', () => {
  const lookAlikes: Array<{ name: string; token: AgentIdTokenOptions }> = [
    { name: 'a guest sub and no act', token: { sub: GUEST_SUB, act: null } },
    { name: 'the anonymous user profile and no act', token: { subProfile: 'urn:auth0:anonymous_user', act: null } },
    { name: 'a guest sub and an act with no poppy_sid', token: { sub: GUEST_SUB, act: { sub: CIMD_URL } } },
  ];

  test.each(lookAlikes)('is refused with $name, and nothing is written', async ({ token }) => {
    const app = await appWithEverything();
    const before = snapshot(app);

    const error = await login(app, token).catch((e: unknown) => e);

    // A guest must not become a user because its Session is missing.
    expect(error).toBeInstanceOf(InvalidPoppySessionError);
    expect((error as Error).message).toBe(new InvalidPoppySessionError('act.poppy_sid').message);
    expectNothingWritten(app, before);
  });

  test('takes the usual path for a customer whose act has no poppy_sid', async () => {
    const app = createApp();

    const result = await login(app, { sub: ANA, act: { sub: CIMD_URL } });

    expect(result).not.toHaveProperty('poppy');
    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.user?.act).toStrictEqual({ sub: CIMD_URL });
    expect(state?.refreshToken).toBe('rt_join');
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
  });

  test.each(lookAlikes)('takes the usual path without the poppy option, with $name', async ({ token }) => {
    const app = createApp({ poppy: false });

    const result = await login(app, token);

    expect(result).not.toHaveProperty('poppy');
    const user = await app.client.getUser(app.browser);
    expect(user?.sub).toBe(token.sub ?? ANA);
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
  });
});

describe('completeInteractiveLogin | a conflict at Auth0', () => {
  test('fails the callback with the error of Auth0, and nothing is written', async () => {
    const app = await appWithEverything();
    const before = snapshot(app);
    const conflict = new URL('https://zepto.example/auth/callback?error=session_conflict&error_description=conflict');

    const error = await login(app, { sub: ANA }, { url: conflict }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(TokenByCodeError);
    expect(error).toMatchObject({ cause: { error: 'session_conflict' } });
    expect(snapshot(app)).toEqual(before);
  });
});

describe('completeInteractiveLogin | without the poppy option', () => {
  test('an ID token with an agent act takes the usual path', async () => {
    const app = createApp({ poppy: false });
    const act = agentAct();

    const result = await login(app, { sub: ANA, act });

    expect(result).not.toHaveProperty('poppy');
    const state = await stateOf(app);
    // The `act` is stored as the token has it, and the refresh token is kept.
    expect(state?.user?.act).toStrictEqual(act);
    expect(state?.refreshToken).toBe('rt_join');
    expect(state?.sessionExpiresAt).toBeUndefined();
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
  });

  test('a normal login still builds on the stored session, even one that has an agent in act', async () => {
    const app = createApp({ poppy: false });
    const stored: StateData = {
      ...ownLogin(ANA),
      user: {
        sub: ANA,
        iss: POPPY_ISSUER,
        act: { sub: CIMD_URL, poppy_sid: OTHER_SESSION_ID, poppy_user_id: USER_ID },
      },
    };
    await app.stateStore.set(STATE_ID, stored, false, app.browser);
    later(600);

    await loginNormally(app, ANA);

    // Nothing changes without the option: the stored user and the time of its first login stay.
    const state = await stateOf(app);
    expect(state?.user?.act?.poppy_sid).toBe(OTHER_SESSION_ID);
    expect(state?.internal.createdAt).toBe(stored.internal.createdAt);
    expect(state?.refreshToken).toBe('rt_join');
  });

  test('a login that looks like a guest does not end a stored session that holds a Poppy Session', async () => {
    const app = createApp({ poppy: false });
    // The usual path stores the `act` as the token has it, so this session holds a Poppy Session.
    await login(app, { sub: ANA, act: agentAct({ poppy_sid: OTHER_SESSION_ID }) });
    const stateDelete = vi.spyOn(app.stateStore, 'delete');

    const result = await joinAsGuest(app, SESSION_ID);

    expect(result).not.toHaveProperty('poppy');
    expect(stateDelete).not.toHaveBeenCalled();
    expect(cookiesOf(app, GUEST_ID)).toEqual([]);
    // The usual path ran, and it wrote the user of this login.
    expect((await app.client.getUser(app.browser))?.sub).toBe(GUEST_SUB);
  });
});

describe('completeInteractiveLogin | a stateful session store', () => {
  // Keeps the sessions on the server. The cookie of the browser holds only the id of the session.
  class MemorySessionStore implements SessionStore<Browser> {
    readonly sessions = new Map<string, StateData>();

    async get(id: string) {
      return this.sessions.get(id);
    }

    async set(id: string, stateData: StateData) {
      this.sessions.set(id, stateData);
    }

    async delete(id: string) {
      this.sessions.delete(id);
    }

    async deleteByLogoutToken() {}
  }

  test('a signed-in join over a login of the same user gets a new session id, and the old one is gone', async () => {
    const sessions = new MemorySessionStore();
    const app = createApp({
      stateStore: (cookies) => new StatefulStateStore<Browser>({ secret: SECRET, store: sessions }, cookies),
    });
    await seedOwnLogin(app, ANA);
    const [oldId] = [...sessions.sessions.keys()];
    expect(oldId).toBeDefined();

    await joinSignedIn(app, ANA);

    // A new login must not keep the id of the browser's earlier session: that would allow session fixation.
    const ids = [...sessions.sessions.keys()];
    expect(ids).toHaveLength(1);
    expect(ids[0]).not.toBe(oldId);
    expect(sessions.sessions.get(ids[0] as string)?.user?.act?.poppy_sid).toBe(SESSION_ID);
    expect(sessions.sessions.get(ids[0] as string)?.refreshToken).toBeUndefined();
  });

  function createStatefulApp() {
    const sessions = new MemorySessionStore();
    const app = createApp({
      stateStore: (cookies) => new StatefulStateStore<Browser>({ secret: SECRET, store: sessions }, cookies),
    });

    return { app, sessions };
  }

  test('a guest join over an agent session removes its record, so no orphan stays in the session store', async () => {
    const { app, sessions } = createStatefulApp();
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    expect(sessions.sessions.size).toBe(1);

    await joinAsGuest(app, SESSION_ID);

    expect(sessions.sessions.size).toBe(0);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect((await guestOf(app))?.poppy.sessionId).toBe(SESSION_ID);
  });

  test('a guest join over the login of a person keeps its record and its cookie', async () => {
    const { app, sessions } = createStatefulApp();
    await seedOwnLogin(app, ANA);
    const [id] = [...sessions.sessions.keys()];
    const own = cookiesOf(app, STATE_ID);
    expect(id).toBeDefined();

    await joinAsGuest(app, SESSION_ID);

    expect([...sessions.sessions.keys()]).toEqual([id]);
    expect(sessions.sessions.get(id as string)?.refreshToken).toBe('rt_old');
    expect(cookiesOf(app, STATE_ID)).toEqual(own);
    expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
  });
});

describe('completeAgentLogin | called directly', () => {
  // A response as the code exchange makes it. The claims can be ones that the exchange would not let through.
  const responseWith = (claims: Record<string, unknown> | undefined) =>
    new TokenResponse(
      'at_join',
      now() + 3600,
      'id.token',
      'rt_join',
      'openid profile',
      claims as unknown as IDTokenClaims | undefined
    );

  const complete = (app: App, response: TokenResponse) =>
    completeAgentLogin({
      response,
      audience: 'default',
      domain: POPPY_DOMAIN,
      stateStore: app.stateStore,
      stateStoreIdentifier: STATE_ID,
      guestStore: app.guestStore,
      guestStoreIdentifier: GUEST_ID,
      agentSessionMaxAge: 7200,
      storeOptions: app.browser,
    });

  const claimsOf = (kind: Kind, more: Record<string, unknown> = {}) => ({
    iss: POPPY_ISSUER,
    aud: POPPY_CLIENT_ID,
    iat: now(),
    exp: now() + 7200,
    act: agentAct(),
    ...(kind === 'guest' ? { sub: GUEST_SUB, sub_profile: ANONYMOUS_USER_PROFILE } : { sub: ANA }),
    ...more,
  });

  // A deadline of 0 is a time in the past. It is not a missing deadline, and it is not a reason to skip the check.
  test.each(KINDS)('refuses a %s whose deadline rounds down to 0', async (kind) => {
    const app = createApp();

    const error = await complete(app, responseWith(claimsOf(kind, { exp: 0.5 }))).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SessionExpiredError);
    expect(snapshot(app)).toEqual({});
  });

  test('gives undefined for a response with no ID token, and writes nothing', async () => {
    const app = createApp();

    expect(await complete(app, responseWith(undefined))).toBeUndefined();
    expect(snapshot(app)).toEqual({});
  });
});
