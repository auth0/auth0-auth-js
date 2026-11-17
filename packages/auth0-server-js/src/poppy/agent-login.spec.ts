import { TokenByRefreshTokenError, TokenResponse } from '@auth0/auth0-auth-js';
import type { IDTokenClaims } from '@auth0/auth0-auth-js';
import { base64url } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { InvalidPoppySessionError, PoppyError, PoppyErrorCode, SessionExpiredError } from '../errors.js';
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
  JOIN_SCOPE,
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
// The cookie that holds the guest: with the defaults (Secure, Path=/) the store gives it the `__Host-` prefix.
const GUEST_COOKIE = '__Host-a0_poppy';
const ANONYMOUS_ID = '__a0_anon';
const CALLBACK = new URL('https://zepto.example/auth/callback?code=c1');
const ANA = 'auth0|ana';
const BOB = 'auth0|bob';

// The ID token and the authorization details that the token endpoint answers with. A test sets them for each login.
let idToken: string | undefined;
let authorizationDetails: Array<Record<string, unknown>> | undefined;
// The scope that the token endpoint answers with. `undefined` leaves the member out.
let tokenScope: string | undefined;
// The tokens that the revocation endpoint was asked to revoke, and the status it answers with.
let revoked: string[] = [];
let revokeStatus = 200;

const server = setupServer(
  http.get(`https://${POPPY_DOMAIN}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: POPPY_ISSUER,
      authorization_endpoint: `https://${POPPY_DOMAIN}/authorize`,
      token_endpoint: `https://${POPPY_DOMAIN}/oauth/token`,
      revocation_endpoint: `https://${POPPY_DOMAIN}/oauth/revoke`,
    })
  ),
  http.post(`https://${POPPY_DOMAIN}/oauth/revoke`, async ({ request }) => {
    revoked.push(new URLSearchParams(await request.text()).get('token') ?? '');

    return new HttpResponse(null, { status: revokeStatus });
  }),
  http.post(`https://${POPPY_DOMAIN}/oauth/token`, () =>
    HttpResponse.json({
      ...(idToken !== undefined && { id_token: idToken }),
      access_token: 'at_join',
      token_type: 'Bearer',
      expires_in: 3600,
      ...(tokenScope !== undefined && { scope: tokenScope }),
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
  tokenScope = JOIN_SCOPE;
  revoked = [];
  revokeStatus = 200;
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
      sub_profile: ANONYMOUS_USER_PROFILE,
      act: agentActClaim({ poppy_sid: sessionId }),
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
    sub_profile: ANONYMOUS_USER_PROFILE,
    act: agentAct({ poppy_sid: expected.sessionId }),
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
  expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);
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

  test('a guest joins a browser with no login. G is written, there is no U, and A stays', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    const guestSet = vi.spyOn(app.guestStore, 'set');
    const stateSet = vi.spyOn(app.stateStore, 'set');
    const at = now();

    const result = await joinAsGuest(app);

    expect(result.poppy).toStrictEqual(agentContext('guest'));
    // The guest is never a user: no session is written to the state store. It is cleared, as a guest join clears any session.
    expect(stateSet).not.toHaveBeenCalled();
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(guestSet).toHaveBeenCalledWith(GUEST_ID, expect.any(Object), false, app.browser);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
    expect(cookiesOf(app, TRANSACTION_ID)).toEqual([]);
  });

  test('a signed-in agent joins a browser with no login. U is fresh, there is no G, and A is cleared', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    const at = now();

    const result = await joinSignedIn(app);

    expect(result.poppy).toStrictEqual(agentContext('signed_in'));
    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(SESSION_ID);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    expect(cookiesOf(app, TRANSACTION_ID)).toEqual([]);
  });

  test('the anonymous session stays with clearAnonymousSessionOnLogin: false', async () => {
    const app = createApp({ clearAnonymousSessionOnLogin: false });
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);

    const result = await joinSignedIn(app);

    expect(result.poppy?.state).toBe('signed_in');
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  // The browser is the agent's now. A person's own login must not stay: the agent must not act with an account that it was
  // not approved for.
  // Deleting the session removes it from this browser only. The refresh token stays valid at Auth0, and a copy of the
  // session cookie would still open it. So the join revokes the token before it deletes the session.
  test("a guest join revokes the refresh token of the person's own login that it replaces", async () => {
    const app = createApp();
    await seedOwnLogin(app);

    const result = await joinAsGuest(app);

    expect(result.poppy).toStrictEqual(agentContext('guest'));
    expect(revoked).toEqual(['rt_old']);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });

  test('a guest join with no session in the browser revokes nothing', async () => {
    const app = createApp();

    await joinAsGuest(app);

    expect(revoked).toEqual([]);
  });

  test('a signed-in join and a normal login revoke nothing: the refresh token of the person is not touched', async () => {
    const app = createApp();
    await seedOwnLogin(app);

    await joinSignedIn(app);
    expect(revoked).toEqual([]);

    await seedOwnLogin(app);
    await loginNormally(app, BOB);
    expect(revoked).toEqual([]);
  });

  test.each([
    ['answers with an error', 500],
    ['answers that the token is not valid', 400],
  ])('a guest join goes on when the revocation %s: the session is still deleted and the guest written', async (_, status) => {
    const app = createApp();
    await seedOwnLogin(app);
    revokeStatus = status;

    const result = await joinAsGuest(app);

    expect(revoked).toEqual(['rt_old']);
    expect(result.poppy).toStrictEqual(agentContext('guest'));
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);
  });

  test("a guest joins a browser with a person's own login. U is deleted, G is written, and A stays", async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedOwnLogin(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    // The premise: the person is logged in before the guest joins.
    expect((await app.client.getUser(app.browser))?.sub).toBe(ANA);
    const at = now();

    const result = await joinAsGuest(app);

    expect(result.poppy).toStrictEqual(agentContext('guest'));
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    await expect(app.client.getAccessToken({}, app.browser)).rejects.toBeInstanceOf(TokenByRefreshTokenError);
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  // A rejoin without an access token ends the sign-in of a Session. The guest replaces an agent session of the browser,
  // whatever Session that one belongs to.
  test.each([
    { name: 'of another Session', earlier: OTHER_SESSION_ID },
    { name: 'of the same Session', earlier: SESSION_ID },
  ])('a guest joins a browser with an agent session $name, so U is deleted, G is written, and A stays', async ({ earlier }) => {
    const app = createApp();
    await joinSignedIn(app, ANA, earlier);
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    // The premise: the agent is signed in before the guest joins.
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(earlier);
    later(60);
    const at = now();

    const result = await joinAsGuest(app, SESSION_ID);

    expect(result.poppy).toStrictEqual(agentContext('guest'));
    // The agent is not signed in any more, for any reader of the session.
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    await expect(app.client.getAccessToken({}, app.browser)).rejects.toBeInstanceOf(TokenByRefreshTokenError);
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  test('a guest joins a browser with a guest of another Session. G is replaced, and A stays', async () => {
    const app = createApp();
    await seedGuest(app, OTHER_SESSION_ID);
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);
    later(60);
    const at = now();

    const result = await joinAsGuest(app, SESSION_ID);

    expect(result.poppy).toStrictEqual(agentContext('guest'));
    expectGuest(await guestOf(app), { sessionId: SESSION_ID, at });
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  test('a signed-in agent joins a browser with a guest. U is fresh, G is deleted, and A is cleared', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedGuest(app, SESSION_ID);
    later(60);
    const at = now();

    const result = await joinSignedIn(app);

    expect(result.poppy).toStrictEqual(agentContext('signed_in'));
    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('a signed-in agent joins over a login of the same user. U is fresh, with nothing old', async () => {
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
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('a signed-in agent joins over an agent session of the same user. U is fresh, with the new one', async () => {
    const app = createApp();
    await joinSignedIn(app, ANA, OTHER_SESSION_ID);
    await seedAnonymousSession(app);
    later(600);
    const at = now();

    await joinSignedIn(app, ANA, SESSION_ID);

    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect((await app.client.getUser(app.browser))?.act?.poppy_sid).toBe(SESSION_ID);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('a signed-in agent joins over a login of another user. U is fresh for the new user', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedOwnLogin(app, BOB);
    later(600);
    const at = now();

    await joinSignedIn(app, ANA);

    expectFreshAgentSession(await stateOf(app), { sub: ANA, sessionId: SESSION_ID, at });
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('a normal login by the same user replaces an agent session. U is fresh, with no act', async () => {
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
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
  });

  test('a normal login in a browser with a guest is refused. G stays, there is no U, and A stays', async () => {
    const app = createApp();
    await seedAnonymousSession(app);
    await seedGuest(app, SESSION_ID);
    const before = snapshot(app);
    later(60);

    const error = await loginNormally(app, ANA).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PoppyError);
    expect((error as PoppyError).code).toBe(PoppyErrorCode.SIGN_IN_REQUIRED);
    expectNothingWritten(app, before);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
  });
});

describe('completeInteractiveLogin | when a store fails', () => {
  test('a signed-in join over a guest: a failed write of the session leaves no guest behind, and no session', async () => {
    const app = createApp();
    await seedGuest(app, SESSION_ID);
    vi.spyOn(app.stateStore, 'set').mockRejectedValueOnce(new Error('state store is down'));

    await expect(joinSignedIn(app)).rejects.toThrow('state store is down');

    // The guest is dropped before the session is written. The visitor has neither, and can join again.
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
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
  // The member that marks a Poppy Session is `poppy_sid`. An `act` without it is the customer's own. The guest join ends
  // the session whatever its `act` is, because the browser is the agent's now.
  test('deletes the own login of a person, even when its act is not a Poppy Session', async () => {
    const app = createApp();
    await app.stateStore.set(
      STATE_ID,
      { ...ownLogin(ANA), user: { sub: ANA, iss: POPPY_ISSUER, act: { sub: CIMD_URL } } },
      false,
      app.browser
    );
    const stateDelete = vi.spyOn(app.stateStore, 'delete');

    await joinAsGuest(app);

    expect(stateDelete).toHaveBeenCalledTimes(1);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect((await guestOf(app))?.act.poppy_sid).toBe(SESSION_ID);
  });

  test("deletes the login of a person who is the same user as the guest's Session names", async () => {
    const app = createApp();
    await seedOwnLogin(app, ANA);

    await joinAsGuest(app);

    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect((await app.client.poppy.getVisitor(app.browser)).kind).toBe('guest');
  });

  describe('when a store fails', () => {
    // A session of the browser, so that the guest join has a session to end.
    async function appWithSession(): Promise<App> {
      const app = createApp();
      await joinSignedIn(app, ANA, OTHER_SESSION_ID);

      return app;
    }

    test('a failing delete of the session reaches the app, and no guest is written', async () => {
      const app = await appWithSession();
      const agentSession = cookiesOf(app, STATE_ID);
      const guestSet = vi.spyOn(app.guestStore, 'set');
      vi.spyOn(app.stateStore, 'delete').mockRejectedValueOnce(new Error('state store is down'));

      await expect(joinAsGuest(app, SESSION_ID)).rejects.toThrow('state store is down');

      // Nothing is half done: the session is as it was, and there is no guest next to it.
      expect(guestSet).not.toHaveBeenCalled();
      expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
      expect(cookiesOf(app, STATE_ID)).toEqual(agentSession);
    });

    test('a failing read of the guest store reaches the app, and nothing is written', async () => {
      const app = await appWithSession();
      const agentSession = cookiesOf(app, STATE_ID);
      const guestSet = vi.spyOn(app.guestStore, 'set');
      const stateDelete = vi.spyOn(app.stateStore, 'delete');
      vi.spyOn(app.guestStore, 'get').mockRejectedValueOnce(new Error('guest store is down'));

      // A store that fails is never read as empty: that would let a login replace a guest that is there.
      await expect(joinAsGuest(app, SESSION_ID)).rejects.toThrow('guest store is down');

      expect(guestSet).not.toHaveBeenCalled();
      expect(stateDelete).not.toHaveBeenCalled();
      expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
      expect(cookiesOf(app, STATE_ID)).toEqual(agentSession);
    });

    test('a failing write of the guest leaves the visitor with neither', async () => {
      const app = await appWithSession();
      vi.spyOn(app.guestStore, 'set').mockRejectedValueOnce(new Error('guest store is down'));

      await expect(joinAsGuest(app, SESSION_ID)).rejects.toThrow('guest store is down');

      // The session goes first, as the guest goes first in a signed-in join. The visitor can join again.
      expect(cookiesOf(app, STATE_ID)).toEqual([]);
      expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    });
  });

  // The session is ended only once the join is accepted.
  describe('that is refused', () => {
    const refusals = [
      {
        name: 'the Session is not well formed',
        act: () => agentAct({ poppy_sid: 42 }),
        code: PoppyErrorCode.INVALID_GUEST,
      },
    ];

    test.each(refusals)('leaves the session as it was when $name', async ({ act, code }) => {
      const app = createApp();
      await joinSignedIn(app, ANA, OTHER_SESSION_ID);
      await seedAnonymousSession(app);
      const before = snapshot(app);
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const thrown = await joinAs(app, 'guest', { act: act() }).catch((e: unknown) => e);

      expect(thrown).toBeInstanceOf(PoppyError);
      expect((thrown as PoppyError).code).toBe(code);
      expectNothingWritten(app, before);
    });

    test('leaves the own login of a person as it was when the deadline of the guest has already passed', async () => {
      const app = createApp();
      await seedOwnLogin(app, ANA);
      const before = snapshot(app);

      const thrown = await joinAs(app, 'guest', { exp: now() - 10 }).catch((e: unknown) => e);

      expect(thrown).toBeInstanceOf(SessionExpiredError);
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
    expect(result.poppy).toStrictEqual(agentContext(kind === 'guest' ? 'guest' : 'signed_in'));
  });

  test('has no poppy member for a normal login', async () => {
    const app = createApp();

    const result = await loginNormally(app);

    expect(result).not.toHaveProperty('poppy');
  });
});

describe('completeInteractiveLogin | the context of an agent join', () => {
  // The whole context is written out, so a member that is added or renamed fails these tests.
  test('a guest: its sub and sub_profile, the whole act, no scopes and the key of the Session', async () => {
    const app = createApp();

    const result = await joinAsGuest(app);

    expect(result.poppy).toStrictEqual({
      kind: 'agent',
      state: 'guest',
      sub: GUEST_SUB,
      sub_profile: 'urn:auth0:anonymous_user',
      act: { sub: CIMD_URL, poppy_sid: SESSION_ID, poppy_user_id: USER_ID, poppy_agent_id: AGENT_ID },
      scopes: [],
      key: '3X_qiM4THChkGSbMHW5cwViMXCkP6myL_fqSvIz33h0',
    });
  });

  test('a signed-in agent: the sub of the user, the whole act, the scopes of the join and the key of the Session', async () => {
    const app = createApp();

    const result = await joinSignedIn(app);

    // The token has no `sub_profile`, so the context has no such member.
    expect(result.poppy).toStrictEqual({
      kind: 'agent',
      state: 'signed_in',
      sub: ANA,
      act: { sub: CIMD_URL, poppy_sid: SESSION_ID, poppy_user_id: USER_ID, poppy_agent_id: AGENT_ID },
      scopes: ['openid', 'profile'],
      key: '3X_qiM4THChkGSbMHW5cwViMXCkP6myL_fqSvIz33h0',
    });
  });

  test('the key is the SHA-256 of the agent, the Session and the user, joined by line breaks', async () => {
    const app = createApp();
    const act = agentAct({ sub: 'agt_Wq3n8', poppy_sid: OTHER_SESSION_ID, poppy_user_id: 'usr_other' });

    const result = await login(app, { sub: ANA, act });

    const text = `agt_Wq3n8\n${OTHER_SESSION_ID}\nusr_other`;
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    expect(result.poppy?.key).toBe(base64url.encode(new Uint8Array(digest)));
    expect(result.poppy?.key).not.toBe(SESSION_KEY);
  });

  // The `act` is the claim as Auth0 sent it. Members that this package does not know, and an act inside it, are kept.
  test.each(KINDS)('keeps the whole act of a %s, with the members that it does not know', async (kind) => {
    const app = createApp();
    const whole = agentAct({
      client_id: POPPY_CLIENT_ID,
      iss: POPPY_ISSUER,
      poppy_extension: { level: 3, tags: ['a', 'b'] },
      act: { sub: 'https://nested.example/agent.json', poppy_sid: 'nested_sid' },
    });

    const result = await joinAs(app, kind, { act: whole });

    expect(result.poppy?.act).toStrictEqual(whole);
    // The same act is in the record that the join leaves.
    const stored = kind === 'guest' ? (await guestOf(app))?.act : (await stateOf(app))?.user?.act;
    expect(stored).toStrictEqual(whole);
  });

  test.each([
    { name: 'a string of profiles', subProfile: 'urn:example:member', kept: 'urn:example:member' },
    { name: 'a list of profiles', subProfile: ['urn:example:member'], kept: undefined },
    { name: 'a number', subProfile: 7, kept: undefined },
  ])('a signed-in agent has the sub_profile of the token when it is a string: $name', async ({ subProfile, kept }) => {
    const app = createApp();

    const result = await login(app, { sub: ANA, subProfile });

    expect(result.poppy).toStrictEqual(agentContext('signed_in', { sub_profile: kept }));
  });

  test('a guest whose sub_profile is a list has no sub_profile in the context or in the record', async () => {
    const app = createApp();

    const result = await login(app, { sub: GUEST_SUB, subProfile: [ANONYMOUS_USER_PROFILE] });

    expect(result.poppy).toStrictEqual(agentContext('guest', { sub_profile: undefined }));
    expect(await guestOf(app)).not.toHaveProperty('sub_profile');
  });

  test.each([
    {
      name: 'the scopes of the token set, in order',
      scope: 'orders:read checkout openid',
      scopes: ['orders:read', 'checkout', 'openid'],
    },
    {
      name: 'no empty scope for a space at the ends or a double space',
      scope: ' orders:read  checkout ',
      scopes: ['orders:read', 'checkout'],
    },
    { name: 'an empty list for an empty scope', scope: '', scopes: [] },
    { name: 'an empty list when the token endpoint sends no scope', scope: undefined, scopes: [] },
  ])('a signed-in agent has $name', async ({ scope, scopes }) => {
    tokenScope = scope;
    const app = createApp();

    const result = await joinSignedIn(app);

    expect(result.poppy?.scopes).toStrictEqual(scopes);
  });

  test('a guest has no scopes, whatever scope the token has', async () => {
    tokenScope = 'orders:read checkout';
    const app = createApp();

    const result = await joinAsGuest(app);

    expect(result.poppy?.scopes).toStrictEqual([]);
    // The scope of the token stays in the token set of the guest, which `getGuestAccessToken()` reads.
    expect((await guestOf(app))?.tokenSets[0]?.scope).toBe('orders:read checkout');
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

describe('completeInteractiveLogin | the act in the result of a guest join', () => {
  test('is a new object, so a change by the app does not reach the guest that the store keeps', async () => {
    const guestStore = new ObjectGuestStore();
    const app = createApp({ guestStore });
    const nested = { sub: 'https://nested.example/agent.json' };
    const whole = agentAct({ act: nested });

    const result = await joinAs(app, 'guest', { act: whole });

    const kept = guestStore.records.get(GUEST_ID)!;
    const { act, scopes } = result.poppy!;
    expect(act).not.toBe(kept.act);
    expect(act).toStrictEqual(whole);
    expect(act).toStrictEqual(kept.act);

    // The app changes what it was given, at the top and inside. The guest keeps the act of the Session, and so keeps its
    // key.
    act.sub = 'https://evil.example/agent.json';
    delete act.poppy_agent_id;
    (act.act as { sub: string }).sub = 'https://evil.example/nested.json';
    scopes.push('admin');
    expect(kept.act).toStrictEqual(whole);
    expect(kept.act.act).toStrictEqual(nested);
  });
});

describe('completeInteractiveLogin | who is a guest', () => {
  test('is a guest with both markers: a sub that starts with anon_poppy@ and the anonymous user profile', async () => {
    const app = createApp();
    const at = now();

    const result = await login(app, { sub: GUEST_SUB, subProfile: ANONYMOUS_USER_PROFILE, act: agentAct() });

    expect(result.poppy).toStrictEqual(agentContext('guest'));
    expect(await app.client.getSession(app.browser)).toBeUndefined();
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await guestOf(app)).toMatchObject({ sub: GUEST_SUB, act: { poppy_sid: SESSION_ID }, createdAt: at });
  });

  // One marker is not enough. The login is refused and never becomes a user or a guest.
  test.each([
    { name: 'a sub that starts with anon_poppy@ and no sub_profile', token: { sub: GUEST_SUB } },
    {
      name: 'a sub that starts with anon_poppy@ and a sub_profile that is user',
      token: { sub: GUEST_SUB, subProfile: 'user' },
    },
    { name: 'the anonymous user profile alone', token: { sub: ANA, subProfile: ANONYMOUS_USER_PROFILE } },
  ])('is refused with invalid_poppy_guest for $name, and nothing is written', async ({ token }) => {
    const app = await appWithEverything();
    const before = snapshot(app);
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const error = await login(app, { act: agentAct(), ...token }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PoppyError);
    expect((error as PoppyError).code).toBe(PoppyErrorCode.INVALID_GUEST);
    expectNothingWritten(app, before);
  });

  test('is signed in with neither marker', async () => {
    const app = createApp();

    const result = await login(app, { sub: ANA, act: agentAct() });

    expect(result.poppy).toStrictEqual(agentContext('signed_in'));
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });
});

describe('completeInteractiveLogin | the deadline of an agent session', () => {
  interface Source {
    name: string;
    app?: AppOptions;
    token: (at: number) => AgentIdTokenOptions;
    seconds: number;
  }

  // Each source is the earliest of the three, so the deadline must be that one.
  const sources: Source[] = [
    { name: 'agentSessionMaxAge', app: { agentSessionMaxAge: 600 }, token: () => ({}), seconds: 600 },
    { name: 'the exp of the ID token', token: (at) => ({ exp: at + 1800 }), seconds: 1800 },
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

    expect(maxAgeOf(guestApp, GUEST_COOKIE)).toBe(600);
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
    // The code exchange accepts an ID token that ended less than 30 seconds ago, so this one reaches the check.
    { name: 'the exp of the ID token is in the past', token: (at) => ({ exp: at - 10 }) },
    // The deadline is judged with the leeway of 30 seconds, as the ceiling of any session is.
    { name: 'the deadline is 30 seconds away', token: (at) => ({ exp: at + 30 }) },
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

    await joinAs(app, 'guest', { exp: at + 31 });

    expect((await guestOf(app))?.expiresAt).toBe(at + 31);
  });
});

describe('completeInteractiveLogin | a Poppy Session that is not well formed', () => {
  const cases = [
    { name: 'no act.sub', act: () => agentAct({ sub: undefined }), member: 'act.sub' as const },
    { name: 'a poppy_sid that is a number', act: () => agentAct({ poppy_sid: 42 }), member: 'act.poppy_sid' as const },
  ];

  // A signed-in agent has no guest marker, so it is the Session that is refused.
  test.each(cases)('is refused with $name for a signed-in agent, and nothing is written', async ({ act, member }) => {
    const app = await appWithEverything();
    const before = snapshot(app);

    const error = await joinAs(app, 'signed-in', { act: act() }).catch((e: unknown) => e);

    // It is not taken for a normal login either: that would write a user session.
    expect(error).toBeInstanceOf(InvalidPoppySessionError);
    expect((error as Error).message).toBe(new InvalidPoppySessionError(member).message);
    expectNothingWritten(app, before);
  });

  // A guest has both markers, so a Session that is not well formed makes the login look like a guest that is not one.
  test.each(cases)(
    'is refused with $name for a guest, as invalid_poppy_guest, and nothing is written',
    async ({ act, member }) => {
      const app = await appWithEverything();
      const before = snapshot(app);
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const error = await joinAs(app, 'guest', { act: act() }).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(PoppyError);
      expect((error as PoppyError).code).toBe(PoppyErrorCode.INVALID_GUEST);
      expect((error as PoppyError).reason).toBe(`${member} is missing or invalid`);
      expectNothingWritten(app, before);
    }
  );
});

describe('completeInteractiveLogin | a token that looks like a guest but is not one', () => {
  const lookAlikes: Array<{ name: string; token: AgentIdTokenOptions; reason: string }> = [
    {
      name: 'a guest sub and no act',
      token: { sub: GUEST_SUB, act: null },
      reason: 'sub starts with anon_poppy@, but sub_profile is missing',
    },
    {
      name: 'the anonymous user profile and no act',
      token: { subProfile: 'urn:auth0:anonymous_user', act: null },
      reason: 'sub_profile marks an anonymous user, but sub does not start with anon_poppy@',
    },
    {
      name: 'a guest sub and an act with no poppy_sid',
      token: { sub: GUEST_SUB, act: { sub: CIMD_URL } },
      reason: 'sub starts with anon_poppy@, but sub_profile is missing',
    },
    {
      name: 'both markers and no act',
      token: { sub: GUEST_SUB, subProfile: ANONYMOUS_USER_PROFILE, act: null },
      reason: 'act is missing or is not an object',
    },
    {
      name: 'both markers and an act with no poppy_sid',
      token: { sub: GUEST_SUB, subProfile: ANONYMOUS_USER_PROFILE, act: { sub: CIMD_URL } },
      reason: 'act.poppy_sid is missing or invalid',
    },
  ];

  test.each(lookAlikes)('is refused with $name, and nothing is written', async ({ token, reason }) => {
    const app = await appWithEverything();
    const before = snapshot(app);
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const error = await login(app, token).catch((e: unknown) => e);

    // A guest must not become a user because a marker or its Session is missing.
    expect(error).toBeInstanceOf(PoppyError);
    expect((error as PoppyError).code).toBe(PoppyErrorCode.INVALID_GUEST);
    expect((error as PoppyError).reason).toBe(reason);
    expectNothingWritten(app, before);
  });

  test('logs the reason once, and no value', async () => {
    const app = createApp();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});

    await login(app, { sub: 'anon_poppy@secret-sub', act: agentAct({ poppy_user_id: 'secret-user' }) }).catch(() => {});

    expect(log).toHaveBeenCalledTimes(1);
    expect(String(log.mock.calls[0]?.join(' '))).toContain('sub starts with anon_poppy@, but sub_profile is missing');
    expect(String(log.mock.calls[0]?.join(' '))).not.toContain('secret');
  });

  test('takes the usual path for a customer whose act has no poppy_sid', async () => {
    const app = createApp();

    const result = await login(app, { sub: ANA, act: { sub: CIMD_URL } });

    expect(result).not.toHaveProperty('poppy');
    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.user?.act).toStrictEqual({ sub: CIMD_URL });
    expect(state?.refreshToken).toBe('rt_join');
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });

  test.each(lookAlikes)('takes the usual path without the poppy option, with $name', async ({ token }) => {
    const app = createApp({ poppy: false });

    const result = await login(app, token);

    expect(result).not.toHaveProperty('poppy');
    const user = await app.client.getUser(app.browser);
    expect(user?.sub).toBe(token.sub ?? ANA);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
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
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
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
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
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
    expect((await guestOf(app))?.act.poppy_sid).toBe(SESSION_ID);
  });

  test('a guest join over the login of a person removes its record, so no orphan stays in the session store', async () => {
    const { app, sessions } = createStatefulApp();
    await seedOwnLogin(app, ANA);
    expect(sessions.sessions.size).toBe(1);

    await joinAsGuest(app, SESSION_ID);

    expect(sessions.sessions.size).toBe(0);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect((await guestOf(app))?.act.poppy_sid).toBe(SESSION_ID);
  });

  test('a refused login leaves the record of the session store as it was', async () => {
    const { app, sessions } = createStatefulApp();
    await seedGuest(app, SESSION_ID);
    const records = [...sessions.sessions];

    const error = await loginNormally(app, ANA).catch((e: unknown) => e);

    expect((error as PoppyError).code).toBe(PoppyErrorCode.SIGN_IN_REQUIRED);
    expect([...sessions.sessions]).toEqual(records);
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
      callback: true,
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

  test('refuses a response with no ID token when a guest is in the browser, as it refuses any person', async () => {
    const app = createApp();
    await seedGuest(app, SESSION_ID);
    const before = snapshot(app);

    const error = await complete(app, responseWith(undefined)).catch((e: unknown) => e);

    expect((error as PoppyError).code).toBe(PoppyErrorCode.SIGN_IN_REQUIRED);
    expect(snapshot(app)).toEqual(before);
  });

  // `exp` is required: a token that has none has no deadline, and there is no `now + agentSessionMaxAge` to fall back to.
  test.each([
    { name: 'no exp', more: { exp: undefined } },
    { name: 'an exp that is a string', more: { exp: `${now() + 7200}` } },
    { name: 'an exp in milliseconds', more: { exp: (now() + 7200) * 1000 } },
  ])('refuses a signed-in agent with $name, and writes nothing', async ({ more }) => {
    const app = createApp();
    const claims = { ...claimsOf('signed-in'), ...more };
    if (more.exp === undefined) delete (claims as Record<string, unknown>).exp;

    const error = await complete(app, responseWith(claims)).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(InvalidPoppySessionError);
    expect((error as Error).message).toBe(new InvalidPoppySessionError('exp').message);
    expect(snapshot(app)).toEqual({});
  });

  test('refuses a guest with no exp as invalid_poppy_guest, and writes nothing', async () => {
    const app = createApp();
    const claims: Record<string, unknown> = claimsOf('guest');
    delete claims.exp;
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const error = await complete(app, responseWith(claims)).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PoppyError);
    expect((error as PoppyError).code).toBe(PoppyErrorCode.INVALID_GUEST);
    expect((error as PoppyError).reason).toBe('exp is missing or invalid');
    expect(snapshot(app)).toEqual({});
  });

  test('refuses a signed-in agent with no sub, and writes nothing', async () => {
    const app = createApp();

    const error = await complete(app, responseWith(claimsOf('signed-in', { sub: '' }))).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(InvalidPoppySessionError);
    expect((error as Error).message).toBe(new InvalidPoppySessionError('sub').message);
    expect(snapshot(app)).toEqual({});
  });

  test('refuses a guest when callback is false, and writes nothing', async () => {
    const app = createApp();

    const error = await completeAgentLogin({
      response: responseWith(claimsOf('guest')),
      audience: 'default',
      domain: POPPY_DOMAIN,
      callback: false,
      stateStore: app.stateStore,
      stateStoreIdentifier: STATE_ID,
      guestStore: app.guestStore,
      guestStoreIdentifier: GUEST_ID,
      agentSessionMaxAge: 7200,
      storeOptions: app.browser,
    }).catch((e: unknown) => e);

    expect((error as PoppyError).code).toBe(PoppyErrorCode.GUEST_NOT_SUPPORTED);
    expect(snapshot(app)).toEqual({});
  });
});
