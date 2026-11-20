import { AuthClient } from '@auth0/auth0-auth-js';
import { base64url } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { PoppyError, PoppyErrorCode, SessionExpiredError } from '../errors.js';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import { StatefulStateStore } from '../store/stateful-state-store.js';
import { StatelessAnonymousStore } from '../store/stateless-anonymous-store.js';
import { StatelessStateStore } from '../store/stateless-state-store.js';
import {
  BrowserCookieHandler,
  GUEST_SUB,
  JOIN_SCOPE,
  OTHER_SESSION_ID,
  POPPY_CLIENT_ID,
  POPPY_DOMAIN,
  POPPY_ISSUER,
  SESSION_ID,
  agentAct,
  agentContext,
  agentIdToken,
  createPoppyConfig,
  guestRecord,
} from '../test-utils/poppy.js';
import type { AgentIdTokenOptions, Browser } from '../test-utils/poppy.js';
import { jwks } from '../test-utils/tokens.js';
import type { SessionStore, StateData, StateStore } from '../types.js';
import { ANONYMOUS_USER_PROFILE } from './constants.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';
import type { PoppyGuestData } from './types.js';

// These tests run the guard of a login on every method that writes a user session: the redirect callback and the six
// others. A fake Auth0 answers every token request with a signed ID token, and one Map (the browser) holds the cookies of
// every store, so a test can see what a login leaves behind and that a refused login leaves nothing.

const SECRET = '<secret>';
const TRANSACTION_ID = '__a0_tx';
const PASSKEY_TRANSACTION_ID = '__a0_passkey_tx';
const STATE_ID = '__a0_session';
const GUEST_ID = '__a0_poppy';
// The cookie that holds the guest: with the defaults (Secure, Path=/) the store gives it the `__Host-` prefix.
const GUEST_COOKIE = '__Host-a0_poppy';
const ANONYMOUS_ID = '__a0_anon';
const CALLBACK = new URL('https://zepto.example/auth/callback?code=c1');
const ANA = 'auth0|ana';
const CHALLENGE = base64url.encode('login-challenge-bytes');
const ENDED = 'The agent session has already ended; refusing to create an already-expired session.';

// The ID token that the fake Auth0 answers with. A test sets it for each login.
let idToken: string | undefined;

const server = setupServer(
  http.get(`https://${POPPY_DOMAIN}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: POPPY_ISSUER,
      authorization_endpoint: `https://${POPPY_DOMAIN}/authorize`,
      token_endpoint: `https://${POPPY_DOMAIN}/oauth/token`,
      backchannel_authentication_endpoint: `https://${POPPY_DOMAIN}/bc-authorize`,
      jwks_uri: `https://${POPPY_DOMAIN}/.well-known/jwks.json`,
    })
  ),
  http.get(`https://${POPPY_DOMAIN}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks })),
  // A short interval, so that the polling of a backchannel login does not slow the test.
  http.post(`https://${POPPY_DOMAIN}/bc-authorize`, () =>
    HttpResponse.json({ auth_req_id: 'auth_req_1', interval: 0.01, expires_in: 60 })
  ),
  http.post(`https://${POPPY_DOMAIN}/passkey/challenge`, () =>
    HttpResponse.json({
      auth_session: 'auth_session_1',
      authn_params_public_key: { challenge: CHALLENGE, rpId: POPPY_DOMAIN, timeout: 60000 },
    })
  ),
  // Every grant gets the same answer: the access token and the refresh token of a login, and the ID token of the test.
  http.post(`https://${POPPY_DOMAIN}/oauth/token`, () =>
    HttpResponse.json({
      ...(idToken !== undefined && { id_token: idToken }),
      access_token: 'at_login',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: JOIN_SCOPE,
      refresh_token: 'rt_login',
    })
  )
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

beforeEach(() => {
  idToken = undefined;
  // Only the clock is fake. The time has a fraction of a second, as the real time has.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-11-10T10:00:00.400Z'));
});

afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const now = () => Math.floor(Date.now() / 1000);

// Moves the clock on.
const later = (seconds: number) => vi.setSystemTime(Date.now() + seconds * 1000);

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

  // Deletes the sessions of the logout token by `sid`, as a real session store does.
  async deleteByLogoutToken(claims: { sid?: string; sub?: string }) {
    for (const [id, stateData] of this.sessions) {
      if (claims.sid !== undefined && stateData.internal.sid === claims.sid) {
        this.sessions.delete(id);
      }
    }
  }
}

// A website with one browser. `poppy: false` leaves the `poppy` option out.
interface App {
  browser: Browser;
  client: ServerClient<Browser>;
  transactionStore: CookieTransactionStore<Browser>;
  stateStore: StateStore<Browser>;
  guestStore: StatelessPoppyGuestStore<Browser>;
  anonymousStore: StatelessAnonymousStore<Browser>;
  /** What a stateful state store keeps on the server. It is empty with a stateless one. */
  sessions: MemorySessionStore;
}

function createApp(
  options: {
    poppy?: boolean;
    stateful?: boolean;
    agentSessionMaxAge?: number;
    clearAnonymousSessionOnLogin?: boolean;
    authorizationParams?: Record<string, string>;
  } = {}
): App {
  const browser: Browser = new Map();
  const cookies = new BrowserCookieHandler();
  const sessions = new MemorySessionStore();
  const transactionStore = new CookieTransactionStore<Browser>({ secret: SECRET }, cookies);
  const stateStore: StateStore<Browser> = options.stateful
    ? new StatefulStateStore<Browser>({ secret: SECRET, store: sessions }, cookies)
    : new StatelessStateStore<Browser>({ secret: SECRET }, cookies);
  const guestStore = new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, cookies);
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
    authorizationParams: options.authorizationParams,
    poppy:
      options.poppy === false
        ? undefined
        : { config: createPoppyConfig(), guestStore, agentSessionMaxAge: options.agentSessionMaxAge },
  });

  return { browser, client, transactionStore, stateStore, guestStore, anonymousStore, sessions };
}

const stateOf = (app: App) => app.stateStore.get(STATE_ID, app.browser);

// The tokens of a login. A guest has both markers. A signed-in agent has the user as `sub`. A person has no `act`.
const guestToken = (more: AgentIdTokenOptions = {}): AgentIdTokenOptions => ({
  sub: GUEST_SUB,
  subProfile: ANONYMOUS_USER_PROFILE,
  act: agentAct(),
  ...more,
});
const agentToken = (more: AgentIdTokenOptions = {}): AgentIdTokenOptions => ({ sub: ANA, act: agentAct(), ...more });
const personToken = (more: AgentIdTokenOptions = {}): AgentIdTokenOptions => ({ sub: ANA, act: null, ...more });

// A guest of an earlier join, written straight into the guest store, so that a test does not depend on the code that it
// tests to set up its browser.
function seedGuest(app: App, overrides: Partial<PoppyGuestData> = {}) {
  return app.guestStore.set(GUEST_ID, guestRecord(overrides), false, app.browser);
}

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

// What a customer's own login leaves in the state store.
function ownLogin(sub = ANA): StateData {
  const at = now();

  return {
    user: { sub, iss: POPPY_ISSUER, name: 'Own Login', email: 'old@zepto.example' },
    idToken: 'old.id.token',
    refreshToken: 'rt_old',
    tokenSets: [{ audience: 'default', accessToken: 'at_old', scope: 'openid profile email', expiresAt: at + 600 }],
    connectionTokenSets: [
      { connection: 'google-oauth2', accessToken: 'ct_old', scope: 'calendar.read', expiresAt: at + 600 },
    ],
    domain: POPPY_DOMAIN,
    sessionExpiresAt: at + 9000,
    internal: { sid: 'old_sid', createdAt: at },
  };
}

const seedOwnLogin = (app: App) => app.stateStore.set(STATE_ID, ownLogin(), false, app.browser);

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

// The raw cookies of one store, by name. Every write encrypts with a new key, so a store that is written again gets new
// values: equal lists mean that the store was not touched.
const cookiesOf = (app: App, name: string): Array<[string, string]> =>
  [...app.browser]
    .filter(([cookie]) => cookie.startsWith(name))
    .map(([cookie, { value }]): [string, string] => [cookie, value])
    .sort(([a], [b]) => a.localeCompare(b));

// Every cookie of the browser except the ones of the transaction of the login, which the code exchange has spent. Equal
// snapshots mean that nothing was added, changed or removed.
const snapshot = (app: App): Record<string, string> =>
  Object.fromEntries(
    [...app.browser]
      .filter(([name]) => !name.startsWith(TRANSACTION_ID) && !name.startsWith(PASSKEY_TRANSACTION_ID))
      .map(([name, { value }]): [string, string] => [name, value])
  );

// What `navigator.credentials.get()` returns for the challenge of the login.
const credential = {
  id: 'cred_1',
  rawId: 'cred_1',
  type: 'public-key',
  response: {
    clientDataJSON: base64url.encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: CHALLENGE,
        origin: 'https://zepto.example',
        crossOrigin: false,
      })
    ),
    authenticatorData: 'fake_authenticator_data',
    signature: 'fake_signature',
  },
};

interface LoginPath {
  name: string;
  /** Whether it is the redirect callback, which is the only path where a guest can join. */
  callback: boolean;
  /** Logs the browser in with the method. The fake Auth0 answers with the current `idToken`. */
  run: (app: App) => Promise<unknown>;
}

// Every method that writes a user session. A new one has to be added here.
const PATHS: LoginPath[] = [
  {
    name: 'completeInteractiveLogin',
    callback: true,
    run: async (app) => {
      await app.transactionStore.set(TRANSACTION_ID, { codeVerifier: 'cv', domain: POPPY_DOMAIN }, false, app.browser);
      await app.client.completeInteractiveLogin(CALLBACK, app.browser);
    },
  },
  {
    name: 'passkey.complete',
    callback: false,
    run: async (app) => {
      await app.client.passkey.startLogin(undefined, app.browser);
      await app.client.passkey.complete({ credential }, app.browser);
    },
  },
  {
    name: 'passkey.getToken',
    callback: false,
    run: (app) => app.client.passkey.getToken({ authSession: 'auth_session_1', credential }, app.browser),
  },
  {
    name: 'completePasswordless',
    callback: false,
    run: (app) =>
      app.client.completePasswordless(
        { connection: 'email', email: 'ana@zepto.example', verificationCode: '123456' },
        app.browser
      ),
  },
  {
    name: 'completePasswordlessMagicLink',
    callback: false,
    run: async (app) => {
      await app.transactionStore.set(TRANSACTION_ID, { state: 'state_1', domain: POPPY_DOMAIN }, false, app.browser);
      await app.client.completePasswordlessMagicLink(
        new URL('https://zepto.example/auth/callback?code=c1&state=state_1'),
        app.browser
      );
    },
  },
  {
    name: 'loginBackchannel',
    callback: false,
    run: (app) => app.client.loginBackchannel({ loginHint: { sub: ANA }, bindingMessage: 'Sign in' }, app.browser),
  },
  {
    name: 'loginWithCustomTokenExchange',
    callback: false,
    run: (app) =>
      app.client.loginWithCustomTokenExchange(
        { subjectToken: 'external_token', subjectTokenType: 'urn:acme:legacy-token' },
        app.browser
      ),
  },
  {
    name: 'mfa.verify',
    callback: false,
    run: (app) => app.client.mfa.verify({ mfaToken: 'mfa_token', factorType: 'otp', otp: '123456' }, app.browser),
  },
];

const NON_CALLBACK_PATHS = PATHS.filter((path) => !path.callback);

// The login of the token with the method, and the error that it throws, or `undefined` when it throws none.
async function attempt(app: App, path: LoginPath, token: AgentIdTokenOptions): Promise<unknown> {
  idToken = await agentIdToken(token);

  return path.run(app).then(
    () => undefined,
    (error: unknown) => error
  );
}

// The login must work, and must not throw.
async function login(app: App, path: LoginPath, token: AgentIdTokenOptions): Promise<void> {
  const error = await attempt(app, path, token);

  expect(error).toBeUndefined();
}

function expectPoppyError(error: unknown, code: PoppyErrorCode): asserts error is PoppyError {
  expect(error).toBeInstanceOf(PoppyError);
  expect((error as PoppyError).code).toBe(code);
}

// A browser that holds a guest, a person's own login and an anonymous session, so that a refusal that writes nothing
// shows: none of the three may change.
async function appWithEverything(options?: Parameters<typeof createApp>[0]): Promise<App> {
  const app = createApp(options);
  await seedGuest(app);
  await seedAnonymousSession(app);

  expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);
  expect(cookiesOf(app, ANONYMOUS_ID)).not.toEqual([]);

  return app;
}

describe.each(PATHS)('$name | a guest in the browser', (path) => {
  test('refuses the login of a person, and writes nothing: the guest stays and there is no user session', async () => {
    const app = await appWithEverything();
    const before = snapshot(app);
    const stateSet = vi.spyOn(app.stateStore, 'set');
    const stateDelete = vi.spyOn(app.stateStore, 'delete');

    const error = await attempt(app, path, personToken());

    expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
    expect(snapshot(app)).toEqual(before);
    expect(stateSet).not.toHaveBeenCalled();
    expect(stateDelete).not.toHaveBeenCalled();
    expect(await app.client.getUser(app.browser)).toBeUndefined();
    expect(await app.client.poppy.getContext(app.browser)).toMatchObject({ kind: 'agent', state: 'guest' });
  });

  test('lets a signed-in agent replace the guest: a fresh agent session, no guest, and no anonymous session', async () => {
    const app = await appWithEverything();
    const at = now();

    await login(app, path, agentToken());

    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.user?.act?.poppy_sid).toBe(SESSION_ID);
    expect(state?.sessionExpiresAt).toBe(at + 3600);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('signed_in'));
  });

  test('lets a signed-in agent of another Session replace the guest: the agent is not compared with the guest', async () => {
    const app = await appWithEverything();

    await login(
      app,
      path,
      agentToken({ act: agentAct({ poppy_sid: OTHER_SESSION_ID, sub: 'https://other.example/a' }) })
    );

    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect((await stateOf(app))?.user?.act?.poppy_sid).toBe(OTHER_SESSION_ID);
  });

  test('is not blocked by a guest that has ended: the login works, and the guest is cleared', async () => {
    const app = createApp();
    // The deadline is 20 seconds away, which is inside the 30 seconds that count as ended.
    await seedGuest(app, { expiresAt: now() + 20 });
    await seedAnonymousSession(app);
    expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);

    await login(app, path, personToken());

    expect((await stateOf(app))?.user?.sub).toBe(ANA);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual({ kind: 'human' });
  });

  test('is not blocked by a guest whose encrypted value has ended: the login works, and the guest is cleared', async () => {
    const app = createApp();
    await seedGuest(app, { expiresAt: now() + 60 });
    // The store keeps the value 15 seconds past the end, and then it fails with an expired JWT.
    later(60 + 16);

    await login(app, path, personToken());

    expect((await stateOf(app))?.user?.sub).toBe(ANA);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });

  test('is not blocked by a guest record that lacks a member, and clears it', async () => {
    const app = createApp();
    await seedGuest(app, { act: { sub: 'https://agent.example/agent.json' } });
    expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual([]);

    await login(app, path, personToken());

    expect((await stateOf(app))?.user?.sub).toBe(ANA);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });

  test('an error of the guest store reaches the app, and nothing is written', async () => {
    const app = await appWithEverything();
    const before = snapshot(app);
    vi.spyOn(app.guestStore, 'get').mockRejectedValueOnce(new Error('guest store is down'));

    const error = await attempt(app, path, personToken());

    expect((error as Error).message).toBe('guest store is down');
    expect(snapshot(app)).toEqual(before);
  });
});

describe.each(PATHS)('$name | a login that looks like a guest but is not one', (path) => {
  // The values are secret, so a test can see that none of them reaches the error or the log.
  const rows: Array<{ name: string; token: AgentIdTokenOptions; reason: string }> = [
    {
      name: 'the guest sub and no sub_profile',
      token: guestToken({ sub: 'anon_poppy@secret-sub', subProfile: undefined }),
      reason: 'sub starts with anon_poppy@, but sub_profile is missing',
    },
    {
      name: 'the anonymous profile and a sub that is a user',
      token: guestToken({ sub: 'auth0|secret-user' }),
      reason: 'sub_profile marks an anonymous user, but sub does not start with anon_poppy@',
    },
    {
      name: 'both markers and no act',
      token: guestToken({ act: null }),
      reason: 'act is missing or is not an object',
    },
    {
      name: 'both markers and a poppy_sid that is not valid',
      token: guestToken({ act: agentAct({ poppy_sid: 'secret+sid' }) }),
      reason: 'act.poppy_sid is missing or invalid',
    },
  ];

  test.each(rows)(
    'refuses $name with invalid_poppy_guest, a reason with no value, and writes nothing',
    async ({ token, reason }) => {
      const app = await appWithEverything();
      await app.stateStore.set(STATE_ID, ownLogin(), false, app.browser);
      const before = snapshot(app);
      const log = vi.spyOn(console, 'error').mockImplementation(() => {});

      const error = await attempt(app, path, token);

      expectPoppyError(error, PoppyErrorCode.INVALID_GUEST);
      expect(error.reason).toBe(reason);
      expect(error.message).not.toContain(reason);
      expect(`${error.message} ${error.reason}`).not.toContain('secret');
      // The reason is logged once, and the log shows no value either.
      expect(log).toHaveBeenCalledTimes(1);
      expect(String(log.mock.calls[0]?.join(' '))).toContain(reason);
      expect(String(log.mock.calls[0]?.join(' '))).not.toContain('secret');
      expect(snapshot(app)).toEqual(before);
    }
  );

  test('is refused whether or not there is a guest in the browser, with a login that is not one either', async () => {
    const app = createApp();
    await seedOwnLogin(app);
    const before = snapshot(app);
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const error = await attempt(app, path, guestToken({ subProfile: 'user' }));

    expectPoppyError(error, PoppyErrorCode.INVALID_GUEST);
    expect(snapshot(app)).toEqual(before);
  });

  test('takes the usual path without the poppy option, as it always did', async () => {
    const app = createApp({ poppy: false });
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});

    await login(app, path, guestToken({ subProfile: 'user' }));

    expect(log).not.toHaveBeenCalled();
    expect((await stateOf(app))?.user?.sub).toBe(GUEST_SUB);
  });
});

describe.each(NON_CALLBACK_PATHS)('$name | a guest', (path) => {
  test('is refused with poppy_guest_not_supported, and nothing is written', async () => {
    const app = createApp();
    await seedOwnLogin(app);
    await seedAnonymousSession(app);
    const before = snapshot(app);

    const error = await attempt(app, path, guestToken());

    expectPoppyError(error, PoppyErrorCode.GUEST_NOT_SUPPORTED);
    expect(error.reason).toBeUndefined();
    expect(snapshot(app)).toEqual(before);
  });

  test('is refused with poppy_guest_not_supported when it is a new guest next to another guest', async () => {
    const app = await appWithEverything();
    const before = snapshot(app);

    const error = await attempt(app, path, guestToken({ act: agentAct({ poppy_sid: OTHER_SESSION_ID }) }));

    expectPoppyError(error, PoppyErrorCode.GUEST_NOT_SUPPORTED);
    expect(snapshot(app)).toEqual(before);
  });

  test('is refused with poppy_guest_not_supported in an empty browser too, and no guest is written', async () => {
    const app = createApp();

    const error = await attempt(app, path, guestToken());

    expectPoppyError(error, PoppyErrorCode.GUEST_NOT_SUPPORTED);
    expect(snapshot(app)).toEqual({});
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual({ kind: 'human' });
  });

  test('takes the usual path without the poppy option', async () => {
    const app = createApp({ poppy: false });

    await login(app, path, guestToken());

    expect((await stateOf(app))?.user?.sub).toBe(GUEST_SUB);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
  });
});

describe.each(NON_CALLBACK_PATHS)('$name | a signed-in agent', (path) => {
  // The same state and the same cap as the callback gives: a fresh session built from this login only, with no refresh
  // token, that ends at the deadline.
  test('gets the same agent state and cap as the callback', async () => {
    const app = createApp();
    await seedOwnLogin(app);
    await seedAnonymousSession(app);
    later(600);
    const at = now();

    await login(app, path, agentToken());

    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.user?.act).toStrictEqual(agentAct());
    // Nothing of the earlier login: not its claims, its token sets, its connection token or its refresh token.
    expect(state?.user).not.toHaveProperty('email');
    expect(state?.user).not.toHaveProperty('name');
    expect(state?.refreshToken).toBeUndefined();
    expect(state).not.toHaveProperty('connectionTokenSets');
    expect(state?.tokenSets).toStrictEqual([
      { audience: 'default', accessToken: 'at_login', scope: JOIN_SCOPE, expiresAt: at + 3600 },
    ]);
    expect(state?.sessionExpiresAt).toBe(at + 3600);
    expect(state?.domain).toBe(POPPY_DOMAIN);
    expect(state?.internal.createdAt).toBe(at);
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(agentContext('signed_in'));
  });

  test('ends at the earliest of agentSessionMaxAge, exp and session_expiry', async () => {
    const at = now();
    const cases = [
      { options: { agentSessionMaxAge: 600 }, token: agentToken(), seconds: 600 },
      { options: {}, token: agentToken({ exp: at + 1800 }), seconds: 1800 },
      { options: {}, token: agentToken({ claims: { session_expiry: at + 3000 } }), seconds: 3000 },
    ];

    for (const { options, token, seconds } of cases) {
      const app = createApp(options);

      await login(app, path, token);

      expect((await stateOf(app))?.sessionExpiresAt).toBe(at + seconds);
    }
  });

  // The default of `agentSessionMaxAge` is the only limit here: the token lasts three hours and has no `session_expiry`.
  test('ends two hours after the login when agentSessionMaxAge is not set and the token lasts longer', async () => {
    const app = createApp();
    const at = now();

    await login(app, path, agentToken({ exp: at + 3 * 3600 }));

    expect((await stateOf(app))?.sessionExpiresAt).toBe(at + 7200);
  });

  // A read never extends the deadline, but a new login does start a new one. `EXAMPLES.md` says so, so the test pins it:
  // a silent login of the same Session, after the first session has ended, gets a deadline from its own time.
  test('gets a new deadline from a new login of the same Session, and a read does not extend it', async () => {
    const app = createApp({ agentSessionMaxAge: 300 });
    const first = now();

    await login(app, path, agentToken());
    expect((await stateOf(app))?.sessionExpiresAt).toBe(first + 300);

    later(100);
    await app.client.getSession(app.browser);
    expect((await stateOf(app))?.sessionExpiresAt).toBe(first + 300);

    later(200);
    const second = now();
    await login(app, path, agentToken());
    expect((await stateOf(app))?.sessionExpiresAt).toBe(second + 300);
  });

  test('is a session that ends 30 seconds before the deadline', async () => {
    const app = createApp({ agentSessionMaxAge: 600 });
    await login(app, path, agentToken());

    later(569);
    expect(await app.client.getSession(app.browser)).toBeDefined();

    later(1);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
  });

  test.each([
    { name: 'the exp of the ID token is in the past', token: (at: number) => agentToken({ exp: at - 10 }) },
    { name: 'the deadline is 30 seconds away', token: (at: number) => agentToken({ exp: at + 30 }) },
    {
      name: 'session_expiry is in the past',
      token: (at: number) => agentToken({ claims: { session_expiry: at - 1 } }),
    },
  ])('is refused with SessionExpiredError when $name, and nothing is written', async ({ token }) => {
    const app = createApp();
    await seedOwnLogin(app);
    await seedAnonymousSession(app);
    const before = snapshot(app);

    const error = await attempt(app, path, token(now()));

    expect(error).toBeInstanceOf(SessionExpiredError);
    expect((error as Error).message).toBe(ENDED);
    expect(snapshot(app)).toEqual(before);
  });

  test.each([
    { name: 'a poppy_sid that is a number', act: () => agentAct({ poppy_sid: 42 }), member: 'act.poppy_sid' as const },
    { name: 'no act.sub', act: () => agentAct({ sub: undefined }), member: 'act.sub' as const },
  ])(
    'is refused with invalid_poppy_agent for $name, with a reason that has no value, and nothing is written',
    async ({ act, member }) => {
      const app = createApp();
      await seedOwnLogin(app);
      const before = snapshot(app);
      const log = vi.spyOn(console, 'error').mockImplementation(() => {});

      const error = await attempt(app, path, agentToken({ act: act() }));

      expectPoppyError(error, PoppyErrorCode.INVALID_AGENT);
      expect(error.reason).toBe(`${member} is missing or invalid`);
      expect(error.message).not.toContain(member);
      // The reason is logged once, as it is for a guest, and it is a claim name, never a value.
      expect(log).toHaveBeenCalledTimes(1);
      expect(log).toHaveBeenCalledWith(
        `[Auth0] Poppy: refused a login with an agent state that is not valid: ${member} is missing or invalid.`
      );
      expect(snapshot(app)).toEqual(before);
    }
  );

  test('takes the usual path without the poppy option: the act is kept as the token has it, and the refresh token too', async () => {
    const app = createApp({ poppy: false });

    await login(app, path, agentToken());

    const state = await stateOf(app);
    expect(state?.user?.act).toStrictEqual(agentAct());
    expect(state?.refreshToken).toBe('rt_login');
    expect(state?.sessionExpiresAt).toBeUndefined();
  });
});

describe.each(PATHS)('$name | a person', (path) => {
  test('logs in as before when there is no guest, and the anonymous session is cleared', async () => {
    const app = createApp();
    await seedAnonymousSession(app);

    await login(app, path, personToken());

    const state = await stateOf(app);
    expect(state?.user?.sub).toBe(ANA);
    expect(state?.refreshToken).toBe('rt_login');
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    expect(await app.client.poppy.getContext(app.browser)).toStrictEqual({ kind: 'human' });
  });

  test('clears a guest cookie that holds nothing the SDK can open', async () => {
    const app = createApp();
    app.browser.set(`${GUEST_COOKIE}.0`, { value: 'not-a-guest' });

    await login(app, path, personToken());

    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect((await stateOf(app))?.user?.sub).toBe(ANA);
  });

  test('over a guest, is refused without the guest being read out loud: nothing of it reaches the error', async () => {
    const app = await appWithEverything();

    const error = await attempt(app, path, personToken());

    expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
    expect(error.reason).toBeUndefined();
    expect(error.message).not.toContain(GUEST_SUB);
    expect(error.message).not.toContain(SESSION_ID);
  });

  test('without the poppy option, is not touched by a guest cookie: no guest is read, and none is cleared', async () => {
    const app = createApp({ poppy: false });
    await seedGuest(app);
    const guest = cookiesOf(app, GUEST_COOKIE);

    await login(app, path, personToken());

    expect((await stateOf(app))?.user?.sub).toBe(ANA);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual(guest);
  });
});

describe('completeInteractiveLogin | a guest in the browser', () => {
  const callback = PATHS[0] as LoginPath;

  test('refuses the same guest coming back from a login that is not silent while its access token is valid, and keeps the guest as it was', async () => {
    const app = await appWithEverything();
    const before = snapshot(app);

    // The same `sub` and the same `poppy_sid` as the guest of the browser.
    const error = await attempt(app, callback, guestToken());

    expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
    expect(snapshot(app)).toEqual(before);
  });

  test.each([
    { name: 'another sub', token: guestToken({ sub: 'anon_poppy@another-guest' }), sessionId: SESSION_ID },
    {
      name: 'another poppy_sid',
      token: guestToken({ act: agentAct({ poppy_sid: OTHER_SESSION_ID }) }),
      sessionId: OTHER_SESSION_ID,
    },
    {
      name: 'another sub and another poppy_sid',
      token: guestToken({ sub: 'anon_poppy@another-guest', act: agentAct({ poppy_sid: OTHER_SESSION_ID }) }),
      sessionId: OTHER_SESSION_ID,
    },
  ])(
    'replaces the guest with a new guest that has $name, and clears the anonymous session',
    async ({ token, sessionId }) => {
      const app = await appWithEverything();
      const before = cookiesOf(app, GUEST_COOKIE);
      later(60);
      const at = now();

      await login(app, callback, token);

      const guest = await guestOf(app);
      expect(guest?.act.poppy_sid).toBe(sessionId);
      expect(guest?.sub).toBe(token.sub);
      expect(guest?.createdAt).toBe(at);
      expect(cookiesOf(app, GUEST_COOKIE)).not.toEqual(before);
      expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
      expect(cookiesOf(app, STATE_ID)).toEqual([]);
      expect(await app.client.getUser(app.browser)).toBeUndefined();
    }
  );

  test('keeps the anonymous session of the browser when clearAnonymousSessionOnLogin is false', async () => {
    const app = createApp({ clearAnonymousSessionOnLogin: false });
    await seedAnonymousSession(app);
    const anonymous = cookiesOf(app, ANONYMOUS_ID);

    await login(app, callback, guestToken());

    expect(await guestOf(app)).toBeDefined();
    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual(anonymous);
  });

  test('clears the anonymous session of the browser when a guest joins a browser that had none other', async () => {
    const app = createApp();
    await seedAnonymousSession(app);

    await login(app, callback, guestToken());

    expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
    expect(await guestOf(app)).toBeDefined();
  });

  // The same guest (`sub` and `poppy_sid`) comes back once its access token has expired: Auth0 answers the silent login of
  // a guest's own session with the same guest. It gets the new token, and keeps the first join's deadline and creation time.
  describe('whose access token has expired', () => {
    // `seedGuest` makes a token that lasts 600 s and a guest that lasts 3600 s.
    const TOKEN_LIFETIME = 600;
    const GUEST_LIFETIME = 3600;

    test('accepts the same guest as a renewal: the new token, the creation time and the deadline of the first join', async () => {
      const app = await appWithEverything();
      const first = await guestOf(app);
      later(TOKEN_LIFETIME + 1);
      const at = now();

      await login(app, callback, guestToken());

      const guest = await guestOf(app);
      expect(guest?.tokenSets?.[0]?.accessToken).toBe('at_login');
      expect(guest?.tokenSets?.[0]?.expiresAt).toBe(at + 3600);
      // Auth0 would give this login an ID token that lasts one more hour, but a renewal never moves the end of the guest.
      expect(guest?.createdAt).toBe(first?.createdAt);
      expect(guest?.expiresAt).toBe(first?.expiresAt);
      expect(cookiesOf(app, ANONYMOUS_ID)).toEqual([]);
      expect(await app.client.poppy.getContext(app.browser)).toMatchObject({ kind: 'agent', state: 'guest' });
    });

    test('accepts it when the token ends at this very second, and refuses it one second before', async () => {
      const app = await appWithEverything();

      later(TOKEN_LIFETIME - 1);
      expectPoppyError(await attempt(app, callback, guestToken()), PoppyErrorCode.SIGN_IN_REQUIRED);

      later(1);
      await login(app, callback, guestToken());
      expect((await guestOf(app))?.tokenSets?.[0]?.accessToken).toBe('at_login');
    });

    test('lets the renewal shorten the deadline, never extend it', async () => {
      const app = createApp({ agentSessionMaxAge: 900 });
      await seedGuest(app);
      const first = await guestOf(app);
      later(TOKEN_LIFETIME + 1);
      const at = now();

      await login(app, callback, guestToken());

      // The new deadline is 900 s from now, which is earlier than the one of the first join.
      expect((await guestOf(app))?.expiresAt).toBe(at + 900);
      expect(at + 900).toBeLessThan(first?.expiresAt as number);
    });

    test('renews a guest of a longer lifetime that no setting can stretch', async () => {
      const app = createApp({ agentSessionMaxAge: 36000 });
      await seedGuest(app);
      const first = await guestOf(app);
      later(TOKEN_LIFETIME + 1);

      await login(app, callback, guestToken({ exp: now() + 7200 }));

      expect((await guestOf(app))?.expiresAt).toBe(first?.expiresAt);
    });

    test('is refused for a person: the browser is still the agent’s, and nothing is written', async () => {
      const app = await appWithEverything();
      later(TOKEN_LIFETIME + 1);
      const before = snapshot(app);

      const error = await attempt(app, callback, personToken());

      expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
      expect(snapshot(app)).toEqual(before);
    });

    test('is a new guest, not a renewal, when the Poppy Session is another one', async () => {
      const app = await appWithEverything();
      later(TOKEN_LIFETIME + 1);
      const at = now();

      await login(app, callback, guestToken({ act: agentAct({ poppy_sid: OTHER_SESSION_ID }) }));

      const guest = await guestOf(app);
      expect(guest?.createdAt).toBe(at);
      expect(guest?.expiresAt).toBe(at + 3600);
      expect(guest?.act.poppy_sid).toBe(OTHER_SESSION_ID);
    });

    test('is a new guest, not a renewal, when the sub is another one', async () => {
      const app = await appWithEverything();
      later(TOKEN_LIFETIME + 1);
      const at = now();

      // The same Poppy Session, but another guest `sub`.
      await login(app, callback, guestToken({ sub: 'anon_poppy@another-guest' }));

      const guest = await guestOf(app);
      expect(guest?.sub).toBe('anon_poppy@another-guest');
      expect(guest?.createdAt).toBe(at);
      expect(guest?.expiresAt).toBe(at + 3600);
    });

    test('is a renewal that sets the creation time to now when the stored guest has none that the SDK can use', async () => {
      const app = createApp();
      // The member is left out of the JSON that the store writes, as a custom store with an odd record would give it.
      await seedGuest(app, { createdAt: undefined as unknown as number });
      const first = await guestOf(app);
      expect(first?.createdAt).toBeUndefined();
      later(TOKEN_LIFETIME + 1);
      const at = now();

      await login(app, callback, guestToken());

      const guest = await guestOf(app);
      expect(guest?.createdAt).toBe(at);
      // The deadline is still clamped to the stored one.
      expect(guest?.expiresAt).toBe(first?.expiresAt);
    });

    test('is a new guest with a new deadline when the stored guest is in its last 30 seconds: that guest has ended', async () => {
      const app = await appWithEverything();
      const first = await guestOf(app);
      later(GUEST_LIFETIME - 20);
      const at = now();

      await login(app, callback, guestToken());

      const guest = await guestOf(app);
      expect(guest?.createdAt).toBe(at);
      expect(guest?.expiresAt).toBe(at + 3600);
      expect(guest?.expiresAt).toBeGreaterThan(first?.expiresAt as number);
    });

    test('is treated as a renewal when the guest holds no token at all', async () => {
      const app = createApp();
      await seedGuest(app, { tokenSets: [] });
      const first = await guestOf(app);
      later(60);

      await login(app, callback, guestToken());

      const guest = await guestOf(app);
      expect(guest?.tokenSets?.[0]?.accessToken).toBe('at_login');
      expect(guest?.createdAt).toBe(first?.createdAt);
      expect(guest?.expiresAt).toBe(first?.expiresAt);
    });

    test('ends where it must: a guest whose deadline has passed is no guest, and a new join starts a new deadline', async () => {
      const app = await appWithEverything();
      later(GUEST_LIFETIME + 1);
      const at = now();

      await login(app, callback, guestToken());

      const guest = await guestOf(app);
      expect(guest?.createdAt).toBe(at);
      expect(guest?.expiresAt).toBe(at + 3600);
    });
  });

  // What Auth0 answers to a `prompt=none` request is the login of its own session: a person's, or the guest's own. The
  // transaction of the login remembers that it was silent, and the guard reads that flag, never `prompt` itself. On Auth0,
  // a silent login over a guest gives the same guest back, and the app started it on purpose, so it is a refresh.
  describe('that makes a silent login (prompt=none)', () => {
    const start = (app: App, authorizationParams: Record<string, string> = { prompt: 'none' }) =>
      app.client.startInteractiveLogin(
        { authorizationParams: { ...authorizationParams, redirect_uri: 'https://zepto.example/auth/callback' } },
        app.browser
      );

    const silent = async (app: App, token: AgentIdTokenOptions) => {
      await start(app);
      idToken = await agentIdToken(token);

      return app.client.completeInteractiveLogin(CALLBACK, app.browser).then(
        () => undefined,
        (error: unknown) => error
      );
    };

    test('over a guest is refused for a person, and writes nothing', async () => {
      // No anonymous session: a login that starts with one asks Auth0 for a transfer token, which is not what this tests.
      const app = createApp();
      await seedGuest(app);
      const before = snapshot(app);

      const error = await silent(app, personToken());

      expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
      expect(snapshot(app)).toEqual(before);
    });

    test('with no guest in the browser is a normal login', async () => {
      const app = createApp();

      const error = await silent(app, personToken());

      expect(error).toBeUndefined();
      expect((await stateOf(app))?.user?.sub).toBe(ANA);
    });

    test('gives the same guest a refresh while its token is valid: the new token, and the first join kept', async () => {
      const app = createApp();
      await seedGuest(app);
      const first = await guestOf(app);
      later(60);
      const at = now();

      const error = await silent(app, guestToken());

      expect(error).toBeUndefined();
      const guest = await guestOf(app);
      expect(guest?.tokenSets?.[0]?.accessToken).toBe('at_login');
      expect(guest?.tokenSets?.[0]?.expiresAt).toBe(at + 3600);
      // A refresh never moves the end of the guest, and the guest is still no user.
      expect(guest?.createdAt).toBe(first?.createdAt);
      expect(guest?.expiresAt).toBe(first?.expiresAt);
      expect(cookiesOf(app, STATE_ID)).toEqual([]);
      expect(await app.client.getUser(app.browser)).toBeUndefined();
      expect(await app.client.poppy.getContext(app.browser)).toMatchObject({ kind: 'agent', state: 'guest' });
    });

    test('lets the refresh shorten the deadline, never extend it', async () => {
      const app = createApp({ agentSessionMaxAge: 900 });
      await seedGuest(app);
      const first = await guestOf(app);
      later(60);
      const at = now();

      expect(await silent(app, guestToken())).toBeUndefined();

      expect((await guestOf(app))?.expiresAt).toBe(at + 900);
      expect(at + 900).toBeLessThan(first?.expiresAt as number);
    });

    test('keeps the first deadline when the guest is refreshed twice', async () => {
      const app = createApp();
      await seedGuest(app);
      const first = await guestOf(app);

      later(60);
      expect(await silent(app, guestToken())).toBeUndefined();
      later(60);
      expect(await silent(app, guestToken())).toBeUndefined();

      expect((await guestOf(app))?.expiresAt).toBe(first?.expiresAt);
      expect((await guestOf(app))?.createdAt).toBe(first?.createdAt);
    });

    test('starts a new guest when the stored guest is in its last 30 seconds', async () => {
      const app = createApp();
      await seedGuest(app, { expiresAt: now() + 20 });
      const at = now();

      expect(await silent(app, guestToken())).toBeUndefined();

      const guest = await guestOf(app);
      expect(guest?.createdAt).toBe(at);
      expect(guest?.expiresAt).toBe(at + 3600);
    });

    test('replaces the guest with a new guest and with a signed-in agent, as any login does', async () => {
      const newGuest = createApp();
      await seedGuest(newGuest);
      expect(await silent(newGuest, guestToken({ sub: 'anon_poppy@another-guest' }))).toBeUndefined();
      expect((await guestOf(newGuest))?.sub).toBe('anon_poppy@another-guest');

      const signedIn = createApp();
      await seedGuest(signedIn);
      expect(await silent(signedIn, agentToken())).toBeUndefined();
      expect(cookiesOf(signedIn, GUEST_COOKIE)).toEqual([]);
      expect((await stateOf(signedIn))?.user?.sub).toBe(ANA);
    });

    test('is a silent login when the client sets prompt=none for every login', async () => {
      const app = createApp({ authorizationParams: { prompt: 'none' } });
      await seedGuest(app);
      const first = await guestOf(app);
      await app.client.startInteractiveLogin(
        { authorizationParams: { redirect_uri: 'https://zepto.example/auth/callback' } },
        app.browser
      );
      idToken = await agentIdToken(guestToken());

      await app.client.completeInteractiveLogin(CALLBACK, app.browser);

      const guest = await guestOf(app);
      expect(guest?.tokenSets?.[0]?.accessToken).toBe('at_login');
      // A refresh, and not a new guest: the first join is kept.
      expect(guest?.createdAt).toBe(first?.createdAt);
      expect(guest?.expiresAt).toBe(first?.expiresAt);
    });

    test('renews a guest whose access token has expired, as it does while the token is valid', async () => {
      const app = createApp();
      await seedGuest(app);
      const first = await guestOf(app);
      later(601);

      expect(await silent(app, guestToken())).toBeUndefined();

      const guest = await guestOf(app);
      expect(guest?.tokenSets?.[0]?.accessToken).toBe('at_login');
      expect(guest?.createdAt).toBe(first?.createdAt);
      expect(guest?.expiresAt).toBe(first?.expiresAt);
    });

    // Only the boolean `true` that the SDK wrote counts. A store that gives back anything else is not trusted.
    test.each(['true', 1, {}, ['none']])('does not take %j in the transaction for a silent login', async (forged) => {
      const app = createApp();
      await seedGuest(app);
      const before = snapshot(app);
      await app.transactionStore.set(
        TRANSACTION_ID,
        { codeVerifier: 'cv', domain: POPPY_DOMAIN, silent: forged as boolean },
        false,
        app.browser
      );
      idToken = await agentIdToken(guestToken());

      const error = await app.client.completeInteractiveLogin(CALLBACK, app.browser).then(
        () => undefined,
        (e: unknown) => e
      );

      expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
      expect(snapshot(app)).toEqual(before);
    });

    // `AuthClient` merges the parameters of the login over those of the client, and drops an `undefined`, so the request
    // that goes to Auth0 has no `prompt`. The transaction must say the same.
    test('is not a silent login when the login takes the prompt of the client away with undefined', async () => {
      const app = createApp({ authorizationParams: { prompt: 'none' } });
      await seedGuest(app);
      const before = snapshot(app);
      const url = await app.client.startInteractiveLogin(
        {
          authorizationParams: {
            prompt: undefined,
            redirect_uri: 'https://zepto.example/auth/callback',
          } as unknown as Record<string, string>,
        },
        app.browser
      );
      idToken = await agentIdToken(guestToken());

      expect(url.searchParams.has('prompt')).toBe(false);
      const error = await app.client.completeInteractiveLogin(CALLBACK, app.browser).then(
        () => undefined,
        (e: unknown) => e
      );

      expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
      expect(snapshot(app)).toEqual(before);
    });

    test.each([
      { name: 'no prompt', params: {} as Record<string, string> },
      { name: 'prompt=login', params: { prompt: 'login' } },
      { name: 'prompt=consent', params: { prompt: 'consent' } },
    ])('is not a silent login with $name: the same guest is refused while its token is valid', async ({ params }) => {
      const app = createApp();
      await seedGuest(app);
      const before = snapshot(app);
      await start(app, params);
      idToken = await agentIdToken(guestToken());

      const error = await app.client.completeInteractiveLogin(CALLBACK, app.browser).then(
        () => undefined,
        (e: unknown) => e
      );

      expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
      expect(snapshot(app)).toEqual(before);
    });
  });

  describe('the transaction of a login', () => {
    const transactionOf = (app: App) => app.transactionStore.get(TRANSACTION_ID, app.browser);
    const start = (app: App, prompt?: string) =>
      app.client.startInteractiveLogin(
        { authorizationParams: { ...(prompt && { prompt }), redirect_uri: 'https://zepto.example/auth/callback' } },
        app.browser
      );

    test('remembers a silent login, with the poppy option', async () => {
      const app = createApp();

      await start(app, 'none');

      expect((await transactionOf(app))?.silent).toBe(true);
    });

    test.each([undefined, 'login', 'consent', 'none login'])('does not remember a login with prompt=%s', async (prompt) => {
      const app = createApp();

      await start(app, prompt);

      expect(await transactionOf(app)).not.toHaveProperty('silent');
    });

    // Without the option, the transaction of an app is what it was before Poppy: nothing new in it.
    test('does not remember anything new without the poppy option', async () => {
      const app = createApp({ poppy: false });

      await start(app, 'none');

      expect(await transactionOf(app)).not.toHaveProperty('silent');
    });
  });
});

describe('the guard | when a store fails', () => {
  const callback = PATHS[0] as LoginPath;

  test('a failing delete of the guest, on an accepted login, reaches the app and no session is written', async () => {
    const app = createApp();
    await seedGuest(app, { expiresAt: now() + 20 });
    vi.spyOn(app.guestStore, 'delete').mockRejectedValueOnce(new Error('guest store is down'));
    const stateSet = vi.spyOn(app.stateStore, 'set');

    const error = await attempt(app, callback, personToken());

    expect((error as Error).message).toBe('guest store is down');
    expect(stateSet).not.toHaveBeenCalled();
  });

  test("a person's login over an ended guest: a failed write of the session leaves no guest behind, and no session", async () => {
    const app = createApp();
    await seedGuest(app, { expiresAt: now() + 20 });
    vi.spyOn(app.stateStore, 'set').mockRejectedValueOnce(new Error('state store is down'));

    const error = await attempt(app, callback, personToken());

    expect((error as Error).message).toBe('state store is down');
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect(cookiesOf(app, STATE_ID)).toEqual([]);
  });
});

describe('the guard | a stateful state store', () => {
  test.each(PATHS)('$name: a refused login leaves the record of the session store as it was', async (path) => {
    const app = createApp({ stateful: true });
    await seedGuest(app);
    const records = [...app.sessions.sessions];

    const error = await attempt(app, path, personToken());

    expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
    expect([...app.sessions.sessions]).toEqual(records);
  });

  test.each(NON_CALLBACK_PATHS)(
    '$name: a signed-in agent gets a new session id, and the old record is gone',
    async (path) => {
      const app = createApp({ stateful: true });
      await seedOwnLogin(app);
      const [oldId] = [...app.sessions.sessions.keys()];

      await login(app, path, agentToken());

      const ids = [...app.sessions.sessions.keys()];
      expect(ids).toHaveLength(1);
      expect(ids[0]).not.toBe(oldId);
      expect(app.sessions.sessions.get(ids[0] as string)?.refreshToken).toBeUndefined();
    }
  );
});

describe('mfa.verify | what the caller gets back', () => {
  const mfa = PATHS.find(({ name }) => name === 'mfa.verify') as LoginPath;

  test('has no refresh token for a signed-in agent, as the session has none', async () => {
    const app = createApp();
    idToken = await agentIdToken(agentToken());

    const result = (await mfa.run(app)) as { refreshToken?: string };

    expect(result).not.toHaveProperty('refreshToken');
    expect((await stateOf(app))?.refreshToken).toBeUndefined();
  });

  test('has the refresh token for a person, as it always had', async () => {
    const app = createApp();
    idToken = await agentIdToken(personToken());

    const result = (await mfa.run(app)) as { refreshToken?: string };

    expect(result.refreshToken).toBe('rt_login');
  });
});

describe('completeInteractiveLogin | the default deadline of a guest', () => {
  test('ends two hours after the join when agentSessionMaxAge is not set and the token lasts longer', async () => {
    const app = createApp();
    const at = now();

    await login(app, PATHS[0] as LoginPath, guestToken({ exp: at + 3 * 3600 }));

    expect((await guestOf(app))?.expiresAt).toBe(at + 7200);
  });
});

// `completeLinkUser()` and `completeUnlinkUser()` go through `completeInteractiveLogin()`, so the guard runs for them
// too. They give back only `appState`.
describe.each(['completeLinkUser', 'completeUnlinkUser'] as const)('%s | the same rules as the callback', (method) => {
  const run = async (app: App, token: AgentIdTokenOptions) => {
    await app.transactionStore.set(TRANSACTION_ID, { codeVerifier: 'cv', domain: POPPY_DOMAIN }, false, app.browser);
    idToken = await agentIdToken(token);

    return app.client[method](CALLBACK, app.browser);
  };

  test('refuses the login of a person over a guest, and writes nothing', async () => {
    const app = await appWithEverything();
    const before = snapshot(app);

    const error = await run(app, personToken()).then(
      () => undefined,
      (caught: unknown) => caught
    );

    expectPoppyError(error, PoppyErrorCode.SIGN_IN_REQUIRED);
    expect(snapshot(app)).toEqual(before);
  });

  test('returns only appState for a signed-in agent, and the guest is gone', async () => {
    const app = await appWithEverything();

    const result = await run(app, agentToken());

    expect(Object.keys(result)).toEqual(['appState']);
    expect(cookiesOf(app, GUEST_COOKIE)).toEqual([]);
    expect((await stateOf(app))?.user?.act?.poppy_sid).toBe(SESSION_ID);
  });
});

// A backchannel logout deletes sessions by the `sid` of the logout token, so it works with a stateful state store.
describe('handleBackchannelLogout | an agent', () => {
  const SID = 'sid_of_the_login';

  const logout = async (app: App) => {
    vi.spyOn(AuthClient.prototype, 'verifyLogoutToken').mockResolvedValue({ sid: SID, sub: ANA });

    await app.client.handleBackchannelLogout('<logout_token>', app.browser);
  };

  test('ends a signed-in agent session of a stateful store', async () => {
    const app = createApp({ stateful: true });
    await login(app, PATHS[0] as LoginPath, agentToken({ claims: { sid: SID } }));
    expect((await stateOf(app))?.internal.sid).toBe(SID);

    await logout(app);

    expect(app.sessions.sessions.size).toBe(0);
    expect(await app.client.getSession(app.browser)).toBeUndefined();
  });

  test('never touches a guest', async () => {
    const app = createApp({ stateful: true });
    await seedGuest(app);
    const before = cookiesOf(app, GUEST_COOKIE);

    await logout(app);

    expect(cookiesOf(app, GUEST_COOKIE)).toEqual(before);
    expect(await app.client.poppy.getContext(app.browser)).toMatchObject({ kind: 'agent', state: 'guest' });
  });
});
