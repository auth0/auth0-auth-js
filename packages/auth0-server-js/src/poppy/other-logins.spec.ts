import { base64url } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import { StatefulStateStore } from '../store/stateful-state-store.js';
import { StatelessStateStore } from '../store/stateless-state-store.js';
import {
  BrowserCookieHandler,
  POPPY_CLIENT_ID,
  POPPY_DOMAIN,
  POPPY_ISSUER,
  SESSION_ID,
  agentAct,
  agentIdToken,
  createPoppyConfig,
} from '../test-utils/poppy.js';
import type { Browser } from '../test-utils/poppy.js';
import { jwks } from '../test-utils/tokens.js';
import type { SessionStore, StateData, StateStore } from '../types.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';

// These tests run the login methods other than `completeInteractiveLogin`. With the `poppy` option, none of them builds on
// an agent session of the browser: a login by a person is a new session, as the interactive login is. Otherwise the
// session would keep the agent in `act`, and it would not end with the Poppy Session. A fake Auth0 answers every token
// request with a signed ID token, and one Map (the browser) holds the cookies of every store.

const SECRET = '<secret>';
const TRANSACTION_ID = '__a0_tx';
const STATE_ID = '__a0_session';
const CALLBACK = new URL('https://zepto.example/auth/callback?code=c1');
const ANA = 'auth0|ana';
const HUMAN = { kind: 'human' };
const CHALLENGE = base64url.encode('login-challenge-bytes');

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
      scope: 'openid profile',
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

  async deleteByLogoutToken() {}
}

// A website with one browser. `poppy: false` leaves the `poppy` option out.
interface App {
  browser: Browser;
  client: ServerClient<Browser>;
  transactionStore: CookieTransactionStore<Browser>;
  stateStore: StateStore<Browser>;
  /** What a stateful state store keeps on the server. It is empty with a stateless one. */
  sessions: MemorySessionStore;
}

function createApp(options: { poppy?: boolean; stateful?: boolean } = {}): App {
  const browser: Browser = new Map();
  const cookies = new BrowserCookieHandler();
  const sessions = new MemorySessionStore();
  const transactionStore = new CookieTransactionStore<Browser>({ secret: SECRET }, cookies);
  const stateStore: StateStore<Browser> = options.stateful
    ? new StatefulStateStore<Browser>({ secret: SECRET, store: sessions }, cookies)
    : new StatelessStateStore<Browser>({ secret: SECRET }, cookies);
  const guestStore = new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, cookies);

  const client = new ServerClient<Browser>({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 0 },
    transactionStore,
    stateStore,
    poppy: options.poppy === false ? undefined : { config: createPoppyConfig(), guestStore },
  });

  return { browser, client, transactionStore, stateStore, sessions };
}

const stateOf = (app: App) => app.stateStore.get(STATE_ID, app.browser);

// The browser joins as a signed-in agent, through the interactive login. This writes the session that the SDK writes.
// Without the `poppy` option the same call takes the usual path, and the session keeps the `act` as the token has it.
async function joinSignedIn(app: App): Promise<void> {
  idToken = await agentIdToken({ sub: ANA, act: agentAct() });
  await app.transactionStore.set(TRANSACTION_ID, { codeVerifier: 'cv', domain: POPPY_DOMAIN }, false, app.browser);
  await app.client.completeInteractiveLogin(CALLBACK, app.browser);
}

// What a customer's own login leaves in the state store. It has a ceiling that ends later than the one of a login.
function ownLogin(): StateData {
  const at = now();

  return {
    user: { sub: ANA, iss: POPPY_ISSUER, name: 'Own Login', email: 'old@zepto.example' },
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

// What `navigator.credentials.get()` returns for the challenge of the login.
const credential = {
  id: 'cred_1',
  rawId: 'cred_1',
  type: 'public-key',
  response: {
    clientDataJSON: base64url.encode(
      JSON.stringify({ type: 'webauthn.get', challenge: CHALLENGE, origin: 'https://zepto.example', crossOrigin: false })
    ),
    authenticatorData: 'fake_authenticator_data',
    signature: 'fake_signature',
  },
};

interface Method {
  name: string;
  /** Whether the method reads the `session_expiry` claim of its login. The others never set a ceiling. */
  stampsCeiling: boolean;
  /** Logs the browser in with the method. The fake Auth0 answers with the current `idToken`. */
  run: (app: App) => Promise<unknown>;
}

const METHODS: Method[] = [
  {
    name: 'loginBackchannel',
    stampsCeiling: true,
    run: (app) => app.client.loginBackchannel({ loginHint: { sub: ANA }, bindingMessage: 'Sign in' }, app.browser),
  },
  {
    name: 'mfa.verify',
    stampsCeiling: true,
    run: (app) => app.client.mfa.verify({ mfaToken: 'mfa_token', factorType: 'otp', otp: '123456' }, app.browser),
  },
  {
    name: 'passkey.complete',
    stampsCeiling: true,
    run: async (app) => {
      await app.client.passkey.startLogin(undefined, app.browser);
      await app.client.passkey.complete({ credential }, app.browser);
    },
  },
  {
    name: 'completePasswordless',
    stampsCeiling: false,
    run: (app) =>
      app.client.completePasswordless(
        { connection: 'email', email: 'ana@zepto.example', verificationCode: '123456' },
        app.browser
      ),
  },
  {
    name: 'completePasswordlessMagicLink',
    stampsCeiling: false,
    run: async (app) => {
      await app.transactionStore.set(TRANSACTION_ID, { state: 'state_1', domain: POPPY_DOMAIN }, false, app.browser);
      await app.client.completePasswordlessMagicLink(
        new URL('https://zepto.example/auth/callback?code=c1&state=state_1'),
        app.browser
      );
    },
  },
  {
    name: 'loginWithCustomTokenExchange',
    stampsCeiling: false,
    run: (app) =>
      app.client.loginWithCustomTokenExchange(
        { subjectToken: 'external_token', subjectTokenType: 'urn:acme:legacy-token' },
        app.browser
      ),
  },
];

// A login by the same user with the method. It is a normal login: the ID token has no `act`. It has a ceiling that ends
// 5000 seconds from the start of the test, which is later than the end of the agent's Session (3600 seconds).
async function loginWith(app: App, method: Method, sessionExpiry: number): Promise<void> {
  idToken = await agentIdToken({ sub: ANA, act: null, claims: { session_expiry: sessionExpiry } });
  await method.run(app);
}

const STORES = [
  { label: 'a stateless state store', stateful: false },
  { label: 'a stateful state store', stateful: true },
];

describe.each(METHODS)('$name', (method) => {
  describe.each(STORES)('with $label', ({ stateful }) => {
    test('over an agent session, starts a fresh session of this login', async () => {
      const app = createApp({ stateful });
      await joinSignedIn(app);
      const agentSessionIds = [...app.sessions.sessions.keys()];
      expect(await app.client.poppy.getContext(app.browser)).toMatchObject({ kind: 'agent', state: 'signed_in' });
      later(600);
      const at = now();

      await loginWith(app, method, at + 5000);

      const state = await stateOf(app);
      expect(state?.user?.sub).toBe(ANA);
      // The user of this login only: no `act`, so no Poppy Session and no agent.
      expect(state?.user).not.toHaveProperty('act');
      expect(JSON.stringify(state?.user)).not.toContain('poppy_');
      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);
      expect(state?.refreshToken).toBe('rt_login');
      expect(state?.tokenSets).toStrictEqual([
        { audience: 'default', accessToken: 'at_login', scope: 'openid profile', expiresAt: at + 3600 },
      ]);
      expect(state?.internal.createdAt).toBe(at);
      // The deadline of this login, and never the one of the agent session (3600 seconds after the join).
      expect(state?.sessionExpiresAt).toBe(method.stampsCeiling ? at + 5000 : undefined);

      if (stateful) {
        // A new session id, and the record of the agent session is gone: no orphan stays in the session store.
        expect(app.sessions.sessions.size).toBe(1);
        expect([...app.sessions.sessions.keys()]).not.toEqual(agentSessionIds);
      }
    });

    test('over the own login of a person, merges into it as before', async () => {
      const app = createApp({ stateful });
      await seedOwnLogin(app);
      const stored = ownLogin();
      const ownSessionIds = [...app.sessions.sessions.keys()];
      later(600);
      const at = now();

      await loginWith(app, method, at + 5000);

      const state = await stateOf(app);
      // The user claims, the time of the first login and the connection token of the own login stay.
      expect(state?.user).toMatchObject({ sub: ANA, name: 'Own Login', email: 'old@zepto.example' });
      expect(state?.internal).toStrictEqual(stored.internal);
      expect(state?.connectionTokenSets).toStrictEqual(stored.connectionTokenSets);
      // The refresh token of this login replaces the old one, and its tokens are added to the token sets.
      expect(state?.refreshToken).toBe('rt_login');
      expect(state?.tokenSets.map((set) => set.accessToken)).toEqual(['at_old', 'at_login']);
      // A method that reads the `session_expiry` of its login stamps it. The others keep the ceiling that is stored.
      expect(state?.sessionExpiresAt).toBe(method.stampsCeiling ? at + 5000 : stored.sessionExpiresAt);
      expect(await app.client.poppy.getContext(app.browser)).toStrictEqual(HUMAN);

      if (stateful) {
        // The id is renewed on a login, with or without the option.
        expect(app.sessions.sessions.size).toBe(1);
        expect([...app.sessions.sessions.keys()]).not.toEqual(ownSessionIds);
      }
    });
  });

  test('without the poppy option, builds on a stored session that holds an agent in act, as before', async () => {
    const app = createApp({ poppy: false });
    await joinSignedIn(app);
    const first = (await stateOf(app))?.internal.createdAt;
    later(600);
    const at = now();

    await loginWith(app, method, at + 5000);

    const state = await stateOf(app);
    // Nothing changes without the option: the stored user, with the agent in `act`, and its first login stay.
    expect(state?.user?.act?.poppy_sid).toBe(SESSION_ID);
    expect(state?.internal.createdAt).toBe(first);
    expect(state?.refreshToken).toBe('rt_login');
  });
});
