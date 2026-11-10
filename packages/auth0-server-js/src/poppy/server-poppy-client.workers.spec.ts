import { afterEach, expect, test, vi } from 'vitest';
import {
  CookieTransactionStore,
  ServerClient,
  StatelessPoppyGuestStore,
  StatelessStateStore,
} from '../../dist/index.js';
import {
  BrowserCookieHandler,
  POPPY_CLIENT_ID,
  POPPY_DOMAIN,
  SESSION_ID,
  SESSION_KEY,
  agentIdToken,
  createPoppyConfig,
} from '../test-utils/poppy.js';
import type { AgentIdTokenOptions, Browser } from '../test-utils/poppy.js';

// The same flows as the unit tests, on the built package and on the Workers runtime: the Session key comes from
// `crypto.subtle`, the guest is encrypted with Web Crypto, and an expired guest is told apart by its error class.

const secret = 'secret-that-is-at-least-32-characters';
const GUEST_ID = '__a0_poppy';

afterEach(() => {
  vi.useRealTimers();
});

function createApp() {
  const cookies = new BrowserCookieHandler();
  const browser: Browser = new Map();
  const transactionStore = new CookieTransactionStore<Browser>({ secret }, cookies);
  let idToken = '';

  // A fake Auth0 that answers the discovery request and the code exchange.
  const customFetch: typeof fetch = async (input) => {
    const url = new URL(input instanceof Request ? input.url : String(input));

    switch (url.pathname) {
      case '/.well-known/openid-configuration':
        return Response.json({
          issuer: `https://${POPPY_DOMAIN}/`,
          authorization_endpoint: `https://${POPPY_DOMAIN}/authorize`,
          token_endpoint: `https://${POPPY_DOMAIN}/oauth/token`,
        });
      case '/oauth/token':
        return Response.json({
          id_token: idToken,
          access_token: 'at_join',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'openid profile',
          refresh_token: 'rt_join',
        });
      default:
        return new Response('not found', { status: 404 });
    }
  };

  const client = new ServerClient<Browser>({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: 'client-secret',
    customFetch,
    transactionStore,
    stateStore: new StatelessStateStore<Browser>({ secret }, cookies),
    poppy: { config: createPoppyConfig(), guestStore: new StatelessPoppyGuestStore<Browser>({ secret }, cookies) },
  });

  // The browser comes back from Auth0 with a code, and the token endpoint answers with an ID token made from `token`.
  async function join(token: AgentIdTokenOptions) {
    idToken = await agentIdToken(token);
    await transactionStore.set('__a0_tx', { codeVerifier: 'cv', domain: POPPY_DOMAIN }, false, browser);

    return client.completeInteractiveLogin(new URL('https://zepto.example/auth/callback?code=c1'), browser);
  }

  return { browser, client, join };
}

const guestToken: AgentIdTokenOptions = {
  sub: 'anon_poppy@z4eHq6gTjlgaMSjrplb3j5j3kb3hEDz9hZx8mgdxQLg',
  subProfile: 'urn:auth0:anonymous_user',
};

test('poppy.getContext - after a guest join, the context is signed_out and has the key of the Session', async () => {
  const { browser, client, join } = createApp();

  await join(guestToken);

  const context = await client.poppy.getContext(browser);
  expect(context).toMatchObject({ kind: 'agent', state: 'signed_out', key: SESSION_KEY });
  expect(await client.getSession(browser)).toBeUndefined();
});

test('poppy.getVisitor - after a guest join, the visitor is a guest with the key of the Session', async () => {
  const { browser, client, join } = createApp();

  await join(guestToken);

  const visitor = await client.poppy.getVisitor(browser);
  expect(visitor).toMatchObject({ kind: 'guest', poppy: { kind: 'agent', state: 'signed_out', key: SESSION_KEY } });
  // A guest is never a user.
  expect(await client.getUser(browser)).toBeUndefined();
});

test('getSession - after a signed-in join, the session has the agent in act and no refresh token', async () => {
  const { browser, client, join } = createApp();

  await join({ sub: 'auth0|ana' });

  const session = await client.getSession(browser);
  expect(session?.user?.act?.poppy_sid).toBe(SESSION_ID);
  expect(session?.refreshToken).toBeUndefined();
  expect(await client.poppy.getContext(browser)).toMatchObject({ kind: 'agent', state: 'signed_in', key: SESSION_KEY });
});

// The guest store throws `JWTExpired` after the 15 seconds of clock tolerance. The built package must tell that error
// by its class, and must not let it reach the app.
test('poppy.getContext - a guest cookie copied back after its deadline gives human, and is deleted', async () => {
  const { browser, client, join } = createApp();
  await join(guestToken);
  const guestCookies = [...browser].filter(([name]) => name.startsWith(GUEST_ID));
  expect(guestCookies).not.toHaveLength(0);

  // The Session of the join ends in an hour, and the guest ends with it.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(Date.now() + (3600 + 16) * 1000);
  guestCookies.forEach(([name, cookie]) => browser.set(name, cookie));

  expect(await client.poppy.getContext(browser)).toStrictEqual({ kind: 'human' });
  expect([...browser].filter(([name]) => name.startsWith(GUEST_ID))).toHaveLength(0);
});
