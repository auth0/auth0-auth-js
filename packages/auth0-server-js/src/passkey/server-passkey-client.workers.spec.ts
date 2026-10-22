import { test, expect } from 'vitest';
import { base64url } from 'jose';
import { AbstractStateStore, CookieTransactionStore, MissingTransactionError, ServerClient } from '../../dist/index.js';
import type { CookieHandler, CookieSerializeOptions, LogoutTokenClaims, StateData } from '../../dist/index.js';
import { generateToken } from '../test-utils/tokens.js';

const domain = 'auth0.local';
const clientId = 'client-id';
const secret = 'secret-that-is-at-least-32-characters';
const challenge = base64url.encode('workers-login-challenge');

type Browser = Map<string, { value: string; options?: CookieSerializeOptions }>;

class BrowserCookieHandler implements CookieHandler<Browser> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, browser?: Browser): void {
    browser!.set(name, { value, options });
  }

  getCookie(name: string, browser?: Browser): string | undefined {
    return browser!.get(name)?.value;
  }

  getCookies(browser?: Browser): Record<string, string> {
    return Object.fromEntries([...browser!].map(([name, cookie]) => [name, cookie.value]));
  }

  deleteCookie(name: string, browser?: Browser): void {
    browser!.delete(name);
  }
}

class TestStateStore extends AbstractStateStore<Browser> {
  readonly #data = new Map<string, StateData>();

  async set(identifier: string, value: StateData): Promise<void> {
    this.#data.set(identifier, value);
  }

  async get(identifier: string): Promise<StateData | undefined> {
    return this.#data.get(identifier);
  }

  async delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async deleteByLogoutToken(_claims: LogoutTokenClaims): Promise<void> {}
}

test('passkey.startLogin and passkey.complete keep the auth session in the transaction cookie', async () => {
  const idToken = await generateToken(domain, 'sub_123', clientId);
  const tokenRequests: Record<string, unknown>[] = [];

  const customFetch: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));

    switch (url.pathname) {
      case '/.well-known/openid-configuration':
        return Response.json({
          issuer: `https://${domain}/`,
          authorization_endpoint: `https://${domain}/authorize`,
          token_endpoint: `https://${domain}/oauth/token`,
          jwks_uri: `https://${domain}/.well-known/jwks.json`,
        });
      case '/passkey/challenge':
        return Response.json({
          auth_session: 'auth_session_login',
          authn_params_public_key: { challenge, rpId: domain, timeout: 60000, userVerification: 'preferred' },
        });
      case '/oauth/token':
        tokenRequests.push(JSON.parse(String(init?.body)));
        return Response.json({ access_token: 'at', id_token: idToken, token_type: 'Bearer', expires_in: 60 });
      default:
        return new Response('not found', { status: 404 });
    }
  };

  const serverClient = new ServerClient<Browser>({
    domain,
    clientId,
    clientSecret: 'client-secret',
    customFetch,
    stateStore: new TestStateStore({ secret }),
    transactionStore: new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler()),
  });
  const browser: Browser = new Map();

  const result = await serverClient.passkey.startLogin(undefined, browser);

  expect(result).not.toHaveProperty('authSession');
  expect(browser.get('__a0_passkey_tx')?.options?.maxAge).toBe(60);

  const credential = (signedChallenge: string) => ({
    id: 'cred_123',
    rawId: 'cred_123',
    type: 'public-key',
    response: {
      clientDataJSON: base64url.encode(JSON.stringify({ type: 'webauthn.get', challenge: signedChallenge })),
      authenticatorData: 'authenticator_data',
      signature: 'signature',
    },
  });

  await expect(
    serverClient.passkey.complete({ credential: credential(base64url.encode('another-challenge')) }, browser)
  ).rejects.toBeInstanceOf(MissingTransactionError);
  expect(tokenRequests).toHaveLength(0);

  await serverClient.passkey.complete({ credential: credential(challenge) }, browser);

  expect(tokenRequests).toHaveLength(1);
  expect(tokenRequests[0]).toMatchObject({ auth_session: 'auth_session_login' });
  expect(browser.has('__a0_passkey_tx')).toBe(false);
  expect((await serverClient.getUser(browser))?.sub).toBe('sub_123');
});
