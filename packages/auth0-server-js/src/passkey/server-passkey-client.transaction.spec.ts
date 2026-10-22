import { expect, test, afterAll, afterEach, beforeAll, vi, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { base64url } from 'jose';
import {
  isMfaRequiredError,
  OrganizationValidationError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
  PasskeyRegisterError,
} from '@auth0/auth0-auth-js';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import type { CookieHandler, CookieSerializeOptions } from '../store/cookie-handler.js';
import { InvalidConfigurationError, MissingRequiredArgumentError, MissingTransactionError } from '../errors.js';
import type { ServerClientOptions, TransactionData, TransactionStore } from '../types.js';
import { generateToken, jwks } from '../test-utils/tokens.js';
import { DefaultStateStore } from '../test-utils/default-state-store.js';
import { DefaultAnonymousStore } from '../test-utils/default-anonymous-store.js';
import { decrypt } from '../test-utils/encryption.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const secret = 'test-secret-that-is-at-least-32-chars';
const passkeyCookie = '__a0_passkey_tx';

// Auth0 issues base64url challenges; the browser echoes them in `clientDataJSON`.
const signupChallenge = base64url.encode('signup-challenge-bytes');
const loginChallenge = base64url.encode('login-challenge-bytes');

let idToken: string;

/**
 * The cookie jar of one browser. It is also the `storeOptions` of every call, so a store call that
 * does not receive `storeOptions` fails.
 */
interface Browser {
  cookies: Map<string, { value: string; options?: CookieSerializeOptions }>;
}

class BrowserCookieHandler implements CookieHandler<Browser> {
  #jar(storeOptions?: Browser) {
    if (!storeOptions) {
      throw new Error('StoreOptions not provided');
    }

    return storeOptions.cookies;
  }

  setCookie(name: string, value: string, options?: CookieSerializeOptions, storeOptions?: Browser): void {
    this.#jar(storeOptions).set(name, { value, options });
  }

  getCookie(name: string, storeOptions?: Browser): string | undefined {
    return this.#jar(storeOptions).get(name)?.value;
  }

  getCookies(storeOptions?: Browser): Record<string, string> {
    return Object.fromEntries([...this.#jar(storeOptions)].map(([name, cookie]) => [name, cookie.value]));
  }

  deleteCookie(name: string, storeOptions?: Browser): void {
    this.#jar(storeOptions).delete(name);
  }
}

const newBrowser = (): Browser => ({ cookies: new Map() });

const readCookie = async (browser: Browser, name = passkeyCookie) => {
  const cookie = browser.cookies.get(name);

  return cookie && { data: await decrypt<Record<string, unknown>>(cookie.value, secret, name), options: cookie.options };
};

const makeClient = (options: Partial<ServerClientOptions<Browser>> = {}) =>
  new ServerClient<Browser>({
    domain,
    clientId,
    clientSecret,
    transactionStore: new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler()),
    stateStore: new DefaultStateStore({ secret }),
    ...options,
  });

const credentialFor = (challenge: string, type = 'webauthn.get') => ({
  id: 'cred_123',
  rawId: 'cred_123',
  type: 'public-key',
  response: {
    clientDataJSON: base64url.encode(
      JSON.stringify({ type, challenge, origin: 'https://app.example.com', crossOrigin: false })
    ),
    authenticatorData: 'fake_authenticator_data',
    signature: 'fake_signature',
  },
});

// What `navigator.credentials.create()` returns for the signup challenge. No test changes it.
const signupCredential = credentialFor(signupChallenge, 'webauthn.create');

// `publicKey` overrides fields of `authn_params_public_key`; an `undefined` value leaves the field out.
const registerApiResponse = (publicKey: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => ({
  auth_session: 'auth_session_signup',
  authn_params_public_key: {
    challenge: signupChallenge,
    rp: { id: domain, name: 'Test' },
    user: { id: 'user_id', name: 'user@example.com', displayName: 'User' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000,
    ...publicKey,
  },
  ...extra,
});

const challengeApiResponse = (publicKey: Record<string, unknown> = {}) => ({
  auth_session: 'auth_session_login',
  authn_params_public_key: {
    challenge: loginChallenge,
    rpId: domain,
    timeout: 60000,
    userVerification: 'preferred',
    ...publicKey,
  },
});

const buildTokenResponse = () => ({
  access_token: 'passkey_access_token',
  id_token: idToken,
  refresh_token: 'passkey_refresh_token',
  token_type: 'Bearer',
  expires_in: 86400,
  scope: 'openid profile email',
});

// The SDK sends the passkey grant as JSON; every other grant is form-encoded.
const readTokenRequestBody = async (request: Request) => {
  const isJson = (request.headers.get('content-type') ?? '').includes('application/json');
  return isJson
    ? ((await request.json()) as Record<string, unknown>)
    : Object.fromEntries(await request.formData());
};

const server = setupServer(
  http.get(`https://${domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `https://${domain}/`,
      authorization_endpoint: `https://${domain}/authorize`,
      token_endpoint: `https://${domain}/oauth/token`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
    })
  ),
  http.get(`https://${domain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks })),
  http.post(`https://${domain}/passkey/register`, () => HttpResponse.json(registerApiResponse())),
  http.post(`https://${domain}/passkey/challenge`, () => HttpResponse.json(challengeApiResponse()))
);

/**
 * Answers the token endpoint with `respond` and records the body of every token request.
 */
const onTokenRequest = (respond: (body: Record<string, unknown>) => Response | Promise<Response>) => {
  const bodies: Record<string, unknown>[] = [];

  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await readTokenRequestBody(request);
      bodies.push(body);
      return respond(body);
    })
  );

  return bodies;
};

const tokenSuccess = () => onTokenRequest(() => HttpResponse.json(buildTokenResponse()));

const tokenError = (status: number, body: Record<string, unknown>) =>
  onTokenRequest(() => HttpResponse.json(body, { status }));

const captureJsonBodies = (path: string, respond: () => Response) => {
  const bodies: Record<string, unknown>[] = [];

  server.use(
    http.post(`https://${domain}${path}`, async ({ request }) => {
      bodies.push((await request.json()) as Record<string, unknown>);
      return respond();
    })
  );

  return bodies;
};

/**
 * Starts a login and returns the browser holding the passkey transaction.
 */
const startLogin = async (sc: ServerClient<Browser>, options?: { realm?: string; organization?: string }) => {
  const browser = newBrowser();
  await sc.passkey.startLogin(options, browser);
  return browser;
};

/**
 * Starts a signup for which Auth0 sends a one-time code to each of `verificationRequired`, and returns
 * the browser holding the passkey transaction.
 */
const startSignupWithCodes = async (
  sc: ServerClient<Browser>,
  verificationRequired: string[],
  options?: { realm?: string; organization?: string }
) => {
  server.use(
    http.post(`https://${domain}/passkey/register`, () =>
      HttpResponse.json(registerApiResponse({ timeout: 900000 }, { verification_required: verificationRequired }))
    )
  );
  const browser = newBrowser();
  await sc.passkey.startSignup({ email: 'user@example.com', phoneNumber: '+15551234567', ...options }, browser);
  return browser;
};

// The body of Auth0's answer to a wrong one-time code, which keeps the auth session.
const wrongCode = (fields: Record<string, unknown> = {}) => ({
  error: 'invalid_grant',
  error_description: 'Invalid or expired session',
  auth_session: 'auth_session_signup',
  ...fields,
});

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  idToken = await generateToken(domain, 'sub_123', clientId);
});

afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});

afterAll(() => {
  server.close();
});

describe('passkey.startSignup', () => {
  test('stores the transaction in an encrypted cookie and returns no authSession', async () => {
    const registerBodies = captureJsonBodies('/passkey/register', () =>
      HttpResponse.json(registerApiResponse({}, { verification_required: ['email'] }))
    );
    const browser = newBrowser();
    // Freeze the clock, so the expiry and the cookie's Max-Age can be asserted exactly.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-16T10:00:00.250Z'));
    const now = Math.floor(Date.now() / 1000);

    const result = await makeClient().passkey.startSignup(
      { email: 'user@example.com', realm: 'Username-Password-Authentication', organization: 'org_123' },
      browser
    );

    expect(result).not.toHaveProperty('authSession');
    expect(result.authnParamsPublicKey.challenge).toBe(signupChallenge);
    expect(result.verificationRequired).toEqual(['email']);
    expect(registerBodies[0]).toMatchObject({ realm: 'Username-Password-Authentication', organization: 'org_123' });

    const cookie = await readCookie(browser);
    expect(cookie!.data).toMatchObject({
      authSession: 'auth_session_signup',
      challenge: signupChallenge,
      domain,
      realm: 'Username-Password-Authentication',
      organization: 'org_123',
      verificationRequired: ['email'],
    });
    expect(cookie!.data.expiresAt).toBe(now + 60);
    expect(cookie!.data.exp).toBe(now + 60);
    expect(cookie!.options).toEqual({ httpOnly: true, sameSite: 'lax', path: '/', maxAge: 60 });

    // The redirect-login transaction is not touched.
    expect(browser.cookies.has('__a0_tx')).toBe(false);
  });

  test('leaves out realm and organization when they are not passed', async () => {
    const browser = newBrowser();

    await makeClient().passkey.startSignup({ email: 'user@example.com' }, browser);

    const cookie = await readCookie(browser);
    expect(cookie!.data).not.toHaveProperty('realm');
    expect(cookie!.data).not.toHaveProperty('organization');
  });

  test.each([
    { timeout: 900000, maxAge: 900, label: 'identifier verification (15 minutes)' },
    { timeout: 1500, maxAge: 2, label: 'a fraction of a second, rounded up' },
    { timeout: 7200000, maxAge: 3600, label: 'longer than an hour, capped' },
    { timeout: undefined, maxAge: 3600, label: 'missing' },
    { timeout: 0, maxAge: 3600, label: 'zero' },
    { timeout: -1000, maxAge: 3600, label: 'negative' },
    { timeout: '60000', maxAge: 3600, label: 'not a number' },
  ])('expires the transaction from the timeout: $label', async ({ timeout, maxAge }) => {
    server.use(
      http.post(`https://${domain}/passkey/register`, () => HttpResponse.json(registerApiResponse({ timeout })))
    );
    const browser = newBrowser();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-16T10:00:00.750Z'));
    const now = Math.floor(Date.now() / 1000);

    await makeClient().passkey.startSignup({ email: 'user@example.com' }, browser);

    const cookie = await readCookie(browser);
    expect(cookie!.options!.maxAge).toBe(maxAge);
    expect(cookie!.data.expiresAt).toBe(now + maxAge);
    expect(cookie!.data.exp).toBe(now + maxAge);
  });

  test('stores nothing when Auth0 rejects the signup challenge', async () => {
    server.use(
      http.post(`https://${domain}/passkey/register`, () =>
        HttpResponse.json({ error: 'invalid_request', error_description: 'User signup failed' }, { status: 400 })
      )
    );
    const browser = newBrowser();

    await expect(makeClient().passkey.startSignup({ email: 'user@example.com' }, browser)).rejects.toBeInstanceOf(
      PasskeyRegisterError
    );
    expect(browser.cookies.size).toBe(0);
  });

  test('passes storeOptions to the domain resolver and the transaction store', async () => {
    const resolver = vi.fn().mockResolvedValue(domain);
    const browser = newBrowser();

    await makeClient({ domain: resolver }).passkey.startSignup({ email: 'user@example.com' }, browser);

    expect(resolver).toHaveBeenCalledWith(browser);
    expect(browser.cookies.has(passkeyCookie)).toBe(true);
  });
});

describe('passkey.startLogin', () => {
  test('stores the transaction and returns only the WebAuthn request options', async () => {
    const challengeBodies = captureJsonBodies('/passkey/challenge', () => HttpResponse.json(challengeApiResponse()));
    const browser = newBrowser();
    // Freeze the clock, so the cookie's Max-Age can be asserted exactly.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-16T10:00:00.250Z'));

    const result = await makeClient().passkey.startLogin({ realm: 'db', organization: 'org_123' }, browser);

    expect(result).toEqual({
      authnParamsPublicKey: { challenge: loginChallenge, rpId: domain, timeout: 60000, userVerification: 'preferred' },
    });
    expect(challengeBodies[0]).toMatchObject({ realm: 'db', organization: 'org_123' });

    const cookie = await readCookie(browser);
    expect(cookie!.data).toMatchObject({
      authSession: 'auth_session_login',
      challenge: loginChallenge,
      domain,
      realm: 'db',
      organization: 'org_123',
    });
    expect(cookie!.options!.maxAge).toBe(60);
  });

  test('works without options', async () => {
    const browser = newBrowser();

    await makeClient().passkey.startLogin(undefined, browser);

    const cookie = await readCookie(browser);
    expect(cookie!.data).toMatchObject({ authSession: 'auth_session_login' });
  });

  test('a new start replaces the stored transaction', async () => {
    const sc = makeClient();
    const browser = newBrowser();

    await sc.passkey.startSignup({ email: 'user@example.com' }, browser);
    await sc.passkey.startLogin(undefined, browser);

    const cookie = await readCookie(browser);
    expect(cookie!.data).toMatchObject({ authSession: 'auth_session_login', challenge: loginChallenge });
  });

  test('surfaces a transaction store failure', async () => {
    const store = new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler());
    vi.spyOn(store, 'set').mockRejectedValue(new Error('store unavailable'));

    await expect(makeClient({ transactionStore: store }).passkey.startLogin(undefined, newBrowser())).rejects.toThrowError(
      'store unavailable'
    );
  });

  test('stores nothing when Auth0 rejects the login challenge', async () => {
    server.use(
      http.post(`https://${domain}/passkey/challenge`, () =>
        HttpResponse.json({ error: 'access_denied', error_description: 'Forbidden' }, { status: 403 })
      )
    );
    const browser = newBrowser();

    await expect(makeClient().passkey.startLogin(undefined, browser)).rejects.toBeInstanceOf(PasskeyChallengeError);
    expect(browser.cookies.size).toBe(0);
  });
});

describe('passkey.complete', () => {
  test('exchanges the credential with the stored values, deletes the transaction and writes the session', async () => {
    const tokenBodies = tokenSuccess();
    const sc = makeClient({ authorizationParams: { scope: 'openid profile', audience: 'https://api.example.com' } });
    const browser = newBrowser();
    await sc.passkey.startSignup({ email: 'user@example.com', realm: 'db' }, browser);

    const result = await sc.passkey.complete(
      { credential: credentialFor(signupChallenge, 'webauthn.create'), verification: { email: '123456' } },
      browser
    );

    expect(result).toEqual({ authorizationDetails: undefined });
    expect(tokenBodies).toHaveLength(1);
    expect(tokenBodies[0]).toMatchObject({
      grant_type: 'urn:okta:params:oauth:grant-type:webauthn',
      auth_session: 'auth_session_signup',
      realm: 'db',
      scope: 'openid profile',
      audience: 'https://api.example.com',
      verification: { email: '123456' },
      authn_response: credentialFor(signupChallenge, 'webauthn.create'),
    });
    expect(tokenBodies[0]).not.toHaveProperty('organization');
    expect(browser.cookies.has(passkeyCookie)).toBe(false);

    const user = await sc.getUser(browser);
    expect(user?.sub).toBe('sub_123');
    const session = await sc.getSession(browser);
    expect(session?.tokenSets[0]?.audience).toBe('https://api.example.com');
  });

  test('passes scope and audience from the options', async () => {
    const tokenBodies = tokenSuccess();
    const sc = makeClient();
    const browser = await startLogin(sc);

    await sc.passkey.complete(
      { credential: credentialFor(loginChallenge), scope: 'read:items', audience: 'https://other.example.com' },
      browser
    );

    expect(tokenBodies[0]).toMatchObject({ scope: 'openid read:items', audience: 'https://other.example.com' });
  });

  test('sends the stored organization and validates the ID token against it', async () => {
    const tokenBodies = onTokenRequest(async () =>
      HttpResponse.json({
        ...buildTokenResponse(),
        id_token: await generateToken(domain, 'sub_123', clientId, undefined, { org_id: 'org_123' }),
      })
    );
    const sc = makeClient();
    const browser = await startLogin(sc, { organization: 'org_123' });

    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser);

    expect(tokenBodies[0]).toMatchObject({ organization: 'org_123' });
    expect((await sc.getUser(browser))?.org_id).toBe('org_123');
  });

  test('uses the domain that started the flow in resolver mode', async () => {
    const tokenBodies = tokenSuccess();
    let resolvedDomain = domain;
    const resolver = vi.fn(async () => resolvedDomain);
    const sc = makeClient({ domain: resolver });
    const browser = await startLogin(sc);

    // Requests for another tenant would hit MSW's unhandled-request error.
    resolvedDomain = 'other-tenant.local';
    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser);

    expect(tokenBodies).toHaveLength(1);
    expect(resolver).toHaveBeenCalledTimes(1);

    resolvedDomain = domain;
    expect((await sc.getSession(browser))?.domain).toBe(domain);
  });

  test('clears the anonymous session after the login', async () => {
    tokenSuccess();
    const anonymousStore = new DefaultAnonymousStore({ secret });
    await anonymousStore.set('__a0_anon', { sessionToken: 'anon_token', createdAt: Math.floor(Date.now() / 1000), tokenSets: [] });
    const sc = makeClient({ anonymousStore });
    const browser = await startLogin(sc);

    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser);

    expect(await anonymousStore.get('__a0_anon')).toBeUndefined();
  });

  test('deletes the used transaction even when writing the session fails', async () => {
    tokenSuccess();
    const stateStore = new DefaultStateStore({ secret });
    vi.spyOn(stateStore, 'set').mockRejectedValue(new Error('state store unavailable'));
    const sc = makeClient({ stateStore });
    const browser = await startLogin(sc);

    await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).rejects.toThrowError(
      'state store unavailable'
    );
    expect(browser.cookies.has(passkeyCookie)).toBe(false);
  });

  test('takes the auth session, realm, organization and domain only from the stored transaction', async () => {
    const tokenBodies = onTokenRequest(async () =>
      HttpResponse.json({
        ...buildTokenResponse(),
        id_token: await generateToken(domain, 'sub_123', clientId, undefined, { org_id: 'org_123' }),
      })
    );
    const sc = makeClient();
    const browser = await startLogin(sc, { realm: 'db', organization: 'org_123' });

    // Fields the type does not allow, as a JavaScript caller or a forwarded request body could send them.
    await sc.passkey.complete(
      {
        credential: credentialFor(loginChallenge),
        authSession: 'auth_session_other',
        realm: 'other-db',
        organization: 'org_other',
        domain: 'other-tenant.local',
      } as never,
      browser
    );

    expect(tokenBodies).toHaveLength(1);
    expect(tokenBodies[0]).toMatchObject({ auth_session: 'auth_session_login', realm: 'db', organization: 'org_123' });
  });

  test('completes the login even when deleting the used transaction fails', async () => {
    tokenSuccess();
    const store = new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler());
    const sc = makeClient({ transactionStore: store });
    const browser = await startLogin(sc);
    vi.spyOn(store, 'delete').mockRejectedValue(new Error('store unavailable'));

    await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).resolves.toBeDefined();
    expect((await sc.getUser(browser))?.sub).toBe('sub_123');
  });

  test('rejects a long malformed clientDataJSON in linear time, without calling Auth0', async () => {
    const tokenBodies = tokenSuccess();
    const sc = makeClient();
    const browser = await startLogin(sc);
    const credential = credentialFor(loginChallenge);
    credential.response.clientDataJSON = '='.repeat(200_000) + 'x';
    const startedAt = performance.now();

    await expect(sc.passkey.complete({ credential }, browser)).rejects.toBeInstanceOf(MissingRequiredArgumentError);
    expect(performance.now() - startedAt).toBeLessThan(1000);
    expect(tokenBodies).toHaveLength(0);
    expect(browser.cookies.has(passkeyCookie)).toBe(true);
  });

  test('throws MissingRequiredArgumentError without a credential', async () => {
    const tokenBodies = tokenSuccess();
    const sc = makeClient();
    const browser = await startLogin(sc);

    await expect(
      sc.passkey.complete({} as unknown as Parameters<typeof sc.passkey.complete>[0], browser)
    ).rejects.toBeInstanceOf(MissingRequiredArgumentError);
    expect(tokenBodies).toHaveLength(0);
    expect(browser.cookies.has(passkeyCookie)).toBe(true);
  });

  test.each([
    ['without a response', { id: 'cred_123', rawId: 'cred_123', type: 'public-key' }],
    ['with an empty clientDataJSON', { ...credentialFor(loginChallenge), response: { clientDataJSON: '' } }],
    [
      'with a clientDataJSON that cannot be read',
      { ...credentialFor(loginChallenge), response: { clientDataJSON: base64url.encode('not json') } },
    ],
  ])('throws MissingRequiredArgumentError for a credential %s, before reading the store', async (_, credential) => {
    const tokenBodies = tokenSuccess();
    const store = new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler());
    const sc = makeClient({ transactionStore: store });
    const browser = await startLogin(sc);
    const read = vi.spyOn(store, 'get');

    const error = await sc.passkey
      .complete({ credential } as unknown as Parameters<typeof sc.passkey.complete>[0], browser)
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(MissingRequiredArgumentError);
    expect((error as Error).message).toContain("'credential.response.clientDataJSON'");
    expect(read).not.toHaveBeenCalled();
    expect(tokenBodies).toHaveLength(0);

    // The flow is kept, so a well-formed credential still completes it.
    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser);
    expect(tokenBodies).toHaveLength(1);
  });

  test('throws MissingTransactionError without calling Auth0 when no flow was started', async () => {
    const tokenBodies = tokenSuccess();

    await expect(
      makeClient().passkey.complete({ credential: credentialFor(loginChallenge) }, newBrowser())
    ).rejects.toThrowError(MissingTransactionError);
    expect(tokenBodies).toHaveLength(0);
  });

  test('throws MissingTransactionError for a credential created for another challenge, keeping the transaction', async () => {
    const tokenBodies = tokenSuccess();
    const sc = makeClient();
    const browser = newBrowser();
    await sc.passkey.startSignup({ email: 'user@example.com' }, browser);
    // A second tab starts a login, which replaces the signup transaction.
    await sc.passkey.startLogin(undefined, browser);
    const stored = browser.cookies.get(passkeyCookie);

    const error = await sc.passkey
      .complete({ credential: credentialFor(signupChallenge, 'webauthn.create') }, browser)
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(MissingTransactionError);
    expect((error as Error).message).toContain('was not created for the passkey signup or login in progress');
    expect(tokenBodies).toHaveLength(0);
    expect(browser.cookies.get(passkeyCookie)).toBe(stored);

    // The newer flow still completes.
    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser);
    expect(tokenBodies).toHaveLength(1);
  });

  test('accepts a challenge encoded as padded base64', async () => {
    tokenSuccess();
    // Bytes whose base64 form uses `+`, `/` and padding.
    const challenge = base64url.encode(new Uint8Array([251, 255, 191, 1]));
    server.use(http.post(`https://${domain}/passkey/challenge`, () => HttpResponse.json(challengeApiResponse({ challenge }))));
    const sc = makeClient();
    const browser = await startLogin(sc);
    const standardBase64 = challenge.replace(/-/g, '+').replace(/_/g, '/') + '==';
    const credential = credentialFor(standardBase64);
    credential.response.clientDataJSON = btoa(atob(credential.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')));

    await expect(sc.passkey.complete({ credential }, browser)).resolves.toBeDefined();
  });

  test('deletes an expired transaction without calling Auth0', async () => {
    const tokenBodies = tokenSuccess();
    vi.useFakeTimers({ toFake: ['Date'] });
    const sc = makeClient();
    const browser = await startLogin(sc);

    // Past `expiresAt`, but within the 15 second clock tolerance of the encrypted cookie.
    vi.setSystemTime(Date.now() + 61 * 1000);

    await expect(
      sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)
    ).rejects.toBeInstanceOf(MissingTransactionError);
    expect(tokenBodies).toHaveLength(0);
    expect(browser.cookies.has(passkeyCookie)).toBe(false);
  });

  test('deletes a transaction whose encrypted cookie has expired without calling Auth0', async () => {
    const tokenBodies = tokenSuccess();
    vi.useFakeTimers({ toFake: ['Date'] });
    const sc = makeClient();
    const browser = await startLogin(sc);

    // Past the cookie's own expiry and its clock tolerance, so decrypting it fails as expired.
    vi.setSystemTime(Date.now() + 120 * 1000);

    await expect(
      sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)
    ).rejects.toBeInstanceOf(MissingTransactionError);
    expect(tokenBodies).toHaveLength(0);
    expect(browser.cookies.has(passkeyCookie)).toBe(false);
  });

  describe('when the exchange fails', () => {
    const expectFailure = async (status: number, body: Record<string, unknown>) => {
      const tokenBodies = tokenError(status, body);
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email']);
      const before = await readCookie(browser);
      const stored = browser.cookies.get(passkeyCookie);

      const error = await sc.passkey
        .complete({ credential: signupCredential, verification: { email: '000000' } }, browser)
        .catch((e: unknown) => e);

      expect(tokenBodies).toHaveLength(1);
      expect(await sc.getSession(browser)).toBeUndefined();

      const after = await readCookie(browser);
      const rewritten = after !== undefined && browser.cookies.get(passkeyCookie) !== stored;

      return { sc, browser, error, before, after, rewritten };
    };

    test('keeps the transaction after a wrong code, so complete() can be called again', async () => {
      const { sc, browser, error, before, after, rewritten } = await expectFailure(
        400,
        wrongCode({ verification_required: ['email'] })
      );

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect((error as PasskeyGetTokenError).isRetryable).toBe(true);
      expect(after!.data).toEqual(before!.data);
      // Auth0 returned the same auth session and the same list, so nothing was written.
      expect(rewritten).toBe(false);

      const tokenBodies = tokenSuccess();
      await sc.passkey.complete({ credential: signupCredential, verification: { email: '123456' } }, browser);

      expect(tokenBodies[0]).toMatchObject({ auth_session: 'auth_session_signup', verification: { email: '123456' } });
      expect(browser.cookies.has(passkeyCookie)).toBe(false);
      expect((await sc.getUser(browser))?.sub).toBe('sub_123');
    });

    test('stores the auth session Auth0 returns after a wrong code, keeping the expiry', async () => {
      tokenError(400, wrongCode({ auth_session: 'auth_session_renewed', verification_required: ['email'] }));
      vi.useFakeTimers({ toFake: ['Date'] });
      const startedAt = Math.floor(Date.now() / 1000);
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email']);
      const before = await readCookie(browser);

      // The user takes 20 seconds to type the code.
      vi.setSystemTime(Date.now() + 20 * 1000);
      const error = await sc.passkey
        .complete({ credential: signupCredential, verification: { email: '000000' } }, browser)
        .catch((e: unknown) => e);

      expect((error as PasskeyGetTokenError).isRetryable).toBe(true);
      // The new auth session is stored, and still kept off the error.
      expect((error as PasskeyGetTokenError).authSession).toBeUndefined();
      expect(JSON.stringify(error)).not.toContain('auth_session_renewed');
      const after = await readCookie(browser);
      expect(after!.data).toEqual({ ...before!.data, authSession: 'auth_session_renewed', exp: startedAt + 900 });
      expect(after!.data.expiresAt).toBe(startedAt + 900);
      expect(after!.options!.maxAge).toBe(880);

      const tokenBodies = tokenSuccess();
      await sc.passkey.complete({ credential: signupCredential, verification: { email: '123456' } }, browser);
      expect(tokenBodies[0]).toMatchObject({ auth_session: 'auth_session_renewed' });
    });

    test('the error does not carry the auth session, which stays in the transaction', async () => {
      const { error, after } = await expectFailure(400, wrongCode({ verification_required: ['email'] }));
      const tokenError = error as PasskeyGetTokenError;

      expect(tokenError.isRetryable).toBe(true);
      expect(tokenError.verificationRequired).toEqual(['email']);
      expect(tokenError.authSession).toBeUndefined();
      expect(tokenError.cause?.auth_session).toBeUndefined();
      expect(JSON.stringify(tokenError)).not.toContain('auth_session_signup');
      expect(after!.data.authSession).toBe('auth_session_signup');
    });

    test('getToken() still returns the auth session on the error', async () => {
      tokenError(400, wrongCode({ verification_required: ['email'] }));

      const error = await makeClient()
        .passkey.getToken({ authSession: 'auth_session_signup', credential: signupCredential }, newBrowser())
        .catch((e: unknown) => e);

      expect((error as PasskeyGetTokenError).authSession).toBe('auth_session_signup');
    });

    test.each([
      { label: 'a used or expired session (403)', status: 403, body: { error: 'invalid_grant', error_description: 'Invalid or expired session' } },
      { label: 'a used or expired session (400)', status: 400, body: { error: 'invalid_grant', error_description: 'Invalid or expired session' } },
      { label: 'an invalid passkey', status: 403, body: { error: 'invalid_grant', error_description: 'Invalid passkey' } },
      {
        label: 'mfa_required',
        status: 403,
        body: { error: 'mfa_required', error_description: 'Multifactor authentication required', mfa_token: 'mfa_token_123' },
      },
      {
        label: 'mfa_required without an mfa_token',
        status: 403,
        body: { error: 'mfa_required', error_description: 'Multifactor authentication required' },
      },
    ])('deletes the transaction after $label', async ({ status, body }) => {
      const { error, after } = await expectFailure(status, body);

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect((error as PasskeyGetTokenError).isRetryable).toBe(false);
      expect(after).toBeUndefined();
    });

    test('keeps mfa_token on the error for the MFA APIs', async () => {
      const { error } = await expectFailure(403, {
        error: 'mfa_required',
        error_description: 'Multifactor authentication required',
        mfa_token: 'mfa_token_123',
      });

      expect(isMfaRequiredError(error)).toBe(true);
    });

    test.each([
      { label: 'a rate limit', status: 429, body: { error: 'access_denied', error_description: 'Too Many Requests' } },
      {
        label: 'a server error',
        status: 500,
        body: { error: 'server_error', error_description: 'Server error while validating OTP ticket' },
      },
      {
        label: 'an invalid request, such as a code that is too long',
        status: 400,
        body: {
          error: 'invalid_request',
          error_description: '"verification.email" length must be less than or equal to 10 characters long',
        },
      },
      { label: 'an Action that denies access', status: 500, body: { error: 'access_denied', error_description: 'Denied' } },
    ])('keeps the transaction after $label', async ({ status, body }) => {
      const { error, before, after, rewritten } = await expectFailure(status, body);

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(after!.data).toEqual(before!.data);
      expect(rewritten).toBe(false);
    });

    test('keeps the transaction after a network error', async () => {
      server.use(http.post(`https://${domain}/oauth/token`, () => HttpResponse.error()));
      const sc = makeClient();
      const browser = await startLogin(sc);
      const before = browser.cookies.get(passkeyCookie);

      await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).rejects.toThrowError();
      expect(browser.cookies.get(passkeyCookie)).toBe(before);
    });

    test('deletes the transaction when the ID token organization does not match', async () => {
      onTokenRequest(async () =>
        HttpResponse.json({
          ...buildTokenResponse(),
          id_token: await generateToken(domain, 'sub_123', clientId, undefined, { org_id: 'org_other' }),
        })
      );
      const sc = makeClient();
      const browser = await startLogin(sc, { organization: 'org_123' });

      await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).rejects.toBeInstanceOf(
        OrganizationValidationError
      );
      expect(browser.cookies.has(passkeyCookie)).toBe(false);
      expect(await sc.getSession(browser)).toBeUndefined();
    });

    test('throws the exchange error when the transaction store fails while deleting the transaction', async () => {
      tokenError(403, { error: 'invalid_grant', error_description: 'Invalid or expired session' });
      const store = new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler());
      const sc = makeClient({ transactionStore: store });
      const browser = await startLogin(sc);
      vi.spyOn(store, 'delete').mockRejectedValue(new Error('store unavailable'));

      await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).rejects.toBeInstanceOf(
        PasskeyGetTokenError
      );
    });

    test('throws the exchange error when the transaction store fails while updating the transaction', async () => {
      tokenError(400, wrongCode({ verification_required: ['phone'] }));
      const store = new CookieTransactionStore<Browser>({ secret }, new BrowserCookieHandler());
      const sc = makeClient({ transactionStore: store });
      const browser = await startSignupWithCodes(sc, ['email', 'phone']);
      const stored = browser.cookies.get(passkeyCookie);
      vi.spyOn(store, 'set').mockRejectedValueOnce(new Error('store unavailable'));

      const error = await sc.passkey
        .complete({ credential: signupCredential, verification: { email: '123456', phone: '000000' } }, browser)
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(error).toMatchObject({ isRetryable: true, verificationRequired: ['phone'] });
      expect((error as PasskeyGetTokenError).authSession).toBeUndefined();
      expect(browser.cookies.get(passkeyCookie)).toBe(stored);

      // The stored list was not narrowed, so the next call also needs the code Auth0 has already accepted.
      const tokenBodies = tokenSuccess();
      await expect(
        sc.passkey.complete({ credential: signupCredential, verification: { phone: '654321' } }, browser)
      ).rejects.toThrowError('Missing required parameter: verification.email');
      expect(tokenBodies).toHaveLength(0);

      await sc.passkey.complete(
        { credential: signupCredential, verification: { email: '123456', phone: '654321' } },
        browser
      );
      expect(tokenBodies).toHaveLength(1);
    });
  });

  describe('when the signup needs one-time codes', () => {
    test.each([
      { label: 'no verification', needed: ['email'], verification: undefined, message: 'Missing required parameter: verification.email' },
      { label: 'a code of only spaces', needed: ['email'], verification: { email: '   ' }, message: '"verification.email" is not allowed to be empty' },
      { label: 'a code for one of two identifiers', needed: ['email', 'phone'], verification: { email: '123456' }, message: 'Missing required parameter: verification.phone' },
      { label: 'two problems, the first listed one', needed: ['phone', 'email'], verification: { email: '' }, message: 'Missing required parameter: verification.phone' },
    ])('rejects $label without calling Auth0, and keeps the flow', async ({ needed, verification, message }) => {
      const tokenBodies = tokenSuccess();
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, needed);
      const stored = browser.cookies.get(passkeyCookie);

      const error = await sc.passkey
        .complete({ credential: signupCredential, verification }, browser)
        .catch((e: unknown) => e);

      // The same kind of error as the one Auth0 returns for a missing code.
      expect(error).toBeInstanceOf(PasskeyGetTokenError);
      expect(error).toMatchObject({
        message,
        cause: { error: 'invalid_request', error_description: message },
        isRetryable: false,
      });
      expect((error as PasskeyGetTokenError).authSession).toBeUndefined();
      expect((error as PasskeyGetTokenError).statusCode).toBeUndefined();
      expect(tokenBodies).toHaveLength(0);
      expect(browser.cookies.get(passkeyCookie)).toBe(stored);

      // The flow is kept, so the codes can still be sent with the same credential.
      await sc.passkey.complete(
        { credential: signupCredential, verification: { email: '123456', phone: '654321' } },
        browser
      );
      expect(tokenBodies).toHaveLength(1);
    });

    test('sends the codes as they are, and leaves codes for identifiers that are not listed to Auth0', async () => {
      const tokenBodies = tokenSuccess();
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email']);

      await sc.passkey.complete(
        { credential: signupCredential, verification: { email: ' 123456 ', phone: '  ' } },
        browser
      );

      expect(tokenBodies[0]).toMatchObject({ verification: { email: ' 123456 ', phone: '  ' } });
    });

    test('after a wrong code, needs codes only for the identifiers Auth0 still lists', async () => {
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email', 'phone']);
      const before = await readCookie(browser);
      tokenError(400, wrongCode({ verification_required: ['phone'] }));

      const error = await sc.passkey
        .complete({ credential: signupCredential, verification: { email: '123456', phone: '000000' } }, browser)
        .catch((e: unknown) => e);

      expect((error as PasskeyGetTokenError).verificationRequired).toEqual(['phone']);
      expect((await readCookie(browser))!.data).toEqual({ ...before!.data, verificationRequired: ['phone'] });

      // The email code was accepted, so only the phone code is needed now.
      const tokenBodies = tokenSuccess();
      await expect(
        sc.passkey.complete({ credential: signupCredential, verification: { email: '123456' } }, browser)
      ).rejects.toThrowError('Missing required parameter: verification.phone');
      expect(tokenBodies).toHaveLength(0);

      await sc.passkey.complete({ credential: signupCredential, verification: { phone: '654321' } }, browser);
      expect(tokenBodies[0]).toMatchObject({ auth_session: 'auth_session_signup', verification: { phone: '654321' } });
      expect(browser.cookies.has(passkeyCookie)).toBe(false);
    });

    test('keeps the realm and organization after a wrong code, and still checks the organization', async () => {
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email', 'phone'], { realm: 'db', organization: 'org_123' });
      tokenError(400, wrongCode({ verification_required: ['phone'] }));

      await expect(
        sc.passkey.complete(
          { credential: signupCredential, verification: { email: '123456', phone: '000000' } },
          browser
        )
      ).rejects.toBeInstanceOf(PasskeyGetTokenError);
      expect((await readCookie(browser))!.data).toMatchObject({
        realm: 'db',
        organization: 'org_123',
        verificationRequired: ['phone'],
      });

      const tokenBodies = onTokenRequest(async () =>
        HttpResponse.json({
          ...buildTokenResponse(),
          id_token: await generateToken(domain, 'sub_123', clientId, undefined, { org_id: 'org_other' }),
        })
      );

      await expect(
        sc.passkey.complete({ credential: signupCredential, verification: { phone: '654321' } }, browser)
      ).rejects.toBeInstanceOf(OrganizationValidationError);
      expect(tokenBodies[0]).toMatchObject({ realm: 'db', organization: 'org_123' });
      expect(await sc.getSession(browser)).toBeUndefined();
    });

    test('keeps the stored list when the wrong-code error lists no identifiers', async () => {
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email', 'phone']);
      const stored = browser.cookies.get(passkeyCookie);
      tokenError(400, wrongCode());

      const error = await sc.passkey
        .complete({ credential: signupCredential, verification: { email: '000000', phone: '000000' } }, browser)
        .catch((e: unknown) => e);

      expect((error as PasskeyGetTokenError).isRetryable).toBe(true);
      // Nothing changed, so nothing was written.
      expect(browser.cookies.get(passkeyCookie)).toBe(stored);
      await expect(
        sc.passkey.complete({ credential: signupCredential, verification: { phone: '654321' } }, browser)
      ).rejects.toThrowError('Missing required parameter: verification.email');
    });

    test('reports a credential from another flow before the missing codes', async () => {
      const tokenBodies = tokenSuccess();
      const sc = makeClient();
      const browser = await startSignupWithCodes(sc, ['email']);

      await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).rejects.toBeInstanceOf(
        MissingTransactionError
      );
      expect(tokenBodies).toHaveLength(0);
    });

    test('treats an empty list from a custom store as no verification', async () => {
      const tokenBodies = tokenSuccess();
      const entry = {
        authSession: 'auth_session_signup',
        challenge: signupChallenge,
        domain,
        expiresAt: Date.now() / 1000 + 60,
        verificationRequired: [],
      };
      const store: TransactionStore<Browser> = { get: vi.fn().mockResolvedValue(entry), set: vi.fn(), delete: vi.fn() };

      await makeClient({ transactionStore: store }).passkey.complete({ credential: signupCredential }, newBrowser());

      expect(tokenBodies).toHaveLength(1);
    });

    test('does not check the codes for a signup without verification, or for a login', async () => {
      const tokenBodies = tokenSuccess();
      const sc = makeClient();
      const signup = newBrowser();
      await sc.passkey.startSignup({ email: 'user@example.com' }, signup);

      await sc.passkey.complete({ credential: signupCredential }, signup);
      await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, await startLogin(sc));

      expect(tokenBodies).toHaveLength(2);
      expect(tokenBodies[0]).not.toHaveProperty('verification');
    });
  });

  describe('with an entry that is not a usable passkey transaction', () => {
    const storeWith = (data: TransactionData) => {
      const store: TransactionStore<Browser> = {
        get: vi.fn().mockResolvedValue(data),
        set: vi.fn(),
        delete: vi.fn(),
      };
      return store;
    };

    test('deletes a malformed passkey entry', async () => {
      const tokenBodies = tokenSuccess();
      const store = storeWith({ challenge: loginChallenge, domain, expiresAt: Date.now() / 1000 + 60 });

      await expect(
        makeClient({ transactionStore: store }).passkey.complete({ credential: credentialFor(loginChallenge) }, newBrowser())
      ).rejects.toBeInstanceOf(MissingTransactionError);
      expect(store.delete).toHaveBeenCalledWith(passkeyCookie, expect.anything());
      expect(tokenBodies).toHaveLength(0);
    });

    test('rethrows a store error other than an expired entry', async () => {
      const store = storeWith({});
      vi.mocked(store.get).mockRejectedValue(new Error('store unavailable'));

      await expect(
        makeClient({ transactionStore: store }).passkey.complete({ credential: credentialFor(loginChallenge) }, newBrowser())
      ).rejects.toThrowError('store unavailable');
      expect(store.delete).not.toHaveBeenCalled();
    });
  });
});

describe('passkey transaction identifier', () => {
  test('uses passkeyTransactionIdentifier as the cookie name', async () => {
    tokenSuccess();
    const sc = makeClient({ passkeyTransactionIdentifier: '__my_passkey' });
    const browser = newBrowser();

    await sc.passkey.startLogin(undefined, browser);
    expect([...browser.cookies.keys()]).toEqual(['__my_passkey']);

    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser);
    expect(browser.cookies.has('__my_passkey')).toBe(false);
  });

  test('the default identifiers are not prefixes of one another', async () => {
    const browser = newBrowser();

    await makeClient({ anonymousStore: new DefaultAnonymousStore({ secret }) }).passkey.startLogin(undefined, browser);

    expect(browser.cookies.has(passkeyCookie)).toBe(true);
  });

  test.each([
    { option: 'transactionIdentifier', value: '__a0_passkey', passkey: undefined },
    { option: 'transactionIdentifier', value: '__a0_tx', passkey: '__a0_tx_passkey' },
    { option: 'transactionIdentifier', value: '__a0_passkey_tx', passkey: undefined },
    { option: 'stateIdentifier', value: '__a0_passkey_tx_session', passkey: undefined },
    { option: 'stateIdentifier', value: '__a0_session', passkey: '__a0_session_passkey' },
    { option: 'anonymousSessionIdentifier', value: '__a0_pass', passkey: undefined },
    { option: 'anonymousSessionIdentifier', value: '__a0_anon', passkey: '__a0_anonymous' },
  ] as const)('rejects $option $value next to passkey identifier $passkey, before calling Auth0', async ({
    option,
    value,
    passkey,
  }) => {
    const challengeBodies = captureJsonBodies('/passkey/challenge', () => HttpResponse.json(challengeApiResponse()));
    const registerBodies = captureJsonBodies('/passkey/register', () => HttpResponse.json(registerApiResponse()));
    const tokenBodies = tokenSuccess();
    const sc = makeClient({
      anonymousStore: new DefaultAnonymousStore({ secret }),
      passkeyTransactionIdentifier: passkey,
      ...({ [option]: value } as Partial<ServerClientOptions<Browser>>),
    });
    const browser = newBrowser();

    await expect(sc.passkey.startLogin(undefined, browser)).rejects.toThrowError(InvalidConfigurationError);
    await expect(sc.passkey.startSignup({ email: 'user@example.com' }, browser)).rejects.toThrowError(
      /must not be a prefix of one another/
    );
    await expect(sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser)).rejects.toThrowError(
      InvalidConfigurationError
    );

    expect(challengeBodies).toHaveLength(0);
    expect(registerBodies).toHaveLength(0);
    expect(tokenBodies).toHaveLength(0);
    expect(browser.cookies.size).toBe(0);
  });

  test('ignores anonymousSessionIdentifier when no anonymousStore is configured', async () => {
    const browser = newBrowser();

    await makeClient({ anonymousSessionIdentifier: '__a0_passkey' }).passkey.startLogin(undefined, browser);

    expect(browser.cookies.has(passkeyCookie)).toBe(true);
  });

  test('does not affect the methods that keep no passkey transaction', async () => {
    tokenSuccess();
    const sc = makeClient({ transactionIdentifier: '__a0_passkey_tx' });
    const browser = newBrowser();

    const { authSession } = await sc.passkey.challenge(undefined, browser);
    await sc.passkey.getToken({ authSession, credential: credentialFor(loginChallenge) }, browser);

    expect((await sc.getUser(browser))?.sub).toBe('sub_123');
    expect(browser.cookies.size).toBe(0);
  });
});

describe('per-request options', () => {
  const captureHeader = (path: string, respond: () => Response) => {
    const seen: (string | null)[] = [];
    server.use(
      http.post(`https://${domain}${path}`, ({ request }) => {
        seen.push(request.headers.get('x-request-tag'));
        return respond();
      })
    );
    return seen;
  };

  test('startSignup forwards requestOptions to the signup challenge request', async () => {
    const seen = captureHeader('/passkey/register', () => HttpResponse.json(registerApiResponse()));

    await makeClient().passkey.startSignup({ email: 'user@example.com' }, newBrowser(), {
      headers: { 'X-Request-Tag': 'signup-1' },
    });

    expect(seen).toEqual(['signup-1']);
  });

  test('startLogin forwards requestOptions to the login challenge request', async () => {
    const seen = captureHeader('/passkey/challenge', () => HttpResponse.json(challengeApiResponse()));

    await makeClient().passkey.startLogin(undefined, newBrowser(), { headers: { 'X-Request-Tag': 'login-1' } });

    expect(seen).toEqual(['login-1']);
  });

  test('complete forwards requestOptions to the token request', async () => {
    const seen = captureHeader('/oauth/token', () => HttpResponse.json(buildTokenResponse()));
    const sc = makeClient();
    const browser = await startLogin(sc);

    await sc.passkey.complete({ credential: credentialFor(loginChallenge) }, browser, {
      headers: { 'X-Request-Tag': 'complete-1' },
    });

    expect(seen).toEqual(['complete-1']);
  });
});

describe('separation from redirect login', () => {
  test('the passkey and redirect-login transactions live in separate cookies', async () => {
    const sc = makeClient({ authorizationParams: { redirect_uri: 'https://app.example.com/callback' } });
    const browser = newBrowser();

    await sc.startInteractiveLogin(undefined, browser);
    await sc.passkey.startLogin(undefined, browser);

    expect([...browser.cookies.keys()].sort()).toEqual(['__a0_passkey_tx', '__a0_tx']);
    expect((await readCookie(browser, '__a0_tx'))!.data).toHaveProperty('codeVerifier');
    expect((await readCookie(browser, '__a0_tx'))!.data).not.toHaveProperty('authSession');
  });
});
