// Kept apart from auth-client.spec.ts because `vi.mock` applies to a whole file.
import { expect, test, afterAll, beforeAll, afterEach, vi, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import * as oidcClient from 'openid-client';
import * as jose from 'jose';
import { AuthClient } from './auth-client.js';
import * as requestFetch from './request-fetch.js';
import { jwks } from './test-utils/tokens.js';

// Wrap the real functions, so the calls still work and their arguments can be checked.
vi.mock('openid-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('openid-client')>();
  return { ...actual, discovery: vi.fn(actual.discovery), refreshTokenGrant: vi.fn(actual.refreshTokenGrant) };
});
vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('jose')>();
  return { ...actual, createRemoteJWKSet: vi.fn(actual.createRemoteJWKSet) };
});
vi.mock('./request-fetch.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./request-fetch.js')>();
  return { ...actual, createTimeoutFetch: vi.fn(actual.createTimeoutFetch) };
});

let domainCounter = 0;
const nextDomain = () => `timeout-options-${++domainCounter}.auth0.local`;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  vi.mocked(oidcClient.discovery).mockClear();
  vi.mocked(oidcClient.refreshTokenGrant).mockClear();
  vi.mocked(jose.createRemoteJWKSet).mockClear();
  vi.mocked(requestFetch.createTimeoutFetch).mockClear();
});

const useDomain = (timeoutDomain: string) => {
  server.use(
    http.get(`https://${timeoutDomain}/.well-known/openid-configuration`, () =>
      HttpResponse.json({
        issuer: `https://${timeoutDomain}/`,
        authorization_endpoint: `https://${timeoutDomain}/authorize`,
        token_endpoint: `https://${timeoutDomain}/oauth/token`,
        jwks_uri: `https://${timeoutDomain}/.well-known/jwks.json`,
      })
    ),
    http.get(`https://${timeoutDomain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks })),
    http.post(`https://${timeoutDomain}/oauth/token`, () =>
      HttpResponse.json({ access_token: '<access_token>', token_type: 'Bearer', expires_in: 3600 })
    )
  );
};

const makeClient = (timeoutDomain: string, httpTimeout?: number) =>
  new AuthClient({ domain: timeoutDomain, clientId: '<client_id>', clientSecret: '<client_secret>', httpTimeout });

// The 5th argument of `discovery` holds the options.
const discoveryOptions = () => vi.mocked(oidcClient.discovery).mock.calls[0]![4] as Record<string, unknown>;

// The configuration that the token request of `getTokenByRefreshToken` is made with.
const tokenRequestConfiguration = () => vi.mocked(oidcClient.refreshTokenGrant).mock.calls[0]![0];

// What openid-client does with a `timeout` in seconds: `AbortSignal.timeout(timeout * 1000)`.
const timerFor = (seconds: number) => seconds * 1000;

describe('httpTimeout - the fetch', () => {
  test('is wrapped when httpTimeout is set', () => {
    makeClient(nextDomain(), 45_000);

    expect(requestFetch.createTimeoutFetch).toHaveBeenCalledTimes(1);
    expect(requestFetch.createTimeoutFetch).toHaveBeenCalledWith(expect.any(Function), 45_000);
  });

  test('is not wrapped when httpTimeout is not set', () => {
    makeClient(nextDomain());

    expect(requestFetch.createTimeoutFetch).not.toHaveBeenCalled();
  });
});

describe('httpTimeout - limits of the underlying libraries', () => {
  test('discovery gets a limit that does not cut httpTimeout short, and is a valid timer', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    await makeClient(timeoutDomain, 45_000).buildAuthorizationUrl();

    const timer = timerFor(discoveryOptions().timeout as number);
    expect(timer).toBeGreaterThanOrEqual(45_000);
    expect(() => AbortSignal.timeout(timer)).not.toThrow();
  });

  // For these values `httpTimeout / 1000 * 1000` is not an integer, and `AbortSignal.timeout` throws on that.
  test.each([1001, 1003, 1005, 2147483001, 2592000000, Number.MAX_SAFE_INTEGER])(
    'discovery works with httpTimeout %s',
    async (httpTimeout) => {
      const timeoutDomain = nextDomain();
      useDomain(timeoutDomain);

      await expect(makeClient(timeoutDomain, httpTimeout).buildAuthorizationUrl()).resolves.toEqual(
        expect.objectContaining({ authorizationUrl: expect.any(URL) })
      );
    }
  );

  test('the token request configuration gets a limit that does not cut httpTimeout short, and is a valid timer', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    await makeClient(timeoutDomain, 45_000).getTokenByRefreshToken({ refreshToken: '<refresh_token>' });

    const timer = timerFor(tokenRequestConfiguration().timeout as number);
    expect(timer).toBeGreaterThanOrEqual(45_000);
    expect(() => AbortSignal.timeout(timer)).not.toThrow();
  });

  test('the token request configuration keeps the openid-client default when httpTimeout is not set', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    await makeClient(timeoutDomain).getTokenByRefreshToken({ refreshToken: '<refresh_token>' });

    // The default depends on the openid-client version: none up to 6.8.7, 30 seconds from 6.8.8.
    const libraryDefault = new oidcClient.Configuration({ issuer: 'https://issuer.example.com' }, '<client_id>')
      .timeout;
    expect(tokenRequestConfiguration().timeout).toBe(libraryDefault);
  });

  test('discovery receives no timeout when httpTimeout is not set', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    await makeClient(timeoutDomain).buildAuthorizationUrl();

    expect(discoveryOptions()).not.toHaveProperty('timeout');
  });

  test('the logout-token key fetch receives the limit as timeoutDuration', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    // The token is not valid; only the key-set options matter here.
    await makeClient(timeoutDomain, 45_000)
      .verifyLogoutToken({ logoutToken: '<logout_token>' })
      .catch(() => undefined);

    expect(vi.mocked(jose.createRemoteJWKSet)).toHaveBeenCalledWith(
      expect.any(URL),
      expect.objectContaining({ timeoutDuration: 45_000 })
    );
  });

  test('the logout-token key fetch caps a huge httpTimeout to the largest timer', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    // 30 days. A timer this long would be set to 1 ms.
    await makeClient(timeoutDomain, 2_592_000_000)
      .verifyLogoutToken({ logoutToken: '<logout_token>' })
      .catch(() => undefined);

    expect(vi.mocked(jose.createRemoteJWKSet)).toHaveBeenCalledWith(
      expect.any(URL),
      expect.objectContaining({ timeoutDuration: 2_147_483_647 })
    );
  });

  test('the logout-token key fetch keeps the jose default when httpTimeout is not set', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    await makeClient(timeoutDomain)
      .verifyLogoutToken({ logoutToken: '<logout_token>' })
      .catch(() => undefined);

    const options = vi.mocked(jose.createRemoteJWKSet).mock.calls[0]![1]!;
    expect(options.timeoutDuration).toBeUndefined();
  });
});
