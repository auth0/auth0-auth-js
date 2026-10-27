// Kept apart from auth-client.spec.ts because `vi.mock` applies to a whole file.
import { expect, test, afterAll, beforeAll, afterEach, vi, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import * as oidcClient from 'openid-client';
import * as jose from 'jose';
import { AuthClient } from './auth-client.js';
import { jwks } from './test-utils/tokens.js';

// Wrap the real functions, so the calls still work and their arguments can be checked.
vi.mock('openid-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('openid-client')>();
  return { ...actual, discovery: vi.fn(actual.discovery) };
});
vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('jose')>();
  return { ...actual, createRemoteJWKSet: vi.fn(actual.createRemoteJWKSet) };
});

let domainCounter = 0;
const nextDomain = () => `timeout-options-${++domainCounter}.auth0.local`;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  vi.mocked(oidcClient.discovery).mockClear();
  vi.mocked(jose.createRemoteJWKSet).mockClear();
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
    http.get(`https://${timeoutDomain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks }))
  );
};

const makeClient = (timeoutDomain: string, httpTimeout?: number) =>
  new AuthClient({ domain: timeoutDomain, clientId: '<client_id>', clientSecret: '<client_secret>', httpTimeout });

// The 5th argument of `discovery` holds the options.
const discoveryOptions = () => vi.mocked(oidcClient.discovery).mock.calls[0]![4] as Record<string, unknown>;

describe('httpTimeout - limits of the underlying libraries', () => {
  test('discovery receives the limit in seconds, so a value above 30 s is not cut short', async () => {
    const timeoutDomain = nextDomain();
    useDomain(timeoutDomain);

    await makeClient(timeoutDomain, 45_000).buildAuthorizationUrl();

    expect(discoveryOptions().timeout).toBe(45);
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
