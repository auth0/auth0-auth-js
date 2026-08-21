import { expect, test, afterAll, afterEach, beforeAll, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ServerClient } from '../server-client.js';
import {
  AnonymousSessionError,
  AnonymousSessionExpiredError,
  InvalidConfigurationError,
  MissingAnonymousSessionError,
} from '../index.js';
import { DefaultStateStore } from '../test-utils/default-state-store.js';
import { DefaultAnonymousStore } from '../test-utils/default-anonymous-store.js';
import { generateToken } from '../test-utils/tokens.js';
import type { AnonymousStateData, AnonymousStore, AuthorizationParameters } from '../types.js';

const domain = 'auth0.local';
const otherDomain = 'other.auth0.local';
const anonymousSessionIdentifier = '__a0_anon';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

interface AnonymousTokenBody {
  client_id?: string;
  client_secret?: string;
  session_token?: string;
  audience?: string;
  scope?: string;
  metadata?: Record<string, string>;
}

/**
 * Records every `POST /anonymous/token` body and answers the way Auth0 does: a create call
 * (no `session_token`) returns a `session_token`, a re-mint (with one) does not.
 */
const mockAnonymousToken = (
  options: {
    host?: string;
    accessToken?: string;
    expiresIn?: number;
    scope?: string;
    sessionToken?: string;
    /** Error returned for a re-mint, to simulate an expired/invalid session token. */
    remintError?: { status: number; error: string; error_description: string };
  } = {}
) => {
  const bodies: AnonymousTokenBody[] = [];
  let createCount = 0;

  server.use(
    http.post(`https://${options.host ?? domain}/anonymous/token`, async ({ request }) => {
      const body = (await request.json()) as AnonymousTokenBody;
      bodies.push(body);

      if (body.session_token) {
        if (options.remintError) {
          const { status, ...error } = options.remintError;
          return HttpResponse.json(error, { status });
        }

        return HttpResponse.json({
          access_token: `${options.accessToken ?? '<access_token>'}_reminted`,
          token_type: 'Bearer',
          expires_in: options.expiresIn ?? 7200,
          ...(options.scope && { scope: options.scope }),
        });
      }

      createCount += 1;
      return HttpResponse.json({
        access_token: `${options.accessToken ?? '<access_token>'}_${createCount}`,
        token_type: 'Bearer',
        expires_in: options.expiresIn ?? 7200,
        session_token: `${options.sessionToken ?? '<session_token>'}_${createCount}`,
        ...(options.scope && { scope: options.scope }),
      });
    })
  );

  return bodies;
};

/**
 * Wraps the in-memory store in the full {@link AnonymousStore} interface, so a test can see
 * the `storeOptions` the SDK passes down. The in-memory store's own two-argument signature
 * structurally cannot observe them, while a real store (a cookie store, for instance) cannot
 * work without them.
 */
const recordingAnonymousStore = (): AnonymousStore => {
  const inner = new DefaultAnonymousStore({ secret: '<secret>' });

  return {
    get: vi.fn((identifier: string) => inner.get(identifier)),
    set: vi.fn((identifier: string, anonymousStateData: AnonymousStateData) =>
      inner.set(identifier, anonymousStateData)
    ),
    delete: vi.fn((identifier: string) => inner.delete(identifier)),
  };
};

const makeClient = (
  overrides: {
    domain?: string | (() => Promise<string>);
    anonymousStore?: AnonymousStore | false;
    authorizationParams?: AuthorizationParameters;
  } = {}
) => {
  const anonymousStore =
    overrides.anonymousStore === false
      ? undefined
      : (overrides.anonymousStore ?? new DefaultAnonymousStore({ secret: '<secret>' }));

  const serverClient = new ServerClient({
    domain: overrides.domain ?? domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    ...(anonymousStore && { anonymousStore }),
    ...(overrides.authorizationParams && { authorizationParams: overrides.authorizationParams }),
  });

  return { serverClient, anonymousStore };
};

test('anonymous - throws InvalidConfigurationError when no anonymousStore is configured', () => {
  const { serverClient } = makeClient({ anonymousStore: false });

  expect(() => serverClient.anonymous).toThrowError(InvalidConfigurationError);
  expect(() => serverClient.anonymous).toThrowError(/anonymousStore/);
});

test('anonymous - exposes the sub-client when an anonymousStore is configured', () => {
  const { serverClient } = makeClient();

  expect(serverClient.anonymous).toBeDefined();
  expect(typeof serverClient.anonymous.createSession).toBe('function');
  expect(typeof serverClient.anonymous.getAccessToken).toBe('function');
  expect(typeof serverClient.anonymous.getSession).toBe('function');
  expect(typeof serverClient.anonymous.logout).toBe('function');
});

test('createSession - returns the access token and stores the session token', async () => {
  const bodies = mockAnonymousToken();
  const { serverClient, anonymousStore } = makeClient();

  const tokenSet = await serverClient.anonymous.createSession({ audience: 'https://api.example.com' });

  expect(tokenSet).toStrictEqual({
    audience: 'https://api.example.com',
    accessToken: '<access_token>_1',
    scope: undefined,
    expiresAt: expect.any(Number),
  });
  expect(bodies[0]).toStrictEqual({
    client_id: '<client_id>',
    client_secret: '<client_secret>',
    audience: 'https://api.example.com',
  });

  const stored = await anonymousStore!.get(anonymousSessionIdentifier);
  expect(stored?.sessionToken).toBe('<session_token>_1');
  expect(stored?.domain).toBe(domain);
  expect(stored?.tokenSets).toHaveLength(1);
  expect(stored?.tokenSets[0]).toMatchObject({
    audience: 'https://api.example.com',
    accessToken: '<access_token>_1',
    expiresAt: tokenSet.expiresAt,
  });
});

test('createSession - forwards metadata and scope, and never returns the session token', async () => {
  const bodies = mockAnonymousToken({ scope: 'read:articles' });
  const { serverClient } = makeClient();

  const tokenSet = await serverClient.anonymous.createSession({
    audience: 'https://api.example.com',
    scope: 'read:articles',
    metadata: { landing: 'pricing' },
  });

  expect(bodies[0]?.metadata).toStrictEqual({ landing: 'pricing' });
  expect(bodies[0]?.scope).toBe('read:articles');
  expect(tokenSet.scope).toBe('read:articles');
  expect(tokenSet).not.toHaveProperty('sessionToken');
});

test('createSession - inherits authorizationParams.audience but not authorizationParams.scope', async () => {
  const bodies = mockAnonymousToken();
  const { serverClient } = makeClient({
    authorizationParams: { audience: 'https://api.example.com', scope: 'openid profile offline_access' },
  });

  const tokenSet = await serverClient.anonymous.createSession();

  expect(bodies[0]?.audience).toBe('https://api.example.com');
  expect(bodies[0]).not.toHaveProperty('scope');
  expect(tokenSet.audience).toBe('https://api.example.com');
});

test('createSession - uses the synthetic default cache key without sending an audience', async () => {
  const bodies = mockAnonymousToken();
  const { serverClient, anonymousStore } = makeClient();

  const tokenSet = await serverClient.anonymous.createSession();

  expect(bodies[0]).not.toHaveProperty('audience');
  expect(tokenSet.audience).toBe('default');
  expect((await anonymousStore!.get(anonymousSessionIdentifier))?.tokenSets[0]?.audience).toBe('default');
});

test('createSession - replaces an existing anonymous session', async () => {
  mockAnonymousToken();
  // Typed as the interface so the spy records the full `set(identifier, data, removeIfExists, options)`
  // signature the SDK calls, not the two-argument override of the in-memory test store.
  const anonymousStore: AnonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const setSpy = vi.spyOn(anonymousStore, 'set');
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession();
  await serverClient.anonymous.createSession();

  // `removeIfExists` is true, so a second creation never merges into the first.
  expect(setSpy.mock.calls[1]?.[2]).toBe(true);
  const stored = await anonymousStore.get(anonymousSessionIdentifier);
  expect(stored?.sessionToken).toBe('<session_token>_2');
  expect(stored?.tokenSets).toHaveLength(1);
});

test('createSession - writes no user session, so getSession and getUser stay empty', async () => {
  mockAnonymousToken();
  const stateStore = new DefaultStateStore({ secret: '<secret>' });
  const setSpy = vi.spyOn(stateStore, 'set');
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore,
    anonymousStore: new DefaultAnonymousStore({ secret: '<secret>' }),
  });

  await serverClient.anonymous.createSession();

  expect(setSpy).not.toHaveBeenCalled();
  expect(await serverClient.getSession()).toBeUndefined();
  expect(await serverClient.getUser()).toBeUndefined();
});

test('createSession - surfaces AnonymousSessionError when Auth0 rejects the request', async () => {
  server.use(
    http.post(`https://${domain}/anonymous/token`, () =>
      HttpResponse.json(
        { error: 'feature_not_enabled', error_description: 'Anonymous sessions are not enabled' },
        { status: 403 }
      )
    )
  );
  const { serverClient, anonymousStore } = makeClient();

  await expect(serverClient.anonymous.createSession()).rejects.toBeInstanceOf(AnonymousSessionError);
  await expect(serverClient.anonymous.createSession()).rejects.toMatchObject({ code: 'feature_not_enabled' });
  expect(await anonymousStore!.get(anonymousSessionIdentifier)).toBeUndefined();
});

test('createSession - stores the anonymous sub read off the access token, and the metadata', async () => {
  const anonymousAccessToken = await generateToken(domain, 'anon@2f1c1b7e', 'https://api.example.com');
  server.use(
    http.post(`https://${domain}/anonymous/token`, () =>
      HttpResponse.json({
        access_token: anonymousAccessToken,
        token_type: 'Bearer',
        expires_in: 7200,
        session_token: '<session_token>_1',
      })
    )
  );
  const { serverClient } = makeClient();

  const tokenSet = await serverClient.anonymous.createSession({
    audience: 'https://api.example.com',
    metadata: { landing: 'pricing' },
  });

  // The application gets the join key it needs to merge anonymous data into the user's
  // account, without decoding the access token itself.
  const session = await serverClient.anonymous.getSession();
  expect(session?.sub).toBe('anon@2f1c1b7e');
  expect(session?.metadata).toStrictEqual({ landing: 'pricing' });
  // The sub is not exposed on the token set: that is the credential, not the session.
  expect(tokenSet).not.toHaveProperty('sub');
});

test('createSession - leaves sub undefined when the access token cannot be read', async () => {
  mockAnonymousToken();
  const { serverClient } = makeClient();

  // `<access_token>_1` is opaque, not a JWT, which is legitimate: the audience may not be
  // configured to issue JWTs. That must not fail the call.
  await serverClient.anonymous.createSession();
  const session = await serverClient.anonymous.getSession();

  expect(session).toBeDefined();
  expect(session?.sub).toBeUndefined();
  expect(session).not.toHaveProperty('metadata');
});

test('getAccessToken - throws MissingAnonymousSessionError when there is no session', async () => {
  const { serverClient } = makeClient();

  await expect(serverClient.anonymous.getAccessToken()).rejects.toBeInstanceOf(MissingAnonymousSessionError);
});

test('getAccessToken - returns the cached token without calling Auth0', async () => {
  const bodies = mockAnonymousToken();
  const { serverClient } = makeClient();

  const created = await serverClient.anonymous.createSession({ audience: 'https://api.example.com' });
  const tokenSet = await serverClient.anonymous.getAccessToken({ audience: 'https://api.example.com' });

  expect(tokenSet.accessToken).toBe(created.accessToken);
  expect(tokenSet.audience).toBe(created.audience);
  expect(tokenSet.expiresAt).toBe(created.expiresAt);
  // A single create call and no re-mint.
  expect(bodies).toHaveLength(1);
});

test('getAccessToken - re-mints an expired token and keeps the session token and createdAt', async () => {
  const bodies = mockAnonymousToken();
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession({ audience: 'https://api.example.com' });

  // Expire the cached access token, leaving the anonymous session itself untouched.
  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  await anonymousStore.set(anonymousSessionIdentifier, {
    ...stored,
    createdAt: stored.createdAt - 1000,
    tokenSets: [{ ...stored.tokenSets[0]!, expiresAt: Math.floor(Date.now() / 1000) - 10 }],
  });

  const tokenSet = await serverClient.anonymous.getAccessToken({ audience: 'https://api.example.com' });

  expect(tokenSet.accessToken).toBe('<access_token>_reminted');
  expect(bodies[1]?.session_token).toBe('<session_token>_1');
  // A re-mint must never carry metadata: Auth0 rejects metadata sent with a session token.
  expect(bodies[1]).not.toHaveProperty('metadata');

  const after = (await anonymousStore.get(anonymousSessionIdentifier))!;
  expect(after.sessionToken).toBe('<session_token>_1');
  expect(after.createdAt).toBe(stored.createdAt - 1000);
  expect(after.tokenSets).toHaveLength(1);
});

test('getAccessToken - fills in a missing sub from a re-minted token', async () => {
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  // The token minted at creation was opaque, so nothing could be read off it.
  mockAnonymousToken();
  await serverClient.anonymous.createSession();
  expect((await serverClient.anonymous.getSession())?.sub).toBeUndefined();

  // A JWT for another audience carries the same anonymous identity, so it can be recovered.
  const anonymousAccessToken = await generateToken(domain, 'anon@2f1c1b7e', 'https://api.example.com');
  server.use(
    http.post(`https://${domain}/anonymous/token`, () =>
      HttpResponse.json({ access_token: anonymousAccessToken, token_type: 'Bearer', expires_in: 7200 })
    )
  );

  await serverClient.anonymous.getAccessToken({ audience: 'https://api.example.com' });

  expect((await serverClient.anonymous.getSession())?.sub).toBe('anon@2f1c1b7e');
});

test('getAccessToken - caches per audience instead of replacing the existing token', async () => {
  mockAnonymousToken();
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession({ audience: 'https://api.one.com' });
  const second = await serverClient.anonymous.getAccessToken({ audience: 'https://api.two.com' });

  expect(second.audience).toBe('https://api.two.com');
  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  expect(stored.tokenSets.map((tokenSet) => tokenSet.audience)).toStrictEqual([
    'https://api.one.com',
    'https://api.two.com',
  ]);
});

test('getAccessToken - keeps a token another request cached while this one waited on Auth0', async () => {
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  mockAnonymousToken();
  await serverClient.anonymous.createSession({ audience: 'https://api.one.com' });

  // Simulates a concurrent request caching a token for another audience while the re-mint
  // below is in flight.
  server.use(
    http.post(`https://${domain}/anonymous/token`, async () => {
      const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
      await anonymousStore.set(anonymousSessionIdentifier, {
        ...stored,
        tokenSets: [
          ...stored.tokenSets,
          {
            audience: 'https://api.two.com',
            accessToken: '<other>',
            scope: undefined,
            expiresAt: Math.floor(Date.now() / 1000) + 7200,
          },
        ],
      });

      return HttpResponse.json({ access_token: '<access_token>_reminted', token_type: 'Bearer', expires_in: 7200 });
    })
  );

  await serverClient.anonymous.getAccessToken({ audience: 'https://api.three.com' });

  const after = (await anonymousStore.get(anonymousSessionIdentifier))!;
  expect(after.tokenSets.map((tokenSet) => tokenSet.audience)).toStrictEqual([
    'https://api.one.com',
    'https://api.two.com',
    'https://api.three.com',
  ]);
});

test('getAccessToken - writes nothing back when the session was dropped while waiting on Auth0', async () => {
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  mockAnonymousToken();
  await serverClient.anonymous.createSession();

  // Simulates a concurrent `logout()` landing while the re-mint is in flight.
  server.use(
    http.post(`https://${domain}/anonymous/token`, async () => {
      await anonymousStore.delete(anonymousSessionIdentifier);

      return HttpResponse.json({ access_token: '<access_token>_reminted', token_type: 'Bearer', expires_in: 7200 });
    })
  );

  const tokenSet = await serverClient.anonymous.getAccessToken({ audience: 'https://api.example.com' });

  expect(tokenSet.accessToken).toBe('<access_token>_reminted');
  expect(await anonymousStore.get(anonymousSessionIdentifier)).toBeUndefined();
});

test('getAccessToken - writes nothing back when the session was replaced while waiting on Auth0', async () => {
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  mockAnonymousToken();
  await serverClient.anonymous.createSession({ audience: 'https://api.one.com' });

  // Simulates a concurrent `createSession()` landing while the re-mint is in flight. The
  // visitor is on a new anonymous identity by the time the token comes back, so a token
  // minted for the old one must not be filed under it.
  server.use(
    http.post(`https://${domain}/anonymous/token`, async () => {
      const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
      await anonymousStore.set(anonymousSessionIdentifier, {
        ...stored,
        sessionToken: '<session_token>_2',
        tokenSets: [],
      });

      return HttpResponse.json({ access_token: '<access_token>_reminted', token_type: 'Bearer', expires_in: 7200 });
    })
  );

  const tokenSet = await serverClient.anonymous.getAccessToken({ audience: 'https://api.two.com' });

  expect(tokenSet.accessToken).toBe('<access_token>_reminted');
  const after = (await anonymousStore.get(anonymousSessionIdentifier))!;
  expect(after.sessionToken).toBe('<session_token>_2');
  expect(after.tokenSets).toStrictEqual([]);
});

test('getAccessToken - inherits authorizationParams.audience for the cache lookup', async () => {
  const bodies = mockAnonymousToken();
  const { serverClient, anonymousStore } = makeClient({
    authorizationParams: { audience: 'https://api.example.com' },
  });

  const created = await serverClient.anonymous.createSession();
  const tokenSet = await serverClient.anonymous.getAccessToken();

  // The default audience is used for the lookup as well as for the request, so the token
  // created for it is reused instead of a second one being minted under the synthetic
  // `default` cache key.
  expect(bodies).toHaveLength(1);
  expect(tokenSet.audience).toBe('https://api.example.com');
  expect(tokenSet.accessToken).toBe(created.accessToken);
  expect((await anonymousStore!.get(anonymousSessionIdentifier))?.tokenSets).toHaveLength(1);
});

test('getAccessToken - caches a token whose granted scope is narrower than requested', async () => {
  // Auth0 answers a request for a scope an anonymous caller is not entitled to with a success
  // and a narrower `scope`.
  const bodies = mockAnonymousToken({ scope: 'read:orders' });
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  const created = await serverClient.anonymous.createSession({
    audience: 'https://api.example.com',
    scope: 'read:orders write:orders',
  });
  expect(created.scope).toBe('read:orders');

  const first = await serverClient.anonymous.getAccessToken({
    audience: 'https://api.example.com',
    scope: 'read:orders write:orders',
  });
  const second = await serverClient.anonymous.getAccessToken({
    audience: 'https://api.example.com',
    scope: 'read:orders write:orders',
  });

  // One create call and no re-mint. Keying the cache on the granted scope alone would miss
  // every time and call Auth0 on every request.
  expect(bodies).toHaveLength(1);
  expect(first.accessToken).toBe(created.accessToken);
  expect(second.accessToken).toBe(created.accessToken);

  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  expect(stored.tokenSets).toHaveLength(1);
  expect(stored.tokenSets[0]).toMatchObject({
    scope: 'read:orders',
    requestedScope: 'read:orders write:orders',
  });
});

test('getAccessToken - re-mints with the requested scope and stores what Auth0 granted', async () => {
  const bodies = mockAnonymousToken({ scope: 'read:orders' });
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession({ audience: 'https://api.example.com' });

  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  await anonymousStore.set(anonymousSessionIdentifier, {
    ...stored,
    tokenSets: [{ ...stored.tokenSets[0]!, expiresAt: Math.floor(Date.now() / 1000) - 10 }],
  });

  const tokenSet = await serverClient.anonymous.getAccessToken({
    audience: 'https://api.example.com',
    scope: 'read:orders write:orders',
  });

  expect(bodies[1]?.scope).toBe('read:orders write:orders');
  expect(tokenSet.scope).toBe('read:orders');

  // One entry per requested scope for the same audience: the token asked for without a scope
  // is not overwritten by the one asked for with it.
  const after = (await anonymousStore.get(anonymousSessionIdentifier))!;
  expect(after.tokenSets).toHaveLength(2);
  expect(after.tokenSets[1]).toMatchObject({
    audience: 'https://api.example.com',
    scope: 'read:orders',
    requestedScope: 'read:orders write:orders',
  });
});

test('getAccessToken - reuses a cached token whose granted scope covers the request', async () => {
  const bodies = mockAnonymousToken({ scope: 'read:orders write:orders' });
  const { serverClient } = makeClient();

  await serverClient.anonymous.createSession({
    audience: 'https://api.example.com',
    scope: 'read:orders write:orders',
  });
  const tokenSet = await serverClient.anonymous.getAccessToken({
    audience: 'https://api.example.com',
    scope: 'write:orders',
  });

  expect(bodies).toHaveLength(1);
  expect(tokenSet.scope).toBe('read:orders write:orders');
});

test('getAccessToken - throws AnonymousSessionExpiredError and clears the store when the session expired', async () => {
  const bodies = mockAnonymousToken({
    remintError: { status: 400, error: 'session_expired', error_description: 'The session token has expired' },
  });
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession();

  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  await anonymousStore.set(anonymousSessionIdentifier, {
    ...stored,
    tokenSets: [{ ...stored.tokenSets[0]!, expiresAt: Math.floor(Date.now() / 1000) - 10 }],
  });

  await expect(serverClient.anonymous.getAccessToken()).rejects.toBeInstanceOf(AnonymousSessionExpiredError);

  // auth0-auth-js silently created a replacement identity. It must not be stored, so the
  // visitor is never moved onto an identity they did not ask for.
  expect(bodies.filter((body) => !body.session_token)).toHaveLength(2);
  expect(await anonymousStore.get(anonymousSessionIdentifier)).toBeUndefined();
});

test('getAccessToken - surfaces other AnonymousSessionError codes without clearing the store', async () => {
  mockAnonymousToken({
    remintError: { status: 400, error: 'invalid_target', error_description: 'Resource server not enabled' },
  });
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession();
  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  await anonymousStore.set(anonymousSessionIdentifier, {
    ...stored,
    tokenSets: [{ ...stored.tokenSets[0]!, expiresAt: Math.floor(Date.now() / 1000) - 10 }],
  });

  await expect(serverClient.anonymous.getAccessToken()).rejects.toMatchObject({ code: 'invalid_target' });
  expect((await anonymousStore.get(anonymousSessionIdentifier))?.sessionToken).toBe('<session_token>_1');
});

test('getSession - returns the session without the session token', async () => {
  mockAnonymousToken();
  const { serverClient } = makeClient();

  await serverClient.anonymous.createSession({ audience: 'https://api.example.com' });
  const session = await serverClient.anonymous.getSession();

  expect(session).toMatchObject({
    createdAt: expect.any(Number),
    domain,
    tokenSets: [
      {
        audience: 'https://api.example.com',
        accessToken: '<access_token>_1',
        expiresAt: expect.any(Number),
      },
    ],
  });
  expect(session).not.toHaveProperty('sessionToken');
});

test('getSession - returns undefined when there is no anonymous session', async () => {
  const { serverClient } = makeClient();

  expect(await serverClient.anonymous.getSession()).toBeUndefined();
});

test('logout - drops the session locally and never calls /anonymous/logout', async () => {
  mockAnonymousToken();
  const logoutCalled = vi.fn();
  server.use(
    http.post(`https://${domain}/anonymous/logout`, () => {
      logoutCalled();
      return new HttpResponse(null, { status: 204 });
    })
  );
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await serverClient.anonymous.createSession();
  await serverClient.anonymous.logout();

  expect(logoutCalled).not.toHaveBeenCalled();
  expect(await anonymousStore.get(anonymousSessionIdentifier)).toBeUndefined();
  await expect(serverClient.anonymous.getAccessToken()).rejects.toBeInstanceOf(MissingAnonymousSessionError);
});

test('logout - is a no-op when there is no anonymous session', async () => {
  const { serverClient } = makeClient();

  await expect(serverClient.anonymous.logout()).resolves.toBeUndefined();
});

test('resolver mode - createSession stores the resolved domain', async () => {
  const bodies = mockAnonymousToken({ host: otherDomain });
  const { serverClient, anonymousStore } = makeClient({ domain: async () => otherDomain });

  await serverClient.anonymous.createSession();

  expect(bodies).toHaveLength(1);
  expect((await anonymousStore!.get(anonymousSessionIdentifier))?.domain).toBe(otherDomain);
});

test('resolver mode - getSession returns the session created for the resolved domain', async () => {
  mockAnonymousToken({ host: otherDomain });
  const { serverClient } = makeClient({ domain: async () => otherDomain });

  await serverClient.anonymous.createSession({ audience: 'https://api.example.com' });
  const session = await serverClient.anonymous.getSession();

  // The domain check rejects a session from another tenant, it does not reject every session:
  // a multi-tenant application has to be able to read the one it just created.
  expect(session?.domain).toBe(otherDomain);
  expect(session?.tokenSets).toHaveLength(1);
});

test('resolver mode - getAccessToken rejects a session created for another domain', async () => {
  mockAnonymousToken();
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  let resolvedDomain = domain;
  const { serverClient } = makeClient({ domain: async () => resolvedDomain, anonymousStore });

  await serverClient.anonymous.createSession();
  resolvedDomain = otherDomain;

  await expect(serverClient.anonymous.getAccessToken()).rejects.toThrowError(
    /created for a different Auth0 domain/
  );
  expect(await serverClient.anonymous.getSession()).toBeUndefined();
});

test('static mode - getAccessToken tolerates a stored session without a domain', async () => {
  mockAnonymousToken();
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const { serverClient } = makeClient({ anonymousStore });

  await anonymousStore.set(anonymousSessionIdentifier, {
    sessionToken: '<session_token>_1',
    createdAt: Math.floor(Date.now() / 1000),
    tokenSets: [],
  });

  const tokenSet = await serverClient.anonymous.getAccessToken();

  expect(tokenSet.accessToken).toBe('<access_token>_reminted');
});

test('storeOptions - createSession forwards them to the store write', async () => {
  mockAnonymousToken();
  const anonymousStore = recordingAnonymousStore();
  const { serverClient } = makeClient({ anonymousStore });
  const storeOptions = { request: '<request>' };

  await serverClient.anonymous.createSession({ audience: 'https://api.example.com' }, storeOptions);

  expect(anonymousStore.set).toHaveBeenCalledWith(
    anonymousSessionIdentifier,
    expect.any(Object),
    true,
    storeOptions
  );
});

test('storeOptions - getAccessToken forwards them on both the read and the write', async () => {
  mockAnonymousToken();
  const anonymousStore = recordingAnonymousStore();
  const { serverClient } = makeClient({ anonymousStore });
  const storeOptions = { request: '<request>' };

  await serverClient.anonymous.createSession({ audience: 'https://api.example.com' }, storeOptions);

  // Expire the cached token, so the call has to read, re-mint and write back.
  const stored = (await anonymousStore.get(anonymousSessionIdentifier))!;
  await anonymousStore.set(anonymousSessionIdentifier, {
    ...stored,
    tokenSets: [{ ...stored.tokenSets[0]!, expiresAt: Math.floor(Date.now() / 1000) - 10 }],
  });

  await serverClient.anonymous.getAccessToken({ audience: 'https://api.example.com' }, storeOptions);

  expect(anonymousStore.get).toHaveBeenCalledWith(anonymousSessionIdentifier, storeOptions);
  // `false`, so only the write-back of the re-minted token can satisfy this.
  expect(anonymousStore.set).toHaveBeenCalledWith(
    anonymousSessionIdentifier,
    expect.any(Object),
    false,
    storeOptions
  );
});

test('storeOptions - getSession and logout forward them to the store', async () => {
  mockAnonymousToken();
  const anonymousStore = recordingAnonymousStore();
  const { serverClient } = makeClient({ anonymousStore });
  const storeOptions = { request: '<request>' };

  // `createSession` never reads, so the only read here comes from `getSession`.
  await serverClient.anonymous.createSession(undefined, storeOptions);
  await serverClient.anonymous.getSession(storeOptions);
  await serverClient.anonymous.logout(storeOptions);

  expect(anonymousStore.get).toHaveBeenCalledWith(anonymousSessionIdentifier, storeOptions);
  expect(anonymousStore.delete).toHaveBeenCalledWith(anonymousSessionIdentifier, storeOptions);
});

test('anonymousSessionIdentifier - is used as the store key', async () => {
  mockAnonymousToken();
  const anonymousStore = new DefaultAnonymousStore({ secret: '<secret>' });
  const serverClient = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
    anonymousStore,
    anonymousSessionIdentifier: '__custom_anon',
  });

  await serverClient.anonymous.createSession();

  expect(await anonymousStore.get('__custom_anon')).toBeDefined();
  expect(await anonymousStore.get(anonymousSessionIdentifier)).toBeUndefined();
});
