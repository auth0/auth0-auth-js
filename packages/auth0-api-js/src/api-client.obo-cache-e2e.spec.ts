/**
 * MSW-mocked end-to-end tests for getTokenOnBehalfOf with a TokenStore.
 *
 * Unlike the unit tests in api-client.spec.ts, these tests do not stub any ApiClient
 * method. Every call runs the complete public pipeline: subject token verification (JWKS
 * served by MSW), cache lookup, token exchange (token endpoint served by MSW), cache
 * write, return.
 *
 * The stores are real Map-backed implementations, so cache interactions are observable
 * through the Maps themselves rather than through mock assertions.
 */

import { expect, test, describe, afterAll, beforeAll, afterEach, beforeEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ApiClient } from './api-client.js';
import { InvalidConfigurationError, InvalidRequestError } from './errors.js';
import type { CachedToken, IndexedTokenStore, TokenIndexMember, TokenStore } from './token-store.js';
import { generateToken, jwks } from './test-utils/tokens.js';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Shared test infrastructure
// ---------------------------------------------------------------------------

const domain = 'obo-e2e.auth0.local';
const downstreamAudience = 'https://downstream.api.example.com';
const apiClientOpts = {
  domain,
  audience: '<audience>',
  clientId: 'e2e-client-id',
  clientSecret: 'e2e-client-secret',
} as const;

/**
 * Minimal in-memory TokenStore backed by a plain Map.
 */
function makeInMemoryStore() {
  const map = new Map<string, CachedToken>();
  const store: TokenStore = {
    get: (key: string) => Promise.resolve(map.get(key)),
    set: (key: string, value: CachedToken) => {
      map.set(key, value);
      return Promise.resolve();
    },
    delete: (key: string) => {
      map.delete(key);
      return Promise.resolve();
    },
  };
  return { store, map };
}

/**
 * In-memory IndexedTokenStore, so non-strict covering lookups can run end to end.
 */
function makeInMemoryIndexedStore() {
  const { store: base, map } = makeInMemoryStore();
  const indexes = new Map<string, Map<string, TokenIndexMember>>();
  const store: IndexedTokenStore = {
    ...base,
    addIndexMember: (indexKey: string, member: TokenIndexMember) => {
      const members = indexes.get(indexKey) ?? new Map<string, TokenIndexMember>();
      members.set(member.tokenKey, member);
      indexes.set(indexKey, members);
      return Promise.resolve();
    },
    listIndexMembers: (indexKey: string) => Promise.resolve([...(indexes.get(indexKey)?.values() ?? [])]),
  };
  return { store, map, indexes };
}

// Base MSW handlers: OIDC discovery + JWKS for the test domain.
const baseHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `https://${domain}/`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
      token_endpoint: `https://${domain}/oauth/token`,
    })
  ),
  http.get(`https://${domain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks })),
];

const server = setupServer(...baseHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generates a DPoP proof key pair and its JWK thumbprint, which a bound token carries as
 * `cnf.jkt`.
 */
async function makeDpopKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  return { key: { jwk, privateKey }, jkt: await calculateJwkThumbprint(jwk) };
}

/**
 * Signs a DPoP proof for a GET of https://api.example.com/resource with `accessToken`.
 */
async function makeDpopProof(key: Awaited<ReturnType<typeof makeDpopKey>>['key'], accessToken: string) {
  return new SignJWT({
    htm: 'GET',
    htu: 'https://api.example.com/resource',
    iat: Math.floor(Date.now() / 1000),
    jti: 'proof-jti',
    ath: createHash('sha256').update(accessToken).digest('base64url'),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: key.jwk })
    .sign(key.privateKey);
}

/**
 * Registers a token endpoint handler that answers every token exchange with the given
 * payload, and returns a counter of the exchanges that reached it.
 */
function registerTokenEndpoint(opts: {
  accessToken: string;
  expiresIn?: number;
  scope?: string;
  tokenType?: string;
  issuedTokenType?: string;
}) {
  let callCount = 0;
  server.use(
    http.post(`https://${domain}/oauth/token`, async ({ request }) => {
      const body = await request.formData();
      const grantType = body.get('grant_type');
      if (grantType !== 'urn:ietf:params:oauth:grant-type:token-exchange') {
        return HttpResponse.json({ error: 'invalid_grant' }, { status: 400 });
      }
      callCount++;
      return HttpResponse.json(
        {
          access_token: opts.accessToken,
          expires_in: opts.expiresIn ?? 3600,
          ...(opts.scope !== undefined && { scope: opts.scope }),
          token_type: opts.tokenType ?? 'Bearer',
          ...(opts.issuedTokenType !== undefined && {
            issued_token_type: opts.issuedTokenType,
          }),
        },
        { status: 200 }
      );
    })
  );
  return { getCallCount: () => callCount };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('getTokenOnBehalfOf OBO cache, MSW end to end (no internal stubs)', () => {
  let subjectToken: string;
  let oboToken: string;
  let apiClient: InstanceType<typeof ApiClient>;

  beforeEach(async () => {
    apiClient = new ApiClient(apiClientOpts);
    // Subject token: signed with the test RSA key; JWKS served by MSW.
    subjectToken = await generateToken(domain, 'user-e2e-001', '<audience>', undefined, undefined, undefined, {
      client_id: 'subject-client',
      org_id: 'org-001',
    });
    // Token issued for the downstream API.
    oboToken = await generateToken(domain, 'user-e2e-001', downstreamAudience);
  });

  test('cache miss: exchanges at the token endpoint and populates the store', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({
      accessToken: oboToken,
      scope: 'read write',
      issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    });

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read write' },
      { store }
    );

    expect(getCallCount()).toBe(1);
    expect(result.accessToken).toBe(oboToken);
    expect(result.expiresAt).toBeTypeOf('number');
    expect(result.scope).toBe('read write');
    expect(result.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(map.size).toBe(1);
    const [, cached] = [...map.entries()][0]!;
    expect(cached.accessToken).toBe(oboToken);
    expect(cached.grantedScopes).toEqual(['read', 'write']);
    expect(cached.expiresAt).toBeTypeOf('number');
  });

  test('cache hit: a second identical call is served from the store and matches the first', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({
      accessToken: oboToken,
      scope: 'read',
      issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    });

    const first = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store });
    expect(getCallCount()).toBe(1);
    expect(map.size).toBe(1);

    const second = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store });

    expect(getCallCount()).toBe(1);
    expect(second).toEqual(first);
  });

  test('near expiry: a cached token expiring inside the clock-skew leeway is exchanged again', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store });
    expect(getCallCount()).toBe(1);

    // Back-date the stored entry so it expires 3 seconds from now, inside the 5 second leeway.
    const nowSeconds = Math.floor(Date.now() / 1000);
    const [key, entry] = [...map.entries()][0]!;
    map.set(key, { ...entry, expiresAt: nowSeconds + 3 });

    const result = await apiClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store });

    expect(getCallCount()).toBe(2);
    expect(result.accessToken).toBe(oboToken);
  });

  test('narrowed grant: the token is returned and cached under the scopes it was granted', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read write' },
      { store }
    );

    expect(result.accessToken).toBe(oboToken);
    expect(result.scope).toBe('read');
    expect(map.size).toBe(1);
    expect([...map.values()][0]!.grantedScopes).toEqual(['read']);

    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store });
    expect(getCallCount()).toBe(1);

    await apiClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read write' }, { store });
    expect(getCallCount()).toBe(2);
  });

  test('empty grant: the empty scope is returned as an empty string and cached as an empty list', async () => {
    const { store, map } = makeInMemoryStore();
    registerTokenEndpoint({ accessToken: oboToken, scope: '' });

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read write' },
      { store }
    );

    expect(result).toHaveProperty('scope', '');
    expect([...map.values()][0]!.grantedScopes).toEqual([]);
  });

  test('without a store the subject token is forwarded without verification', async () => {
    const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });
    const verifySpy = vi.spyOn(apiClient, 'verifyAccessToken');

    // Not a verifiable JWT. With no store there is nothing to key, so it is forwarded as is.
    const result = await apiClient.getTokenOnBehalfOf('opaque-subject-token', { audience: downstreamAudience, scope: 'read' });

    expect(verifySpy).toHaveBeenCalledTimes(0);
    expect(getCallCount()).toBe(1);
    expect(result.accessToken).toBe(oboToken);
  });

  test('with a store, a subject token that does not verify is rejected and nothing is exchanged', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

    await expect(
      apiClient.getTokenOnBehalfOf('opaque-subject-token', { audience: downstreamAudience, scope: 'read' }, { store })
    ).rejects.toMatchObject({ code: 'verify_access_token_error' });

    expect(getCallCount()).toBe(0);
    expect(map.size).toBe(0);
  });

  // -------------------------------------------------------------------------
  // dpop mode "required"
  // -------------------------------------------------------------------------
  describe('dpop mode "required"', () => {
    test('without context.verified the internal bearer verification is rejected and nothing is exchanged', async () => {
      // Documented limitation: see the getTokenOnBehalfOf documentation.
      const requiredClient = new ApiClient({ ...apiClientOpts, dpop: { mode: 'required' } });
      const { store } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

      await expect(
        requiredClient.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store })
      ).rejects.toBeInstanceOf(InvalidRequestError);

      expect(getCallCount()).toBe(0);
    });

    test('with context.verified from the same client the exchange succeeds, caches, and is served from cache', async () => {
      // The client verifies the DPoP-bound token where the request context exists, with the
      // scheme and proof, then hands the very claims object it got back to the exchange.
      const requiredClient = new ApiClient({ ...apiClientOpts, dpop: { mode: 'required' } });
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

      const { key, jkt } = await makeDpopKey();
      const boundToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
        cnf: { jkt },
      });
      const claims = await requiredClient.verifyAccessToken({
        accessToken: boundToken,
        scheme: 'dpop',
        dpopProof: await makeDpopProof(key, boundToken),
        httpMethod: 'GET',
        httpUrl: 'https://api.example.com/resource',
      });
      const requiredVerifySpy = vi.spyOn(requiredClient, 'verifyAccessToken');
      const context = { store, verified: { accessToken: boundToken, claims } };

      const first = await requiredClient.getTokenOnBehalfOf(boundToken, { audience: downstreamAudience, scope: 'read' }, context);
      const second = await requiredClient.getTokenOnBehalfOf(boundToken, { audience: downstreamAudience, scope: 'read' }, context);

      expect(first).toEqual({
        accessToken: oboToken,
        expiresAt: expect.any(Number),
        grantedScopes: ['read'],
        scope: 'read',
        tokenType: expect.stringMatching(/^bearer$/i),
      });
      expect(second).toEqual(first);
      expect(getCallCount()).toBe(1);
      expect(map.size).toBe(1);
      expect(requiredVerifySpy).toHaveBeenCalledTimes(0);
    });

    test('claims verified by a different client are refused, even when that client accepted the same token', async () => {
      const ingressClient = new ApiClient(apiClientOpts);
      const requiredClient = new ApiClient({ ...apiClientOpts, dpop: { mode: 'required' } });
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });
      const claims = await ingressClient.verifyAccessToken({ accessToken: subjectToken });

      await expect(
        requiredClient.getTokenOnBehalfOf(
          subjectToken,
          { audience: downstreamAudience, scope: 'read' },
          { store, verified: { accessToken: subjectToken, claims } }
        )
      ).rejects.toBeInstanceOf(InvalidConfigurationError);

      expect(getCallCount()).toBe(0);
      expect(map.size).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Non-strict matching
  // -------------------------------------------------------------------------
  test('non_strict: a narrower request is served from a cached superset through the real index', async () => {
    const client = new ApiClient({ ...apiClientOpts, scopeMatching: 'non_strict' });
    const { store, map, indexes } = makeInMemoryIndexedStore();
    const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken, scope: 'read write admin' });

    await client.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read write admin' }, { store });
    const narrower = await client.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read' }, { store });

    expect(getCallCount()).toBe(1);
    expect(narrower.accessToken).toBe(oboToken);
    expect(map.size).toBe(1);
    expect(indexes.size).toBe(1);

    // A scope the cached token does not cover is not served from it.
    await client.getTokenOnBehalfOf(subjectToken, { audience: downstreamAudience, scope: 'read delete' }, { store });
    expect(getCallCount()).toBe(2);
  });

  // -------------------------------------------------------------------------
  // Cache key isolation: one test per axis, real tokens, one shared store.
  // -------------------------------------------------------------------------
  describe('cache key isolation across a shared store', () => {
    const baseClaims = { client_id: 'cid-base', org_id: 'org-base', sid: 'session-base' };

    const subjectWith = (sub: string, claims: Record<string, unknown> = {}) =>
      generateToken(domain, sub, '<audience>', undefined, undefined, undefined, { ...baseClaims, ...claims });

    async function expectIsolated(
      first: () => Promise<unknown>,
      second: () => Promise<unknown>,
      getCallCount: () => number,
      map: Map<string, CachedToken>
    ) {
      await first();
      await second();
      expect(getCallCount()).toBe(2);
      expect(map.size).toBe(2);
      expect(new Set(map.keys()).size).toBe(2);
    }

    test('different exchanging clientId', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const token = await subjectWith('sub-A');
      const clientX = new ApiClient({ ...apiClientOpts, clientId: 'exchange-X' });
      const clientY = new ApiClient({ ...apiClientOpts, clientId: 'exchange-Y' });

      await expectIsolated(
        () => clientX.getTokenOnBehalfOf(token, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => clientY.getTokenOnBehalfOf(token, { audience: downstreamAudience, scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('different configured audience', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const clientX = new ApiClient({ ...apiClientOpts, audience: 'https://audience-x.example.com' });
      const clientY = new ApiClient({ ...apiClientOpts, audience: 'https://audience-y.example.com' });
      const tokenX = await generateToken(domain, 'sub-A', 'https://audience-x.example.com', undefined, undefined, undefined, baseClaims);
      const tokenY = await generateToken(domain, 'sub-A', 'https://audience-y.example.com', undefined, undefined, undefined, baseClaims);

      await expectIsolated(
        () => clientX.getTokenOnBehalfOf(tokenX, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => clientY.getTokenOnBehalfOf(tokenY, { audience: downstreamAudience, scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('different requested downstream audience', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const token = await subjectWith('sub-A');

      await expectIsolated(
        () => apiClient.getTokenOnBehalfOf(token, { audience: 'https://one.example.com', scope: 'read' }, { store }),
        () => apiClient.getTokenOnBehalfOf(token, { audience: 'https://two.example.com', scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('different sub', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const tokenA = await subjectWith('sub-A');
      const tokenB = await subjectWith('sub-B');

      await expectIsolated(
        () => apiClient.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => apiClient.getTokenOnBehalfOf(tokenB, { audience: downstreamAudience, scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('different org_id', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const tokenA = await subjectWith('sub-A');
      const tokenB = await subjectWith('sub-A', { org_id: 'org-other' });

      await expectIsolated(
        () => apiClient.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => apiClient.getTokenOnBehalfOf(tokenB, { audience: downstreamAudience, scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('different iss', async () => {
      const otherDomain = 'obo-e2e-other.auth0.local';
      server.use(
        http.get(`https://${otherDomain}/.well-known/openid-configuration`, () =>
          HttpResponse.json({
            issuer: `https://${otherDomain}/`,
            jwks_uri: `https://${otherDomain}/.well-known/jwks.json`,
            token_endpoint: `https://${otherDomain}/oauth/token`,
          })
        ),
        http.get(`https://${otherDomain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks }))
      );
      // One client trusts both issuers and exchanges at its own domain, so the issuer is
      // the only thing that differs between the two calls.
      const multiIssuerClient = new ApiClient({ ...apiClientOpts, domains: [domain, otherDomain] });
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const tokenA = await subjectWith('sub-A');
      const tokenB = await generateToken(otherDomain, 'sub-A', '<audience>', undefined, undefined, undefined, baseClaims);

      await expectIsolated(
        () => multiIssuerClient.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => multiIssuerClient.getTokenOnBehalfOf(tokenB, { audience: downstreamAudience, scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('different sid (the session)', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const sessionOne = await subjectWith('sub-A', { sid: 'session-one' });
      const sessionTwo = await subjectWith('sub-A', { sid: 'session-two' });

      await expectIsolated(
        () => apiClient.getTokenOnBehalfOf(sessionOne, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => apiClient.getTokenOnBehalfOf(sessionTwo, { audience: downstreamAudience, scope: 'read' }, { store }),
        getCallCount,
        map
      );
    });

    test('the same sid on two different subject tokens reuses one entry, so the session claim and not the token drives the key', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const firstToken = await subjectWith('sub-A', { sid: 'session-shared', nonce: 'one' });
      const secondToken = await subjectWith('sub-A', { sid: 'session-shared', nonce: 'two' });
      expect(firstToken).not.toBe(secondToken);

      await apiClient.getTokenOnBehalfOf(firstToken, { audience: downstreamAudience, scope: 'read' }, { store });
      await apiClient.getTokenOnBehalfOf(secondToken, { audience: downstreamAudience, scope: 'read' }, { store });

      expect(getCallCount()).toBe(1);
      expect(map.size).toBe(1);
    });

    test('different requested scope sets', async () => {
      const { store, map } = makeInMemoryStore();
      const { getCallCount } = registerTokenEndpoint({ accessToken: oboToken });
      const token = await subjectWith('sub-A');

      await expectIsolated(
        () => apiClient.getTokenOnBehalfOf(token, { audience: downstreamAudience, scope: 'read' }, { store }),
        () => apiClient.getTokenOnBehalfOf(token, { audience: downstreamAudience, scope: 'read write' }, { store }),
        getCallCount,
        map
      );
    });
  });
});
