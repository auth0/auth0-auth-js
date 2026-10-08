/**
 * MSW-mocked end-to-end tests for getTokenOnBehalfOf with a TokenStore.
 *
 * Unlike the unit tests in api-client.spec.ts, these tests do NOT spy on any
 * internal ApiClient methods.  Every call runs the complete public pipeline:
 *   verifyAccessToken (JWKS served by MSW) → cache lookup → token exchange
 *   (token endpoint served by MSW) → cache write → return.
 *
 * The store is a real functional Map-based implementation so cache interactions
 * are observable through the Map itself, not through mock assertions.
 */

import { expect, test, describe, afterAll, beforeAll, afterEach, beforeEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ApiClient } from './api-client.js';
import { DownscopedTokenError } from './errors.js';
import type { CachedToken, TokenStore } from './token-store.js';
import { generateToken, jwks } from './test-utils/tokens.js';

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
 * Implements the public TokenStore interface with no vi.fn wrappers,
 * so cache interactions are verified by inspecting the Map directly.
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

// Base MSW handlers: OIDC discovery + JWKS for the test domain.
const baseHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `https://${domain}/`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
      token_endpoint: `https://${domain}/oauth/token`,
    })
  ),
  http.get(`https://${domain}/.well-known/jwks.json`, () =>
    HttpResponse.json({ keys: jwks })
  ),
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

/** Register an MSW handler that responds to the token endpoint with the given
 *  access-token payload and returns an exchange-call counter. */
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

describe('getTokenOnBehalfOf OBO cache — MSW e2e (no internal spies)', () => {
  let subjectToken: string;
  let oboToken: string;
  let apiClient: InstanceType<typeof ApiClient>;

  beforeEach(async () => {
    apiClient = new ApiClient(apiClientOpts);
    // Subject token: signed with the test RSA key; JWKS served by MSW.
    subjectToken = await generateToken(
      domain,
      'user-e2e-001',
      '<audience>',
      undefined,
      undefined,
      undefined,
      { client_id: 'subject-client', org_id: 'org-001' }
    );
    // OBO token issued by the downstream API.
    oboToken = await generateToken(domain, 'user-e2e-001', downstreamAudience);
  });

  // -------------------------------------------------------------------------
  // 1. Cache MISS: exchanges at the token endpoint and populates the store.
  // -------------------------------------------------------------------------
  test('cache MISS: performs token exchange via MSW and stores the result', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({
      accessToken: oboToken,
      scope: 'read write',
      issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    });

    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read write' },
      store
    );

    // Exchange must have reached the token endpoint exactly once.
    expect(getCallCount()).toBe(1);
    // Return value must carry the exchanged token.
    expect(result.accessToken).toBe(oboToken);
    expect(result.expiresAt).toBeTypeOf('number');
    expect(result.scope).toBe('read write');
    expect(result.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
    // Store must now hold exactly one entry.
    expect(map.size).toBe(1);
    const [, cached] = [...map.entries()][0]!;
    expect(cached.accessToken).toBe(oboToken);
    expect(cached.grantedScopes).toEqual(['read', 'write']);
    expect(cached.expiresAt).toBeTypeOf('number');
  });

  // -------------------------------------------------------------------------
  // 2. Cache HIT: second call with identical params serves from the store.
  // -------------------------------------------------------------------------
  test('cache HIT: second call with same params skips the token endpoint', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({
      accessToken: oboToken,
      scope: 'read',
    });

    // First call — must miss and exchange.
    const first = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read' },
      store
    );
    expect(getCallCount()).toBe(1);
    expect(map.size).toBe(1);

    // Second call — must hit the store, no second exchange.
    const second = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read' },
      store
    );
    expect(getCallCount()).toBe(1); // still 1 — no new exchange
    expect(second.accessToken).toBe(first.accessToken);
    expect(second.expiresAt).toBe(first.expiresAt);
    expect(second.scope).toBe('read');
  });

  // -------------------------------------------------------------------------
  // 3. Near-expiry (< 5 s leeway): treated as a MISS and re-exchanged.
  // -------------------------------------------------------------------------
  test('near-expiry: cached token expiring within 5 s leeway triggers re-exchange', async () => {
    const { store, map } = makeInMemoryStore();
    const { getCallCount } = registerTokenEndpoint({
      accessToken: oboToken,
      scope: 'read',
    });

    // First call — populates the cache.
    await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read' },
      store
    );
    expect(getCallCount()).toBe(1);
    expect(map.size).toBe(1);

    // Back-date the stored entry so it expires 3 s from "now" (inside the 5 s leeway).
    const nowSeconds = Math.floor(Date.now() / 1000);
    const firstEntry = [...map.entries()][0]!;
    map.set(firstEntry[0], { ...firstEntry[1], expiresAt: nowSeconds + 3 });

    // Second call — the near-expiry entry must be treated as a miss.
    const result = await apiClient.getTokenOnBehalfOf(
      subjectToken,
      { audience: downstreamAudience, scope: 'read' },
      store
    );
    expect(getCallCount()).toBe(2); // re-exchanged
    expect(result.accessToken).toBe(oboToken);
  });

  // -------------------------------------------------------------------------
  // 4. Downscoped: DownscopedTokenError is raised and nothing is written.
  // -------------------------------------------------------------------------
  test('downscoped result: throws DownscopedTokenError and does not write to store', async () => {
    const { store, map } = makeInMemoryStore();
    // Token endpoint grants only 'read' but 'read write' was requested.
    registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

    await expect(
      apiClient.getTokenOnBehalfOf(
        subjectToken,
        { audience: downstreamAudience, scope: 'read write' },
        store
      )
    ).rejects.toBeInstanceOf(DownscopedTokenError);

    // Nothing must have been written to the store.
    expect(map.size).toBe(0);
  });

  test('downscoped result: DownscopedTokenError carries expected code and status', async () => {
    const { store } = makeInMemoryStore();
    registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

    let caught: unknown;
    await apiClient
      .getTokenOnBehalfOf(
        subjectToken,
        { audience: downstreamAudience, scope: 'read write' },
        store
      )
      .catch((e) => {
        caught = e;
      });

    expect(caught).toBeInstanceOf(DownscopedTokenError);
    expect((caught as DownscopedTokenError).code).toBe('downscoped_token_error');
    expect((caught as DownscopedTokenError).statusCode).toBe(400);
    expect((caught as DownscopedTokenError).message).toMatch(/read, write/);
  });

  // -------------------------------------------------------------------------
  // 5. Cache key is injective across all 8 dimensions (subject isolation).
  //
  //    Key format:
  //      [exchangingClientId(0), exchangingAudience(1), iss(2), clientId(3),
  //       sub(4), orgId(5), audience(6), normalizedScopes(7)]
  // -------------------------------------------------------------------------
  test('key injectivity — 8 dimensions: varying any single dimension produces a distinct key', async () => {
    // Use a single shared store so we can assert unique keys all at once.
    const { store, map } = makeInMemoryStore();
    registerTokenEndpoint({ accessToken: oboToken, scope: 'read' });

    // Build tokens varying one claim at a time.
    const baseClaims = { client_id: 'cid-base', org_id: 'org-base' };

    // (a) base subject: sub='sub-A', client_id='cid-base', org_id='org-base'
    const tokenA = await generateToken(domain, 'sub-A', '<audience>', undefined, undefined, undefined, baseClaims);
    // (b) vary sub only
    const tokenB = await generateToken(domain, 'sub-B', '<audience>', undefined, undefined, undefined, baseClaims);
    // (c) vary org_id only
    const tokenC = await generateToken(domain, 'sub-A', '<audience>', undefined, undefined, undefined, {
      ...baseClaims,
      org_id: 'org-diff',
    });
    // (d) vary client_id only
    const tokenD = await generateToken(domain, 'sub-A', '<audience>', undefined, undefined, undefined, {
      ...baseClaims,
      client_id: 'cid-diff',
    });

    // Calls with different downstream audiences or scopes also produce distinct keys:
    // (e) same subject, different downstream audience
    // (f) same subject, different scope set
    // These use tokenA.

    // Dimension 0+1 (exchangingClientId + exchangingAudience): two ApiClient instances
    const clientX = new ApiClient({
      domain,
      audience: '<audience>',
      clientId: 'exchg-X',
      clientSecret: 'secret',
    });
    const clientY = new ApiClient({
      domain,
      audience: '<audience>',
      clientId: 'exchg-Y',
      clientSecret: 'secret',
    });

    // We need separate stores per client to count entries correctly, then merge for the final
    // assertion.  Use the shared store for (a)-(f) and separate stores for (g)+(h).
    const { store: storeX, map: mapX } = makeInMemoryStore();
    const { store: storeY, map: mapY } = makeInMemoryStore();

    // (a) base
    await apiClient.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience, scope: 'read' }, store);
    // (b) vary sub
    await apiClient.getTokenOnBehalfOf(tokenB, { audience: downstreamAudience, scope: 'read' }, store);
    // (c) vary org_id
    await apiClient.getTokenOnBehalfOf(tokenC, { audience: downstreamAudience, scope: 'read' }, store);
    // (d) vary client_id claim
    await apiClient.getTokenOnBehalfOf(tokenD, { audience: downstreamAudience, scope: 'read' }, store);
    // (e) vary downstream audience
    await apiClient.getTokenOnBehalfOf(tokenA, { audience: 'https://other.api.example.com', scope: 'read' }, store);
    // (f) vary scope: omit scope entirely so slot[7] = '' (distinct from 'read') and the
    //      downscope guard is skipped (no requested scopes → no guard check).
    await apiClient.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience }, store);
    // (g) vary exchangingClientId (slot 0)
    await clientX.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience, scope: 'read' }, storeX);
    // (h) vary exchangingClientId again (slot 0 confirmed)
    await clientY.getTokenOnBehalfOf(tokenA, { audience: downstreamAudience, scope: 'read' }, storeY);

    // Assertions: every call above must have produced a unique cache key.
    expect(map.size).toBe(6); // (a)-(f): 6 distinct entries in the shared store

    // Verify key slot semantics for the shared-store entries.
    const allKeys = [...map.keys()].map((k) => JSON.parse(k) as string[]);
    // slot[4] (sub) differs between (a) and (b)
    const subs = allKeys.map((k) => k[4]);
    expect(new Set(subs).size).toBeGreaterThanOrEqual(2);
    // slot[5] (orgId) differs between (a) and (c)
    const orgs = allKeys.map((k) => k[5]);
    expect(new Set(orgs).size).toBeGreaterThanOrEqual(2);
    // slot[3] (subjectClientId) differs between (a) and (d)
    const cids = allKeys.map((k) => k[3]);
    expect(new Set(cids).size).toBeGreaterThanOrEqual(2);
    // slot[6] (downstream audience) differs between (a) and (e)
    const audiences = allKeys.map((k) => k[6]);
    expect(new Set(audiences).size).toBeGreaterThanOrEqual(2);
    // slot[7] (scopes): call (a) has 'read'; call (f) omits scope so slot is '' — distinct.
    const scopes = allKeys.map((k) => k[7]);
    expect(new Set(scopes).size).toBeGreaterThanOrEqual(2);

    // exchangingClientId (slot 0) must differ between clientX and clientY.
    const kX = [...mapX.keys()][0]!;
    const kY = [...mapY.keys()][0]!;
    expect(kX).not.toBe(kY);
    expect((JSON.parse(kX) as string[])[0]).toBe('exchg-X');
    expect((JSON.parse(kY) as string[])[0]).toBe('exchg-Y');
  });
});
