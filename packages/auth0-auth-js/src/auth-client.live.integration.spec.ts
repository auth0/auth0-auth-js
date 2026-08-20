/**
 * Tier 1b LIVE integration tests — Group C smoke checks
 *
 * Spec: /Users/tushar.pandey/src/node-auth0/.forge/features/auth-separation/TIER1B-SLICE-PLAN.md
 * Matrix: CHECK-MATRIX.md Group C (C-live-01..04)
 *
 * Hits REAL Auth0 tenant using creds from .env.validation (repo root, gitignored).
 * Guards: suite skipped when AUTH0_M2M_CLIENT_ID absent (dev machines, forks).
 *
 * Required env:
 * - AUTH0_DOMAIN, AUTH0_M2M_CLIENT_ID, AUTH0_M2M_CLIENT_SECRET, AUTH0_AUDIENCE (M2M → test API)
 * - AUTH0_MGMT_AUDIENCE (M2M → Mgmt API)
 * - AUTH0_WEB_CLIENT_ID, AUTH0_WEB_CLIENT_SECRET (web app)
 * - AUTH0_TEST_USER_EMAIL, AUTH0_TEST_USER_PASSWORD, AUTH0_DB_CONNECTION (password-realm)
 */

import { describe, it, expect } from 'vitest';
import { AuthClient } from './auth-client.js';

describe.skipIf(!process.env.AUTH0_M2M_CLIENT_ID)('live smoke (Tier 1b) [Group C]', () => {
  it('C-live-01: M2M client-credentials → test API returns access token with expected scope', async () => {
    const client = new AuthClient({
      domain: process.env.AUTH0_DOMAIN!,
      clientId: process.env.AUTH0_M2M_CLIENT_ID!,
      clientSecret: process.env.AUTH0_M2M_CLIENT_SECRET!,
    });

    const response = await client.getTokenByClientCredentials({
      audience: process.env.AUTH0_AUDIENCE!,
    });

    expect(response.accessToken).toBeDefined();
    expect(response.accessToken.length).toBeGreaterThan(0);
    expect(response.scope).toBeDefined();
    expect(response.scope).toContain('read:test');
    expect(response.scope).toContain('write:test');
  });

  it('C-live-02: M2M → Management API audience returns usable token; trivial GET /users succeeds', async () => {
    const client = new AuthClient({
      domain: process.env.AUTH0_DOMAIN!,
      clientId: process.env.AUTH0_M2M_CLIENT_ID!,
      clientSecret: process.env.AUTH0_M2M_CLIENT_SECRET!,
    });

    const response = await client.getTokenByClientCredentials({
      audience: process.env.AUTH0_MGMT_AUDIENCE!,
    });

    expect(response.accessToken).toBeDefined();
    expect(response.accessToken.length).toBeGreaterThan(0);

    // Verify token is usable against Mgmt API
    const mgmtResponse = await fetch(`${process.env.AUTH0_MGMT_AUDIENCE!}users?per_page=1`, {
      headers: {
        Authorization: `Bearer ${response.accessToken}`,
      },
    });

    expect(mgmtResponse.status).toBe(200);
  });

  // retry:0 — password grants against a live user; retries re-trigger brute-force block (too_many_attempts)
  it('C-live-03: password-realm grant with test user succeeds', { retry: 0 }, async () => {
    const client = new AuthClient({
      domain: process.env.AUTH0_DOMAIN!,
      clientId: process.env.AUTH0_WEB_CLIENT_ID!,
      clientSecret: process.env.AUTH0_WEB_CLIENT_SECRET!,
    });

    const response = await client.getTokenByPassword({
      username: process.env.AUTH0_TEST_USER_EMAIL!,
      password: process.env.AUTH0_TEST_USER_PASSWORD!,
      realm: process.env.AUTH0_DB_CONNECTION!,
      audience: process.env.AUTH0_AUDIENCE!,
      scope: 'openid profile read:test',
    });

    expect(response.accessToken).toBeDefined();
    expect(response.accessToken.length).toBeGreaterThan(0);
  });

  // retry:0 — see C-live-03
  it('C-live-04: offline_access yields refresh token; getTokenByRefreshToken exchanges it', { retry: 0 }, async () => {
    const client = new AuthClient({
      domain: process.env.AUTH0_DOMAIN!,
      clientId: process.env.AUTH0_WEB_CLIENT_ID!,
      clientSecret: process.env.AUTH0_WEB_CLIENT_SECRET!,
    });

    // Get initial tokens with offline_access
    const initialResponse = await client.getTokenByPassword({
      username: process.env.AUTH0_TEST_USER_EMAIL!,
      password: process.env.AUTH0_TEST_USER_PASSWORD!,
      realm: process.env.AUTH0_DB_CONNECTION!,
      audience: process.env.AUTH0_AUDIENCE!,
      scope: 'openid profile offline_access read:test write:test',
    });

    expect(initialResponse.accessToken).toBeDefined();
    expect(initialResponse.refreshToken).toBeDefined();
    expect(initialResponse.refreshToken!.length).toBeGreaterThan(0);

    // Exchange refresh token for new access token
    const refreshResponse = await client.getTokenByRefreshToken({
      refreshToken: initialResponse.refreshToken!,
      audience: process.env.AUTH0_AUDIENCE!,
    });

    expect(refreshResponse.accessToken).toBeDefined();
    expect(refreshResponse.accessToken.length).toBeGreaterThan(0);
    // New access token should differ from initial
    expect(refreshResponse.accessToken).not.toBe(initialResponse.accessToken);
  });

  it('C-live-05: fullResponse: true returns a real Response envelope with status 200 and headers', async () => {
    const client = new AuthClient({
      domain: process.env.AUTH0_DOMAIN!,
      clientId: process.env.AUTH0_M2M_CLIENT_ID!,
      clientSecret: process.env.AUTH0_M2M_CLIENT_SECRET!,
    });

    const { data, response } = await client.getTokenByClientCredentials({
      audience: process.env.AUTH0_AUDIENCE!,
      fullResponse: true,
    });

    expect(data.accessToken).toBeTruthy();
    expect(data.accessToken.length).toBeGreaterThan(0);
    expect(response).toBeInstanceOf(Response);
    expect(response.status).toBe(200);
    // Real Auth0 responses carry rate-limit and/or date headers
    expect(response.headers.get('x-ratelimit-limit') ?? response.headers.get('date')).toBeTruthy();
  });

  it('C-live-06: per-request customFetch + header reach the wire; aborted signal rejects', async () => {
    const client = new AuthClient({
      domain: process.env.AUTH0_DOMAIN!,
      clientId: process.env.AUTH0_M2M_CLIENT_ID!,
      clientSecret: process.env.AUTH0_M2M_CLIENT_SECRET!,
    });

    // Spy customFetch wrapping global fetch, checking for caller-supplied header.
    let spyCalled = false;
    let sawCustomHeader = false;
    const spyFetch: typeof fetch = (input, init) => {
      spyCalled = true;
      sawCustomHeader = new Headers(init?.headers).get('x-dx-parity-live') === 'c-live-06';
      return fetch(input, init);
    };

    const token = await client.getTokenByClientCredentials(
      { audience: process.env.AUTH0_AUDIENCE! },
      { customFetch: spyFetch, headers: { 'x-dx-parity-live': 'c-live-06' } }
    );

    expect(spyCalled).toBe(true);
    expect(sawCustomHeader).toBe(true);
    expect(token.accessToken).toBeTruthy();

    // Already-aborted signal → real cancellation, request rejects.
    await expect(
      client.getTokenByClientCredentials(
        { audience: process.env.AUTH0_AUDIENCE! },
        { signal: AbortSignal.abort(new Error('c-live-06 abort')) }
      )
    ).rejects.toThrow();
  });
});
