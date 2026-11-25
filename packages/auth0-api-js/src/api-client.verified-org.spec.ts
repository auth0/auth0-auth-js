import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { createHash } from 'node:crypto';
import { ApiClient } from './api-client.js';
import { MissingOrganizationError, OrganizationNotAllowedError, VerifyAccessTokenError } from './errors.js';
import type { CachedToken, VerifiedToken } from './token-store.js';
import type { ApiClientOptions } from './types.js';
import { generateToken, jwks } from './test-utils/tokens.js';

// A client that enforces organization policy never hands out claims that violate it:
// verifyAccessToken rejects them first. To exercise the check that getTokenOnBehalfOf
// repeats on pre-verified claims, these tests change what the token's organization looks
// like after verifyAccessToken has enforced the policy and before the claims are recorded.
// The hook below does that, and is a pass-through unless a test installs one.
const hooks = vi.hoisted(() => ({
  tamper: undefined as undefined | ((payload: Record<string, unknown>) => Record<string, unknown>),
}));

vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('jose')>();
  const verify = vi.fn(async (...args: unknown[]) => {
    const result = await (actual.jwtVerify as (...a: unknown[]) => Promise<{ payload: Record<string, unknown> }>)(
      ...args
    );
    // Only subject tokens carry a sub; DPoP proofs do not.
    if (hooks.tamper && result.payload['sub'] !== undefined) {
      return { ...result, payload: hooks.tamper(result.payload) };
    }
    return result;
  });
  return { ...actual, jwtVerify: verify };
});

const domain = 'auth0.local';
const backendAudience = 'https://api.backend.com';
const validOrg = 'org_ok';

const server = setupServer(
  http.get(`https://${domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `https://${domain}/`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
      token_endpoint: `https://${domain}/oauth/token`,
    })
  ),
  http.get(`https://${domain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks }))
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  hooks.tamper = undefined;
  vi.restoreAllMocks();
});

/**
 * Makes the token's `org_id` read as `validOrg` while verifyAccessToken enforces the
 * policy, as `orgAfterVerify` in the copy recorded right after, and as `validOrg` again
 * for anything that reads the object handed to the caller later.
 */
function orgChangesAfterVerification(orgAfterVerify: string | undefined, orgDuringVerify: string = validOrg) {
  hooks.tamper = (payload) => {
    const copy = { ...payload };
    delete copy['org_id'];
    let reads = 0;
    Object.defineProperty(copy, 'org_id', {
      enumerable: true,
      configurable: true,
      get() {
        reads++;
        if (reads === 1) return orgDuringVerify;
        if (reads === 2) return orgAfterVerify;
        return validOrg;
      },
    });
    return copy;
  };
}

function makeStore() {
  const map = new Map<string, CachedToken>();
  return {
    map,
    get: vi.fn((key: string): Promise<CachedToken | undefined> => Promise.resolve(map.get(key))),
    set: vi.fn((key: string, value: CachedToken): Promise<void> => {
      map.set(key, value);
      return Promise.resolve();
    }),
    delete: vi.fn((key: string): Promise<void> => {
      map.delete(key);
      return Promise.resolve();
    }),
  };
}

function useExchange(accessToken: string) {
  const state = { count: 0 };
  server.use(
    http.post(`https://${domain}/oauth/token`, () => {
      state.count++;
      return HttpResponse.json({ access_token: accessToken, expires_in: 3600, token_type: 'Bearer', scope: 'read' });
    })
  );
  return state;
}

const baseOptions = {
  domain,
  audience: '<audience>',
  clientId: 'my-client-id',
  clientSecret: 'my-client-secret',
} as const;

async function subjectToken() {
  return generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
    client_id: 'client-abc',
    org_id: validOrg,
  });
}

async function verify(client: ApiClient): Promise<VerifiedToken> {
  const accessToken = await subjectToken();
  return { accessToken, claims: await client.verifyAccessToken({ accessToken }) };
}

function exchange(client: ApiClient, verified: VerifiedToken, store: ReturnType<typeof makeStore>) {
  return client.getTokenOnBehalfOf(
    verified.accessToken,
    { audience: backendAudience, scope: 'read' },
    { store, verified }
  );
}

function challengesOf(err: { headers?: Record<string, string | string[]> }): string[] {
  const value = err.headers?.['www-authenticate'];
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

describe('organization policy on a pre-verified subject token', () => {
  test('a "required" policy rejects claims without an organization, before any store access or exchange', async () => {
    const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required' });
    orgChangesAfterVerification(undefined);
    const verified = await verify(client);
    const store = makeStore();
    const token = useExchange('downstream-token');

    const err = await exchange(client, verified, store).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(MissingOrganizationError);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    const failure = err as MissingOrganizationError;
    expect(failure.statusCode).toBe(401);
    expect(failure.code).toBe('missing_organization');

    // dpop.mode defaults to 'allowed', so both challenges are offered; a claims object
    // without a key binding was presented as a bearer token, so the error is on that one.
    const challenges = challengesOf(failure);
    expect(challenges).toHaveLength(2);
    expect(challenges.find((c) => c.startsWith('Bearer '))).toContain('error="invalid_token"');
    expect(challenges.find((c) => c.startsWith('DPoP '))).not.toContain('error=');

    expect(token.count).toBe(0);
    expect(store.get).toHaveBeenCalledTimes(0);
    expect(store.set).toHaveBeenCalledTimes(0);
    expect(store.map.size).toBe(0);
  });

  test('an allowlist rejects claims whose organization is not on it, with no exchange', async () => {
    const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required', organizationId: [validOrg] });
    orgChangesAfterVerification('org_other');
    const verified = await verify(client);
    const store = makeStore();
    const token = useExchange('downstream-token');

    const err = await exchange(client, verified, store).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OrganizationNotAllowedError);
    expect((err as OrganizationNotAllowedError).statusCode).toBe(401);
    expect((err as OrganizationNotAllowedError).code).toBe('organization_not_allowed');
    expect(token.count).toBe(0);
    expect(store.get).toHaveBeenCalledTimes(0);
    expect(store.set).toHaveBeenCalledTimes(0);
  });

  test('an allowlist accepts claims whose organization is on it, and exchanges once', async () => {
    const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required', organizationId: [validOrg] });
    const verified = await verify(client);
    const store = makeStore();
    const token = useExchange('downstream-token');

    const result = await exchange(client, verified, store);

    expect(result.accessToken).toBe('downstream-token');
    expect(token.count).toBe(1);
    expect(store.map.size).toBe(1);
  });

  test('enforcement does not verify the subject token a second time', async () => {
    const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required', organizationId: [validOrg] });
    const verified = await verify(client);
    const store = makeStore();
    useExchange('downstream-token');
    const verifySpy = vi.spyOn(client, 'verifyAccessToken');
    vi.mocked(jwtVerify).mockClear();

    await exchange(client, verified, store);

    expect(verifySpy).toHaveBeenCalledTimes(0);
    expect(jwtVerify).toHaveBeenCalledTimes(0);
  });

  test('the policy and allowlist in force are the ones captured at construction', async () => {
    const options: ApiClientOptions = { ...baseOptions, organizationPolicy: 'required', organizationId: [validOrg] };
    const client = new ApiClient(options);
    orgChangesAfterVerification('org_other');
    const verified = await verify(client);
    const store = makeStore();
    const token = useExchange('downstream-token');

    // Widen the allowlist, then switch the policy off, on the object the caller still holds.
    options.organizationId = [validOrg, 'org_other'];
    const widened = await exchange(client, verified, store).catch((e: unknown) => e);
    options.organizationPolicy = undefined;
    options.organizationId = undefined;
    const disabled = await exchange(client, verified, store).catch((e: unknown) => e);

    expect(widened).toBeInstanceOf(OrganizationNotAllowedError);
    expect(disabled).toBeInstanceOf(OrganizationNotAllowedError);
    expect(token.count).toBe(0);
  });

  test('an "allow" policy lets claims without an organization through', async () => {
    const client = new ApiClient({ ...baseOptions, organizationPolicy: 'allow' });
    orgChangesAfterVerification(undefined);
    const verified = await verify(client);
    const store = makeStore();
    const token = useExchange('downstream-token');

    const result = await exchange(client, verified, store);

    expect(result.accessToken).toBe('downstream-token');
    expect(token.count).toBe(1);
  });

  test('no policy configured lets claims without an organization through', async () => {
    const client = new ApiClient(baseOptions);
    orgChangesAfterVerification(undefined);
    const verified = await verify(client);
    const token = useExchange('downstream-token');

    const result = await exchange(client, verified, makeStore());

    expect(result.accessToken).toBe('downstream-token');
    expect(token.count).toBe(1);
  });

  test('changes the caller makes to the claims object after verification do not satisfy the policy', async () => {
    const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required' });
    orgChangesAfterVerification(undefined);
    const verified = await verify(client);
    // The caller adds an organization to the object it holds; the copy recorded at
    // verification time is what must be checked.
    Object.defineProperty(verified.claims, 'org_id', { value: validOrg, configurable: true, enumerable: true });
    const store = makeStore();
    const token = useExchange('downstream-token');

    const err = await exchange(client, verified, store).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(MissingOrganizationError);
    expect(token.count).toBe(0);
    expect(store.get).toHaveBeenCalledTimes(0);
  });

  describe('DPoP-bound claims', () => {
    let keyPair: ReturnType<typeof generateKeyPair> | undefined;

    async function makeDpopRequest() {
      keyPair ??= generateKeyPair('ES256');
      const { publicKey, privateKey } = await keyPair;
      const jwk = await exportJWK(publicKey);
      const jkt = await calculateJwkThumbprint(jwk);
      const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
        client_id: 'client-abc',
        org_id: validOrg,
        cnf: { jkt },
      });
      const proof = await new SignJWT({
        htm: 'GET',
        htu: 'https://api.example.com/resource',
        iat: Math.floor(Date.now() / 1000),
        jti: 'proof-jti',
        ath: createHash('sha256').update(accessToken).digest('base64url'),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
        .sign(privateKey);

      return {
        accessToken,
        verifyOptions: {
          accessToken,
          scheme: 'dpop',
          dpopProof: proof,
          httpMethod: 'GET',
          httpUrl: 'https://api.example.com/resource',
        },
      };
    }

    test('the challenge for a key-bound token targets the DPoP scheme', async () => {
      const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required' });
      orgChangesAfterVerification(undefined);
      const request = await makeDpopRequest();
      const verified = {
        accessToken: request.accessToken,
        claims: await client.verifyAccessToken(request.verifyOptions),
      };
      const store = makeStore();
      const token = useExchange('downstream-token');

      const err = await exchange(client, verified, store).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(MissingOrganizationError);
      const challenges = challengesOf(err as MissingOrganizationError);
      expect(challenges).toHaveLength(2);
      const dpop = challenges.find((c) => c.startsWith('DPoP '))!;
      expect(dpop).toContain('error="invalid_token"');
      expect(dpop).not.toContain('missing_organization');
      expect(challenges.find((c) => c.startsWith('Bearer '))).not.toContain('error=');
      expect(token.count).toBe(0);
      expect(store.get).toHaveBeenCalledTimes(0);
    });

    test('with DPoP disabled, a claim named cnf.jkt does not move the challenge off the bearer scheme', async () => {
      const client = new ApiClient({ ...baseOptions, organizationPolicy: 'required', dpop: { mode: 'disabled' } });
      orgChangesAfterVerification(undefined);
      const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
        client_id: 'client-abc',
        org_id: validOrg,
        cnf: { jkt: 'some-thumbprint' },
      });
      const verified = { accessToken, claims: await client.verifyAccessToken({ accessToken }) };

      const err = await exchange(client, verified, makeStore()).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(MissingOrganizationError);
      const challenges = challengesOf(err as MissingOrganizationError);
      expect(challenges.join(',')).not.toContain('DPoP');
      expect(challenges.find((c) => c.startsWith('Bearer '))).toContain('error="invalid_token"');
    });
  });
});
