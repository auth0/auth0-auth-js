import { afterEach, describe, expect, test, vi } from 'vitest';
import { buildOboIndexKey, buildOboTokenKey, deriveSessionKey } from './obo-cache-key.js';
import { InvalidConfigurationError } from './errors.js';
import type { OboCacheKeyIdentity } from './obo-cache-key.js';
import type { VerifiedAccessTokenClaims } from './types.js';

// The expected strings below were produced by the original implementation, which hashed with
// node's createHash. They pin the key format byte for byte: a change to the field order, the
// separator, the length prefixes or the digest encoding would orphan every entry already
// sitting in a shared store, so it has to fail here and not in production.

const base = {
  exchangeTenant: 'tenant.auth0.com',
  exchangeClientId: 'cid',
  exchangeAudience: 'https://mcp.example/',
  requestedAudience: 'https://api.example/',
};

const withSid: OboCacheKeyIdentity = {
  ...base,
  verified: {
    accessToken: 'at.sid',
    claims: {
      iss: 'https://tenant.auth0.com/',
      client_id: 'sub-client',
      sub: 'auth0|123',
      org_id: 'org_1',
      sid: 'sid-1',
      jti: 'jti-1',
    } as VerifiedAccessTokenClaims,
  },
};

const withoutSessionClaims: OboCacheKeyIdentity = {
  ...base,
  verified: {
    accessToken: 'header.payload.signature',
    claims: { iss: 'https://tenant.auth0.com/', azp: 'sub-client', sub: 'auth0|123' } as VerifiedAccessTokenClaims,
  },
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('OBO cache key golden values', () => {
  test('strict token key with a sid and unsorted, duplicated scopes', async () => {
    await expect(buildOboTokenKey({ ...withSid, layout: 'strict', scope: 'write read read' })).resolves.toBe(
      'a0.obo.v1.strict.i4wSAbMGTkA8J-c46HLz3IioRwsDRmdsX3Znpei6gWY'
    );
  });

  test('non-strict index key', async () => {
    await expect(buildOboIndexKey(withSid)).resolves.toBe(
      'a0.obo.index.v1.ysPkOB3o6xgIk3XyIBXYrVJMoj2j0oyiBClm-254gKM'
    );
  });

  test('session key falls back to a hash of the access token', async () => {
    await expect(deriveSessionKey(withoutSessionClaims.verified)).resolves.toBe(
      'at:JW0E205eSsMIdR7QiFtyK3WGMFZ8U6cSXtn70Gjlw_Y'
    );
  });
});

describe('missing Web Crypto', () => {
  test('building a key that needs a hash throws a configuration error, not a TypeError', async () => {
    vi.stubGlobal('crypto', undefined);

    const failure = await buildOboTokenKey({ ...withSid, layout: 'strict', scope: 'read' }).catch((error) => error);

    expect(failure).toBeInstanceOf(InvalidConfigurationError);
    expect(failure.message).toBe('Web Crypto (crypto.subtle) is required to build OBO cache keys.');
  });

  test('the same error is raised when crypto exists without subtle', async () => {
    vi.stubGlobal('crypto', {});

    await expect(deriveSessionKey(withoutSessionClaims.verified)).rejects.toBeInstanceOf(InvalidConfigurationError);
  });
});
