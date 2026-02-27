import { describe, expect, test, beforeEach, vi } from 'vitest';

import { ApiClient } from './api-client.js';
import type { DPoPOptions, VerifyAccessTokenOptions } from './types.js';
import {
  InvalidRequestError,
  InvalidConfigurationError,
  VerifyAccessTokenError,
} from './errors.js';

// Hoisted mocks
const {
  jwtVerifyMock,
  createRemoteJWKSetMock,
  verifyDpopProofMock,
  discoveryRequestMock,
  processDiscoveryResponseMock,
} = vi.hoisted(() => ({
  jwtVerifyMock: vi.fn(),
  createRemoteJWKSetMock: vi.fn(),
  verifyDpopProofMock: vi.fn(),
  discoveryRequestMock: vi.fn(),
  processDiscoveryResponseMock: vi.fn(),
}));

vi.mock('oauth4webapi', () => ({
  customFetch: Symbol('customFetch'),
  discoveryRequest: discoveryRequestMock,
  processDiscoveryResponse: processDiscoveryResponseMock,
}));

vi.mock('jose', () => ({
  jwtVerify: jwtVerifyMock,
  createRemoteJWKSet: createRemoteJWKSetMock,
  customFetch: Symbol('customFetch'),
  decodeJwt: vi.fn(() => ({})),
  decodeProtectedHeader: vi.fn(() => ({})),
  // Minimal placeholder to satisfy verifyProofJwt signature
  EmbeddedJWK: Symbol('EmbeddedJWK'),
}));

vi.mock('./dpop-api.js', async () => {
  const actual = await vi.importActual<typeof import('./dpop-api.js')>('./dpop-api.js');
  return {
    ...actual,
    verifyDpopProof: verifyDpopProofMock,
  };
});

const domain = 'auth0.local';
const audience = 'https://api';

beforeEach(() => {
  jwtVerifyMock.mockReset();
  createRemoteJWKSetMock.mockReset();
  verifyDpopProofMock.mockReset();
  discoveryRequestMock.mockReset();
  processDiscoveryResponseMock.mockReset();

  createRemoteJWKSetMock.mockImplementation(() => vi.fn());
  discoveryRequestMock.mockResolvedValue({});
  processDiscoveryResponseMock.mockImplementation(() => ({
    issuer: 'https://auth0.local/',
    jwks_uri: 'https://auth0.local/.well-known/jwks.json',
  }));
  jwtVerifyMock.mockImplementation(async (token: string) => {
    if (!token) throw new Error('missing token');
    if (token.includes('invalid')) throw new Error('signature verification failed');
    const payload: Record<string, unknown> = { sub: 'user' };
    if (token.includes('bound')) payload.cnf = { jkt: 'thumb' };
    return { payload, protectedHeader: {} };
  });
  verifyDpopProofMock.mockResolvedValue(undefined);
});

const getChallenges = (err: unknown) => {
  const wa = (err as { headers?: Record<string, string | string[]> })?.headers?.['www-authenticate'];
  return Array.isArray(wa) ? wa : wa ? [wa] : [];
};

const verify = (client: ApiClient, opts: VerifyAccessTokenOptions) => client.verifyAccessToken(opts);

describe('ApiClient.verifyAccessToken DPoP behaviors', () => {
  describe('constructor validation', () => {
    test('rejects non-object dpop config', () => {
      expect(() => new ApiClient({ domain, audience, dpop: 'bad' as DPoPOptions })).toThrow(
        InvalidConfigurationError
      );
    });

    test('rejects invalid dpop mode', () => {
      expect(() => new ApiClient({ domain, audience, dpop: { mode: 'weird' as DPoPOptions['mode'] } })).toThrow(
        InvalidConfigurationError
      );
    });

    test('rejects non-finite iatOffset', () => {
      expect(
        () => new ApiClient({ domain, audience, dpop: { mode: 'allowed', iatOffset: Number.NaN } })
      ).toThrow(InvalidConfigurationError);
    });

    test('rejects non-finite iatLeeway', () => {
      expect(
        () => new ApiClient({ domain, audience, dpop: { mode: 'allowed', iatLeeway: Infinity } })
      ).toThrow(InvalidConfigurationError);
    });

    test('rejects negative iatOffset', () => {
      expect(() => new ApiClient({ domain, audience, dpop: { mode: 'allowed', iatOffset: -1 } })).toThrow(
        InvalidConfigurationError
      );
    });

    test('rejects negative iatLeeway', () => {
      expect(() => new ApiClient({ domain, audience, dpop: { mode: 'allowed', iatLeeway: -5 } })).toThrow(
        InvalidConfigurationError
      );
    });

    test('accepts valid dpop config', () => {
      expect(() =>
        new ApiClient({
          domain,
          audience,
          dpop: { mode: 'required', iatOffset: 10, iatLeeway: 5 },
        })
      ).not.toThrow();
    });
  });

  test('dpop params without scheme | invalid_request asking for DPoP scheme', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, {
      accessToken: 'valid',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    } as unknown as VerifyAccessTokenOptions).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.message).toBe('');
    expect(err.cause).toEqual({ code: 'invalid_auth_scheme' });
    expect(verifyDpopProofMock).not.toHaveBeenCalled();
    const challenges = getChallenges(err);
    expect(challenges).toContain('DPoP algs="ES256"');
  });

  test('missing access token | verify_access_token_error with dual challenges', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, { accessToken: '' }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.code).toBe('verify_access_token_error');
    expect(err.message).toBe('');
    const challenges = getChallenges(err);
    expect(challenges.some((c) => c.startsWith('Bearer realm="api"'))).toBe(true);
    expect(challenges.some((c) => c === 'DPoP algs="ES256"')).toBe(true);
    expect(challenges.some((c) => c.includes('error='))).toBe(false);
  });

  test('disabled mode rejects dpop scheme before verify', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'disabled' } });
    const err = await verify(client, { accessToken: 'valid', scheme: 'dpop' }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.cause).toEqual({ code: 'invalid_auth_scheme' });
    expect(getChallenges(err)).toContain('Bearer realm="api"');
  });

  test('required mode rejects bearer scheme before verify', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'required' } });
    const err = await verify(client, { accessToken: 'valid', scheme: 'bearer' }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.cause).toEqual({ code: 'invalid_auth_scheme' });
    const challenges = getChallenges(err);
    expect(challenges).toContain('DPoP algs="ES256"');
    expect(challenges.some((c: string) => c.includes('Bearer'))).toBe(false);
  });

  test('unsupported scheme when enabled | invalid_request with dual challenges', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, { accessToken: 'valid', scheme: 'weird' }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.cause).toEqual({ code: 'invalid_auth_scheme' });
    const challenges = getChallenges(err);
    expect(challenges).toContain('Bearer realm="api"');
    expect(challenges).toContain('DPoP algs="ES256"');
  });

  test('bearer scheme with bound token | invalid_token and dual challenges', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, { accessToken: 'valid-bound', scheme: 'bearer' }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.code).toBe('verify_access_token_error');
    const challenges = getChallenges(err);
    expect(
      challenges.some(
        (c) =>
          c.startsWith('Bearer realm="api"') &&
          c.includes('error="invalid_token"') &&
          c.includes('DPoP-bound token requires the DPoP authentication scheme')
      )
    ).toBe(true);
    expect(challenges).toContain('DPoP algs="ES256"');
  });

  test('bearer scheme with proof but unbound token | invalid_request, error on bearer challenge', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, {
      accessToken: 'valid',
      scheme: 'bearer',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    const challenges = getChallenges(err);
    expect(
      challenges.some((c: string) =>
        c.includes('error="invalid_request"') &&
        c.includes('DPoP proof requires the DPoP authentication scheme, not Bearer')
      )
    ).toBe(true);
  });

  test('dpop scheme without proof | invalid_request, no error params in challenges', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'dpop',
    }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.message).toBe('');
    const challenges = getChallenges(err);
    expect(challenges).toContain('Bearer realm="api"');
    expect(challenges).toContain('DPoP algs="ES256"');
    expect(challenges.some((c: string) => c.includes('error='))).toBe(false);
  });

  test('dpop scheme with proof missing httpMethod | missing_required_argument', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'dpop',
      dpopProof: 'proof',
      httpUrl: 'https://api/resource',
    } as unknown as VerifyAccessTokenOptions).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.message).toContain('HTTP method is required');
  });

  test('dpop scheme with proof missing httpUrl | missing_required_argument', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'dpop',
      dpopProof: 'proof',
      httpMethod: 'GET',
    } as unknown as VerifyAccessTokenOptions).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.message).toContain('HTTP URL is required');
  });

  test('uppercase DPoP scheme with proof | accepted after normalization', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const payload = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'DPoP',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    });
    expect(payload.sub).toBe('user');
    expect(verifyDpopProofMock).toHaveBeenCalled();
  });

  test('disabled mode | ignores provided dpop proof', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'disabled' } });
    const payload = await verify(client, {
      accessToken: 'valid',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    } as unknown as VerifyAccessTokenOptions);
    expect(payload.sub).toBe('user');
    expect(verifyDpopProofMock).not.toHaveBeenCalled();
  });

  test('required mode | dpop params but no scheme', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'required' } });
    const err = await verify(client, {
      accessToken: 'valid-bound',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    } as unknown as VerifyAccessTokenOptions).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.cause).toEqual({ code: 'invalid_auth_scheme' });
    expect(getChallenges(err)).toEqual(['DPoP algs="ES256"']);
  });

  test('required mode | bearer scheme with dpop params', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'required' } });
    const err = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'bearer',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    expect(err.cause).toEqual({ code: 'invalid_auth_scheme' });
    expect(getChallenges(err)).toEqual(['DPoP algs="ES256"']);
  });

  test('required mode | uppercase DPoP scheme with proof succeeds', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'required' } });
    const payload = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'DPoP',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    });
    expect(payload.sub).toBe('user');
    expect(verifyDpopProofMock).toHaveBeenCalled();
  });

  test('dpop scheme with unbound token | invalid_token and DPoP error challenge', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, {
      accessToken: 'valid',
      scheme: 'dpop',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.cause).toEqual({ code: 'dpop_binding_mismatch' });
    const challenges = getChallenges(err);
    expect(challenges.some((c: string) => c.includes('DPoP error="invalid_token"'))).toBe(true);
  });

  test('dpop proof InvalidRequestError adds DPoP challenge', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    verifyDpopProofMock.mockRejectedValueOnce(new InvalidRequestError('bad proof'));
    const err = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'dpop',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidRequestError);
    const challenges = getChallenges(err);
    expect(challenges.some((c: string) => c.includes('DPoP error="invalid_request"'))).toBe(true);
  });

  test('dpop proof unexpected error is rethrown and normalized', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    verifyDpopProofMock.mockRejectedValueOnce(new Error('dpop proof failed'));
    const err = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'dpop',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.message).toContain('dpop proof failed');
  });

  test('jwtVerify non-error rejection is stringified', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    jwtVerifyMock.mockRejectedValueOnce('jwt verification failed');
    const err = await verify(client, { accessToken: 'valid', scheme: 'bearer' }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.message).toContain('jwt verification failed');
  });

  test('invalid token | signature bubbles invalid_token with dual challenges', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const err = await verify(client, { accessToken: 'invalid-token', scheme: 'bearer' }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.code).toBe('verify_access_token_error');
    const challenges = getChallenges(err);
    expect(
      challenges.some(
        (c) =>
          c.startsWith('Bearer realm="api"') &&
          c.includes('error="invalid_token"') &&
          c.includes('signature verification failed')
      )
    ).toBe(true);
    expect(challenges).toContain('DPoP algs="ES256"');
  });

  test('happy path | unbound bearer token succeeds', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const payload = await verify(client, { accessToken: 'valid', scheme: 'bearer' });
    expect(payload.sub).toBe('user');
    expect(verifyDpopProofMock).not.toHaveBeenCalled();
  });

  test('happy path | bound token with proof and dpop scheme succeeds', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    const payload = await verify(client, {
      accessToken: 'valid-bound',
      scheme: 'dpop',
      dpopProof: 'proof',
      httpMethod: 'GET',
      httpUrl: 'https://api/resource',
    });
    expect(payload.sub).toBe('user');
    expect(verifyDpopProofMock).toHaveBeenCalled();
  });

  test('verifyAccessToken reuses discovery metadata across calls', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    await verify(client, { accessToken: 'valid', scheme: 'bearer' });
    await verify(client, { accessToken: 'valid', scheme: 'bearer' });
    expect(discoveryRequestMock).toHaveBeenCalledTimes(1);
    expect(processDiscoveryResponseMock).toHaveBeenCalledTimes(1);
  });

  test('verifyAccessToken passes custom algorithms to jwtVerify', async () => {
    const client = new ApiClient({ domain, audience, dpop: { mode: 'allowed' } });
    await verify(client, { accessToken: 'valid', scheme: 'bearer', algorithms: ['RS256', 'ES256'] });
    expect(jwtVerifyMock).toHaveBeenCalledWith(
      'valid',
      expect.anything(),
      expect.objectContaining({
        algorithms: ['RS256', 'ES256']
      })
    );
  });
});
