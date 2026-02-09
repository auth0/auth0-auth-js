import { beforeEach, describe, expect, test, vi } from 'vitest';
import { createHash } from 'crypto';

const { jwtVerifyMock } = vi.hoisted(() => ({
  jwtVerifyMock: vi.fn(),
}));

vi.mock('jose', async () => {
  const actual = await vi.importActual<typeof import('jose')>('jose');
  return {
    ...actual,
    jwtVerify: jwtVerifyMock,
  };
});

import { base64url } from 'jose';
import { DPOP_ERROR_MESSAGES, verifyDpopProof } from './dpop-api.js';
import { InvalidDpopProofError } from './errors.js';

const baseOptions = {
  proof: 'proof',
  accessToken: 'token',
  method: 'GET',
  url: 'https://api/resource',
  cnfJkt: 'thumb',
  iatOffset: 300,
  iatLeeway: 30,
  algorithms: ['ES256'],
};

const buildClaims = (accessToken: string, method: string, url: string) => {
  const hash = createHash('sha256').update(accessToken).digest();
  const ath = base64url.encode(hash);
  return {
    jti: 'jti',
    iat: Math.floor(Date.now() / 1000),
    htm: method,
    htu: url,
    ath,
  };
};

beforeEach(() => {
  jwtVerifyMock.mockReset();
});

describe('verifyDpopProof jwk header checks', () => {
  test('missing jwk in header throws InvalidDpopProofError', async () => {
    jwtVerifyMock.mockResolvedValueOnce({
      payload: buildClaims(baseOptions.accessToken, baseOptions.method, baseOptions.url),
      protectedHeader: {},
    });

    const err = await verifyDpopProof(baseOptions).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidDpopProofError);
    expect(err.message).toBe(DPOP_ERROR_MESSAGES.MISSING_JWK);
  });

  test('private key in jwk header throws InvalidDpopProofError', async () => {
    jwtVerifyMock.mockResolvedValueOnce({
      payload: buildClaims(baseOptions.accessToken, baseOptions.method, baseOptions.url),
      protectedHeader: { jwk: { d: 'secret' } },
    });

    const err = await verifyDpopProof(baseOptions).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidDpopProofError);
    expect(err.message).toBe(DPOP_ERROR_MESSAGES.PRIVATE_KEY_MATERIAL);
  });
});
