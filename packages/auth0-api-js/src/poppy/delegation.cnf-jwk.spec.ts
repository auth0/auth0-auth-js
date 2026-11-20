import { CompactSign, base64url, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK } from 'jose';
import { beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';

import { rejectionOf } from '../test-utils/poppy.js';
import { AgentMetadataFetcher } from './agent-metadata.js';
import { DELEGATION_JWT_TYP } from './constants.js';
import { DelegationVerifier } from './delegation.js';
import { InvalidSessionError } from './errors.js';

// Deno imports an EC key without checking the point: a coordinate that is too short, or a point that is not on the
// curve, is imported all the same (denoland/deno issue 37031). Here `importJWK` accepts every key, as Deno does, and it
// gives back a real public key. With it, this spec shows that the SDK checks the point itself, before it imports the
// key, so the result does not depend on the runtime. `delegation.spec.ts` has rows for the same keys with the real
// `importJWK`, and `p256-point.spec.ts` covers the check one case at a time.
vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('jose')>();
  const { publicKey } = await actual.generateKeyPair('ES256');
  return { ...actual, importJWK: vi.fn(async () => publicKey) };
});

const CIMD_URL = 'https://agent.example/agent.json';
const JWKS_URI = 'https://agent.example/jwks.json';
const CNF_INVALID_MESSAGE = 'The delegation cnf.jwk must be an EC P-256 public key.';
const CNF_PRIVATE_KEY_MESSAGE = 'The delegation cnf.jwk must not have private key members.';
// 32 zero bytes: the right length for a coordinate of P-256, and (0, 0) is no point of that curve.
const ZEROS = 'A'.repeat(43);

const dropFirstByte = (coordinate: string): string => base64url.encode(base64url.decode(coordinate).subarray(1));
const addLeadingZeroByte = (coordinate: string): string =>
  base64url.encode(Uint8Array.of(0, ...base64url.decode(coordinate)));
// Another 32 bytes, so another number: a point of the curve with a probability of about 2^-256, and so none.
const changeFirstCharacter = (coordinate: string): string =>
  `${coordinate.startsWith('A') ? 'B' : 'A'}${coordinate.slice(1)}`;

interface PublicKey {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

/** An agent made by hand: it serves its metadata and key set, and signs a delegation with any `cnf.jwk`. */
interface Agent {
  fetch: typeof fetch;
  sign(cnfJwk: unknown): Promise<string>;
}

async function createAgent(): Promise<Agent> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  const metadata = { client_id: CIMD_URL, client_name: 'Hand Built Agent', jwks_uri: JWKS_URI };
  const jwks = { keys: [{ ...publicJwk, kid, alg: 'ES256', use: 'sig' }] };
  const fetchFromAgent = async (input: RequestInfo | URL): Promise<Response> => {
    const requested = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const body = requested === CIMD_URL ? metadata : requested === JWKS_URI ? jwks : undefined;
    return body === undefined
      ? new Response('Not found', { status: 404 })
      : new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return {
    fetch: fetchFromAgent as typeof fetch,
    sign: (cnfJwk) => {
      const iat = Math.floor(Date.now() / 1000);
      const payload = { iss: CIMD_URL, cnf: { jwk: cnfJwk }, iat, exp: iat + 3600, jti: 'dlg-1' };
      return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader({ alg: 'ES256', typ: DELEGATION_JWT_TYP, kid })
        .sign(privateKey);
    },
  };
}

function createVerifier(agent: Agent): DelegationVerifier {
  const fetcher = new AgentMetadataFetcher({
    fetch: agent.fetch,
    ttlMs: 600_000,
    maxEntries: 100,
    timeoutMs: 5000,
    maxBytes: 65_536,
    allowPrivateAddresses: false,
  });
  return new DelegationVerifier(fetcher, { iatWindowSeconds: 60, cacheMaxEntries: 100, ttlMs: 600_000 });
}

/** A delegation that is refused: a 400 `invalid_session` with the reason `delegation_invalid`, and the cause. */
async function expectRefused(promise: Promise<unknown>, cause: string, message: string): Promise<void> {
  const error = await rejectionOf(promise);

  expect(error).toBeInstanceOf(InvalidSessionError);
  const invalid = error as InvalidSessionError;
  expect(invalid.reason).toBe('delegation_invalid');
  expect(invalid.code).toBe('invalid_session');
  expect(invalid.statusCode).toBe(400);
  expect(invalid.cause).toEqual({ code: cause });
  // The text is fixed: nothing of the key is in it.
  expect(invalid.message).toBe(message);
}

describe('DelegationVerifier with a runtime that imports any EC key', () => {
  let agent: Agent;
  let valid: PublicKey;

  beforeAll(async () => {
    agent = await createAgent();
    const { publicKey } = await generateKeyPair('ES256');
    const { kty, crv, x, y } = await exportJWK(publicKey);
    valid = { kty, crv, x, y } as PublicKey;
  });

  beforeEach(() => {
    vi.mocked(importJWK).mockClear();
  });

  async function verifyWithKey(jwk: unknown) {
    return createVerifier(agent).verify(await agent.sign(jwk), CIMD_URL);
  }

  test('has an importJWK that accepts a key that is not a point of the curve, as Deno does', async () => {
    const offCurve = { ...valid, x: 'A'.repeat(43), y: 'A'.repeat(43) };

    await expect(importJWK(offCurve, 'ES256')).resolves.toBeDefined();
  });

  test.each([
    { name: 'an x that is too short', jwk: () => ({ ...valid, x: 'AQAB' }) },
    { name: 'a y that is too short', jwk: () => ({ ...valid, y: 'AQAB' }) },
    { name: 'an x of 31 bytes', jwk: () => ({ ...valid, x: dropFirstByte(valid.x) }) },
    { name: 'a y of 33 bytes', jwk: () => ({ ...valid, y: addLeadingZeroByte(valid.y) }) },
    { name: 'a key that is not a point of the curve', jwk: () => ({ ...valid, x: ZEROS, y: ZEROS }) },
    {
      name: 'a y with its first character changed, which is not a point of the curve',
      jwk: () => ({ ...valid, y: changeFirstCharacter(valid.y) }),
    },
  ])('refuses $name, and does not hand it to importJWK', async ({ jwk }) => {
    await expectRefused(verifyWithKey(jwk()), 'cnf_invalid', CNF_INVALID_MESSAGE);

    expect(importJWK).not.toHaveBeenCalled();
  });

  test('still reports a private member before it looks at the point', async () => {
    // As before the point was checked: a key with a private member is a private key, whatever its point is.
    const jwk = { ...valid, x: 'AQAB', d: 'AQAB' };

    await expectRefused(verifyWithKey(jwk), 'cnf_private_key', CNF_PRIVATE_KEY_MESSAGE);
    expect(importJWK).not.toHaveBeenCalled();
  });

  test('accepts a valid key, and imports it', async () => {
    const verified = await verifyWithKey(valid);

    expect(verified.sessionKeyThumbprint).toBe(await calculateJwkThumbprint(valid));
    expect(verified.iss).toBe(CIMD_URL);
    expect(importJWK).toHaveBeenCalledTimes(1);
    expect(importJWK).toHaveBeenCalledWith({ kty: 'EC', crv: 'P-256', x: valid.x, y: valid.y }, 'ES256');
  });

  test('keeps a valid key in the cache as before, so the second call imports nothing', async () => {
    const verifier = createVerifier(agent);
    const delegation = await agent.sign(valid);

    const first = await verifier.verify(delegation, CIMD_URL);
    const second = await verifier.verify(delegation, CIMD_URL);

    expect(second).toBe(first);
    expect(importJWK).toHaveBeenCalledTimes(1);
  });
});
