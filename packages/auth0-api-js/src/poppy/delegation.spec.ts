import {
  CompactSign,
  base64url,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type CompactJWSHeaderParameters,
  type JWK,
} from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';

import { rejectionOf } from '../test-utils/poppy.js';
import { AgentMetadataFetcher } from './agent-metadata.js';
import {
  DEFAULT_DELEGATION_CACHE_MAX_ENTRIES,
  DEFAULT_RETRY_AFTER_SECONDS,
  DELEGATION_JWT_TYP,
  MAX_DELEGATION_LIFETIME_SECONDS,
  SESSION_JWT_TYP,
  UNKNOWN_KID_REFETCH_INTERVAL_MS,
} from './constants.js';
import { DelegationVerifier, type VerifiedDelegation } from './delegation.js';
import { InvalidSessionError, PoppyUnavailableError } from './errors.js';
import { parseSessionJwt } from './session-jwt.js';
import { createTestAgent, type TestAgent, type TestSessionJwtOptions } from './testing/test-agent.js';

const CIMD_URL = 'https://agent.example/agent.json';
const JWKS_URI = 'https://agent.example/jwks.json';
const OTHER_CIMD_URL = 'https://other.example/agent.json';
const OTHER_ORIGIN = 'https://other.example/';
const PS_CIMD_URL = 'https://ps.example/agent.json';
const PS_JWKS_URI = 'https://ps.example/jwks.json';
const HAND_CIMD_URL = 'https://hand.example/agent.json';
const HAND_JWKS_URI = 'https://hand.example/jwks.json';
const AUD = 'https://example.auth0.com/';
const HTU = 'https://api.zepto.example/orders';
const START = Date.UTC(2026, 10, 6, 12, 0, 0);
const START_SECONDS = START / 1000;
const DEFAULT_LIFETIME_SECONDS = 3600;
const IAT_WINDOW_SECONDS = 60;
const ATTACKER_JKU = 'https://attacker.example/jwks.json';
const ATTACKER_X5U = 'https://attacker.example/certificate.pem';
// 32 zero bytes as a coordinate: base64url characters of the right length for P-256, and no point of that curve.
const OFF_CURVE_COORDINATE = 'A'.repeat(43);
// The public key of RFC 8037, appendix A.2. It is an Ed25519 key, and nothing is verified with it.
const ED25519_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
// The delegated key in the example of section 5.2 of the specification
// (https://personalagentprotocol.org/docs/0.3/spec), and the `kid` that the example gives the Session JWT it signs,
// which is the thumbprint of the key (RFC 7638). The `kid` is copied from the specification and is not computed here,
// so the check does not depend on this code or on jose.
const SPEC_EXAMPLE_X = 'B484TQp7695xQfzTcW5Rf8HUNC3a-Bt9zYTlgxtJUeU';
const SPEC_EXAMPLE_Y = '5ji2Z0dKOVQLXZJ2yzHiryVoopigNfpEVr_D36MPgwM';
const SPEC_EXAMPLE_KID = '9E421cSqd5UfAq5slDKYxXQd8Zmm8B3CIsT9cDxRHx8';

// The messages of the errors, word for word. They say which check failed and nothing else: no value of the delegation,
// of a key or of a URL is in them, so the same text comes back for every bad value of a check.
const MESSAGES = {
  delegation_malformed: 'The delegation is not a well-formed JWT.',
  delegation_typ: 'The delegation typ header must be poppy-delegation+jwt.',
  delegation_alg: 'The delegation alg header must be ES256 or PS384.',
  delegation_kid: 'The delegation kid header must be a non-empty string.',
  delegation_key_unknown: 'The key set of the agent has no usable key with the kid of the delegation.',
  delegation_signature: 'The delegation could not be verified with the key of the agent.',
  delegation_expired: 'The delegation has expired.',
  delegation_claims: 'The delegation iat, exp or nbf claim is missing or not valid.',
  delegation_lifetime: 'The delegation must expire after it was issued, and at most 24 hours after.',
  delegation_iat: 'The delegation was issued in the future.',
  delegation_iss: 'The delegation iss is not the iss of the Session JWT.',
  cnf_invalid: 'The delegation cnf.jwk must be an EC P-256 public key.',
  cnf_private_key: 'The delegation cnf.jwk must not have private key members.',
} as const;

type Cause = keyof typeof MESSAGES;

// Pins `Date` only: the clock of the caches and of `jose` moves, and the timers of the runtime keep working.
function pinClock(): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
}

function advance(milliseconds: number): void {
  vi.setSystemTime(Date.now() + milliseconds);
}

function urlOf(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

/** Wraps a `fetch` and records the URL of every call. */
function recordFetch(inner: typeof fetch): { fetch: typeof fetch; urls: string[] } {
  const urls: string[] = [];
  const recording = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    urls.push(urlOf(input));
    return inner(input, init);
  };
  return { fetch: recording as typeof fetch, urls };
}

/** Replaces the global `fetch` with one that refuses, and records its calls: nothing in a test may use the network. */
function forbidGlobalFetch() {
  return vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('The global fetch must not be used.'));
}

// A year: for a test that has nothing to do with the time to live of the delegation cache, which is then never reached.
const LONG_TTL_MS = 365 * 24 * 60 * 60 * 1000;

interface VerifierSetup {
  fetch: typeof fetch;
  iatWindowSeconds?: number;
  cacheMaxEntries?: number;
  /** How long the fetcher keeps the keys of an agent. */
  ttlMs?: number;
  /** How long the verifier keeps a verified delegation, at most. The default is long enough never to matter. */
  delegationTtlMs?: number;
}

/** A real fetcher over `fetch`, wrapped to count the calls, and a verifier over that fetcher. */
function createVerifier(setup: VerifierSetup): {
  verifier: DelegationVerifier;
  fetcher: AgentMetadataFetcher;
  urls: string[];
} {
  const { fetch, urls } = recordFetch(setup.fetch);
  const fetcher = new AgentMetadataFetcher({
    fetch,
    ttlMs: setup.ttlMs ?? 600_000,
    maxEntries: 100,
    timeoutMs: 5000,
    maxBytes: 65_536,
    allowPrivateAddresses: false,
  });
  const verifier = new DelegationVerifier(fetcher, {
    iatWindowSeconds: setup.iatWindowSeconds ?? IAT_WINDOW_SECONDS,
    cacheMaxEntries: setup.cacheMaxEntries ?? DEFAULT_DELEGATION_CACHE_MAX_ENTRIES,
    ttlMs: setup.delegationTtlMs ?? LONG_TTL_MS,
  });
  return { verifier, fetcher, urls };
}

/** A Session JWT of the agent, parsed: its delegation, its `iss` and its `kid`. */
async function mint(
  agent: TestAgent,
  options: Partial<TestSessionJwtOptions> = {}
): Promise<{ delegation: string; iss: string; kid: string }> {
  const jwt = await agent.createSessionJwt({ aud: AUD, htm: 'GET', htu: HTU, ...options });
  const session = parseSessionJwt(jwt);
  return { delegation: session.header.poppy_dlg, iss: session.claims.iss, kid: session.header.kid };
}

/** A delegation that is refused: a 400 `invalid_session` with the reason `delegation_invalid`, and the cause. */
async function expectInvalid(promise: Promise<unknown>, cause: Cause): Promise<InvalidSessionError> {
  const error = await rejectionOf(promise);

  expect(error).toBeInstanceOf(InvalidSessionError);
  const invalid = error as InvalidSessionError;
  expect(invalid.reason).toBe('delegation_invalid');
  expect(invalid.code).toBe('invalid_session');
  expect(invalid.statusCode).toBe(400);
  expect(invalid.cause).toEqual({ code: cause });
  expect(invalid.message).toBe(MESSAGES[cause]);
  return invalid;
}

/** Puts `changes` over `base`, on a copy. A value replaces the member, and `undefined` removes it. */
function merge(base: Record<string, unknown>, changes: Record<string, unknown> = {}): Record<string, unknown> {
  const merged = { ...base };
  for (const [name, value] of Object.entries(changes)) {
    if (value === undefined) {
      delete merged[name];
    } else {
      merged[name] = value;
    }
  }
  return merged;
}

async function publicJwkOf(alg: 'ES256' | 'ES384' | 'RS256'): Promise<JWK> {
  return exportJWK((await generateKeyPair(alg)).publicKey);
}

function encodeJson(value: object): string {
  return base64url.encode(JSON.stringify(value));
}

/** A JWT made of text, with the signature given: for what no key can sign. */
function assemble(header: object, payload: object, signature = ''): string {
  return `${encodeJson(header)}.${encodeJson(payload)}.${signature}`;
}

async function sign(
  key: CryptoKey | Uint8Array,
  header: Record<string, unknown>,
  payload: string | object
): Promise<string> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  // jose signs a header with `crit` only if the caller says that it knows the extensions, so a test that wants a
  // critical header that the verifier does not know says so here.
  const crit = Array.isArray(header.crit)
    ? Object.fromEntries((header.crit as string[]).map((name) => [name, true]))
    : undefined;
  return new CompactSign(new TextEncoder().encode(text))
    .setProtectedHeader(header as CompactJWSHeaderParameters)
    .sign(key, crit === undefined ? undefined : { crit });
}

interface RsaPssKey {
  privateKey: CryptoKey;
  publicJwk: JWK;
}

/** An RSA-PSS key made with Web Crypto, because `jose` makes RSA keys of 2048 bits and more only. */
async function generateRsaPssKey(modulusLength: number, kid: string): Promise<RsaPssKey> {
  const algorithm: RsaHashedKeyGenParams = {
    name: 'RSA-PSS',
    modulusLength,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-384',
  };
  const { privateKey, publicKey } = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const { n, e } = await crypto.subtle.exportKey('jwk', publicKey);
  return { privateKey, publicJwk: { kty: 'RSA', n, e, kid, alg: 'PS384', use: 'sig' } };
}

/** A PS384 JWT signed with Web Crypto directly: RSA-PSS, SHA-384, and a salt of 48 bytes. */
async function signPs384(privateKey: CryptoKey, header: object, payload: object): Promise<string> {
  const signingInput = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 48 },
    privateKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${base64url.encode(new Uint8Array(signature))}`;
}

/**
 * An agent made by hand, for the delegations the test agent can't make. It has one `ES256` key in its key set, plus the
 * keys given, and it signs any header and any payload with that key. Its delegations are valid until a test changes
 * one thing in them.
 */
interface HandBuiltAgent {
  fetch: typeof fetch;
  /** The `kid` of its key. */
  kid: string;
  /** The valid header of a delegation. */
  header(): Record<string, unknown>;
  /** The valid payload of a delegation of the key `cnfJwk`, made now. */
  payload(cnfJwk: JWK): Record<string, unknown>;
  /** Signs `header` and `payload` with the key of the agent. The payload can be given as the JSON text. */
  sign(header: Record<string, unknown>, payload: string | object): Promise<string>;
}

interface HandBuiltAgentOptions {
  /** More keys for the key set. */
  extraKeys?: JWK[];
  /** Whether the key set has the key of the agent twice. */
  duplicateKey?: boolean;
  /** Members to put over the ones the key of the agent has in the key set, such as `use`. */
  keyMembers?: Record<string, unknown>;
}

async function createHandBuiltAgent(options: HandBuiltAgentOptions = {}): Promise<HandBuiltAgent> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  const ownKey: JWK = { ...publicJwk, kid, alg: 'ES256', use: 'sig', ...options.keyMembers };
  const metadata = { client_id: HAND_CIMD_URL, client_name: 'Hand Built Agent', jwks_uri: HAND_JWKS_URI };
  const jwks = { keys: [ownKey, ...(options.duplicateKey ? [ownKey] : []), ...(options.extraKeys ?? [])] };
  const fetchFromAgent = async (input: RequestInfo | URL): Promise<Response> => {
    const requested = urlOf(input);
    const body = requested === HAND_CIMD_URL ? metadata : requested === HAND_JWKS_URI ? jwks : undefined;
    return body === undefined
      ? new Response('Not found', { status: 404 })
      : new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return {
    fetch: fetchFromAgent as typeof fetch,
    kid,
    header: () => ({ alg: 'ES256', typ: DELEGATION_JWT_TYP, kid }),
    payload: (cnfJwk) => {
      const iat = Math.floor(Date.now() / 1000);
      return { iss: HAND_CIMD_URL, cnf: { jwk: cnfJwk }, iat, exp: iat + DEFAULT_LIFETIME_SECONDS, jti: 'dlg-1' };
    },
    sign: (header, payload) => sign(privateKey, header, payload),
  };
}

describe('DelegationVerifier', () => {
  let agent: TestAgent;
  let psAgent: TestAgent;
  let delegatedJwk: JWK;

  beforeAll(async () => {
    agent = await createTestAgent({ cimdUrl: CIMD_URL });
    psAgent = await createTestAgent({ cimdUrl: PS_CIMD_URL, delegationAlg: 'PS384' });
    delegatedJwk = await publicJwkOf('ES256');
  });

  beforeEach(() => {
    pinClock();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('a valid delegation', () => {
    test('gives the issuer, the expiry, the delegated key and its thumbprint', async () => {
      const { verifier, urls } = createVerifier({ fetch: agent.fetch });
      const { delegation, iss, kid } = await mint(agent);

      const verified = await verifier.verify(delegation, iss);

      expect(verified.iss).toBe(CIMD_URL);
      expect(verified.exp).toBe(START_SECONDS + DEFAULT_LIFETIME_SECONDS);
      // The thumbprint is the `kid` of the Session JWT that carries the delegation.
      expect(verified.sessionKeyThumbprint).toBe(kid);
      expect(verified.sessionKey.type).toBe('public');
      expect(verified.sessionKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
      expect(verified.sessionKey.usages).toEqual(['verify']);
      expect(Object.keys(verified).sort()).toEqual(['exp', 'iss', 'sessionKey', 'sessionKeyThumbprint']);
      expect(urls).toEqual([CIMD_URL, JWKS_URI]);
    });

    test('accepts a delegation that an agent signed with PS384', async () => {
      const { verifier, urls } = createVerifier({ fetch: psAgent.fetch });
      const { delegation, iss, kid } = await mint(psAgent);

      const verified = await verifier.verify(delegation, iss);

      expect(verified.iss).toBe(PS_CIMD_URL);
      expect(verified.sessionKeyThumbprint).toBe(kid);
      expect(urls).toEqual([PS_CIMD_URL, PS_JWKS_URI]);
    });

    test('gives each User its own delegated key and thumbprint', async () => {
      const { verifier } = createVerifier({ fetch: agent.fetch });
      const first = await mint(agent, { sub: 'usr_one' });
      const second = await mint(agent, { sub: 'usr_two' });

      const one = await verifier.verify(first.delegation, first.iss);
      const two = await verifier.verify(second.delegation, second.iss);

      expect(one.sessionKeyThumbprint).toBe(first.kid);
      expect(two.sessionKeyThumbprint).toBe(second.kid);
      expect(one.sessionKeyThumbprint).not.toBe(two.sessionKeyThumbprint);
    });

    test('accepts a delegation that lasts exactly 24 hours', async () => {
      const longAgent = await createTestAgent({
        cimdUrl: CIMD_URL,
        delegationLifetimeSeconds: MAX_DELEGATION_LIFETIME_SECONDS,
      });
      const { verifier } = createVerifier({ fetch: longAgent.fetch });
      const { delegation, iss } = await mint(longAgent);

      const verified = await verifier.verify(delegation, iss);

      expect(verified.exp).toBe(START_SECONDS + MAX_DELEGATION_LIFETIME_SECONDS);
    });

    test.each(['Poppy-Delegation+JWT', 'application/poppy-delegation+jwt', 'APPLICATION/POPPY-DELEGATION+JWT'])(
      'accepts the typ %s, by the rule that the typ of a Session JWT follows',
      async (typ) => {
        const hand = await createHandBuiltAgent();
        const delegation = await hand.sign(merge(hand.header(), { typ }), hand.payload(delegatedJwk));
        const { verifier } = createVerifier({ fetch: hand.fetch });

        await expect(verifier.verify(delegation, HAND_CIMD_URL)).resolves.toMatchObject({ iss: HAND_CIMD_URL });
      }
    );
  });

  describe('a delegation with a defect of the test agent', () => {
    test.each([
      { defect: 'expired_delegation', cause: 'delegation_expired' },
      { defect: 'delegation_too_long', cause: 'delegation_lifetime' },
      { defect: 'delegation_from_future', cause: 'delegation_iat' },
      { defect: 'delegation_iss_mismatch', cause: 'delegation_iss' },
      { defect: 'delegation_wrong_typ', cause: 'delegation_typ' },
      { defect: 'delegation_private_cnf', cause: 'cnf_private_key' },
    ] as const)('refuses $defect with the cause $cause', async ({ defect, cause }) => {
      const { verifier } = createVerifier({ fetch: agent.fetch });
      const { delegation, iss } = await mint(agent, { defect });

      await expectInvalid(verifier.verify(delegation, iss), cause);
    });

    test('refuses delegation_unknown_kid after exactly one refetch of the keys', async () => {
      const { verifier, urls } = createVerifier({ fetch: agent.fetch });
      const { delegation, iss } = await mint(agent, { defect: 'delegation_unknown_kid' });

      await expectInvalid(verifier.verify(delegation, iss), 'delegation_key_unknown');

      // The keys, then one refetch of the metadata and the key set.
      expect(urls).toEqual([CIMD_URL, JWKS_URI, CIMD_URL, JWKS_URI]);
    });

    test('refetches the keys again only after the interval, however many unknown key IDs come', async () => {
      const { verifier, urls } = createVerifier({ fetch: agent.fetch });
      const first = await mint(agent, { defect: 'delegation_unknown_kid' });
      const second = await mint(agent, { defect: 'delegation_unknown_kid' });

      await expectInvalid(verifier.verify(first.delegation, first.iss), 'delegation_key_unknown');
      expect(urls).toHaveLength(4);

      // Within the interval the refetch is held back, and the delegation is refused all the same.
      await expectInvalid(verifier.verify(second.delegation, second.iss), 'delegation_key_unknown');
      expect(urls).toHaveLength(4);

      advance(UNKNOWN_KID_REFETCH_INTERVAL_MS);
      const third = await mint(agent, { defect: 'delegation_unknown_kid' });
      await expectInvalid(verifier.verify(third.delegation, third.iss), 'delegation_key_unknown');
      expect(urls).toHaveLength(6);
    });
  });

  describe('the header', () => {
    test.each([
      { name: 'no typ', header: { typ: undefined }, cause: 'delegation_typ' },
      { name: 'a typ of JWT', header: { typ: 'JWT' }, cause: 'delegation_typ' },
      { name: 'the typ of a Session JWT', header: { typ: SESSION_JWT_TYP }, cause: 'delegation_typ' },
      { name: 'a typ that is a number', header: { typ: 1 }, cause: 'delegation_typ' },
      { name: 'a typ that is a list of the right typ', header: { typ: [DELEGATION_JWT_TYP] }, cause: 'delegation_typ' },
      { name: 'a typ with a space before it', header: { typ: ` ${DELEGATION_JWT_TYP}` }, cause: 'delegation_typ' },
      {
        name: 'a typ with application/ twice',
        header: { typ: `application/application/${DELEGATION_JWT_TYP}` },
        cause: 'delegation_typ',
      },
      { name: 'no kid', header: { kid: undefined }, cause: 'delegation_kid' },
      { name: 'a kid that is empty', header: { kid: '' }, cause: 'delegation_kid' },
      { name: 'a kid that is a number', header: { kid: 7 }, cause: 'delegation_kid' },
      { name: 'a kid that is null', header: { kid: null }, cause: 'delegation_kid' },
      { name: 'a kid that is a list', header: { kid: ['a'] }, cause: 'delegation_kid' },
      { name: 'no alg', header: { alg: undefined }, cause: 'delegation_alg' },
    ] as const)('refuses $name before it fetches anything', async ({ header, cause }) => {
      const hand = await createHandBuiltAgent();
      // Made from text: a header with no alg, or a typ that is a number, is not one that a library signs.
      const delegation = assemble(merge(hand.header(), header), hand.payload(delegatedJwk), 'c2ln');
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), cause);
      expect(urls).toEqual([]);
    });

    test.each(['ES384', 'ES512', 'PS256', 'PS512', 'RS384', 'EdDSA', 'HS384', 'es256', 'ES256 ', ''])(
      'refuses the alg %j before it fetches anything',
      async (alg) => {
        const hand = await createHandBuiltAgent();
        const delegation = assemble(merge(hand.header(), { alg }), hand.payload(delegatedJwk), 'c2ln');
        const { verifier, urls } = createVerifier({ fetch: hand.fetch });

        await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_alg');
        expect(urls).toEqual([]);
      }
    );

    test('refuses alg none, an unsecured JWT with no signature', async () => {
      const hand = await createHandBuiltAgent();
      const delegation = assemble(merge(hand.header(), { alg: 'none' }), hand.payload(delegatedJwk));
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_alg');
      expect(urls).toEqual([]);
    });

    test('refuses alg RS256 that a key of the agent signed validly', async () => {
      const { privateKey, publicKey } = await generateKeyPair('RS256');
      const rsaJwk: JWK = { ...(await exportJWK(publicKey)), kid: 'rsa-1', alg: 'RS256', use: 'sig' };
      const hand = await createHandBuiltAgent({ extraKeys: [rsaJwk] });
      const delegation = await sign(
        privateKey,
        { alg: 'RS256', typ: DELEGATION_JWT_TYP, kid: 'rsa-1' },
        hand.payload(delegatedJwk)
      );
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_alg');
      expect(urls).toEqual([]);
    });

    test('refuses alg HS256 with the public key of the agent as the secret', async () => {
      const hand = await createHandBuiltAgent();
      const secret = new TextEncoder().encode(JSON.stringify(delegatedJwk));
      const delegation = await sign(
        secret,
        { alg: 'HS256', typ: DELEGATION_JWT_TYP, kid: hand.kid },
        hand.payload(delegatedJwk)
      );
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_alg');
      expect(urls).toEqual([]);
    });

    test('refuses a delegation with no kid with no fetch at all', async () => {
      const hand = await createHandBuiltAgent();
      const delegation = await hand.sign(merge(hand.header(), { kid: undefined }), hand.payload(delegatedJwk));
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_kid');
      expect(urls).toHaveLength(0);
    });

    test.each([
      { name: 'an empty string', jwt: '' },
      { name: 'a word', jwt: 'abc' },
      { name: 'two parts', jwt: 'a.b' },
      { name: 'three parts that are not base64url JSON', jwt: 'a.b.c' },
      { name: 'a header that is JSON and not an object', jwt: `${base64url.encode('[]')}.e30.c2ln` },
      { name: 'a header that is a string', jwt: `${base64url.encode('"x"')}.e30.c2ln` },
      { name: 'a header that is text', jwt: `${base64url.encode('not json')}.e30.c2ln` },
    ])('refuses $name as malformed before it fetches anything', async ({ jwt }) => {
      const { verifier, urls } = createVerifier({ fetch: agent.fetch });

      await expectInvalid(verifier.verify(jwt, CIMD_URL), 'delegation_malformed');
      expect(urls).toEqual([]);
    });

    test('refuses a delegation with a critical header that it does not know', async () => {
      const hand = await createHandBuiltAgent();
      const delegation = await hand.sign(
        merge(hand.header(), { crit: ['x-custom'], 'x-custom': true }),
        hand.payload(delegatedJwk)
      );
      const { verifier } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_signature');
    });
  });

  describe('the key set of the agent', () => {
    test('finds a rotated key with one refresh of the keys', async () => {
      // Two agents with one URL and two key sets: the agent before the rotation, and the agent after it.
      const before = await createTestAgent({ cimdUrl: CIMD_URL });
      const after = await createTestAgent({ cimdUrl: CIMD_URL });
      let current = before;
      const { verifier, urls } = createVerifier({ fetch: (input, init) => current.fetch(input, init) });
      const first = await mint(before);
      await verifier.verify(first.delegation, first.iss);
      expect(urls).toEqual([CIMD_URL, JWKS_URI]);

      current = after;
      const second = await mint(after);
      const verified = await verifier.verify(second.delegation, second.iss);

      // One refresh: the metadata and the key set, once.
      expect(urls).toEqual([CIMD_URL, JWKS_URI, CIMD_URL, JWKS_URI]);
      expect(verified.sessionKeyThumbprint).toBe(second.kid);

      // The new keys are in the cache now, so the next delegation of the agent needs no fetch.
      const third = await mint(after, { sub: 'usr_another' });
      await verifier.verify(third.delegation, third.iss);
      expect(urls).toHaveLength(4);
    });

    test('refuses a delegation of a key that the agent has taken out of its key set', async () => {
      const before = await createTestAgent({ cimdUrl: CIMD_URL });
      const after = await createTestAgent({ cimdUrl: CIMD_URL });
      let current = before;
      const { verifier } = createVerifier({ fetch: (input, init) => current.fetch(input, init), ttlMs: 1 });
      const first = await mint(before, { sub: 'usr_one' });
      await verifier.verify(first.delegation, first.iss);

      // The cached keys have expired, and the agent serves other keys. A new delegation of the old key is refused.
      current = after;
      advance(5);
      const stale = await mint(before, { sub: 'usr_two' });

      await expectInvalid(verifier.verify(stale.delegation, stale.iss), 'delegation_key_unknown');
    });

    test('ignores the jwk, jku and x5u headers of a delegation that an attacker signed with its own key', async () => {
      const hand = await createHandBuiltAgent();
      const attacker = await generateKeyPair('ES256');
      const attackerJwk = await exportJWK(attacker.publicKey);
      const attackerKid = await calculateJwkThumbprint(attackerJwk);
      const forged = await sign(
        attacker.privateKey,
        {
          alg: 'ES256',
          typ: DELEGATION_JWT_TYP,
          kid: attackerKid,
          jwk: attackerJwk,
          jku: ATTACKER_JKU,
          x5u: ATTACKER_X5U,
        },
        hand.payload(delegatedJwk)
      );
      const globalFetch = forbidGlobalFetch();
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(forged, HAND_CIMD_URL), 'delegation_key_unknown');

      // Only the metadata and the key set of the agent were fetched, and nothing from the attacker.
      expect(urls).toEqual([HAND_CIMD_URL, HAND_JWKS_URI, HAND_CIMD_URL, HAND_JWKS_URI]);
      expect(urls).not.toContain(ATTACKER_JKU);
      expect(urls).not.toContain(ATTACKER_X5U);
      // Nothing went around the fetcher, either: no code of the verifier or of jose used the global fetch.
      expect(globalFetch).not.toHaveBeenCalled();
    });

    test('refuses a signature of an attacker that carries the kid of a real key of the agent', async () => {
      const hand = await createHandBuiltAgent();
      const attacker = await generateKeyPair('ES256');
      const attackerJwk = await exportJWK(attacker.publicKey);
      const forged = await sign(
        attacker.privateKey,
        {
          alg: 'ES256',
          typ: DELEGATION_JWT_TYP,
          kid: hand.kid,
          jwk: attackerJwk,
          jku: ATTACKER_JKU,
          x5u: ATTACKER_X5U,
        },
        hand.payload(delegatedJwk)
      );
      const globalFetch = forbidGlobalFetch();
      const { verifier, urls } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(forged, HAND_CIMD_URL), 'delegation_signature');

      // The same payload, signed with the key of the agent, is accepted: the key is the only defect.
      const genuine = await hand.sign(hand.header(), hand.payload(delegatedJwk));
      await expect(verifier.verify(genuine, HAND_CIMD_URL)).resolves.toMatchObject({ iss: HAND_CIMD_URL });
      expect(urls).toEqual([HAND_CIMD_URL, HAND_JWKS_URI]);
      expect(globalFetch).not.toHaveBeenCalled();
    });

    test('refuses a delegation whose kid belongs to two keys of the key set', async () => {
      const hand = await createHandBuiltAgent({ duplicateKey: true });
      const delegation = await hand.sign(hand.header(), hand.payload(delegatedJwk));
      const { verifier } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_signature');
    });

    test('refuses a signature of an RSA key of 1024 bits, which jose does not use', async () => {
      // jose can't make or sign with an RSA key under 2048 bits, so Web Crypto does both.
      const weak = await generateRsaPssKey(1024, 'rsa-1024');
      const strong = await generateRsaPssKey(2048, 'rsa-2048');
      const hand = await createHandBuiltAgent({ extraKeys: [weak.publicJwk, strong.publicJwk] });
      const payload = hand.payload(delegatedJwk);
      const { verifier } = createVerifier({ fetch: hand.fetch });

      const weakDelegation = await signPs384(
        weak.privateKey,
        { alg: 'PS384', typ: DELEGATION_JWT_TYP, kid: 'rsa-1024' },
        payload
      );
      await expectInvalid(verifier.verify(weakDelegation, HAND_CIMD_URL), 'delegation_signature');

      // The same delegation, made the same way with a key of 2048 bits, is accepted: the size is the only defect.
      const strongDelegation = await signPs384(
        strong.privateKey,
        { alg: 'PS384', typ: DELEGATION_JWT_TYP, kid: 'rsa-2048' },
        payload
      );
      await expect(verifier.verify(strongDelegation, HAND_CIMD_URL)).resolves.toMatchObject({ iss: HAND_CIMD_URL });
    });

    // The key set has the key with the `kid`, and the key signed the delegation, but the key says it is for something
    // else. `jose` does not offer such a key for the delegation, so it finds none, and the error must not say that the
    // `kid` is missing.
    test.each([
      { member: 'alg', unfit: { alg: 'ES384' }, fit: { alg: 'ES256' } },
      { member: 'use', unfit: { use: 'enc' }, fit: { use: 'sig' } },
      { member: 'key_ops', unfit: { key_ops: ['sign'] }, fit: { key_ops: ['verify'] } },
    ])('refuses a key whose $member does not fit the delegation, with a message that says so', async (row) => {
      const unusable = await createHandBuiltAgent({ keyMembers: row.unfit });
      const usable = await createHandBuiltAgent({ keyMembers: row.fit });
      const unusableDelegation = await unusable.sign(unusable.header(), unusable.payload(delegatedJwk));
      const usableDelegation = await usable.sign(usable.header(), usable.payload(delegatedJwk));

      const error = await expectInvalid(
        createVerifier({ fetch: unusable.fetch }).verifier.verify(unusableDelegation, HAND_CIMD_URL),
        'delegation_key_unknown'
      );

      expect(error.message).toContain('no usable key');
      expect(error.message).not.toContain('is not in');
      // The same delegation of a key whose member fits is accepted: the member is the only defect.
      await expect(
        createVerifier({ fetch: usable.fetch }).verifier.verify(usableDelegation, HAND_CIMD_URL)
      ).resolves.toMatchObject({ iss: HAND_CIMD_URL });
    });
  });

  describe('the claims', () => {
    test.each([
      { name: 'no iat', changes: { iat: undefined }, cause: 'delegation_claims' },
      { name: 'no exp', changes: { exp: undefined }, cause: 'delegation_claims' },
      { name: 'an iat that is a string', changes: { iat: String(START_SECONDS) }, cause: 'delegation_claims' },
      { name: 'an exp that is a string', changes: { exp: String(START_SECONDS + 600) }, cause: 'delegation_claims' },
      { name: 'an iat that is null', changes: { iat: null }, cause: 'delegation_claims' },
      { name: 'an nbf that is still ahead', changes: { nbf: START_SECONDS + 600 }, cause: 'delegation_claims' },
      { name: 'an nbf that is a string', changes: { nbf: '1' }, cause: 'delegation_claims' },
      { name: 'an exp that has passed', changes: { exp: START_SECONDS - 1 }, cause: 'delegation_expired' },
      { name: 'an exp that is now', changes: { exp: START_SECONDS }, cause: 'delegation_expired' },
      { name: 'no iss', changes: { iss: undefined }, cause: 'delegation_iss' },
      { name: 'the iss of another agent', changes: { iss: OTHER_CIMD_URL }, cause: 'delegation_iss' },
      { name: 'an iss that is a number', changes: { iss: 7 }, cause: 'delegation_iss' },
      { name: 'an iss with a slash added', changes: { iss: `${HAND_CIMD_URL}/` }, cause: 'delegation_iss' },
      { name: 'an iss in capital letters', changes: { iss: HAND_CIMD_URL.toUpperCase() }, cause: 'delegation_iss' },
      {
        name: 'an exp 24 hours and a second after the iat',
        changes: { iat: START_SECONDS, exp: START_SECONDS + MAX_DELEGATION_LIFETIME_SECONDS + 1 },
        cause: 'delegation_lifetime',
      },
      {
        name: 'an exp before the iat',
        changes: { iat: START_SECONDS + 30, exp: START_SECONDS + 10 },
        cause: 'delegation_lifetime',
      },
      {
        name: 'an exp that is the iat',
        changes: { iat: START_SECONDS + 30, exp: START_SECONDS + 30 },
        cause: 'delegation_lifetime',
      },
      {
        name: 'an iat more than the window ahead',
        changes: { iat: START_SECONDS + IAT_WINDOW_SECONDS + 1, exp: START_SECONDS + 3600 },
        cause: 'delegation_iat',
      },
    ] as const)('refuses $name', async ({ changes, cause }) => {
      const hand = await createHandBuiltAgent();
      const delegation = await hand.sign(hand.header(), merge(hand.payload(delegatedJwk), changes));
      const { verifier } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), cause);
    });

    test('accepts an iat exactly the window ahead, an exp one second ahead and a lifetime of 24 hours', async () => {
      const hand = await createHandBuiltAgent();
      const { verifier } = createVerifier({ fetch: hand.fetch });
      const edges = [
        { iat: START_SECONDS + IAT_WINDOW_SECONDS, exp: START_SECONDS + 3600 },
        { iat: START_SECONDS - 100, exp: START_SECONDS + 1 },
        { iat: START_SECONDS, exp: START_SECONDS + MAX_DELEGATION_LIFETIME_SECONDS },
        { iat: START_SECONDS - 60, exp: START_SECONDS - 60 + MAX_DELEGATION_LIFETIME_SECONDS },
      ];

      for (const edge of edges) {
        const delegation = await hand.sign(hand.header(), merge(hand.payload(delegatedJwk), edge));
        await expect(verifier.verify(delegation, HAND_CIMD_URL)).resolves.toMatchObject({ exp: edge.exp });
      }
    });

    test.each([
      { name: 'an iat and an exp that are not finite', text: '"iat":1e999,"exp":1e999' },
      { name: 'an exp that is not finite', text: `"iat":${START_SECONDS},"exp":1e999` },
    ])('refuses $name', async ({ text }) => {
      const hand = await createHandBuiltAgent();
      // `JSON.stringify` writes `null` for Infinity, so the payload is written as text.
      const payload = `{"iss":"${HAND_CIMD_URL}","cnf":{"jwk":${JSON.stringify(delegatedJwk)}},${text}}`;
      const delegation = await hand.sign(hand.header(), payload);
      const { verifier } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_claims');
    });

    test('refuses a payload that is JSON and not an object', async () => {
      const hand = await createHandBuiltAgent();
      const delegation = await hand.sign(hand.header(), '[1,2]');
      const { verifier } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_malformed');
    });

    test('refuses a delegation issued a year ahead, although it lasts only 24 hours', async () => {
      const hand = await createHandBuiltAgent();
      const iat = START_SECONDS + 365 * 24 * 3600;
      const delegation = await hand.sign(hand.header(), {
        ...hand.payload(delegatedJwk),
        iat,
        exp: iat + MAX_DELEGATION_LIFETIME_SECONDS,
      });
      const { verifier } = createVerifier({ fetch: hand.fetch });

      await expectInvalid(verifier.verify(delegation, HAND_CIMD_URL), 'delegation_iat');
    });

    test.each([
      { name: 'exactly the window ahead', offset: IAT_WINDOW_SECONDS, passes: true },
      { name: 'one second more than the window ahead', offset: IAT_WINDOW_SECONDS + 1, passes: false },
      { name: 'now', offset: 0, passes: true },
    ])('a delegation issued $name', async ({ offset, passes }) => {
      // The delegation is made at START, and the clock of the verifier goes back from there.
      const { delegation, iss } = await mint(agent);
      advance(-offset * 1000);
      const { verifier } = createVerifier({ fetch: agent.fetch });

      const result = verifier.verify(delegation, iss);

      if (passes) {
        await expect(result).resolves.toMatchObject({ iss: CIMD_URL });
      } else {
        await expectInvalid(result, 'delegation_iat');
      }
    });

    test('measures the iat of a delegation against the window the verifier was made with', async () => {
      const { delegation, iss } = await mint(agent);
      advance(-1000);

      const strict = createVerifier({ fetch: agent.fetch, iatWindowSeconds: 0 });
      await expectInvalid(strict.verifier.verify(delegation, iss), 'delegation_iat');

      const wide = createVerifier({ fetch: agent.fetch, iatWindowSeconds: 5 });
      await expect(wide.verifier.verify(delegation, iss)).resolves.toMatchObject({ iss: CIMD_URL });
    });

    test('refuses a delegation at its exp and accepts it one second before', async () => {
      const shortAgent = await createTestAgent({ cimdUrl: CIMD_URL, delegationLifetimeSeconds: 600 });
      const { delegation, iss } = await mint(shortAgent);

      advance(599 * 1000);
      const before = createVerifier({ fetch: shortAgent.fetch, ttlMs: 86_400_000 });
      await expect(before.verifier.verify(delegation, iss)).resolves.toMatchObject({ exp: START_SECONDS + 600 });

      advance(1000);
      const atExp = createVerifier({ fetch: shortAgent.fetch, ttlMs: 86_400_000 });
      await expectInvalid(atExp.verifier.verify(delegation, iss), 'delegation_expired');
    });
  });

  describe('cnf.jwk', () => {
    let p384Jwk: JWK;
    let rsaJwk: JWK;

    beforeAll(async () => {
      p384Jwk = await publicJwkOf('ES384');
      rsaJwk = await publicJwkOf('RS256');
    });

    /** Verifies the delegation of a hand-built agent that has `cnf` as its confirmation claim. */
    async function verifyWithCnf(cnf: unknown): Promise<VerifiedDelegation> {
      const hand = await createHandBuiltAgent();
      const delegation = await hand.sign(hand.header(), merge(hand.payload(delegatedJwk), { cnf }));
      const { verifier } = createVerifier({ fetch: hand.fetch });
      return verifier.verify(delegation, HAND_CIMD_URL);
    }

    test.each([
      { name: 'no cnf', cnf: () => undefined },
      { name: 'a cnf that is a string', cnf: () => 'jwk' },
      { name: 'a cnf that is a list', cnf: () => [{ jwk: delegatedJwk }] },
      { name: 'a cnf that is null', cnf: () => null },
      { name: 'a cnf with a jkt and no jwk', cnf: () => ({ jkt: 'abc' }) },
      { name: 'a jwk that is a string', cnf: () => ({ jwk: 'abc' }) },
      { name: 'a jwk that is a list', cnf: () => ({ jwk: [delegatedJwk] }) },
      { name: 'a jwk that is null', cnf: () => ({ jwk: null }) },
      { name: 'a jwk that is empty', cnf: () => ({ jwk: {} }) },
      { name: 'an OKP key', cnf: () => ({ jwk: { kty: 'OKP', crv: 'Ed25519', x: ED25519_X } }) },
      { name: 'an oct key', cnf: () => ({ jwk: { kty: 'oct', k: 'AAAA' } }) },
      { name: 'an RSA key', cnf: () => ({ jwk: rsaJwk }) },
      { name: 'a P-384 key', cnf: () => ({ jwk: p384Jwk }) },
      { name: 'a key with the kty in lower case', cnf: () => ({ jwk: { ...delegatedJwk, kty: 'ec' } }) },
      { name: 'a key with the crv in lower case', cnf: () => ({ jwk: { ...delegatedJwk, crv: 'p-256' } }) },
      { name: 'a key with no crv', cnf: () => ({ jwk: { ...delegatedJwk, crv: undefined } }) },
      { name: 'a key with an x that is a number', cnf: () => ({ jwk: { ...delegatedJwk, x: 1 } }) },
      { name: 'a key with no x', cnf: () => ({ jwk: { ...delegatedJwk, x: undefined } }) },
      { name: 'a key with a y that is null', cnf: () => ({ jwk: { ...delegatedJwk, y: null } }) },
      { name: 'a key with no y', cnf: () => ({ jwk: { ...delegatedJwk, y: undefined } }) },
      { name: 'a key with an x that is empty', cnf: () => ({ jwk: { ...delegatedJwk, x: '' } }) },
      { name: 'a key with an x that is not base64url', cnf: () => ({ jwk: { ...delegatedJwk, x: '!!!' } }) },
      { name: 'a key with an x that is too short', cnf: () => ({ jwk: { ...delegatedJwk, x: 'AQAB' } }) },
      {
        name: 'a key that is not a point of the curve',
        cnf: () => ({ jwk: { ...delegatedJwk, x: OFF_CURVE_COORDINATE, y: OFF_CURVE_COORDINATE } }),
      },
    ])('refuses $name', async ({ cnf }) => {
      await expectInvalid(verifyWithCnf(cnf()), 'cnf_invalid');
    });

    test.each(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth', 'priv'])(
      'refuses a key with the private member %s',
      async (member) => {
        await expectInvalid(verifyWithCnf({ jwk: { ...delegatedJwk, [member]: 'AQAB' } }), 'cnf_private_key');
      }
    );

    test.each([
      { name: 'empty', value: '' },
      { name: 'null', value: null },
      { name: 'false', value: false },
      { name: 'an object', value: {} },
    ])('refuses a key whose private member d is $name, as the name is what counts', async ({ value }) => {
      await expectInvalid(verifyWithCnf({ jwk: { ...delegatedJwk, d: value } }), 'cnf_private_key');
    });

    test('reads only kty, crv, x and y of the key, whatever else it says about itself', async () => {
      const decorated = {
        ...delegatedJwk,
        kid: 'my-key',
        use: 'sig',
        alg: 'ES256',
        key_ops: ['verify'],
        ext: true,
        'x-note': 'anything',
      };

      const verified = await verifyWithCnf({ jwk: decorated });

      expect(verified.sessionKeyThumbprint).toBe(await calculateJwkThumbprint(delegatedJwk));
      expect(verified.sessionKey.usages).toEqual(['verify']);
    });

    test('does not read what the key says it is for, which is not part of the key', async () => {
      // The delegation is signed by the agent, so the key is the one the agent means, whatever it says about its use.
      const odd = { ...delegatedJwk, use: 'enc', alg: 'ECDH-ES', key_ops: ['sign'], ext: false };

      const verified = await verifyWithCnf({ jwk: odd });

      expect(verified.sessionKeyThumbprint).toBe(await calculateJwkThumbprint(delegatedJwk));
      expect(verified.sessionKey.usages).toEqual(['verify']);
    });

    test('gives the thumbprint of RFC 7638 for the key', async () => {
      const verified = await verifyWithCnf({ jwk: delegatedJwk });

      expect(verified.sessionKeyThumbprint).toBe(await calculateJwkThumbprint(delegatedJwk));
      expect(verified.sessionKeyThumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    test('gives the kid that the specification gives its example key', async () => {
      const verified = await verifyWithCnf({
        jwk: { kty: 'EC', crv: 'P-256', x: SPEC_EXAMPLE_X, y: SPEC_EXAMPLE_Y },
      });

      expect(verified.sessionKeyThumbprint).toBe(SPEC_EXAMPLE_KID);
    });
  });

  describe('the cache', () => {
    test('serves a delegation that was verified once without another look at the keys', async () => {
      const { verifier, fetcher, urls } = createVerifier({ fetch: agent.fetch });
      const getKeys = vi.spyOn(fetcher, 'getKeys');
      const refreshKeys = vi.spyOn(fetcher, 'refreshKeys');
      const { delegation, iss } = await mint(agent);

      const first = await verifier.verify(delegation, iss);
      expect(getKeys).toHaveBeenCalledTimes(1);
      expect(urls).toHaveLength(2);

      const second = await verifier.verify(delegation, iss);

      expect(getKeys).toHaveBeenCalledTimes(1);
      expect(refreshKeys).not.toHaveBeenCalled();
      expect(urls).toHaveLength(2);
      expect(second).toEqual(first);
      expect(second.sessionKey).toBe(first.sessionKey);
    });

    test('serves a delegation from the cache while the host of the agent is down', async () => {
      let down = false;
      const { verifier } = createVerifier({
        fetch: async (input, init) => (down ? new Response('Unavailable', { status: 503 }) : agent.fetch(input, init)),
        ttlMs: 1,
      });
      const { delegation, iss } = await mint(agent);
      await verifier.verify(delegation, iss);

      down = true;
      advance(5);

      await expect(verifier.verify(delegation, iss)).resolves.toMatchObject({ iss: CIMD_URL });
    });

    test('stops serving a delegation at its exp, and serves it one second before', async () => {
      const shortAgent = await createTestAgent({ cimdUrl: CIMD_URL, delegationLifetimeSeconds: 600 });
      const { verifier, fetcher } = createVerifier({ fetch: shortAgent.fetch, ttlMs: 86_400_000 });
      const getKeys = vi.spyOn(fetcher, 'getKeys');
      const { delegation, iss } = await mint(shortAgent);
      await verifier.verify(delegation, iss);

      advance(599 * 1000);
      await expect(verifier.verify(delegation, iss)).resolves.toMatchObject({ exp: START_SECONDS + 600 });
      expect(getKeys).toHaveBeenCalledTimes(1);

      advance(1000);
      await expectInvalid(verifier.verify(delegation, iss), 'delegation_expired');

      advance(3600 * 1000);
      await expectInvalid(verifier.verify(delegation, iss), 'delegation_expired');
    });

    describe('the time to live', () => {
      // The delegations of the test agent last an hour, and the time to live is a minute: it is the time to live that
      // ends the entry, and not the exp of the delegation.
      const TTL_MS = 60_000;

      test('serves a delegation inside the time to live, and verifies it again from the time to live on', async () => {
        const { verifier, fetcher } = createVerifier({ fetch: agent.fetch, delegationTtlMs: TTL_MS });
        const getKeys = vi.spyOn(fetcher, 'getKeys');
        const { delegation, iss } = await mint(agent);
        const first = await verifier.verify(delegation, iss);
        expect(first.exp).toBe(START_SECONDS + DEFAULT_LIFETIME_SECONDS);
        expect(getKeys).toHaveBeenCalledTimes(1);

        advance(TTL_MS - 1);
        await expect(verifier.verify(delegation, iss)).resolves.toBe(first);
        expect(getKeys).toHaveBeenCalledTimes(1);

        advance(1);
        const again = await verifier.verify(delegation, iss);

        expect(getKeys).toHaveBeenCalledTimes(2);
        expect(again.sessionKeyThumbprint).toBe(first.sessionKeyThumbprint);
        expect(again).not.toBe(first);
      });

      test('counts the time to live from the verification, and not from the last use', async () => {
        const { verifier, fetcher } = createVerifier({ fetch: agent.fetch, delegationTtlMs: TTL_MS });
        const getKeys = vi.spyOn(fetcher, 'getKeys');
        const { delegation, iss } = await mint(agent);
        await verifier.verify(delegation, iss);

        // Used often, and still checked again when its time is up.
        for (let used = 0; used < 5; used += 1) {
          advance(TTL_MS / 5 - 1);
          await verifier.verify(delegation, iss);
        }
        expect(getKeys).toHaveBeenCalledTimes(1);
        advance(5);
        await verifier.verify(delegation, iss);

        expect(getKeys).toHaveBeenCalledTimes(2);
      });

      test('ends a delegation at its exp when that comes first', async () => {
        const shortAgent = await createTestAgent({ cimdUrl: CIMD_URL, delegationLifetimeSeconds: 30 });
        const { verifier } = createVerifier({ fetch: shortAgent.fetch, delegationTtlMs: TTL_MS });
        const { delegation, iss } = await mint(shortAgent);
        await verifier.verify(delegation, iss);

        advance(29_000);
        await expect(verifier.verify(delegation, iss)).resolves.toMatchObject({ exp: START_SECONDS + 30 });

        advance(1_000);
        await expectInvalid(verifier.verify(delegation, iss), 'delegation_expired');
      });

      test('refuses a delegation of a key that the agent has taken out of its key set, once the time to live is up', async () => {
        const before = await createTestAgent({ cimdUrl: CIMD_URL });
        const after = await createTestAgent({ cimdUrl: CIMD_URL });
        let current = before;
        const { verifier } = createVerifier({
          fetch: (input, init) => current.fetch(input, init),
          ttlMs: TTL_MS,
          delegationTtlMs: TTL_MS,
        });
        const seen = await mint(before);
        await verifier.verify(seen.delegation, seen.iss);

        // The agent takes the key out of its key set. A delegation that this verifier has seen is served for a while.
        current = after;
        advance(TTL_MS - 1);
        await expect(verifier.verify(seen.delegation, seen.iss)).resolves.toMatchObject({ iss: CIMD_URL });

        // The delegation lasts for another hour, but it is checked against the key set again, and the key is not there.
        advance(1);
        await expectInvalid(verifier.verify(seen.delegation, seen.iss), 'delegation_key_unknown');
      });

      test('keeps nothing when the time to live is 0, and does not read 0 as no limit', async () => {
        const { verifier, fetcher } = createVerifier({ fetch: agent.fetch, delegationTtlMs: 0 });
        const getKeys = vi.spyOn(fetcher, 'getKeys');
        const { delegation, iss } = await mint(agent);

        await verifier.verify(delegation, iss);
        await verifier.verify(delegation, iss);
        await verifier.verify(delegation, iss);

        expect(getKeys).toHaveBeenCalledTimes(3);
      });
    });

    test('refuses a delegation of the cache that is presented for another issuer', async () => {
      const other = await createTestAgent({ cimdUrl: OTHER_CIMD_URL });
      const { verifier, urls } = createVerifier({
        fetch: (input, init) => (urlOf(input).startsWith(OTHER_ORIGIN) ? other : agent).fetch(input, init),
      });
      const { delegation, iss } = await mint(agent);
      await verifier.verify(delegation, iss);

      // The delegation is in the cache for its agent. For another agent it is verified in full, and its key is unknown.
      await expectInvalid(verifier.verify(delegation, OTHER_CIMD_URL), 'delegation_key_unknown');
      expect(urls.filter((url) => url.startsWith(OTHER_ORIGIN))).not.toHaveLength(0);

      // The refusal took nothing out of the cache.
      const fetched = urls.length;
      await expect(verifier.verify(delegation, iss)).resolves.toMatchObject({ iss: CIMD_URL });
      expect(urls).toHaveLength(fetched);
    });

    test('keeps at most the number of delegations it was made for, the least recently used going first', async () => {
      const { verifier, fetcher } = createVerifier({ fetch: agent.fetch, cacheMaxEntries: 1 });
      const getKeys = vi.spyOn(fetcher, 'getKeys');
      const first = await mint(agent, { sub: 'usr_one' });
      const second = await mint(agent, { sub: 'usr_two' });

      await verifier.verify(first.delegation, first.iss);
      await verifier.verify(first.delegation, first.iss);
      expect(getKeys).toHaveBeenCalledTimes(1);

      await verifier.verify(second.delegation, second.iss);
      expect(getKeys).toHaveBeenCalledTimes(2);

      // The first delegation was pushed out by the second, so it is verified again.
      await verifier.verify(first.delegation, first.iss);
      expect(getKeys).toHaveBeenCalledTimes(3);
    });

    test('keeps nothing when it was made for no entries', async () => {
      const { verifier, fetcher } = createVerifier({ fetch: agent.fetch, cacheMaxEntries: 0 });
      const getKeys = vi.spyOn(fetcher, 'getKeys');
      const { delegation, iss } = await mint(agent);

      await verifier.verify(delegation, iss);
      await verifier.verify(delegation, iss);

      expect(getKeys).toHaveBeenCalledTimes(2);
    });

    test.each(['delegation_iss_mismatch', 'delegation_private_cnf', 'expired_delegation'] as const)(
      'does not keep a delegation that failed, even a late failure, with the defect %s',
      async (defect) => {
        const { verifier, fetcher } = createVerifier({ fetch: agent.fetch });
        const getKeys = vi.spyOn(fetcher, 'getKeys');
        const { delegation, iss } = await mint(agent, { defect });

        await rejectionOf(verifier.verify(delegation, iss));
        await rejectionOf(verifier.verify(delegation, iss));

        // Each attempt verifies the delegation in full: a failure is never served from the cache.
        expect(getKeys).toHaveBeenCalledTimes(2);
      }
    );

    test('lets verifications of one delegation that start together all finish, and leaves one good entry', async () => {
      const { verifier, fetcher } = createVerifier({ fetch: agent.fetch });
      const getKeys = vi.spyOn(fetcher, 'getKeys');
      const { delegation, iss, kid } = await mint(agent);

      const results = await Promise.all([1, 2, 3, 4, 5].map(() => verifier.verify(delegation, iss)));

      for (const result of results) {
        expect(result.iss).toBe(CIMD_URL);
        expect(result.exp).toBe(START_SECONDS + DEFAULT_LIFETIME_SECONDS);
        expect(result.sessionKeyThumbprint).toBe(kid);
      }
      const verifiedTogether = getKeys.mock.calls.length;

      // A later call is served from the cache.
      await expect(verifier.verify(delegation, iss)).resolves.toMatchObject({ sessionKeyThumbprint: kid });
      expect(getKeys).toHaveBeenCalledTimes(verifiedTogether);
    });

    test.each([
      { field: 'sessionKeyThumbprint', value: 'forged' },
      { field: 'exp', value: 1e12 },
    ])('is not changed by a caller that writes $field in the result it got', async ({ field, value }) => {
      const { verifier } = createVerifier({ fetch: agent.fetch });
      const { delegation, iss } = await mint(agent);
      const first = await verifier.verify(delegation, iss);
      const original = first[field as 'exp' | 'sessionKeyThumbprint'];

      try {
        (first as unknown as Record<string, unknown>)[field] = value;
      } catch {
        // A result that can't be changed refuses the write, which is as good.
      }
      const second = await verifier.verify(delegation, iss);

      // The write must change neither this result nor what the cache gives to the next caller.
      expect(second[field as 'exp' | 'sessionKeyThumbprint']).toBe(original);
      expect(first[field as 'exp' | 'sessionKeyThumbprint']).toBe(original);
    });
  });

  describe('errors of the fetcher', () => {
    test('passes an agent_metadata_invalid error through as it is', async () => {
      const { verifier } = createVerifier({ fetch: async () => new Response('Not found', { status: 404 }) });
      const { delegation, iss } = await mint(agent);

      const error = await rejectionOf(verifier.verify(delegation, iss));

      expect(error).toBeInstanceOf(InvalidSessionError);
      expect((error as InvalidSessionError).reason).toBe('agent_metadata_invalid');
      expect((error as InvalidSessionError).cause).toEqual({ code: 'metadata_status' });
    });

    test('passes a PoppyUnavailableError through as it is', async () => {
      const { verifier } = createVerifier({ fetch: async () => new Response('Unavailable', { status: 503 }) });
      const { delegation, iss } = await mint(agent);

      const error = await rejectionOf(verifier.verify(delegation, iss));

      expect(error).toBeInstanceOf(PoppyUnavailableError);
      expect(error).toMatchObject({ code: 'temporarily_unavailable', statusCode: 503 });
      expect((error as PoppyUnavailableError).retryAfter).toBe(DEFAULT_RETRY_AFTER_SECONDS);
      expect((error as PoppyUnavailableError).cause).toEqual({ code: 'upstream_unavailable' });
    });

    test('passes an agent_not_allowed error through as it is', async () => {
      const { verifier, urls } = createVerifier({ fetch: agent.fetch });
      const { delegation } = await mint(agent);

      const error = await rejectionOf(verifier.verify(delegation, 'http://agent.example/agent.json'));

      expect(error).toBeInstanceOf(InvalidSessionError);
      expect((error as InvalidSessionError).reason).toBe('agent_not_allowed');
      expect((error as InvalidSessionError).cause).toEqual({ code: 'agent_url_invalid' });
      expect(urls).toEqual([]);
    });

    test('passes an error of the refresh of the keys through as it is', async () => {
      let down = false;
      const { verifier } = createVerifier({
        fetch: async (input, init) => (down ? new Response('Unavailable', { status: 503 }) : agent.fetch(input, init)),
      });
      const known = await mint(agent);
      await verifier.verify(known.delegation, known.iss);

      // The keys are in the cache, so the key ID that is not in them makes a refresh, and the host is down for it.
      down = true;
      const unknown = await mint(agent, { defect: 'delegation_unknown_kid' });
      const error = await rejectionOf(verifier.verify(unknown.delegation, unknown.iss));

      expect(error).toBeInstanceOf(PoppyUnavailableError);
    });

    test('leaves no value of the delegation in the message or the cause of the error it throws', async () => {
      const { verifier } = createVerifier({ fetch: agent.fetch });
      const { delegation, iss, kid } = await mint(agent, { defect: 'delegation_iss_mismatch' });

      const error = (await rejectionOf(verifier.verify(delegation, iss))) as InvalidSessionError;

      for (const secret of [delegation, kid, iss, OTHER_CIMD_URL, delegation.split('.')[1] ?? '']) {
        expect(error.message).not.toContain(secret);
        expect(JSON.stringify(error.cause)).not.toContain(secret);
      }
    });
  });
});
