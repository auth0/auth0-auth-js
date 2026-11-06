import {
  CompactSign,
  base64url,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type CompactJWSHeaderParameters,
  type JWK,
} from 'jose';
import { DELEGATION_JWT_TYP, MAX_DELEGATION_LIFETIME_SECONDS, MAX_URL_LENGTH, SESSION_JWT_TYP } from '../constants.js';

// A fake Personal Agent for tests, shipped as `@auth0/auth0-api-js/testing`. It imports only `jose` and the protocol
// constants. It never imports the verifier, so a bug in the verifier is not copied into the JWTs made here. It does
// share `constants.ts` with the verifier, so a wrong protocol string or number there would be wrong on both sides:
// the specification, and not this file, is the check for those.

const DEFAULT_CIMD_URL = 'https://agent.example/agent.json';
const DEFAULT_DELEGATION_LIFETIME_SECONDS = 3600;
const DEFAULT_SUB = 'usr_test';
const CLIENT_NAME = 'Test Agent';

// Session JWTs are always signed with ES256 (spec section 5.2), so every delegated key is a P-256 key.
const SESSION_ALG = 'ES256';
const RSA_MODULUS_LENGTH = 2048;
// 16 random bytes are 22 characters of the URL-safe base64 alphabet.
const RANDOM_ID_BYTES = 16;

// The values behind the defects.
const PLAIN_JWT_TYP = 'JWT';
// URLs of other agents, for the `delegation_iss_mismatch` defect. It uses the first one, and the second one when the
// first is the URL of the agent itself, so the `iss` of the delegation is never the URL of the agent.
const OTHER_AGENT_URL = 'https://other.example/agent.json';
const ANOTHER_AGENT_URL = 'https://another.example/agent.json';
const UNKNOWN_KID = 'kid-that-is-not-in-the-key-set';
const EXPIRED_AGO_SECONDS = 3600;
const ISSUED_AHEAD_SECONDS = 3600;

/**
 * Options for {@link createTestAgent}.
 *
 * @example
 * ```typescript
 * const agent = await createTestAgent({
 *   cimdUrl: 'https://my-agent.test/agent.json',
 *   delegationAlg: 'PS384',
 *   delegationLifetimeSeconds: 600,
 * });
 * ```
 *
 * @beta
 * @category Poppy
 */
export interface CreateTestAgentOptions {
  /**
   * The URL of the client metadata document of the agent. It is the `client_id` of the agent and the `iss` of its
   * Session JWTs. It must be an `https:` URL in canonical form, which is the one spelling that a verifier accepts for an
   * agent URL: a host in lower case, no default port, a path of at least `/`, no fragment and no user name or password.
   * It must equal `new URL(cimdUrl).href`. The URL of the key set is `/jwks.json` on the same origin.
   *
   * Each agent makes its own keys. Two agents with the same `cimdUrl`, the default included, have the same `client_id`
   * and different keys. See {@link createTestAgent} for what that means for a verifier.
   *
   * @defaultValue `'https://agent.example/agent.json'`
   */
  cimdUrl?: string;

  /**
   * The algorithm of the key in the key set of the agent, which signs its delegations: `ES256`, or `PS384` with an RSA
   * key of 2048 bits. The Session JWTs are signed with `ES256`, except the one that has the defect
   * `signed_with_agent_key`: it is signed with the key of the agent, so for a `PS384` agent its `alg` is `PS384`.
   *
   * @defaultValue `'ES256'`
   */
  delegationAlg?: 'ES256' | 'PS384';

  /**
   * How long a delegation lasts, in seconds, from its `iat` to its `exp`. It must be an integer from 1 to 86400, the 24
   * hours that the specification allows at most.
   *
   * @defaultValue `3600`
   */
  delegationLifetimeSeconds?: number;
}

/**
 * One deliberate defect for a negative test. Each value changes one thing in a Session JWT that is otherwise valid, so
 * the check named in its description is the one that should refuse it.
 *
 * @example
 * ```typescript
 * const sessionJwt = await agent.createSessionJwt({
 *   aud: 'https://example.auth0.com/',
 *   htm: 'POST',
 *   htu: 'https://api.example.com/orders',
 *   defect: 'expired_delegation',
 * });
 * ```
 *
 * @see {@link https://personalagentprotocol.org/docs/0.3/spec Poppy 0.3 specification}, sections 5.2 and 5.3
 * @beta
 * @category Poppy
 */
export type TestSessionJwtDefect =
  /** No `poppy_dlg` in the header, so no delegation. The check that a delegation is present should refuse it. */
  | 'missing_delegation'
  /**
   * Signed with a `jwks_uri` key, with no `poppy_dlg`. The check that a delegation is present should refuse it. For a
   * `PS384` agent the JWT also has `alg` `PS384`, a second deviation, because a Session JWT must use `ES256`.
   */
  | 'signed_with_agent_key'
  /** The delegation expired an hour ago. The check that the delegation has not expired should refuse it. */
  | 'expired_delegation'
  /** The delegation's `exp` is 24 hours and 1 second after its `iat`. The 24-hour limit should refuse it. */
  | 'delegation_too_long'
  /** The delegation was issued an hour from now. The check that it is not from the future should refuse it. */
  | 'delegation_from_future'
  /** The delegation's `iss` is another agent. The check that it equals the Session JWT `iss` should refuse it. */
  | 'delegation_iss_mismatch'
  /** The delegation's `typ` is `JWT`. The check of the delegation `typ` should refuse it. */
  | 'delegation_wrong_typ'
  /** The delegation's `kid` is not in the key set of the agent. The key lookup for the delegation should refuse it. */
  | 'delegation_unknown_kid'
  /** The delegation's `cnf.jwk` has the private member `d`. The check for private key members should refuse it. */
  | 'delegation_private_cnf'
  /** The Session JWT's `typ` is `JWT`. The check of the Session JWT `typ` should refuse it. */
  | 'session_wrong_typ'
  /** The Session JWT's `kid` is not the thumbprint of `cnf.jwk`. The check of the `kid` should refuse it. */
  | 'session_wrong_kid'
  /** Signed with a key that is not the delegated key. The check of the signature with `cnf.jwk` should refuse it. */
  | 'session_bad_signature';

/**
 * What goes into a Session JWT made by {@link TestAgent.createSessionJwt}.
 *
 * @example
 * ```typescript
 * const options: TestSessionJwtOptions = {
 *   aud: 'https://example.auth0.com/',
 *   htm: 'POST',
 *   htu: 'https://api.example.com/orders',
 *   sub: 'usr_123',
 * };
 * ```
 *
 * @beta
 * @category Poppy
 */
export interface TestSessionJwtOptions {
  /**
   * The `aud` claim: the identifier of your Company, which is the issuer of your Auth0 domain, for example
   * `https://example.auth0.com/`.
   */
  aud: string;

  /**
   * The `htm` claim: the HTTP method of the request that the JWT is for, for example `POST`.
   */
  htm: string;

  /**
   * The `htu` claim: the URL of the request without its query and fragment, for example
   * `https://api.example.com/orders`.
   */
  htu: string;

  /**
   * The `sid` claim: the Session ID. The default is new for every JWT, so pass the same `sid` to each JWT of a Session
   * that you want to continue.
   *
   * @defaultValue 22 random characters of the URL-safe base64 alphabet
   */
  sid?: string;

  /**
   * The `sub` claim: the User ID. The agent signs the JWTs of one `sub` with one delegated key and its delegation, and
   * uses a different key for each `sub`, as the specification asks (section 5.2).
   *
   * @defaultValue `'usr_test'`
   */
  sub?: string;

  /**
   * The `agent_id` claim: the Agent ID. Left out when not set.
   */
  agentId?: string;

  /**
   * The access token that the request carries. The JWT gets `ath`, the base64url SHA-256 hash of it. The token itself
   * is not put in the JWT. Without it, there is no `ath`.
   */
  accessToken?: string;

  /**
   * The `iat` claim, in Unix seconds. It does not change the times of the delegation, which follow the clock.
   *
   * @defaultValue the current time
   */
  iat?: number;

  /**
   * The `jti` claim.
   *
   * @defaultValue 22 random characters of the URL-safe base64 alphabet
   */
  jti?: string;

  /**
   * Claims to merge into the payload last, after the `defect`. A value replaces the claim, and `undefined` removes it.
   */
  claims?: Record<string, unknown>;

  /**
   * Parameters to merge into the protected header last, after the `defect`. A value replaces the parameter, and
   * `undefined` removes it. The JWT is signed for real, so leave `alg` as it is: a key signs with its own algorithm
   * only.
   */
  header?: Record<string, unknown>;

  /**
   * One deliberate defect, for a negative test.
   */
  defect?: TestSessionJwtDefect;
}

/**
 * A fake Personal Agent for tests, made by {@link createTestAgent}. It has its own keys, serves its client metadata and
 * its key set through {@link TestAgent.fetch}, and signs Session JWTs, valid ones or ones with one deliberate defect.
 *
 * The keys are made in memory for each agent and are not saved. Use the agent in tests only.
 *
 * @example
 * ```typescript
 * const agent = await createTestAgent();
 * const response = await agent.fetch(agent.cimdUrl);
 * console.log(await response.json()); // { client_id: 'https://agent.example/agent.json', ... }
 * ```
 *
 * @beta
 * @category Poppy
 */
export interface TestAgent {
  /**
   * The URL of the client metadata document of the agent. It is the `client_id` of the agent and the `iss` of its
   * Session JWTs.
   */
  readonly cimdUrl: string;

  /**
   * The URL of the key set of the agent, which is the `jwks_uri` of its metadata.
   */
  readonly jwksUri: string;

  /**
   * The client metadata document of the agent, as {@link TestAgent.fetch} serves it for `cimdUrl`.
   */
  readonly metadata: {
    client_id: string;
    client_name: string;
    jwks_uri: string;
    token_endpoint_auth_method: 'private_key_jwt';
  };

  /**
   * The key set of the agent, as {@link TestAgent.fetch} serves it for `jwksUri`. It has the public key that signs the
   * delegations and nothing private.
   */
  readonly jwks: { keys: JWK[] };

  /**
   * A `fetch` that answers like the host of the agent, without a network: the client metadata for `cimdUrl` and the key
   * set for `jwksUri`, both as JSON with status 200, and status 404 for any other URL. Pass it as the
   * `agentMetadata.fetch` of the `poppy` option of `ApiClient`.
   *
   * It takes a string, a `URL` or a `Request`, and it does not use `this`, so you can pass it around as a bare
   * function. It ignores its second argument, `init`, so a `signal` or `headers` that you pass have no effect. It reads
   * `metadata` and `jwks` when it is called, so a change to them changes what it serves.
   */
  readonly fetch: typeof fetch;

  /**
   * Makes a Session JWT for one request: the value of its `Poppy-Session` header. The JWT is signed with a delegated
   * key. Its header carries a delegation that vouches for that key, signed with the key from the key set of the agent.
   *
   * The agent makes the delegated key for a `sub` the first time it needs it, and keeps it. It keeps the delegation
   * too, and puts the same one in every JWT of the `sub` while it is valid. After its `exp`, the next JWT gets a new
   * delegation for the same key. A JWT with a delegation defect gets a new delegation of its own, and the one that is
   * kept stays as it was. The clock is read on every call.
   *
   * @param options - What goes into the JWT.
   * @returns The Session JWT.
   */
  createSessionJwt(options: TestSessionJwtOptions): Promise<string>;
}

interface AgentKey {
  privateKey: CryptoKey;
  publicJwk: JWK;
  kid: string;
  alg: string;
}

interface DelegatedKey {
  privateKey: CryptoKey;
  publicJwk: JWK;
  privateJwk: JWK;
  thumbprint: string;
}

// Everything that goes into a delegation and can be wrong in one.
interface DelegationParts {
  typ: string;
  kid: string;
  iss: string;
  iat: number;
  exp: number;
  cnfJwk: JWK;
}

const nowInSeconds = (): number => Math.floor(Date.now() / 1000);

function randomId(): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(RANDOM_ID_BYTES)));
}

async function hashAccessToken(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
  return base64url.encode(new Uint8Array(digest));
}

function signCompact(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey
): Promise<string> {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader(header as CompactJWSHeaderParameters)
    .sign(key);
}

// Puts `overrides` over `base`, on a copy. A value replaces the member, and `undefined` removes it.
function applyOverrides(base: Record<string, unknown>, overrides?: Record<string, unknown>): Record<string, unknown> {
  const merged = { ...base };
  for (const [name, value] of Object.entries(overrides ?? {})) {
    if (value === undefined) {
      delete merged[name];
    } else {
      merged[name] = value;
    }
  }
  return merged;
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

const NOT_HTTPS_MESSAGE = 'createTestAgent: cimdUrl must be an https: URL in canonical form.';

const NOT_CANONICAL_MESSAGE =
  'createTestAgent: cimdUrl must be an https: URL in canonical form, which is how a verifier compares agent URLs: ' +
  'a host in lower case, no default port, a path of at least "/", no fragment, no user name or password, and at most ' +
  `${MAX_URL_LENGTH} characters. It must equal new URL(cimdUrl).href.`;

// The one spelling of an agent URL that a verifier accepts (spec section 4.1): an `https:` URL with no user name,
// password or fragment that is the text `new URL(value).href` gives, because a `client_id` is compared character by
// character. It is written here, and not imported from the verifier, so a mistake in the rule of the verifier is not
// copied into the agent. An empty fragment is in `href` but not in `url.hash`, so the text is searched for the `#`.
function isCanonicalUrl(value: string): boolean {
  const url = new URL(value);
  return (
    value.length <= MAX_URL_LENGTH &&
    url.username === '' &&
    url.password === '' &&
    !value.includes('#') &&
    url.href === value
  );
}

async function createAgentKey(alg: 'ES256' | 'PS384'): Promise<AgentKey> {
  // The modulus length is for PS384 only. An ES256 key ignores it.
  const { privateKey, publicKey } = await generateKeyPair(alg, { modulusLength: RSA_MODULUS_LENGTH });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return { privateKey, publicJwk: { ...publicJwk, kid, alg }, kid, alg };
}

async function createDelegatedKey(): Promise<DelegatedKey> {
  // Extractable, so the `delegation_private_cnf` defect can put the private key in a delegation.
  const { privateKey, publicKey } = await generateKeyPair(SESSION_ALG, { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  return {
    privateKey,
    publicJwk,
    privateJwk: await exportJWK(privateKey),
    thumbprint: await calculateJwkThumbprint(publicJwk),
  };
}

/**
 * Creates a fake Personal Agent for tests. It lets you test the routes of your API that verify Poppy requests without
 * a real agent and without a network: the agent makes the Session JWTs that your routes receive, and its `fetch`
 * stands in for the host of the agent.
 *
 * This is test-only code. Import it from `@auth0/auth0-api-js/testing`, and not from code that runs in production.
 *
 * Every call makes new keys. Two agents with the same `cimdUrl`, the default included, have the same `client_id` and
 * different keys. A verifier that caches the keys of an agent by its URL, as the SDK does, keeps the keys of the first
 * agent it saw at that URL, so it can refuse the JWTs of the second one. Use one agent for each `ApiClient`, or give
 * each agent its own `cimdUrl`.
 *
 * @param options - How the agent is set up. All of them are optional.
 * @returns The test agent.
 * @throws {TypeError} The returned promise rejects with a `TypeError` when `cimdUrl` is not an `https:` URL, or is not in
 * canonical form (see {@link CreateTestAgentOptions.cimdUrl}).
 * @throws {RangeError} The returned promise rejects with a `RangeError` when `delegationLifetimeSeconds` is not an
 * integer from 1 to 86400.
 *
 * @example
 * ```typescript
 * import { ApiClient } from '@auth0/auth0-api-js';
 * import { createTestAgent } from '@auth0/auth0-api-js/testing';
 *
 * const agent = await createTestAgent();
 * const apiClient = new ApiClient({
 *   domain: 'example.auth0.com',
 *   audience: 'https://api.example.com/',
 *   poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
 * });
 *
 * const sessionJwt = await agent.createSessionJwt({
 *   aud: 'https://example.auth0.com/',
 *   htm: 'POST',
 *   htu: 'https://api.example.com/orders',
 * });
 * await apiClient.verifyPoppyRequest({
 *   method: 'POST',
 *   url: 'https://api.example.com/orders',
 *   headers: { 'poppy-session': sessionJwt },
 * });
 * ```
 *
 * @see {@link https://personalagentprotocol.org/docs/0.3/spec Poppy 0.3 specification}
 * @beta
 * @category Poppy
 */
export async function createTestAgent(options: CreateTestAgentOptions = {}): Promise<TestAgent> {
  const {
    cimdUrl = DEFAULT_CIMD_URL,
    delegationAlg = 'ES256',
    delegationLifetimeSeconds = DEFAULT_DELEGATION_LIFETIME_SECONDS,
  } = options;

  // The messages are fixed, and have nothing of the URL in them: a URL can hold a user name and a password, and a test
  // runner prints the message in the log of a CI job.
  if (!isHttpsUrl(cimdUrl)) {
    throw new TypeError(NOT_HTTPS_MESSAGE);
  }
  if (!isCanonicalUrl(cimdUrl)) {
    throw new TypeError(NOT_CANONICAL_MESSAGE);
  }
  if (
    !Number.isInteger(delegationLifetimeSeconds) ||
    delegationLifetimeSeconds < 1 ||
    delegationLifetimeSeconds > MAX_DELEGATION_LIFETIME_SECONDS
  ) {
    throw new RangeError(
      `createTestAgent: delegationLifetimeSeconds must be an integer from 1 to ${MAX_DELEGATION_LIFETIME_SECONDS}, ` +
        `but it is ${String(delegationLifetimeSeconds)} (${typeof delegationLifetimeSeconds}).`
    );
  }

  const cimdHref = new URL(cimdUrl).href;
  const otherAgentUrl = cimdHref === OTHER_AGENT_URL ? ANOTHER_AGENT_URL : OTHER_AGENT_URL;
  const jwksUri = new URL('/jwks.json', cimdUrl).href;
  const agentKey = await createAgentKey(delegationAlg);
  const metadata: TestAgent['metadata'] = {
    client_id: cimdUrl,
    client_name: CLIENT_NAME,
    jwks_uri: jwksUri,
    token_endpoint_auth_method: 'private_key_jwt',
  };
  const jwks: TestAgent['jwks'] = { keys: [agentKey.publicJwk] };

  // The promises are kept, and not their results, so calls that run together share one key and one delegation.
  const delegatedKeys = new Map<string, Promise<DelegatedKey>>();
  const delegations = new Map<string, { iat: number; exp: number; jwt: Promise<string> }>();

  const getDelegatedKey = (sub: string): Promise<DelegatedKey> => {
    let key = delegatedKeys.get(sub);
    if (!key) {
      key = createDelegatedKey();
      delegatedKeys.set(sub, key);
    }
    return key;
  };

  const signDelegation = (parts: DelegationParts): Promise<string> =>
    signCompact(
      { alg: delegationAlg, typ: parts.typ, kid: parts.kid },
      { iss: parts.iss, cnf: { jwk: parts.cnfJwk }, iat: parts.iat, exp: parts.exp, jti: randomId() },
      agentKey.privateKey
    );

  const validDelegationParts = (key: DelegatedKey, now: number): DelegationParts => ({
    typ: DELEGATION_JWT_TYP,
    kid: agentKey.kid,
    iss: cimdUrl,
    iat: now,
    exp: now + delegationLifetimeSeconds,
    cnfJwk: key.publicJwk,
  });

  // The delegation that the Session JWTs of a `sub` carry while it is valid. It is kept before it is signed, so calls
  // that run together get the same one.
  const getDelegation = (sub: string, key: DelegatedKey, now: number): Promise<string> => {
    const kept = delegations.get(sub);
    if (kept && kept.iat <= now && now < kept.exp) {
      return kept.jwt;
    }
    const parts = validDelegationParts(key, now);
    const jwt = signDelegation(parts);
    delegations.set(sub, { iat: parts.iat, exp: parts.exp, jwt });
    return jwt;
  };

  // The parts of a delegation with the defect, or `undefined` when the defect is not about the delegation.
  const defectiveDelegationParts = (
    defect: TestSessionJwtDefect | undefined,
    key: DelegatedKey,
    now: number
  ): DelegationParts | undefined => {
    const valid = validDelegationParts(key, now);
    switch (defect) {
      case 'expired_delegation': {
        const exp = now - EXPIRED_AGO_SECONDS;
        return { ...valid, iat: exp - delegationLifetimeSeconds, exp };
      }
      case 'delegation_too_long':
        return { ...valid, exp: valid.iat + MAX_DELEGATION_LIFETIME_SECONDS + 1 };
      case 'delegation_from_future': {
        const iat = now + ISSUED_AHEAD_SECONDS;
        return { ...valid, iat, exp: iat + delegationLifetimeSeconds };
      }
      case 'delegation_iss_mismatch':
        return { ...valid, iss: otherAgentUrl };
      case 'delegation_wrong_typ':
        return { ...valid, typ: PLAIN_JWT_TYP };
      case 'delegation_unknown_kid':
        return { ...valid, kid: UNKNOWN_KID };
      case 'delegation_private_cnf':
        return { ...valid, cnfJwk: key.privateJwk };
      default:
        return undefined;
    }
  };

  const createSessionJwt = async (sessionOptions: TestSessionJwtOptions): Promise<string> => {
    const now = nowInSeconds();
    const { defect } = sessionOptions;
    const sub = sessionOptions.sub ?? DEFAULT_SUB;
    const key = await getDelegatedKey(sub);

    let delegation: string | undefined;
    if (defect !== 'missing_delegation' && defect !== 'signed_with_agent_key') {
      const defective = defectiveDelegationParts(defect, key, now);
      delegation = defective ? await signDelegation(defective) : await getDelegation(sub, key, now);
    }

    const header: Record<string, unknown> = { typ: SESSION_JWT_TYP, alg: SESSION_ALG, kid: key.thumbprint };
    if (delegation !== undefined) {
      header.poppy_dlg = delegation;
    }
    let signingKey = key.privateKey;
    if (defect === 'signed_with_agent_key') {
      header.alg = agentKey.alg;
      header.kid = agentKey.kid;
      signingKey = agentKey.privateKey;
    }
    if (defect === 'session_wrong_typ') {
      header.typ = PLAIN_JWT_TYP;
    }
    if (defect === 'session_wrong_kid') {
      // The thumbprint of a key that is not the delegated key.
      header.kid = agentKey.kid;
    }
    if (defect === 'session_bad_signature') {
      signingKey = (await generateKeyPair(SESSION_ALG)).privateKey;
    }

    const payload: Record<string, unknown> = {
      iss: cimdUrl,
      aud: sessionOptions.aud,
      sid: sessionOptions.sid ?? randomId(),
      sub,
      ...(sessionOptions.agentId === undefined ? {} : { agent_id: sessionOptions.agentId }),
      htm: sessionOptions.htm,
      htu: sessionOptions.htu,
      iat: sessionOptions.iat ?? now,
      jti: sessionOptions.jti ?? randomId(),
      ...(sessionOptions.accessToken === undefined ? {} : { ath: await hashAccessToken(sessionOptions.accessToken) }),
    };

    return signCompact(
      applyOverrides(header, sessionOptions.header),
      applyOverrides(payload, sessionOptions.claims),
      signingKey
    );
  };

  const respondWithJson = (body: unknown): Response =>
    new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });

  // An arrow function that uses no `this`, so it works as a bare function.
  const fetchFromAgent = async (input: string | URL | Request): Promise<Response> => {
    const requested = new URL(typeof input === 'string' ? input : 'href' in input ? input.href : input.url).href;
    if (requested === cimdHref) {
      return respondWithJson(metadata);
    }
    if (requested === jwksUri) {
      return respondWithJson(jwks);
    }
    return new Response('Not found', { status: 404 });
  };

  return { cimdUrl, jwksUri, metadata, jwks, fetch: fetchFromAgent, createSessionJwt };
}
