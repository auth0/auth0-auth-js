import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeProtectedHeader,
  errors,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from 'jose';
import { LruCache } from '../lru-cache.js';
import type { AgentMetadataFetcher } from './agent-metadata.js';
import {
  DELEGATION_JWT_ALGORITHMS,
  DELEGATION_JWT_TYP,
  MAX_DELEGATION_LIFETIME_SECONDS,
  PRIVATE_KEY_MEMBERS,
} from './constants.js';
import { InvalidSessionError } from './errors.js';
import { isRecord } from './is-record.js';
import { isP256Point } from './p256-point.js';
import { normalizeTyp } from './session-jwt.js';

// Verifies the delegation of a Session JWT: the step that turns a key of the agent, which signs delegations only, into
// the delegated key that signs the Session JWTs. A key in the `jwks_uri` of the agent signs a delegation, the
// delegation vouches for a P-256 key, and that key signs the Session JWT (see `session-verifier.ts`). The agent uses a
// delegated key for one User ID only and decides when to replace it (spec section 5.2, "Delegated keys").
//
// It trusts nothing in the delegation until the signature is verified, and it takes the key for that signature from
// the key set of the agent only. The `jwk`, `jku`, `x5u` and `x5c` headers of the delegation are never read: `jose`
// does not look at them for a key set that is given to it, and this module reads three headers (`typ`, `alg` and
// `kid`) and no other. It fails closed: whatever cannot be shown to be fine is refused.
// Spec: https://personalagentprotocol.org/docs/0.3/spec, section 5.2 ("Delegated keys") and section 5.3, step 2.

/**
 * The diagnostic codes of the errors that this module throws for a delegation. Every one is an
 * {@link InvalidSessionError} with the reason `delegation_invalid`, and the code is in `error.cause.code`, for logs and
 * tests.
 *
 * The message of an error is a fixed text that says which check failed. A value of the delegation, of a key or of a URL
 * never goes into a message, because a message goes back to the agent as its `error_description`, and into logs.
 *
 * Refused before anything is fetched, from the header:
 * - `delegation_malformed`: the delegation is not a JWT in compact form, its header is not a JSON object, or (after the
 *   signature was verified) its payload is not.
 * - `delegation_typ`: `typ` is not `poppy-delegation+jwt` (in any letter case, with `application/` before it or not).
 * - `delegation_alg`: `alg` is not `ES256` or `PS384`. `none`, `HS*` and the other `RS*`, `PS*` and `ES*` are refused.
 * - `delegation_kid`: `kid` is not a non-empty string.
 *
 * Refused by the check of the signature:
 * - `delegation_key_unknown`: no key of the key set of the agent is usable for the delegation, not even after the keys
 *   were fetched again, or the keys could not be fetched again yet (the fetcher allows one fetch for each agent in 30
 *   seconds). A key is usable when it has the `kid`, its key type and curve fit the `alg` of the delegation, its `alg`
 *   (if it has one) is that `alg`, its `use` (if it has one) is `sig`, and its `key_ops` (if it has them) has `verify`.
 * - `delegation_signature`: the signature is wrong, or the key can't verify it (two keys have the `kid`, the key is an
 *   RSA key of less than 2048 bits, or the delegation has a critical header that is not known).
 *
 * Refused by the check of the claims, in this order:
 * - `delegation_expired`: `exp` is now or in the past.
 * - `delegation_claims`: `iat` or `exp` is missing or is not a finite number, or `nbf` is ahead of now.
 * - `delegation_iss`: `iss` is not the agent that sent the Session JWT, compared character by character.
 * - `delegation_lifetime`: `exp` is not after `iat`, or is more than 24 hours after it.
 * - `delegation_iat`: `iat` is more than the `iat` window ahead of now. The specification does not say so, but without
 *   it a delegation that is issued a year from now would pass the 24 hour limit.
 *
 * Refused by the check of the confirmation claim `cnf.jwk`, which is the delegated key:
 * - `cnf_invalid`: `cnf.jwk` is missing, is not an EC key on P-256 with a string `x` and a string `y`, or is not a
 *   point of that curve. The SDK checks the point itself (`isP256Point`: `x` and `y` of the full 32 bytes, below the
 *   prime of the field, and on the curve), because not every runtime refuses a bad key when it imports one.
 * - `cnf_private_key`: `cnf.jwk` has a private member, whatever its value ({@link PRIVATE_KEY_MEMBERS}).
 *
 * An error of the fetcher is not one of these. It reaches the caller as it is: `agent_not_allowed` and
 * `agent_metadata_invalid` for an agent that is refused, and a `PoppyUnavailableError` for a host that is down.
 */
const DELEGATION_PROBLEMS = {
  delegation_malformed: 'The delegation is not a well-formed JWT.',
  delegation_typ: `The delegation typ header must be ${DELEGATION_JWT_TYP}.`,
  delegation_alg: `The delegation alg header must be ${DELEGATION_JWT_ALGORITHMS.join(' or ')}.`,
  delegation_kid: 'The delegation kid header must be a non-empty string.',
  delegation_key_unknown: 'The key set of the agent has no usable key with the kid of the delegation.',
  delegation_signature: 'The delegation could not be verified with the key of the agent.',
  delegation_expired: 'The delegation has expired.',
  delegation_claims: 'The delegation iat, exp or nbf claim is missing or not valid.',
  delegation_iss: 'The delegation iss is not the iss of the Session JWT.',
  delegation_lifetime: 'The delegation must expire after it was issued, and at most 24 hours after.',
  delegation_iat: 'The delegation was issued in the future.',
  cnf_invalid: 'The delegation cnf.jwk must be an EC P-256 public key.',
  cnf_private_key: 'The delegation cnf.jwk must not have private key members.',
} as const;

type DelegationProblem = keyof typeof DELEGATION_PROBLEMS;

/** A new error each time, so callers never share an error or a stack. */
function invalid(problem: DelegationProblem): InvalidSessionError {
  const error = new InvalidSessionError('delegation_invalid', DELEGATION_PROBLEMS[problem]);
  error.cause = { code: problem };
  return error;
}

/**
 * A delegation that was verified: the agent, the time it expires, and the delegated key that signs the Session JWTs
 * it vouches for.
 */
export interface VerifiedDelegation {
  /** The agent that signed the delegation: its `client_id`, the `iss` of the delegation and of the Session JWT. */
  readonly iss: string;

  /** When the delegation expires, in Unix seconds. It is not valid at this second or later. */
  readonly exp: number;

  /** The delegated key, imported to verify `ES256` signatures. It is a public key on P-256. */
  readonly sessionKey: CryptoKey;

  /** The thumbprint of the delegated key (RFC 7638), which is the `kid` of a Session JWT that it signed. */
  readonly sessionKeyThumbprint: string;
}

/** The options of a {@link DelegationVerifier}. */
export interface DelegationVerifierOptions {
  /**
   * How far ahead of the current time the `iat` of a delegation may be, in seconds. It is the `iat` window of the
   * Session JWT, and the edge is accepted. A delegation can't be issued after now, but the clock of the agent can run
   * ahead of the clock of this server.
   */
  iatWindowSeconds: number;

  /** How many verified delegations are kept. With 0 none are kept, and every call verifies in full. */
  cacheMaxEntries: number;

  /**
   * How long a verified delegation is kept at most, in milliseconds, counted from its verification. It is the time the
   * keys of the agent are kept (`agentMetadata.cache.ttl`), so a delegation is checked against the key set of the agent
   * at least that often. The key set is kept for that time too, so a key that the agent removes stops working within
   * about twice that time (spec section 10.7).
   * A delegation is dropped at its own `exp` too, if that comes first. With 0 nothing is kept, and every call verifies
   * in full: 0 is a time that is up at once, and is not read as no limit.
   */
  ttlMs: number;
}

/**
 * Checks the three header parameters that the SDK reads: `typ`, `alg` and `kid`. Any other parameter, such as `jwk`,
 * `jku` and `x5u`, is not read. It makes no network call, so a delegation that fails here costs nothing.
 *
 * @throws {InvalidSessionError} With reason `delegation_invalid` when the header is not a JSON object, or a parameter
 * is not what it should be.
 */
function checkHeader(delegationJwt: string): void {
  // `jose` types a header by what it should hold, and the content is JSON of any shape, so each member is read as
  // `unknown` and checked.
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(delegationJwt);
  } catch {
    throw invalid('delegation_malformed');
  }

  const { typ, alg, kid } = header;
  if (typeof typ !== 'string' || normalizeTyp(typ) !== DELEGATION_JWT_TYP) {
    throw invalid('delegation_typ');
  }
  if (typeof alg !== 'string' || !DELEGATION_JWT_ALGORITHMS.includes(alg)) {
    throw invalid('delegation_alg');
  }
  if (typeof kid !== 'string' || kid === '') {
    throw invalid('delegation_kid');
  }
}

/** What an error of `jose` says about the delegation, as a diagnostic code. */
function problemOf(error: unknown): DelegationProblem {
  if (error instanceof errors.JWTExpired) {
    return 'delegation_expired';
  }
  if (error instanceof errors.JWTClaimValidationFailed) {
    return error.claim === 'typ' ? 'delegation_typ' : 'delegation_claims';
  }
  if (error instanceof errors.JWSInvalid || error instanceof errors.JWTInvalid) {
    return 'delegation_malformed';
  }
  // A wrong signature, a key that can't verify (such as an RSA key of less than 2048 bits), two keys with one `kid`,
  // and a critical header that is not known: the delegation can't be verified.
  return 'delegation_signature';
}

/**
 * Verifies the signature of the delegation with the key of `keys` that has its `kid`, and the claims that `jose`
 * checks: `typ`, `alg`, that `iat` and `exp` are there and are numbers, `exp` and `nbf`. `currentDate` is given, so the
 * check of `exp` and the other checks of the caller use the same time.
 *
 * `jose` takes the key from the key set only. It never fetches a key, and it does not read the `jwk`, `jku`, `x5u` and
 * `x5c` headers when it is given a key set.
 *
 * @returns The payload, or `undefined` when no key of `keys` has the `kid`.
 * @throws {InvalidSessionError} With reason `delegation_invalid` when the delegation fails any other check.
 */
async function verifyWithKeys(delegationJwt: string, keys: JWK[], now: Date): Promise<JWTPayload | undefined> {
  try {
    const { payload } = await jwtVerify(delegationJwt, createLocalJWKSet({ keys }), {
      typ: DELEGATION_JWT_TYP,
      algorithms: [...DELEGATION_JWT_ALGORITHMS],
      requiredClaims: ['iat', 'exp'],
      currentDate: now,
    });
    return payload;
  } catch (error) {
    if (error instanceof errors.JWKSNoMatchingKey) {
      return undefined;
    }
    throw invalid(problemOf(error));
  }
}

/**
 * The delegated key of a `cnf` claim, with the members that make it a key and no others: `kty`, `crv`, `x` and `y`.
 * What else the key says about itself, such as `kid`, `use`, `alg` or `key_ops`, is not read.
 *
 * The point is checked here, and the runtime is not left to do it when the key is imported: Deno imports a key whose
 * coordinates are too short, or that is not on the curve.
 */
function readDelegatedKey(cnf: unknown): { kty: 'EC'; crv: 'P-256'; x: string; y: string } {
  const jwk = isRecord(cnf) ? cnf.jwk : undefined;
  if (
    !isRecord(jwk) ||
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' ||
    typeof jwk.y !== 'string'
  ) {
    throw invalid('cnf_invalid');
  }
  // The name is what counts, and not the value: a `d` that is empty or null is still a key that has a `d`.
  if (PRIVATE_KEY_MEMBERS.some((member) => Object.hasOwn(jwk, member))) {
    throw invalid('cnf_private_key');
  }
  if (!isP256Point(jwk.x, jwk.y)) {
    throw invalid('cnf_invalid');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

/**
 * Verifies the delegations of Session JWTs, and keeps the ones that it verified until they expire.
 *
 * `verify` follows the order of the specification (section 5.2, "Delegated keys"):
 * 1. A delegation in the cache counts only if its `iss` is the one expected and its `exp` is still ahead.
 * 2. The header must have the `typ` `poppy-delegation+jwt`, an `alg` of `ES256` or `PS384`, and a `kid`. This is
 *    checked before anything is fetched.
 * 3. The signature is verified with the key of the agent that has the `kid`. The key set comes from the
 *    {@link AgentMetadataFetcher}. A `kid` that is not in it, or a key with that `kid` that does not fit the delegation
 *    (its `alg`, `use` or `key_ops`), makes one refetch of the keys, which the fetcher allows once for each agent in 30
 *    seconds. If there is no usable key after that, or the refetch is not allowed yet, the delegation is refused.
 * 4. The claims: `iss` is the agent that is expected, `exp` is ahead, `exp` is after `iat` and at most 24 hours after,
 *    and `iat` is not more than the `iat` window ahead of now.
 * 5. `cnf.jwk` is a public key on P-256, with no private member. It is imported for `ES256`, and its RFC 7638
 *    thumbprint is computed.
 *
 * Only a delegation that passed all of this is cached, by its whole text. It is kept until its `exp`, or for `ttlMs`
 * from the time it was verified, whichever comes first. The `exp` of the delegation is checked on every read, so a
 * delegation stops being served at its `exp`, whatever the cache has done. `ttlMs` is the time the keys of the agent
 * are kept, so a delegation that was seen is verified again against the key set of the agent at least that often. The
 * agent can take a key out of its key set to stop the delegations of that key (spec section 10.7). The key set is kept
 * for that time too, so they stop working here within about twice that time. With a `ttlMs` of 0 nothing is kept.
 * Calls for one delegation that run together may each verify it in full: there is no sharing of a call that is
 * running, and each one stores the same result.
 *
 * A result is frozen, so a caller that writes to it can't change what the next call gets.
 */
export class DelegationVerifier {
  readonly #fetcher: AgentMetadataFetcher;
  readonly #iatWindowSeconds: number;
  readonly #cache: LruCache<VerifiedDelegation>;

  /**
   * @param fetcher - Where the keys of the agents come from.
   * @param options - The `iat` window, the size of the cache and the time a delegation is kept.
   */
  constructor(fetcher: AgentMetadataFetcher, options: DelegationVerifierOptions) {
    this.#fetcher = fetcher;
    this.#iatWindowSeconds = options.iatWindowSeconds;
    // The cache drops an entry once `ttlMs` has passed, and the `exp` of each delegation is checked when the entry is
    // read. A `ttlMs` of 0 is an entry that is dropped at once, and not an entry that is kept for ever.
    this.#cache = new LruCache<VerifiedDelegation>(options.ttlMs, options.cacheMaxEntries);
  }

  /**
   * Verifies a delegation, or gives the result of an earlier verification of the same delegation.
   *
   * @param delegationJwt - The delegation, in compact form: the `poppy_dlg` header of a Session JWT.
   * @param expectedIss - The agent that the delegation must come from: the `iss` of the Session JWT, which is the URL
   * of the client metadata of the agent. The keys are fetched from there.
   * @returns The agent, the expiry, the delegated key and its thumbprint.
   * @throws {InvalidSessionError} With reason `delegation_invalid` when the delegation fails a check. The code of the
   * check is in `cause.code`. See `DELEGATION_PROBLEMS` for the codes. With reason `agent_not_allowed` or
   * `agent_metadata_invalid` when the fetcher refuses the agent, as it did.
   * @throws {PoppyUnavailableError} When the host of the agent can't be reached, as the fetcher said.
   */
  async verify(delegationJwt: string, expectedIss: string): Promise<VerifiedDelegation> {
    // One reading of the clock, so the cache, `jose` and the claims agree on what time it is.
    const nowMs = Date.now();
    const now = Math.floor(nowMs / 1000);

    const cached = this.#cache.get(delegationJwt);
    if (cached !== undefined && cached.iss === expectedIss && cached.exp > now) {
      return cached;
    }

    checkHeader(delegationJwt);
    const payload = await this.#verifySignature(delegationJwt, expectedIss, new Date(nowMs));
    const delegation = await this.#readClaims(payload, expectedIss, now);

    this.#cache.set(delegationJwt, delegation);
    return delegation;
  }

  /**
   * The payload of the delegation, with the signature verified by a key of the agent. An error of the fetcher is not
   * caught: it reaches the caller as it is.
   */
  async #verifySignature(delegationJwt: string, cimdUrl: string, now: Date): Promise<JWTPayload> {
    const known = await this.#fetcher.getKeys(cimdUrl);
    const payload = await verifyWithKeys(delegationJwt, known.keys, now);
    if (payload !== undefined) {
      return payload;
    }

    // The agent may have added the key since the keys were fetched. The fetcher refetches once in a while at most,
    // because anyone can send a delegation with a `kid` that is made up.
    const refreshed = await this.#fetcher.refreshKeys(cimdUrl);
    if (refreshed === undefined) {
      throw invalid('delegation_key_unknown');
    }
    const afterRefresh = await verifyWithKeys(delegationJwt, refreshed.keys, now);
    if (afterRefresh === undefined) {
      throw invalid('delegation_key_unknown');
    }
    return afterRefresh;
  }

  /** The checks of the claims and of the delegated key, for a payload whose signature was verified. */
  async #readClaims(payload: JWTPayload, expectedIss: string, now: number): Promise<VerifiedDelegation> {
    const { iss, iat, exp, cnf } = payload;
    // `jose` has checked that both are numbers. JSON can write a number that is not finite, such as 1e999.
    if (typeof iat !== 'number' || typeof exp !== 'number' || !Number.isFinite(iat) || !Number.isFinite(exp)) {
      throw invalid('delegation_claims');
    }
    if (iss !== expectedIss) {
      throw invalid('delegation_iss');
    }
    if (exp <= iat || exp - iat > MAX_DELEGATION_LIFETIME_SECONDS) {
      throw invalid('delegation_lifetime');
    }
    if (iat > now + this.#iatWindowSeconds) {
      throw invalid('delegation_iat');
    }

    const delegatedKey = readDelegatedKey(cnf);
    let sessionKey: CryptoKey;
    let sessionKeyThumbprint: string;
    try {
      const imported = await importJWK(delegatedKey, 'ES256');
      // This cannot run: `readDelegatedKey` lets only an EC P-256 key through, and `importJWK` gives a `Uint8Array`
      // only for a symmetric (`oct`) key. The check is here to narrow the type.
      if (imported instanceof Uint8Array) {
        throw new TypeError('The delegated key is not an asymmetric key.');
      }
      sessionKey = imported;
      sessionKeyThumbprint = await calculateJwkThumbprint(delegatedKey);
    } catch {
      // The point was checked in `readDelegatedKey`, so this is a key that the runtime does not accept all the same.
      throw invalid('cnf_invalid');
    }

    // Frozen, because the same object goes to every caller that presents this delegation.
    return Object.freeze({ iss: expectedIss, exp, sessionKey, sessionKeyThumbprint });
  }
}
