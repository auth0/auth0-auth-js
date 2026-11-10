import type { InvalidSessionReason } from '../types.js';

// Protocol strings, limits and defaults for Poppy (Personal Agent Protocol) 0.3.
// Spec: https://personalagentprotocol.org/docs/0.3/spec

/** The request header that carries the Session JWT, in lowercase for matching (spec section 5.2). */
export const POPPY_SESSION_HEADER = 'poppy-session';

/** The `typ` of a Session JWT (spec section 5.2). */
export const SESSION_JWT_TYP = 'poppy-session+jwt';

/** The `typ` of a delegation (spec section 5.2, "Delegated keys"). */
export const DELEGATION_JWT_TYP = 'poppy-delegation+jwt';

/**
 * The algorithms accepted for a Session JWT: `ES256` only (spec section 5.2). It is a tuple, so a type can be made
 * from it and the code that checks against it cannot differ from that type.
 */
export const SESSION_JWT_ALGORITHMS = ['ES256'] as const;

/**
 * The algorithms accepted for a delegation (spec section 5.2, "Delegated keys"): `ES256`, which a Company must
 * accept, and `PS384`, which it should accept.
 */
export const DELEGATION_JWT_ALGORITHMS: readonly string[] = ['ES256', 'PS384'];

/** A delegation's `exp` is at most 24 hours after its `iat` (spec section 5.2, "Delegated keys"). */
export const MAX_DELEGATION_LIFETIME_SECONDS = 86400;

/**
 * The default window for the `iat` of a Session JWT, in seconds and in both directions. The specification suggests
 * one minute (section 5.3).
 */
export const DEFAULT_IAT_WINDOW_SECONDS = 60;

/**
 * The longest Session ID, in characters. Section 8.2 ("IDs") sets this limit for the IDs it names, and a `sid` has the
 * same characters (section 5.2), so the SDK applies the limit to it.
 */
export const MAX_SESSION_ID_LENGTH = 256;

/**
 * A Session ID: 1 to {@link MAX_SESSION_ID_LENGTH} characters of the URL-safe base64 alphabet (spec section 5.2 for
 * `sid`, which uses the characters of section 8.2, "IDs").
 */
export const SESSION_ID_PATTERN = new RegExp(`^[A-Za-z0-9_-]{1,${MAX_SESSION_ID_LENGTH}}$`);

/** The longest agent URL the SDK accepts, in characters. This is an SDK limit. */
export const MAX_URL_LENGTH = 2048;

/** The longest `Poppy-Session` header value the SDK parses, in characters. This is an SDK limit. */
export const MAX_SESSION_JWT_LENGTH = 16384;

/** The default time limit, in milliseconds, for one request for agent metadata or keys. */
export const DEFAULT_AGENT_METADATA_TIMEOUT_MS = 5000;

/**
 * The longest time limit, in milliseconds, that can be set for one request for agent metadata or keys: 2^31 - 1, about
 * 24.8 days, which is the longest delay that a timer takes. `AbortSignal.timeout` throws for a longer one, or runs it
 * as 1 millisecond and so cuts every request short.
 */
export const MAX_AGENT_METADATA_TIMEOUT_MS = 2147483647;

/** The default size limit, in bytes, for one response with agent metadata or keys. */
export const DEFAULT_AGENT_METADATA_MAX_BYTES = 65536;

/** The most keys the SDK accepts in the key set of an agent. This is an SDK limit. */
export const MAX_AGENT_KEYS = 100;

/**
 * The members of a JWK that only a private key has: `d` of an EC, RSA or OKP key, `p`, `q`, `dp`, `dq`, `qi` and `oth`
 * of an RSA key, and `k` of a symmetric key (RFC 7518 section 6, RFC 8037 section 2). `priv` is where an AKP key, a
 * post-quantum key type, keeps its private key. A key set holds public keys only (spec section 4.1), and so does the
 * `cnf.jwk` of a delegation (spec section 5.2, "Delegated keys"), so a key with one of these members, whatever its
 * value, is refused.
 */
export const PRIVATE_KEY_MEMBERS: readonly string[] = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'];

/** The default time, in seconds, to cache agent metadata and keys. The same as `discoveryCache`. */
export const DEFAULT_AGENT_METADATA_CACHE_TTL_SECONDS = 600;

/** The default number of agents whose metadata and keys are cached. The same as `discoveryCache`. */
export const DEFAULT_AGENT_METADATA_CACHE_MAX_ENTRIES = 100;

/** The number of verified delegations to cache. There is one per agent and User, so this is more than the agents. */
export const DEFAULT_DELEGATION_CACHE_MAX_ENTRIES = 1000;

/** The shortest time between two fetches of an agent's keys because of a key ID that is not in its key set. */
export const UNKNOWN_KID_REFETCH_INTERVAL_MS = 30000;

/** How long a failed fetch of agent metadata or keys is remembered, so a host that is down is not hammered. */
export const FAILED_FETCH_CACHE_MS = 30000;

/** The default `Retry-After` of a 503, in seconds. */
export const DEFAULT_RETRY_AFTER_SECONDS = 30;

/** The access token claims that hold the URL of the agent a token was issued to, in the order they are tried. */
export const DEFAULT_AGENT_CLIENT_ID_CLAIMS: readonly string[] = ['client_id', 'azp'];

/**
 * The members of the `act` claim that carry a Session in an access token Auth0 issues to a web app. These are
 * Auth0's beta access token claims, and the names may change.
 */
export const ACT_CLAIMS = {
  sessionId: 'poppy_sid',
  userId: 'poppy_user_id',
  agentId: 'poppy_agent_id',
} as const;

/**
 * The word of the `sub_profile` claim that Auth0 puts on the access token of an anonymous user, such as the guest of a
 * Poppy browser join. `sub_profile` lists the types of the subject as words: `user urn:auth0:anonymous_user`.
 */
export const ANONYMOUS_SUBJECT_PROFILE = 'urn:auth0:anonymous_user';

/** The start of the `sub` that Auth0 gives to the guest of a Poppy browser join. The rest is a hash. */
export const GUEST_SUBJECT_PREFIX = 'anon_poppy@';

/** The default `error_description` of an `invalid_session` error, for each reason. */
export const INVALID_SESSION_MESSAGES: Record<InvalidSessionReason, string> = {
  missing_session: 'This request needs a verified Session, and it has no Poppy-Session header.',
  malformed_session: 'The Poppy-Session header is not a well-formed Session JWT.',
  agent_not_allowed: 'The agent named in the Session JWT is not allowed.',
  agent_metadata_invalid: "The agent's client metadata or keys can't be used.",
  delegation_invalid: "The Session JWT's delegation failed verification.",
  signature_invalid: "The Session JWT's signature failed verification.",
  claim_mismatch: "A Session JWT claim (aud, htm or htu) doesn't match the request.",
  iat_out_of_window: "The Session JWT's iat is outside the accepted window.",
  ath_mismatch: "The Session JWT's ath doesn't match the access token.",
  token_client_mismatch: "The access token wasn't issued to the agent named in the Session JWT.",
  session_mismatch: "The Session JWT's User ID or Agent ID doesn't match the Session.",
};

/**
 * The `error_description` of the `missing_session` error for the request of a registered agent that has an access token
 * and no `Poppy-Session` header. The default text for `missing_session` is about a route that needs a Session, so this
 * one says what is wrong with this request.
 */
export const REGISTERED_AGENT_NEEDS_SESSION_MESSAGE = "A registered agent's request needs the Poppy-Session header.";

/**
 * The `error_description` of the `malformed_session` error for the `act` claim of an access token. The default text for
 * `malformed_session` names the `Poppy-Session` header, which this request does not use for the Session. The member
 * that is wrong is in `error.cause.code`, and never in this text.
 */
export const TOKEN_SESSION_MALFORMED_MESSAGE = "The access token's act claim does not hold a well-formed Session.";

/**
 * The message of the `invalid_request` error for an `Authorization` header that is not one credential: it has two or
 * more values, or a comma in its value. It is fixed, so no part of the header goes back to the agent.
 */
export const AUTHORIZATION_MALFORMED_MESSAGE = 'The request must carry one Authorization header with one credential.';

/** The default `error_description` of a `session_ended` error. */
export const SESSION_ENDED_MESSAGE =
  'The Session has ended. Start a new Session with a new sid and send the request again.';

/** The default message of a `sign_in_required` error. */
export const SIGN_IN_REQUIRED_MESSAGE =
  "This request needs the User's account, and it has no access token. The challenge names the scopes needed.";

/** The default `error_description` of a `temporarily_unavailable` error. */
export const POPPY_UNAVAILABLE_MESSAGE =
  "The agent's client metadata or keys can't be fetched right now. Try again later.";
