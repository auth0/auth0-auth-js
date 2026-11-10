import { base64url, jwtVerify } from 'jose';
import { normalizeUrl } from '../dpop-api.js';
import { InvalidConfigurationError, InvalidRequestError } from '../errors.js';
import { SESSION_JWT_ALGORITHMS, SESSION_JWT_TYP } from './constants.js';
import type { VerifiedDelegation } from './delegation.js';
import { InvalidSessionError } from './errors.js';
import type { UnverifiedSessionJwt } from './session-jwt.js';
import { parseUrl } from './url-rules.js';

// The checks that bind a Session JWT to the key that signed it, and to the request it came with: the signature, the
// claims, the hash of the access token and the key of the Session. The delegation that vouches for the signing key is
// verified before (see `delegation.ts`), and the Session record is checked after.
// Spec: https://personalagentprotocol.org/docs/0.3/spec, section 5.2 ("Delegated keys", step 3) and section 5.3,
// step 2.

/**
 * The diagnostic codes of the errors that this module throws for a Session JWT. The code is in `error.cause.code`, for
 * logs and tests.
 *
 * The message of an error is a fixed text that says which check failed. A value of the JWT or of the request never goes
 * into a message, because a message goes back to the agent as its `error_description`, and into logs.
 *
 * With the reason `signature_invalid`, from {@link verifySessionSignature}:
 * - `session_kid`: the `kid` of the JWT is not the thumbprint of the delegated key.
 * - `session_signature`: `jose` refused the JWT with the delegated key. The signature is wrong, `typ` is not
 *   `poppy-session+jwt`, `alg` is not `ES256`, or `exp` or `nbf` (which the specification does not ask for, and which
 *   `jose` honours when the JWT has them) says the JWT is not valid now.
 *
 * With the reason `claim_mismatch`, from {@link checkSessionClaims}:
 * - `aud`: `aud` is not one of the audiences, compared character by character.
 * - `htm`: `htm` is not the method of the request, in any letter case.
 * - `htu`: `htu` is not an `https` URL, or is not the URL of the request.
 *
 * With the reason `iat_out_of_window`, from {@link checkSessionClaims}:
 * - `iat`: `iat` is further from the current time than the window, in either direction.
 */
const SESSION_PROBLEMS = {
  session_kid: 'The Session JWT kid is not the thumbprint of the delegated key.',
  session_signature: 'The Session JWT could not be verified with the delegated key.',
  aud: 'The Session JWT aud is not the identifier of your Company.',
  htm: 'The Session JWT htm is not the method of the request.',
  htu: 'The Session JWT htu is not the URL of the request, or is not an https URL.',
  iat: 'The Session JWT iat is outside the accepted window.',
} as const;

type SessionProblem = keyof typeof SESSION_PROBLEMS;

const REASONS = {
  session_kid: 'signature_invalid',
  session_signature: 'signature_invalid',
  aud: 'claim_mismatch',
  htm: 'claim_mismatch',
  htu: 'claim_mismatch',
  iat: 'iat_out_of_window',
} as const satisfies Record<SessionProblem, 'signature_invalid' | 'claim_mismatch' | 'iat_out_of_window'>;

/** A new error each time, so callers never share an error or a stack. */
function refused(problem: SessionProblem): InvalidSessionError {
  const error = new InvalidSessionError(REASONS[problem], SESSION_PROBLEMS[problem]);
  error.cause = { code: problem };
  return error;
}

const NO_PUBLIC_ORIGIN_MESSAGE =
  'Invalid poppy configuration: the URL of the request must be a full URL, such as https://api.example.com/orders, ' +
  'when the public origin of the API is not known. Pass the full URL, or set poppy.publicOrigin.';

const UNUSABLE_URL_MESSAGE = 'The request URL must be an absolute URL or a path that starts with "/".';

/**
 * Verifies the signature of a Session JWT with the delegated key of its delegation (spec section 5.2, "Delegated
 * keys", step 3). Verify the delegation first, with a `DelegationVerifier`: this function trusts `delegation` and
 * nothing in `session`.
 *
 * Two checks, in this order:
 * 1. The `kid` of the JWT must be the thumbprint of the delegated key. It costs nothing, and it refuses a JWT that
 *    carries the delegation of another key, such as the one of another User, before any signature is verified.
 * 2. `jose` verifies the signature of the JWT, its `typ` and its `alg`. Only `ES256` is accepted, and `jose` takes the
 *    key from `delegation` and from nowhere else, so no header of the JWT can name another key. `jose` checks `exp` and
 *    `nbf` too when the JWT has them.
 *
 * @param session - The Session JWT, parsed.
 * @param delegation - The verified delegation that the JWT carries.
 * @throws {InvalidSessionError} With reason `signature_invalid` when a check fails. The code is `session_kid` or
 * `session_signature`, in `cause.code`.
 */
export async function verifySessionSignature(
  session: UnverifiedSessionJwt,
  delegation: VerifiedDelegation
): Promise<void> {
  if (session.header.kid !== delegation.sessionKeyThumbprint) {
    throw refused('session_kid');
  }
  try {
    await jwtVerify(session.jwt, delegation.sessionKey, {
      typ: SESSION_JWT_TYP,
      algorithms: [...SESSION_JWT_ALGORITHMS],
    });
  } catch {
    throw refused('session_signature');
  }
}

/**
 * The URL that the `htu` of a Session JWT must be, for the URL of a request.
 *
 * With a public origin, the origin of the URL of the request is not used, because behind a proxy or a load balancer the
 * server sees the address of the proxy and not the one that the agent signed. The result is the public origin and the
 * path of the URL. The query and the fragment are dropped, as `htu` has neither (RFC 9449, section 4.2).
 * - `http://10.0.0.5:8080/orders?x=1` with the origin `https://api.example.com` gives `https://api.example.com/orders`.
 * - A `url` that starts with `/` is a path. It is joined to the origin as text and parsed with it, so a path such as
 *   `//host/x` stays a path, and is not read as a URL with the host `host`.
 *
 * Without a public origin, the URL is the one the server saw, and it must be absolute.
 *
 * Compare the result with `htu` by {@link checkSessionClaims}, which normalizes both the way the DPoP check of this
 * package compares URLs: dot segments are resolved, and an escaped character that needs no escape is decoded, so
 * `/a/./b` is `/a/b` and `%41` is `A`. Nothing else in the path changes, so `/a%2Fb` is not `/a/b`.
 *
 * @param url - The URL of the request: an absolute URL, or a path with an optional query.
 * @param publicOrigin - The public origin of the API, such as `https://api.example.com`, from `ResolvedPoppyOptions`.
 * It is an origin: no path, and no slash at the end.
 * @returns The URL to compare with `htu`.
 * @throws {InvalidConfigurationError} When there is no public origin and `url` is not absolute. That is a mistake of
 * the setup, and not of the agent. The message tells how to fix it, and has no part of `url` in it.
 * @throws {InvalidRequestError} When there is a public origin, and `url` is neither a path nor an absolute URL with a
 * path. A URL such as `mailto:x@example.com` has no path to take.
 */
export function expectedRequestUrl(url: string, publicOrigin: string | undefined): string {
  if (publicOrigin === undefined) {
    if (parseUrl(url) === undefined) {
      throw new InvalidConfigurationError(NO_PUBLIC_ORIGIN_MESSAGE);
    }
    return url;
  }

  const parsed = parseUrl(url.startsWith('/') ? `${publicOrigin}${url}` : url);
  // A URL such as `mailto:x` or `a:b` has a path that does not start with a slash. It is not the URL of a request, and
  // joining the origin to it would make another host.
  if (parsed === undefined || !parsed.pathname.startsWith('/')) {
    throw new InvalidRequestError(UNUSABLE_URL_MESSAGE);
  }
  return `${publicOrigin}${parsed.pathname}`;
}

/** Whether `htu` is an `https` URL for the same origin and path as the request, compared as DPoP does. */
function htuMatches(htu: string, requestUrl: string): boolean {
  try {
    if (new URL(htu).protocol !== 'https:') {
      return false;
    }
    return normalizeUrl(htu, 'proof') === normalizeUrl(requestUrl, 'request');
  } catch {
    // A URL that can't be normalized can't be the URL of the request.
    return false;
  }
}

/**
 * Checks the claims of a Session JWT against the request (spec section 5.3, step 2). Call it after the signature is
 * verified: until then the claims are not to be trusted.
 *
 * The checks, in this order:
 * 1. `aud` is one of `audiences`, character by character.
 * 2. `htm` is the method of the request, in any letter case, as for a DPoP proof (RFC 9449, section 4.3).
 * 3. `htu` is an `https` URL, and for the same origin and path as `url`. Both are normalized as for a DPoP proof: the
 *    query and the fragment are dropped, the host is in lower case, a default port is dropped, and an escape of a
 *    character that needs none is decoded. A `url` that can't be normalized never matches.
 * 4. `iat` is within `iatWindowSeconds` of the current time, in both directions. The edges are accepted.
 *
 * @param session - The Session JWT, parsed.
 * @param expected - What the request says:
 * - `audiences`: the identifiers of your Company that `aud` may be. An empty list refuses every JWT.
 * - `method`: the HTTP method of the request.
 * - `url`: the URL of the request, as {@link expectedRequestUrl} gives it.
 * - `iatWindowSeconds`: how far `iat` may be from `now`, in seconds.
 * - `now`: the current time in Unix seconds, to compare `iat` with. The default is the clock.
 * @throws {InvalidSessionError} With reason `claim_mismatch` for `aud`, `htm` and `htu`, and with reason
 * `iat_out_of_window` for `iat`. The claim is the code, in `cause.code`.
 */
export function checkSessionClaims(
  session: UnverifiedSessionJwt,
  expected: { audiences: readonly string[]; method: string; url: string; iatWindowSeconds: number; now?: number }
): void {
  const { aud, htm, htu, iat } = session.claims;

  if (!expected.audiences.includes(aud)) {
    throw refused('aud');
  }
  if (htm.toUpperCase() !== expected.method.toUpperCase()) {
    throw refused('htm');
  }
  if (!htuMatches(htu, expected.url)) {
    throw refused('htu');
  }
  const now = expected.now ?? Math.floor(Date.now() / 1000);
  // Written so that a window or a time that is not a number refuses the JWT, and does not accept it.
  if (!(Math.abs(now - iat) <= expected.iatWindowSeconds)) {
    throw refused('iat');
  }
}

async function sha256Base64Url(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return base64url.encode(new Uint8Array(digest));
}

/**
 * The `ath` of an access token: the SHA-256 hash of the token, base64url-encoded without padding (RFC 9449, section
 * 4.2), made with Web Crypto. The token is encoded as UTF-8, which for an ASCII token is the same bytes as ASCII, and
 * is what the DPoP check of this SDK hashes.
 *
 * @param accessToken - The access token, as it came in the `Authorization` header, without the scheme.
 * @returns The hash, 43 characters of the base64url alphabet.
 */
export function computeAth(accessToken: string): Promise<string> {
  return sha256Base64Url(accessToken);
}

/**
 * The key of a Session: an opaque, stable name for the pair of an agent and a Session ID, for the application to key
 * its state by. Two agents can pick the same `sid`, so the `sid` alone is not a key.
 *
 * ```
 * key = base64url(SHA-256(UTF-8(cimdUrl + "\n" + sessionId)))    (no padding, 43 characters)
 * ```
 *
 * `cimdUrl` is the `iss` of the Session JWT, which is the URL of the client metadata of the agent, and `sessionId` is
 * its `sid`. Neither can hold a newline: the URL is in canonical form, and a Session ID has the base64url characters
 * only. So two different pairs never make one text.
 *
 * **The formula is a contract between SDKs.** `auth0-server-js` must build the key of a Session with the same formula,
 * so that an application that uses both SDKs sees one Session as one. Do not change it in one SDK alone.
 *
 * @param cimdUrl - The URL of the client metadata of the agent: the `client_id`, the `iss` of the Session JWT.
 * @param sessionId - The Session ID: the `sid` of the Session JWT.
 * @returns The key.
 */
export function computeSessionKey(cimdUrl: string, sessionId: string): Promise<string> {
  return sha256Base64Url(`${cimdUrl}\n${sessionId}`);
}
