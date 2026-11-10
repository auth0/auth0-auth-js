import { ALLOWED_DPOP_ALGORITHMS, buildChallenges } from '../dpop-api.js';
import { AuthError, InvalidConfigurationError } from '../errors.js';
import type { InvalidSessionReason } from '../types.js';
import {
  DEFAULT_RETRY_AFTER_SECONDS,
  INVALID_SESSION_MESSAGES,
  POPPY_UNAVAILABLE_MESSAGE,
  SESSION_ENDED_MESSAGE,
  SIGN_IN_REQUIRED_MESSAGE,
} from './constants.js';

// The Poppy errors live here, and not in `src/errors.ts`, because `dpop-api.ts` imports that file and
// `SignInRequiredError` needs `buildChallenges` from `dpop-api.ts`.

// One scope token, as RFC 6749 section 3.3 defines it: printable ASCII without space, double quote and backslash.
// It keeps a scope inside the quoted string of a `WWW-Authenticate` challenge, so it cannot inject a header.
const SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

const INVALID_SCOPE_MESSAGE =
  'Invalid poppy configuration: the scope of a sign-in challenge must have at least one scope. Scopes are separated ' +
  'by spaces, and a scope has printable ASCII characters only, without a double quote or a backslash.';

// Splits on spaces and drops the empty pieces, so extra spaces and empty entries are harmless. What is left must be
// at least one scope, and every scope must be a valid token.
function toScopeString(scope: string | string[]): string {
  const tokens = (typeof scope === 'string' ? [scope] : scope)
    .flatMap((entry) => entry.split(' '))
    .filter((token) => token !== '');
  if (tokens.length === 0 || !tokens.every((token) => SCOPE_TOKEN_PATTERN.test(token))) {
    throw new InvalidConfigurationError(INVALID_SCOPE_MESSAGE);
  }
  return tokens.join(' ');
}

/**
 * Error thrown when a request carries no valid Poppy Session, or its Session does not match what the API knows about
 * it. Answer with status 400 and the JSON body `{ "error": "invalid_session" }`, which is what
 * {@link toHttpErrorResponse} builds. A new Session does not fix it: the agent stops sending the request until it
 * fixes the cause.
 *
 * `code` is `invalid_session`, and `statusCode` is `400`. `reason` says which check failed.
 *
 * @beta
 * @category Poppy
 */
export class InvalidSessionError extends AuthError {
  /**
   * Which check failed. A stable value for logs and tests.
   */
  readonly reason: InvalidSessionReason;

  /**
   * @param reason - Which check failed.
   * @param message - The `error_description` for the developer. Defaults to a text for the `reason`. Do not put the
   * content of a token or of a JWT in it.
   */
  constructor(reason: InvalidSessionReason, message?: string) {
    super(message ?? INVALID_SESSION_MESSAGES[reason], 'invalid_session', 400);
    this.name = 'InvalidSessionError';
    this.reason = reason;
  }
}

/**
 * Error thrown when the Poppy Session of a request has ended, either because the store marks it as ended or because
 * the app refuses it. Answer with status 400 and the JSON body `{ "error": "session_ended" }`, which is what
 * {@link toHttpErrorResponse} builds. The agent then starts a new Session with a new `sid` and sends the request
 * again, once.
 *
 * `code` is `session_ended`, and `statusCode` is `400`.
 *
 * @beta
 * @category Poppy
 */
export class SessionEndedError extends AuthError {
  /**
   * @param message - The `error_description` for the developer. Defaults to a short standard text.
   */
  constructor(message?: string) {
    super(message ?? SESSION_ENDED_MESSAGE, 'session_ended', 400);
    this.name = 'SessionEndedError';
  }
}

/**
 * Error thrown when a request needs the User's account and has no access token. Answer with status 401 and the
 * `WWW-Authenticate` challenges of `headers`, which name the scopes needed in their `scope` attribute and carry no
 * `error`. The agent gets an access token with those scopes, and sends the request again.
 *
 * `code` is `sign_in_required`, and `statusCode` is `401`.
 *
 * @beta
 * @category Poppy
 */
export class SignInRequiredError extends AuthError {
  /**
   * The scopes the request needs, joined by single spaces. It is the `scope` attribute of the challenges.
   */
  readonly scope: string;

  /**
   * @param options.scope - The scopes the request needs: a string of scopes separated by spaces, or a list of such
   * strings. Each string is split on spaces, and empty pieces are ignored, so extra spaces and empty entries do no
   * harm. Each scope that is left must be a token as RFC 6749 section 3.3 defines it, which keeps the challenge
   * intact. The `scope` of the error is these scopes joined by single spaces.
   * @param options.dpopMode - The DPoP mode of the API, which decides the challenges to send: `Bearer`, `DPoP` or both.
   * The error cannot read it, so pass the `dpop.mode` that your `ApiClient` is set up with. Without it the challenges
   * are those of `'allowed'`, whatever your client uses. Defaults to `'allowed'`.
   * @param options.message - The message for the developer. Defaults to a short standard text.
   * @throws {InvalidConfigurationError} When no scope is left once the empty pieces are ignored, or when a scope is not
   * a valid token.
   */
  constructor(options: { scope: string | string[]; dpopMode?: 'allowed' | 'required' | 'disabled'; message?: string }) {
    const scope = toScopeString(options.scope);
    super(
      options.message ?? SIGN_IN_REQUIRED_MESSAGE,
      'sign_in_required',
      401,
      buildChallenges(options.dpopMode ?? 'allowed', ALLOWED_DPOP_ALGORITHMS, { scope })
    );
    this.name = 'SignInRequiredError';
    this.scope = scope;
  }
}

/**
 * Error thrown when the API can't verify a Session right now because the metadata host of the agent can't be reached.
 * The specification does not define this case. Answer with status 503 and the `Retry-After` of `headers`, and not
 * with `invalid_session`, which tells the agent to stop sending the request. The agent retries later. The request is
 * never accepted.
 *
 * `code` is `temporarily_unavailable`, and `statusCode` is `503`.
 *
 * @beta
 * @category Poppy
 */
export class PoppyUnavailableError extends AuthError {
  /**
   * The seconds after which the agent can retry. It is the `Retry-After` header.
   */
  readonly retryAfter: number;

  /**
   * @param message - The `error_description` for the developer. Defaults to a short standard text.
   * @param retryAfter - The seconds after which the agent can retry, as a whole number. Defaults to 30.
   */
  constructor(message?: string, retryAfter = DEFAULT_RETRY_AFTER_SECONDS) {
    super(message ?? POPPY_UNAVAILABLE_MESSAGE, 'temporarily_unavailable', 503, { 'retry-after': String(retryAfter) });
    this.name = 'PoppyUnavailableError';
    this.retryAfter = retryAfter;
  }
}
