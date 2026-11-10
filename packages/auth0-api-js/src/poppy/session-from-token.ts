import { getCurrentActor } from '../act.js';
import { InvalidRequestError } from '../errors.js';
import type { PoppySession, VerifiedAccessTokenClaims } from '../types.js';
import {
  ACT_CLAIMS,
  ANONYMOUS_SUBJECT_PROFILE,
  GUEST_SUBJECT_PREFIX,
  SESSION_ID_PATTERN,
  TOKEN_SESSION_MALFORMED_MESSAGE,
} from './constants.js';
import { InvalidSessionError } from './errors.js';

// Reads the Poppy Session that Auth0 puts in the `act` claim of an access token for a web app, after a User joined the
// Session of an agent in the browser. The names of the members are Auth0's beta claims (see `ACT_CLAIMS`).

/**
 * The member of the `act` claim that is wrong, for the `cause.code` of the `malformed_session` error that
 * {@link sessionFromToken} throws, in the order in which the members are checked:
 * - `act_sub`: `act.sub` is missing or is not a usable string. It is the URL of the agent.
 * - `poppy_sid`: `act.poppy_sid` is not a Session ID, which is 1 to 256 characters of the base64url alphabet.
 * - `poppy_user_id`: `act.poppy_user_id` is not a non-empty string.
 * - `poppy_agent_id`: `act.poppy_agent_id` is there and is not a non-empty string.
 *
 * The message of the error is fixed and names no value of the token, because it goes back to the agent as its
 * `error_description`.
 */
type TokenSessionProblem = 'act_sub' | 'poppy_sid' | 'poppy_user_id' | 'poppy_agent_id';

/** A new error each time, so callers never share an error or a stack. */
function malformed(problem: TokenSessionProblem): InvalidSessionError {
  const error = new InvalidSessionError('malformed_session', TOKEN_SESSION_MALFORMED_MESSAGE);
  error.cause = { code: problem };
  return error;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

// `act.sub` through `getCurrentActor`, which throws `InvalidRequestError` for an `act` without a usable `sub`. For an
// `act` that holds a Session, that is a Session that is not well formed, and not a mistake of the request. Only that
// error is reported so: any other error is a bug, and is let through.
function actorOf(claims: VerifiedAccessTokenClaims): string {
  try {
    const actor = getCurrentActor(claims);
    if (actor !== undefined) {
      return actor;
    }
  } catch (error) {
    if (!(error instanceof InvalidRequestError)) {
      throw error;
    }
    // Reported below, as it is for an `act` with no actor at all.
  }
  throw malformed('act_sub');
}

/**
 * Reads the Poppy Session from the `act` claim of a verified access token. Pass claims that `verifyAccessToken`
 * returned: nothing here checks a signature.
 *
 * A token with no `act`, an `act` that is not an object, or an `act` without a `poppy_sid` holds no Session, and the
 * result is `undefined`. That includes a plain delegation as RFC 8693 defines it, whose `act` has a `sub` and nothing
 * more. Once the `act` has a `poppy_sid`, the whole Session must be well formed, or the call throws:
 * - `act.sub`, as {@link getCurrentActor} reads it, is the URL of the agent, and a usable string.
 * - `act.poppy_sid` is a Session ID: 1 to 256 characters of the base64url alphabet.
 * - `act.poppy_user_id` is a non-empty string.
 * - `act.poppy_agent_id` is left out, or is a non-empty string.
 *
 * The members are read from the outermost `act`, as the current actor is.
 *
 * @param claims - The claims of a verified access token.
 * @returns The Session ID, the User ID and the agent, or `undefined` when the token holds no Session. `agent` has no
 * `poppyAgentId` when the token has no `poppy_agent_id`.
 * @throws {InvalidSessionError} With reason `malformed_session` and a fixed message that names the `act` claim of the
 * access token. The member that is wrong is the code in `cause.code`: see {@link TokenSessionProblem}.
 */
export function sessionFromToken(
  claims: VerifiedAccessTokenClaims
): Pick<PoppySession, 'sessionId' | 'userId' | 'agent'> | undefined {
  const act: unknown = claims.act;
  // A member that the object only inherits is not a member of the claim, and the JSON of a token has none.
  if (typeof act !== 'object' || act === null || !Object.hasOwn(act, ACT_CLAIMS.sessionId)) {
    return undefined;
  }

  const members = act as Record<string, unknown>;
  const cimdUrl = actorOf(claims);
  const sessionId = members[ACT_CLAIMS.sessionId];
  // The type first: `RegExp.test` turns a list of one string into that string.
  if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)) {
    throw malformed('poppy_sid');
  }
  const userId = members[ACT_CLAIMS.userId];
  if (!isNonEmptyString(userId)) {
    throw malformed('poppy_user_id');
  }
  const agentId = members[ACT_CLAIMS.agentId];
  if (agentId !== undefined && !isNonEmptyString(agentId)) {
    throw malformed('poppy_agent_id');
  }

  // A member is set only when it has a value, so the agent has no key that is `undefined`.
  return { sessionId, userId, agent: agentId === undefined ? { cimdUrl } : { cimdUrl, poppyAgentId: agentId } };
}

/**
 * Whether a verified access token is the token of a guest: an anonymous user whom an agent joined to your web app in
 * the browser. Auth0 marks that token in two ways, and either one is enough:
 * - `sub_profile` lists the subject types as words, and one of them is `urn:auth0:anonymous_user`.
 * - `sub` starts with `anon_poppy@`.
 *
 * Only the claims of the token itself are read. `act.sub_profile` is the agent's, not the user's, so it does not count.
 * Call it only for a token that holds a Session: the same marker is on the token of a guest of the Anonymous Sessions
 * feature, which is not a Poppy guest.
 *
 * @param claims - The claims of a verified access token.
 */
export function isGuestToken(claims: VerifiedAccessTokenClaims): boolean {
  const { sub, sub_profile: profile } = claims;
  if (typeof profile === 'string' && profile.split(/\s+/).includes(ANONYMOUS_SUBJECT_PROFILE)) {
    return true;
  }
  return typeof sub === 'string' && sub.startsWith(GUEST_SUBJECT_PREFIX);
}
