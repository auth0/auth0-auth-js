import { InvalidPoppySessionError } from '../errors.js';
import {
  ACT_CLAIMS,
  ANONYMOUS_USER_PROFILE,
  GUEST_SUB_PREFIX,
  MAX_PLAUSIBLE_UNIX_SECONDS,
  SESSION_ID_PATTERN,
} from './constants.js';
import type { PoppyAgent } from './types.js';

// Reads the Poppy Session that Auth0 puts in the `act` claim of the ID token after an agent's browser has joined a
// Session. The rules are those of `sessionFromToken` in `@auth0/auth0-api-js`, so that both SDKs accept the same
// Sessions. The names of the members are Auth0's beta claims (see `ACT_CLAIMS`).

/**
 * @internal
 * An agent's login, as read from the claims of an ID token.
 */
export interface AgentLogin {
  /** The id of the Poppy Session. */
  sessionId: string;
  /** The id of the user, as the Personal Agent knows them at the website. It is opaque. */
  userId: string;
  /** The agent that drives the browser. */
  agent: PoppyAgent;
  /** Whether the login is a guest: the agent's browser joined the Session without signing in as a user. */
  isGuest: boolean;
  /** When the Poppy Session ends, in Unix seconds. Left out when the token has none that can be trusted. */
  sessionExp?: number;
}

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value !== '';

// The end of the Poppy Session as a whole number of seconds, or `undefined` when the value cannot be trusted. It has
// to be a number above 0 and below the range of milliseconds, so a time in milliseconds is ignored, and so are a
// string, `NaN` and an infinite number. A fraction is rounded down, which is the earlier time, as the `exp` of the ID
// token is, so a platform that does not round the time does not lose the bound. A value that is ignored never ends a
// login early.
const toSessionExp = (value: unknown): number | undefined =>
  typeof value === 'number' && value > 0 && value < MAX_PLAUSIBLE_UNIX_SECONDS ? Math.floor(value) : undefined;

// The `act` claim, when it holds a Poppy Session: an object, and not a list, that has its own `poppy_sid`.
function sessionAct(claims: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  const act = claims?.act;

  // A member that the object only inherits is not a member of the claim, and the JSON of a token has none.
  if (typeof act !== 'object' || act === null || Array.isArray(act) || !Object.hasOwn(act, ACT_CLAIMS.sessionId)) {
    return undefined;
  }

  return act as Record<string, unknown>;
}

// The profiles in one string. Any run of white space separates two of them (a space, a tab or a line break), and white
// space at either end is dropped. A guest must not be read as a user because of how the profiles were spaced.
const splitProfiles = (profiles: string): string[] => profiles.trim().split(/\s+/);

// The profiles in `sub_profile`, which is a string of profiles, or a list of such strings. An entry of a list is split
// in the same way, so an entry that holds two profiles is read too. An entry that is not a string is kept as it is, and
// it never matches a profile.
function profilesOf(subProfile: unknown): unknown[] {
  if (typeof subProfile === 'string') {
    return splitProfiles(subProfile);
  }

  if (!Array.isArray(subProfile)) {
    return [];
  }

  return subProfile.flatMap((entry: unknown) => (typeof entry === 'string' ? splitProfiles(entry) : [entry]));
}

/**
 * @internal
 * Whether the claims of an ID token carry Auth0's guest marker: the anonymous user profile in `sub_profile`. Until Auth0
 * puts `sub_profile` on the token of a guest, the start of the `sub` marks a guest too.
 *
 * The profile has to be one whole token, written exactly, capital letters included: a longer one, such as
 * `urn:auth0:anonymous_user_x` or `x-urn:auth0:anonymous_user`, does not count.
 *
 * This says only that a token looks like a guest's. It does not say that the token holds a Poppy Session. A login that
 * looks like a guest and holds no valid Session must be refused, and never be treated as a user.
 *
 * @param claims - The claims of an ID token that has been verified.
 */
export function looksLikeGuest(claims: Record<string, unknown> | undefined): boolean {
  const sub = claims?.sub;

  return (
    profilesOf(claims?.sub_profile).includes(ANONYMOUS_USER_PROFILE) ||
    (typeof sub === 'string' && sub.startsWith(GUEST_SUB_PREFIX))
  );
}

/**
 * @internal
 * Whether the `act` claim of an ID token holds a Poppy Session: `act` is an object, and not a list, with its own
 * `poppy_sid`.
 *
 * Whether the Session is well formed is for {@link readAgentLogin} to check. A token that holds a Session and is
 * malformed must be refused, and never be treated as a login that has no agent.
 *
 * @param claims - The claims of an ID token that has been verified.
 */
export function holdsPoppySession(claims: Record<string, unknown> | undefined): boolean {
  return sessionAct(claims) !== undefined;
}

/**
 * @internal
 * Reads an agent's login from the claims of an ID token that has been verified. Nothing here checks a signature.
 *
 * A token that holds no Poppy Session (see {@link holdsPoppySession}) gives `undefined`. Once the `act` has a
 * `poppy_sid`, the whole Session must be well formed. The members are checked in this order, and are read from the
 * outermost `act`:
 * - `act.sub` is a string with something other than white space in it. It is the URL of the agent.
 * - `act.poppy_sid` is a string of 1 to 256 characters of the base64url alphabet.
 * - `act.poppy_user_id` is a non-empty string.
 * - `act.poppy_agent_id` is left out, or is a non-empty string.
 *
 * `act.poppy_session_exp` is used only when it is a number of seconds that is above 0 and below the range of
 * milliseconds. A fraction is rounded down, to the earlier second, as the `exp` of the ID token is. Any other value is
 * ignored.
 *
 * @param claims - The claims of an ID token that has been verified.
 * @returns The login, or `undefined` when the claims hold no Poppy Session. `agent` has no `poppyAgentId` when the
 * `act` has no `poppy_agent_id`, and the login has no `sessionExp` when the `act` has no usable `poppy_session_exp`.
 * @throws {InvalidPoppySessionError} When the `act` holds a Session that is not well formed. The error names the
 * member that is wrong and never shows its value.
 */
export function readAgentLogin(claims: Record<string, unknown> | undefined): AgentLogin | undefined {
  const act = sessionAct(claims);

  if (act === undefined) {
    return undefined;
  }

  const cimdUrl = act.sub;
  if (typeof cimdUrl !== 'string' || cimdUrl.trim() === '') {
    throw new InvalidPoppySessionError('act.sub');
  }

  const sessionId = act[ACT_CLAIMS.sessionId];
  // The type first: `RegExp.test` turns a list of one string into that string.
  if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)) {
    throw new InvalidPoppySessionError('act.poppy_sid');
  }

  const userId = act[ACT_CLAIMS.userId];
  if (!isNonEmptyString(userId)) {
    throw new InvalidPoppySessionError('act.poppy_user_id');
  }

  const agentId = act[ACT_CLAIMS.agentId];
  if (agentId !== undefined && !isNonEmptyString(agentId)) {
    throw new InvalidPoppySessionError('act.poppy_agent_id');
  }

  const sessionExp = toSessionExp(act[ACT_CLAIMS.sessionExp]);

  // A member is set only when it has a value, so the login has no key that is `undefined`.
  return {
    sessionId,
    userId,
    agent: agentId === undefined ? { cimdUrl } : { cimdUrl, poppyAgentId: agentId },
    isGuest: looksLikeGuest(claims),
    ...(sessionExp !== undefined && { sessionExp }),
  };
}

/**
 * @internal
 * When an agent's login on the website ends, in Unix seconds. It is the earliest of these:
 * - `now + maxAge`: the longest an agent's session lasts.
 * - The `exp` of the ID token, rounded down, when it is a number above 0 and below the range of milliseconds.
 * - `sessionExp`: when the Poppy Session ends.
 * - `sessionExpiry`: the `session_expiry` ceiling of the identity provider.
 *
 * A candidate that is missing is left out, and so is an `exp` that is not a number in that range. The max age is always
 * there, so the result is always a time.
 *
 * See {@link https://personalagentprotocol.org/docs/0.3/spec#web-browsing the specification, section 6}, for when the
 * sign-in of a Session ends.
 *
 * @param input.now - The current time, in Unix seconds.
 * @param input.maxAge - The longest an agent's session lasts, in seconds.
 * @param input.exp - The `exp` claim of the ID token, as the token holds it.
 * @param input.sessionExp - When the Poppy Session ends, from {@link AgentLogin}.
 * @param input.sessionExpiry - The `session_expiry` ceiling, when the login has one.
 */
export function agentSessionDeadline(input: {
  now: number;
  maxAge: number;
  exp: unknown;
  sessionExp?: number;
  sessionExpiry?: number;
}): number {
  const { now, maxAge, exp, sessionExp, sessionExpiry } = input;
  // `NaN` fails these comparisons, and so do the infinite numbers.
  const idTokenExp =
    typeof exp === 'number' && exp > 0 && exp < MAX_PLAUSIBLE_UNIX_SECONDS ? Math.floor(exp) : undefined;
  const candidates = [now + maxAge, idTokenExp, sessionExp, sessionExpiry];

  return Math.min(...candidates.filter((candidate): candidate is number => candidate !== undefined));
}
