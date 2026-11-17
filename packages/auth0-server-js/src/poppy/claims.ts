import { InvalidPoppySessionError } from '../errors.js';
import type { PoppySessionMember } from '../errors.js';
import { ACT_CLAIMS, SESSION_ID_PATTERN } from './constants.js';
import type { PoppyActClaim } from './types.js';

// Reads the Poppy Session that Auth0 puts in the `act` claim of the ID token after an agent's browser has joined a
// Session. The rules are those of `sessionFromToken` in `@auth0/auth0-api-js`, so that both SDKs accept the same
// Sessions. The names of the members are Auth0's beta claims (see `ACT_CLAIMS`).

/**
 * @internal
 * An `act` claim that holds a well-formed Poppy Session. The two members that name the Session are there, and are
 * strings.
 */
export type PoppySessionAct = PoppyActClaim & { poppy_sid: string; poppy_user_id: string };

/**
 * @internal
 * An agent's login, as read from the claims of an ID token. `sub`, `sub_profile` and `act` keep the names of the claims.
 */
export interface AgentLogin {
  /** The `sub` of the ID token: the guest, or the user. */
  sub: string;
  /** The `sub_profile` of the ID token. It is left out when the claim is missing or is not a string. */
  sub_profile?: string;
  /**
   * The `act` claim, whole and as the token has it: a copy, so a change to it never reaches the claims. The agent is
   * `act.sub`.
   */
  act: PoppySessionAct;
}

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value !== '';

// The `act` claim, when it holds a Poppy Session: an object, and not a list, that has its own `poppy_sid`.
function sessionAct(claims: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  const act = claims?.act;

  // A member that the object only inherits is not a member of the claim, and the JSON of a token has none.
  if (typeof act !== 'object' || act === null || Array.isArray(act) || !Object.hasOwn(act, ACT_CLAIMS.sessionId)) {
    return undefined;
  }

  return act as Record<string, unknown>;
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
 * Checks the members of an `act` claim that holds a Poppy Session (see {@link holdsPoppySession}), in this order, and
 * gives the first one that is not well formed:
 * - `act.sub` is a string with something other than white space in it. It identifies the agent: the URL of its client
 *   metadata document, or the ID of its Auth0 agent when it is linked to one.
 * - `act.poppy_sid` is a string of 1 to 256 characters of the base64url alphabet.
 * - `act.poppy_user_id` is a non-empty string.
 * - `act.poppy_agent_id` is left out, or is a non-empty string.
 *
 * @returns The name of the first member that is not well formed, or `undefined` when all are.
 */
export function findSessionActIssue(act: Record<string, unknown>): PoppySessionMember | undefined {
  const agentActor = act.sub;
  if (typeof agentActor !== 'string' || agentActor.trim() === '') {
    return 'act.sub';
  }

  const sessionId = act[ACT_CLAIMS.sessionId];
  // The type first: `RegExp.test` turns a list of one string into that string.
  if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)) {
    return 'act.poppy_sid';
  }

  if (!isNonEmptyString(act[ACT_CLAIMS.userId])) {
    return 'act.poppy_user_id';
  }

  const agentId = act[ACT_CLAIMS.agentId];
  if (agentId !== undefined && !isNonEmptyString(agentId)) {
    return 'act.poppy_agent_id';
  }

  return undefined;
}

/**
 * @internal
 * Reads an agent's login from the claims of an ID token that has been verified. Nothing here checks a signature.
 *
 * A token that holds no Poppy Session (see {@link holdsPoppySession}) gives `undefined`. Once the `act` has a
 * `poppy_sid`, the whole Session must be well formed (see {@link findSessionActIssue}), and the members are read from
 * the outermost `act`.
 *
 * This reads the Session only. It does not decide what kind of login it is, and it does not read `exp`: the claims can
 * be those of a stored session. {@link classifyLogin} decides, for the claims of a login.
 *
 * @param claims - The claims of an ID token that has been verified.
 * @returns The login, or `undefined` when the claims hold no Poppy Session. `act` is a copy of the whole claim, with the
 * members that this package does not know.
 * @throws {InvalidPoppySessionError} When the `act` holds a Session that is not well formed. The error names the
 * member that is wrong and never shows its value.
 */
export function readAgentLogin(claims: Record<string, unknown> | undefined): AgentLogin | undefined {
  const act = sessionAct(claims);

  if (act === undefined) {
    return undefined;
  }

  const issue = findSessionActIssue(act);
  if (issue !== undefined) {
    throw new InvalidPoppySessionError(issue);
  }

  // The claims are those of an ID token that has been verified, and such a token has a `sub`.
  const { sub, sub_profile: subProfile } = claims as Record<string, unknown>;

  // A member is set only when it has a value, so the login has no key that is `undefined`. The `act` is copied whole:
  // it is the claim as Auth0 sent it, and it is not built again member by member.
  return {
    sub: sub as string,
    ...(typeof subProfile === 'string' && { sub_profile: subProfile }),
    act: structuredClone(act) as PoppySessionAct,
  };
}

/**
 * @internal
 * When an agent's login on the website ends, in Unix seconds. It is the earliest of these:
 * - `now + maxAge`: the longest an agent's session lasts.
 * - The `exp` of the ID token, rounded down. A login has one: {@link classifyLogin} refuses an agent's login that has
 *   not a valid `exp`, so there is no fallback for a missing one.
 * - `sessionExpiry`: the `session_expiry` ceiling of the identity provider, when the login has one.
 *
 * See {@link https://personalagentprotocol.org/docs/1.0/spec#web-browsing the specification, section 6}, for when the
 * sign-in of a Session ends.
 *
 * @param input.now - The current time, in Unix seconds.
 * @param input.maxAge - The longest an agent's session lasts, in seconds.
 * @param input.exp - The `exp` claim of the ID token, in Unix seconds, as {@link classifyLogin} has checked it.
 * @param input.sessionExpiry - The `session_expiry` ceiling, when the login has one.
 */
export function agentSessionDeadline(input: {
  now: number;
  maxAge: number;
  exp: number;
  sessionExpiry?: number;
}): number {
  const { now, maxAge, exp, sessionExpiry } = input;
  const candidates = [now + maxAge, Math.floor(exp), sessionExpiry];

  return Math.min(...candidates.filter((candidate): candidate is number => candidate !== undefined));
}
