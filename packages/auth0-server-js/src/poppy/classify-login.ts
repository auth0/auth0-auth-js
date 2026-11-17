import { InvalidPoppySessionError } from '../errors.js';
import type { PoppySessionMember } from '../errors.js';
import { findSessionActIssue, holdsPoppySession, readAgentLogin } from './claims.js';
import type { AgentLogin } from './claims.js';
import { ANONYMOUS_USER_PROFILE, GUEST_SUB_PREFIX, MAX_PLAUSIBLE_UNIX_SECONDS } from './constants.js';

/**
 * @internal
 * What kind of login the claims of an ID token are. See {@link classifyLogin}.
 *
 * - `human`: the login of a person. It holds no Poppy Session and no guest marker.
 * - `agent`: a signed-in agent. The `login` is the user and the Session. `exp` is the `exp` of the token, in Unix
 *   seconds, which is the end of the join's tokens and so the cap of the session.
 * - `guest`: an agent's browser that has joined without signing in. It has the same members as an `agent`.
 * - `invalid_guest`: the claims have a guest marker but are not a valid guest. `reason` says which check failed. It names
 *   claims and shows no value, except `sub_profile`, which is a short label.
 */
export type LoginClassification =
  | { kind: 'human' }
  | { kind: 'agent' | 'guest'; login: AgentLogin; exp: number }
  | { kind: 'invalid_guest'; reason: string };

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value !== '';

// A finite number above 0 and below the range of milliseconds, which is the bound that the `session_expiry` check in
// `state/utils.ts` uses. It is a Unix time in seconds, and not a count of milliseconds. A fraction is fine here, unlike
// for `session_expiry`: `exp` of an ID token is a number of seconds, and the deadline uses its whole seconds.
const isUnixSeconds = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value) && value > 0 && value < MAX_PLAUSIBLE_UNIX_SECONDS;

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

// The part of the claims that makes an agent state, or the name of the first claim that is wrong. The `act` is checked
// first, then the `sub` of the token, then its `exp`. `act` stands for an `act` that is no object at all.
type AgentStateIssue = 'act' | PoppySessionMember;

function findAgentStateIssue(claims: Record<string, unknown>): AgentStateIssue | undefined {
  if (!holdsPoppySession(claims)) {
    // The claim is missing, is not an object, or has no `poppy_sid` of its own.
    const act = claims.act;

    return typeof act === 'object' && act !== null && !Array.isArray(act) ? 'act.poppy_sid' : 'act';
  }

  const actIssue = findSessionActIssue(claims.act as Record<string, unknown>);

  if (actIssue !== undefined) {
    return actIssue;
  }

  if (!isNonEmptyString(claims.sub)) {
    return 'sub';
  }

  return isUnixSeconds(claims.exp) ? undefined : 'exp';
}

// What the sub_profile is, in a reason: a short label for a string, quoted, so that a line break shows as `\n`, and cut at
// 64 characters. It is the one value that a reason shows.
function describeSubProfile(subProfile: unknown): string {
  if (subProfile === undefined) {
    return 'is missing';
  }

  if (typeof subProfile !== 'string') {
    return `does not hold ${ANONYMOUS_USER_PROFILE}`;
  }

  const label = subProfile.length > 64 ? `${subProfile.slice(0, 64)}...` : subProfile;

  return `is ${JSON.stringify(label)} and does not hold ${ANONYMOUS_USER_PROFILE}`;
}

const failed = (reason: string): LoginClassification => ({ kind: 'invalid_guest', reason });

// The claims have at least one guest marker. They are a guest only when they have both, and a valid agent state.
function classifyGuest(
  claims: Record<string, unknown>,
  markers: { sub: boolean; profile: boolean }
): LoginClassification {
  if (!markers.sub) {
    return failed(`sub_profile marks an anonymous user, but sub does not start with ${GUEST_SUB_PREFIX}`);
  }

  if (!markers.profile) {
    return failed(`sub starts with ${GUEST_SUB_PREFIX}, but sub_profile ${describeSubProfile(claims.sub_profile)}`);
  }

  const issue = findAgentStateIssue(claims);

  if (issue === 'act') {
    return failed('act is missing or is not an object');
  }

  if (issue !== undefined) {
    return failed(`${issue} is missing or invalid`);
  }

  // `findAgentStateIssue` has checked the Session, so this does not throw.
  return { kind: 'guest', login: readAgentLogin(claims) as AgentLogin, exp: claims.exp as number };
}

/**
 * @internal
 * Decides what kind of login the claims of a verified ID token are. Every login method asks this once, before it writes
 * anything.
 *
 * - A guest has all of: a `sub` that starts with `anon_poppy@`, a `sub_profile` that holds `urn:auth0:anonymous_user`,
 *   and a valid agent state. A login that has one guest marker but is not a full guest is `invalid_guest`, so an
 *   anonymous subject never becomes a user.
 * - A valid agent state is a Poppy Session in `act` that is well formed (see {@link findSessionActIssue}), a top-level
 *   `sub` that is not empty, and an `exp` that is a Unix time in seconds. `exp` is required: there is no deadline to fall
 *   back to.
 * - A signed-in agent has a valid agent state and no guest marker.
 * - Anything else is a person.
 *
 * The `sub_profile` is matched as whole profiles, written exactly: a profile is one token, so `urn:auth0:anonymous_user_x`
 * and `x-urn:auth0:anonymous_user` do not count.
 *
 * @param claims - The claims of an ID token that has been verified. No claims is a person.
 * @throws {InvalidPoppySessionError} When the `act` holds a Poppy Session (it has a `poppy_sid`) that is not well formed,
 * or the token has no `sub` or no valid `exp`, and the claims have no guest marker. A login with a guest marker is
 * `invalid_guest` instead.
 */
export function classifyLogin(claims: Record<string, unknown> | undefined): LoginClassification {
  if (claims === undefined) {
    return { kind: 'human' };
  }

  const markers = {
    sub: typeof claims.sub === 'string' && claims.sub.startsWith(GUEST_SUB_PREFIX),
    profile: profilesOf(claims.sub_profile).includes(ANONYMOUS_USER_PROFILE),
  };

  if (markers.sub || markers.profile) {
    return classifyGuest(claims, markers);
  }

  if (!holdsPoppySession(claims)) {
    return { kind: 'human' };
  }

  // An act that holds a Session must be well formed. It is not read as a person's login: that would write a user session
  // without the cap of an agent.
  // The claims hold a Session, so the issue cannot be `act`.
  const issue = findAgentStateIssue(claims) as PoppySessionMember | undefined;

  if (issue !== undefined) {
    throw new InvalidPoppySessionError(issue);
  }

  return { kind: 'agent', login: readAgentLogin(claims) as AgentLogin, exp: claims.exp as number };
}
