import type { TokenResponse } from '@auth0/auth0-auth-js';
import { InvalidPoppySessionError, SessionExpiredError } from '../errors.js';
import { extractSessionExpiry, isSessionExpiryInPast, updateStateData } from '../state/utils.js';
import type { StateStore } from '../types.js';
import { agentSessionDeadline, holdsPoppySession, looksLikeGuest, readAgentLogin } from './claims.js';
import { computePoppySessionKey } from './session-key.js';
import type { PoppyAgentContext, PoppyGuestStore, PoppySessionState } from './types.js';

/**
 * @internal
 * What `completeAgentLogin` needs from the callback of a login.
 */
export interface CompleteAgentLoginInput<TStoreOptions> {
  /** The tokens of the code exchange. */
  response: TokenResponse;
  /** The audience of the access token. */
  audience: string;
  /** The Auth0 domain that the login went through. */
  domain: string;
  stateStore: StateStore<TStoreOptions>;
  stateStoreIdentifier: string;
  guestStore: PoppyGuestStore<TStoreOptions>;
  guestStoreIdentifier: string;
  /** The longest an agent's session lasts, in seconds. */
  agentSessionMaxAge: number;
  /** The options of the stores. They are passed to every store call. */
  storeOptions?: TStoreOptions;
}

/**
 * @internal
 * Turns the login of an agent's browser into the right session on the website. `completeInteractiveLogin` calls it with
 * the tokens of the code exchange, before it writes any session.
 *
 * - A login with no Poppy Session gives `undefined`, and the normal login goes on.
 * - A guest goes to the guest store. It is never written to the state store, and the anonymous session is not touched,
 *   so a guest is never a user. An agent session of the browser (a user session that holds a Poppy Session) is deleted
 *   first, because a rejoin without an access token ends the sign-in of a Session (see
 *   {@link https://personalagentprotocol.org/docs/0.3/spec#web-browsing the specification, section 6}). The login of a
 *   person is left as it is.
 * - A signed-in agent gets a fresh user session, built from the tokens of this login only. Nothing of an earlier
 *   session is kept, not even if it is the same user's. The guest of the browser is dropped.
 *
 * Both end at the deadline (see {@link agentSessionDeadline}). The session has no refresh token and nothing can extend
 * it.
 *
 * @returns The Poppy context of the agent, or `undefined` when the login is not an agent's. The caller clears the
 * anonymous session after a signed-in login.
 * @throws {InvalidPoppySessionError} When the `act` claim holds a Session that is not well formed. It also throws when
 * the token carries Auth0's guest marker but holds no Session, because that login must never become a user.
 * @throws {SessionExpiredError} When the deadline has already passed, or is 30 seconds away or less.
 */
export async function completeAgentLogin<TStoreOptions>(
  input: CompleteAgentLoginInput<TStoreOptions>
): Promise<PoppyAgentContext | undefined> {
  const {
    response,
    audience,
    domain,
    stateStore,
    stateStoreIdentifier,
    guestStore,
    guestStoreIdentifier,
    agentSessionMaxAge,
    storeOptions,
  } = input;
  const claims = response.claims;

  // A response with no ID token has no claims to read, so it is not an agent's login.
  if (claims === undefined) {
    return undefined;
  }

  // A Session that is not well formed throws here. It is never read as a normal login.
  const login = readAgentLogin(claims);

  if (login === undefined) {
    // Auth0's guest marker with no valid Session must not fall through to a user session.
    if (looksLikeGuest(claims)) {
      throw new InvalidPoppySessionError('act.poppy_sid');
    }

    return undefined;
  }

  const now = Math.floor(Date.now() / 1000);
  const deadline = agentSessionDeadline({
    now,
    maxAge: agentSessionMaxAge,
    exp: claims.exp,
    sessionExp: login.sessionExp,
    sessionExpiry: extractSessionExpiry(claims),
  });

  // The deadline is checked as a number, not as a truthy value: one that rounds down to 0 is a time in the past. With
  // no `iat` the check compares with the current time. It counts a deadline that is 30 seconds away or less as passed,
  // as it does for the ceiling of any session.
  if (isSessionExpiryInPast(deadline)) {
    throw new SessionExpiredError(
      'The agent session has already ended; refusing to create an already-expired session.'
    );
  }

  const key = await computePoppySessionKey(login.agent.cimdUrl, login.sessionId);
  const contextFor = (state: PoppySessionState): PoppyAgentContext => ({
    kind: 'agent',
    state,
    sessionId: login.sessionId,
    userId: login.userId,
    // A copy, so the object that the app gets is not the one that the guest store is given. A store of the app's own
    // may keep that object, and a change by the app must not reach it.
    agent: { ...login.agent },
    key,
  });

  if (login.isGuest) {
    // The sign-in of a Session ends when the agent joins again without an access token, so a guest join ends an agent
    // session of this browser: a user session that holds a Poppy Session, of this Session or of another one. The login
    // of a person holds no Poppy Session and is left as it is. The agent session goes first, as the guest does in a
    // signed-in join. If the write of the guest fails, the visitor ends with neither, and not with both. A store that
    // fails is never read as empty, so no step here is best-effort.
    const existing = await stateStore.get(stateStoreIdentifier, storeOptions);

    if (holdsPoppySession(existing?.user)) {
      await stateStore.delete(stateStoreIdentifier, storeOptions);
    }

    await guestStore.set(
      guestStoreIdentifier,
      {
        sub: claims.sub,
        poppy: { sessionId: login.sessionId, userId: login.userId, agent: login.agent },
        tokenSets: [
          {
            audience,
            accessToken: response.accessToken,
            scope: response.scope,
            expiresAt: response.expiresAt,
          },
        ],
        createdAt: now,
        expiresAt: deadline,
      },
      false,
      storeOptions
    );

    return contextFor('signed_out');
  }

  // The guest of this browser goes first. If the write of the session fails, the visitor ends with neither, and not
  // with both.
  await guestStore.delete(guestStoreIdentifier, storeOptions);

  // `undefined` as the existing state makes the session fresh: nothing of an earlier session of the same user is kept
  // (their claims, token sets or refresh token). The refresh token of this login is left out too, because nothing may
  // extend the session past its deadline. `true` gives a stateful store a new session id, which stops session fixation.
  await stateStore.set(
    stateStoreIdentifier,
    {
      ...updateStateData(audience, undefined, response, { domain }),
      refreshToken: undefined,
      sessionExpiresAt: deadline,
    },
    true,
    storeOptions
  );

  return contextFor('signed_in');
}
