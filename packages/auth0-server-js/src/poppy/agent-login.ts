import type { TokenResponse } from '@auth0/auth0-auth-js';
import { InvalidPoppySessionError, PoppyError, PoppyErrorCode, SessionExpiredError } from '../errors.js';
import { extractSessionExpiry, isSessionExpiryInPast, updateStateData } from '../state/utils.js';
import type { StateStore } from '../types.js';
import { buildAgentContext, splitScopes } from './agent-context.js';
import { classifyLogin } from './classify-login.js';
import type { LoginClassification } from './classify-login.js';
import { agentSessionDeadline } from './claims.js';
import type { AgentLogin } from './claims.js';
import { guestTokenIsUsable, readGuest } from './read-guest.js';
import type { StoredGuest } from './read-guest.js';
import type { PoppyAgentContext, PoppyGuestStore } from './types.js';

/**
 * @internal
 * What `completeAgentLogin` needs from a login.
 */
export interface CompleteAgentLoginInput<TStoreOptions> {
  /** The tokens of the login. */
  response: TokenResponse;
  /** The audience of the access token. */
  audience: string;
  /** The Auth0 domain that the login went through. */
  domain: string;
  /**
   * Whether the login is the redirect callback (`completeInteractiveLogin`). A guest joins only there: on any other
   * method, a guest login is refused.
   */
  callback: boolean;
  stateStore: StateStore<TStoreOptions>;
  stateStoreIdentifier: string;
  guestStore: PoppyGuestStore<TStoreOptions>;
  guestStoreIdentifier: string;
  /** The longest an agent's session lasts, in seconds. */
  agentSessionMaxAge: number;
  /**
   * Revokes the refresh token of the session in the state store. A guest join calls it before it deletes that session.
   * It is best-effort: a failure, or a session with no refresh token, never stops the join.
   */
  revokeReplacedSession?: () => Promise<unknown>;
  /** The options of the stores. They are passed to every store call. */
  storeOptions?: TStoreOptions;
}

// Whether a login comes from the guest that is in the browser: the same `sub` and the same Poppy Session. On Auth0 a
// guest's own login comes back as that same guest, and so does a new join of the same Poppy Session.
function isSameGuest(login: AgentLogin, guest: StoredGuest): boolean {
  return login.sub === guest.sub && login.act.poppy_sid === guest.act.poppy_sid;
}

// Whether a login may replace the guest that is in the browser. Three logins may:
// - any login with a valid Poppy agent `act` (a signed-in agent). It is not compared with the guest, because its
//   `act.sub`, `poppy_user_id` and `poppy_sid` can differ from those of the guest's join.
// - a new guest join: its `sub` or its `poppy_sid` differs from those of the guest.
// - the same guest coming back, but only once its access token has expired (see `guestTokenIsUsable`, the test that
//   `getGuestAccessToken()` makes). That is the renewal of a token that a guest has no other way to get. While the
//   token is valid the same guest is refused: the login of a guest's own session comes back as that same guest, so a
//   page that sends a guest to log in would loop.
// A person's login is always refused: the browser is the agent's.
function mayReplaceGuest(login: LoginClassification, guest: StoredGuest): boolean {
  if (login.kind === 'agent') {
    return true;
  }

  if (login.kind !== 'guest') {
    return false;
  }

  return !isSameGuest(login.login, guest) || !guestTokenIsUsable(guest.tokenSets?.[0]);
}

// Refuses the login when a guest that has not ended is in the browser and the login may not replace it. The guest store is
// read here and nothing is written. A store that fails is never read as empty, so its error reaches the caller. It gives
// back the guest that the login will replace, or `undefined` when the browser has none that is active.
async function assertGuestAllowsLogin<TStoreOptions>(
  login: LoginClassification,
  guestStore: PoppyGuestStore<TStoreOptions>,
  guestStoreIdentifier: string,
  storeOptions?: TStoreOptions
): Promise<StoredGuest | undefined> {
  const current = await readGuest(guestStore, guestStoreIdentifier, storeOptions);

  if (current.status !== 'active') {
    return undefined;
  }

  if (!mayReplaceGuest(login, current.guest)) {
    throw new PoppyError(PoppyErrorCode.SIGN_IN_REQUIRED);
  }

  return current.guest;
}

/**
 * @internal
 * The guard that every login method runs, with the `poppy` option, after it has the tokens and before it writes
 * anything: the redirect callback (`completeInteractiveLogin`), `passkey.complete`, `passkey.getToken`,
 * `completePasswordless`, `completePasswordlessMagicLink`, `loginBackchannel`, `loginWithCustomTokenExchange` and
 * `mfa.verify`. It decides from the claims of the ID token (see {@link classifyLogin}) and writes in this order only
 * after every check has passed, so a refused login changes nothing.
 *
 * A login is refused with a {@link PoppyError} when:
 * - it looks like a guest but is not a valid one (`invalid_poppy_guest`, and the reason is logged once),
 * - its `act` claim holds a Poppy Session that is not well formed, or the token of a signed-in agent has no valid `sub`
 *   or `exp` (`invalid_poppy_agent`, and the reason is logged once),
 * - it is a guest on any method but the redirect callback (`poppy_guest_not_supported`),
 * - a guest that has not ended is in the browser, and the login is neither a signed-in agent, a new guest, nor the same
 *   guest coming back after its access token has expired (`poppy_sign_in_required`). A person's login, and the same
 *   guest coming back while its token is valid (a silent login too), are refused. A guest that has ended blocks nothing.
 *
 * Then, by the kind of login:
 * - A person's login gives `undefined`, and the caller goes on with the normal login. The guest of the browser is
 *   cleared first, so the visitor has no guest and no session if the write that follows fails.
 * - A guest ends any session in the state store, a person's login too, because the browser is the agent's now. The guest
 *   replaces any guest of the browser. It is never written to the state store, so a guest is never a user. The same guest
 *   coming back after its token has expired is a renewal: it gets the new token and keeps the creation time and the
 *   deadline of the first join (the deadline can only get earlier).
 * - A signed-in agent gets a fresh user session, built from the tokens of this login only. Nothing of an earlier session
 *   is kept, not even if it is the same user's, and there is no refresh token. The guest of the browser is dropped.
 *
 * The guest and the signed-in session end at the deadline (see {@link agentSessionDeadline}). No read or refresh extends it,
 * and neither does the renewal of a guest. A new login of any other kind starts a new deadline.
 *
 * @returns The Poppy context of the agent, or `undefined` when the login is a person's. The context holds the `sub`, the
 * `sub_profile` and the `act` of the ID token, the scopes of the token of the join (none for a guest) and the key of the
 * Session. The caller clears the regular anonymous session after any agent login, a guest's too.
 * @throws {PoppyError} When the login is refused, as above. Nothing is written.
 * @throws {SessionExpiredError} When the deadline of an agent's login has already passed, or is 30 seconds away or less.
 */
export async function completeAgentLogin<TStoreOptions>(
  input: CompleteAgentLoginInput<TStoreOptions>
): Promise<PoppyAgentContext | undefined> {
  const {
    response,
    audience,
    domain,
    callback,
    stateStore,
    stateStoreIdentifier,
    guestStore,
    guestStoreIdentifier,
    agentSessionMaxAge,
    revokeReplacedSession,
    storeOptions,
  } = input;

  // A response with no ID token has no claims. It is a person's login, and it is checked like one.
  let login: LoginClassification;

  try {
    login = classifyLogin(response.claims);
  } catch (error) {
    if (error instanceof InvalidPoppySessionError) {
      // The reason names a claim and shows no value, so it is safe to log. It is kept out of the message of the error,
      // which an app may show.
      const reason = `${error.member} is missing or invalid`;

      console.error(`[Auth0] Poppy: refused a login with an agent state that is not valid: ${reason}.`);

      throw new PoppyError(PoppyErrorCode.INVALID_AGENT, reason);
    }

    throw error;
  }

  if (login.kind === 'invalid_guest') {
    // The reason names claims and shows no value, so it is safe to log. It is kept out of the message of the error, which
    // an app may show.
    console.error(`[Auth0] Poppy: refused a login that looks like a guest: ${login.reason}.`);

    throw new PoppyError(PoppyErrorCode.INVALID_GUEST, login.reason);
  }

  if (login.kind === 'guest' && !callback) {
    throw new PoppyError(PoppyErrorCode.GUEST_NOT_SUPPORTED);
  }

  if (login.kind === 'human') {
    await assertGuestAllowsLogin(login, guestStore, guestStoreIdentifier, storeOptions);

    // An accepted login that is not a guest clears the guest, one that has ended included. It goes first: if the write of
    // the session fails, the visitor ends with neither, and not with both. The store is cleared whatever the read found,
    // because it can hold a value that cannot be opened.
    await guestStore.delete(guestStoreIdentifier, storeOptions);

    return undefined;
  }

  const now = Math.floor(Date.now() / 1000);
  const deadline = agentSessionDeadline({
    now,
    maxAge: agentSessionMaxAge,
    exp: login.exp,
    sessionExpiry: extractSessionExpiry(response.claims),
  });

  // The deadline is checked as a number, not as a truthy value: one that rounds down to 0 is a time in the past. With no
  // `iat` the check compares with the current time. It counts a deadline that is 30 seconds away or less as passed, as it
  // does for the ceiling of any session.
  if (isSessionExpiryInPast(deadline)) {
    throw new SessionExpiredError(
      'The agent session has already ended; refusing to create an already-expired session.'
    );
  }

  const replaced = await assertGuestAllowsLogin(login, guestStore, guestStoreIdentifier, storeOptions);

  // The same guest coming back is a renewal of its token. It keeps the creation time and the deadline of the first join
  // (the deadline can only get earlier), so that a renewal never moves the end of the guest later: every silent login
  // gets tokens that last up to two hours from now, and a guest that renewed would outlive the session of Auth0, which
  // ends two hours after the first join. The clamp holds while the stored guest is still there and more than 30 seconds
  // from its end. A login after that is a new guest.
  const renewal = login.kind === 'guest' && replaced !== undefined && isSameGuest(login.login, replaced);

  // The context is built before any write, so a failure here leaves the stores as they were. A guest has no scopes: its
  // access token is read with `getGuestAccessToken()`. The scopes of a signed-in agent are those of the token of the join.
  const context = await buildAgentContext(
    login.kind === 'guest' ? 'guest' : 'signed_in',
    login.login,
    login.kind === 'guest' ? [] : splitScopes(response.scope)
  );

  if (login.kind === 'guest') {
    // The browser is the agent's now, so any session in the state store ends, a person's own login too: the agent must
    // not act with an account that it was not approved for. The session goes first, as the guest does in a signed-in join.
    // If the write of the guest fails, the visitor ends with neither, and not with both.
    //
    // The refresh token of that session is revoked first, because a guest is a different identity that takes over the
    // browser. Deleting the session removes it from this browser only: the token stays valid at Auth0, and a copy of an
    // encrypted session cookie (a stateless store) would still open it. A signed-in agent does not revoke (see below):
    // it is the same account signing in again, as with any new login, and the old session is only replaced.
    try {
      await revokeReplacedSession?.();
    } catch {
      // best-effort: a failed revocation must not block the join, as it does not block a logout
    }

    await stateStore.delete(stateStoreIdentifier, storeOptions);

    await guestStore.set(
      guestStoreIdentifier,
      {
        sub: login.login.sub,
        ...(login.login.sub_profile !== undefined && { sub_profile: login.login.sub_profile }),
        act: login.login.act,
        tokenSets: [
          {
            audience,
            accessToken: response.accessToken,
            scope: response.scope,
            expiresAt: response.expiresAt,
          },
        ],
        // A renewal keeps the first join: nothing about it moves, only the token.
        createdAt: renewal && Number.isFinite(replaced.createdAt) ? replaced.createdAt : now,
        expiresAt: renewal ? Math.min(deadline, replaced.expiresAt) : deadline,
      },
      // `true` asks a store that has ids of its own for a new one on every write, as the write of a signed-in session
      // does. That stops session fixation. A cookie-backed store has no id and ignores it.
      true,
      storeOptions
    );

    return context;
  }

  // The guest of this browser goes first. If the write of the session fails, the visitor ends with neither, and not
  // with both.
  await guestStore.delete(guestStoreIdentifier, storeOptions);

  // `undefined` as the existing state makes the session fresh: nothing of an earlier session is kept (their claims, token
  // sets or refresh token). The refresh token of this login is left out too, because nothing may extend the session past
  // its deadline. `true` gives a stateful store a new session id, which stops session fixation.
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

  return context;
}
