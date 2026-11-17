import type { TokenResponse } from '@auth0/auth0-auth-js';
import { PoppyError, PoppyErrorCode, SessionExpiredError } from '../errors.js';
import { extractSessionExpiry, isSessionExpiryInPast, updateStateData } from '../state/utils.js';
import type { StateStore } from '../types.js';
import { buildAgentContext, splitScopes } from './agent-context.js';
import { classifyLogin } from './classify-login.js';
import type { LoginClassification } from './classify-login.js';
import { agentSessionDeadline } from './claims.js';
import { readGuest } from './read-guest.js';
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

// Whether a login may replace the guest that is in the browser. Only two logins may: any login with a valid Poppy agent
// `act` (a signed-in agent), and a new guest join. A signed-in agent is not compared with the guest, because its `act.sub`,
// `poppy_user_id` and `poppy_sid` can differ from those of the guest's join. A guest is new when its `sub` or its
// `poppy_sid` differs. A person's login, and the same guest coming back, are refused: the browser is the agent's, and on
// Auth0 the login of a guest's own session comes back as that same guest.
function mayReplaceGuest(login: LoginClassification, guest: StoredGuest): boolean {
  if (login.kind === 'agent') {
    return true;
  }

  return login.kind === 'guest' && (login.login.sub !== guest.sub || login.login.act.poppy_sid !== guest.act.poppy_sid);
}

// Refuses the login when a guest that has not ended is in the browser and the login may not replace it. The guest store is
// read here and nothing is written. A store that fails is never read as empty, so its error reaches the caller.
async function assertGuestAllowsLogin<TStoreOptions>(
  login: LoginClassification,
  guestStore: PoppyGuestStore<TStoreOptions>,
  guestStoreIdentifier: string,
  storeOptions?: TStoreOptions
): Promise<void> {
  const current = await readGuest(guestStore, guestStoreIdentifier, storeOptions);

  if (current.status === 'active' && !mayReplaceGuest(login, current.guest)) {
    throw new PoppyError(PoppyErrorCode.SIGN_IN_REQUIRED);
  }
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
 * - it is a guest on any method but the redirect callback (`poppy_guest_not_supported`),
 * - a guest that has not ended is in the browser, and the login is neither a signed-in agent nor a new guest
 *   (`poppy_sign_in_required`). A person's login, the same guest coming back and a silent login are refused. A guest that
 *   has ended blocks nothing.
 *
 * Then, by the kind of login:
 * - A person's login gives `undefined`, and the caller goes on with the normal login. The guest of the browser is
 *   cleared first, so the visitor has no guest and no session if the write that follows fails.
 * - A guest ends any session in the state store, a person's login too, because the browser is the agent's now. It leaves
 *   the regular anonymous session alone: that is not an account. The guest replaces any guest of the browser. It is never
 *   written to the state store, so a guest is never a user.
 * - A signed-in agent gets a fresh user session, built from the tokens of this login only. Nothing of an earlier session
 *   is kept, not even if it is the same user's, and there is no refresh token. The guest of the browser is dropped.
 *
 * The guest and the signed-in session end at the deadline (see {@link agentSessionDeadline}). No read or refresh extends it. A new login starts a new deadline.
 *
 * @returns The Poppy context of the agent, or `undefined` when the login is a person's. The context holds the `sub`, the
 * `sub_profile` and the `act` of the ID token, the scopes of the token of the join (none for a guest) and the key of the
 * Session. The caller clears the anonymous session after a signed-in login.
 * @throws {PoppyError} When the login is refused, as above. Nothing is written.
 * @throws {InvalidPoppySessionError} When the `act` claim holds a Session that is not well formed and the claims have no
 * guest marker, or the token of an agent has no valid `sub` or `exp`.
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
  const login = classifyLogin(response.claims);

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

  await assertGuestAllowsLogin(login, guestStore, guestStoreIdentifier, storeOptions);

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
    // If the write of the guest fails, the visitor ends with neither, and not with both. The regular anonymous session is
    // not an account, and it stays.
    //
    // The refresh token of that session is revoked first. Deleting the session removes it from this browser only: the
    // token stays valid at Auth0, and a copy of an encrypted session cookie (a stateless store) would still open it.
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
        createdAt: now,
        expiresAt: deadline,
      },
      false,
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
