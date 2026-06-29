import type { AccessTokenForConnectionOptions, StateData } from '../types.js';
import { TokenResponse } from '@auth0/auth0-auth-js';
import { SessionExpiredError } from '../errors.js';

/**
 * Negative leeway (in seconds) applied to the `session_expiry` ceiling to absorb
 * clock skew between the SDK and the Auth0 platform. The session is treated as
 * expired slightly BEFORE the wall-clock ceiling, never after.
 */
export const SESSION_EXPIRY_LEEWAY = 30;

/**
 * Upper bound (exclusive) for a value to be accepted as a Unix timestamp in seconds.
 *
 * `1e10` (10,000,000,000) is the year ~2286 — far beyond any real session ceiling, yet well below
 * a millisecond timestamp for the current era (`Date.now()` is ~1.7e12). This lets us reject a
 * `session_expiry` (or `iat`) that was mistakenly provided in milliseconds: such a value would
 * otherwise look like a valid far-future seconds timestamp and silently disable the ceiling.
 * Since `session_expiry` can be set by a customer Post-Login Action, a milliseconds mix-up is a
 * realistic input, not just a platform glitch. The threshold matches the cross-SDK convention.
 */
const MAX_PLAUSIBLE_UNIX_SECONDS = 1e10;

/**
 * Returns whether a value is a plausible Unix timestamp in seconds: a positive integer below the
 * milliseconds range. Used to reject values mistakenly expressed in milliseconds.
 */
function isPlausibleUnixSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 && value < MAX_PLAUSIBLE_UNIX_SECONDS;
}

/**
 * Reads the IPSIE `session_expiry` claim (absolute Unix seconds) from ID token claims.
 *
 * Fail-open by design: returns `undefined` (meaning "no ceiling") unless the value is a plausible
 * Unix-seconds timestamp (positive integer below the milliseconds range). A missing or malformed
 * claim MUST NEVER be treated as an already-expired session — a platform glitch must not lock out
 * every enterprise user. A value in milliseconds is rejected rather than accepted as a far-future
 * ceiling (which would silently disable enforcement).
 *
 * @param claims The decoded ID token claims, or undefined.
 * @returns The ceiling in Unix seconds, or undefined when absent/invalid.
 */
export function extractSessionExpiry(claims: TokenResponse['claims'] | undefined): number | undefined {
  const value = claims?.session_expiry;
  return isPlausibleUnixSeconds(value) ? value : undefined;
}

/**
 * Returns whether the `session_expiry` ceiling has been reached, applying the negative leeway.
 *
 * @param sessionExpiresAt The stored ceiling in Unix seconds, or undefined for "no ceiling".
 * @param nowSeconds Optional current time in Unix seconds (defaults to now). Injectable for tests.
 * @returns `true` when the session must be treated as expired; `false` when there is no ceiling
 *          or it has not yet been reached.
 */
export function isSessionExpiryReached(sessionExpiresAt: number | undefined, nowSeconds?: number): boolean {
  if (sessionExpiresAt === undefined) {
    return false;
  }
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  return now >= sessionExpiresAt - SESSION_EXPIRY_LEEWAY;
}

/**
 * Creates an updated token set object from the token endpoint response
 * @param audience The audience for which the token was requested
 * @param response The response from the token endpoint
 * @returns Updated token set object
 */
const createUpdatedTokenSet = (audience: string, response: TokenResponse) => ({
  audience,
  accessToken: response.accessToken,
  scope: response.scope,
  expiresAt: response.expiresAt,
});

/**
 * Returns whether a `session_expiry` ceiling is already in the past at login — i.e. the session
 * would be born expired and MUST NOT be persisted (the caller should throw `SessionExpiredError`).
 *
 * Compares the ceiling against the ID token `iat` (issued-at), or the current time when `iat` is
 * absent, applying the same negative leeway as {@link isSessionExpiryReached}. `iat` is only
 * trusted when it is a plausible Unix-seconds value; an absent or malformed `iat` (e.g.
 * milliseconds) falls back to now, so a bad `iat` cannot itself manufacture a false lockout.
 *
 * This is enforced at the login sites (interactive login, backchannel login, MFA verify) rather
 * than inside {@link updateStateData}, so the ceiling is only ever derived from a genuine
 * authentication event — never re-derived from a refresh-token response.
 *
 * Companion to {@link isSessionExpiryReached}: that one gates *reads* of an already-stored session
 * against the current wall clock (`now`), whereas this one gates *login* against the token's `iat`,
 * so a token minted with an already-past ceiling is rejected before it is ever persisted.
 *
 * @param sessionExpiresAt The extracted ceiling in Unix seconds, or undefined for "no ceiling".
 * @param issuedAt The ID token `iat` claim, if present.
 * @returns `true` when the ceiling is already reached at login; `false` when there is no ceiling.
 */
export function isSessionExpiryInPast(sessionExpiresAt: number | undefined, issuedAt?: number): boolean {
  if (sessionExpiresAt === undefined) {
    return false;
  }
  const reference = isPlausibleUnixSeconds(issuedAt) ? issuedAt : Math.floor(Date.now() / 1000);
  return sessionExpiresAt <= reference + SESSION_EXPIRY_LEEWAY;
}

/**
 * Stamps the IPSIE `session_expiry` ceiling onto freshly-built login state.
 *
 * Call this ONLY at the login sites (interactive login, backchannel login, MFA verify) — i.e.
 * with the state produced by {@link updateStateData} from a genuine authentication response.
 * It must NOT be called on the refresh path: the ceiling is write-once per authentication and
 * preserved unchanged across refreshes (see {@link updateStateData}).
 *
 * Behavior:
 * - Extracts the ceiling from the response claims (rejecting malformed/millisecond values).
 * - Throws {@link SessionExpiredError} when the ceiling is already in the past at login, so a
 *   born-expired session is never persisted.
 * - Returns the state with `sessionExpiresAt` set to the extracted value. On a re-login this
 *   overwrites any preserved ceiling — including clearing it (to `undefined`) when the new login
 *   is through a connection that asserts no ceiling — so the value always reflects the most
 *   recent authentication event.
 *
 * @param stateData The login state to stamp (from {@link updateStateData}).
 * @param claims The decoded ID token claims from the authentication response.
 * @returns The state data with `sessionExpiresAt` reflecting this login.
 * @throws {SessionExpiredError} When the ceiling is at or before the issued-at time.
 */
export function applySessionExpiryAtLogin(stateData: StateData, claims: TokenResponse['claims']): StateData {
  const sessionExpiresAt = extractSessionExpiry(claims);

  if (isSessionExpiryInPast(sessionExpiresAt, claims?.iat)) {
    throw new SessionExpiredError(
      'The upstream identity provider session_expiry is at or before the issued-at time; refusing to create an already-expired session.'
    );
  }

  return { ...stateData, sessionExpiresAt };
}

/**
 * Utility function to update the state with a new response from the token endpoint
 * @param audience The audience of the token endpoint response
 * @param stateData The existing state data to update, or undefined if no state data available.
 * @param tokenEndpointResponse The response from the token endpoint.
 * @returns Updated state data.
 */
export function updateStateData(
  audience: string,
  stateData: StateData | undefined,
  tokenEndpointResponse: TokenResponse,
  context?: { domain?: string }
): StateData {
  // If we already have a session and the new token belongs to a different user (iss or sub mismatch),
  // wipe the existing state to start a fresh session. This handles the case where a user logs in
  // as a different user without explicitly logging out first.
  if (stateData && tokenEndpointResponse.claims) {
    const newSub = tokenEndpointResponse.claims.sub;
    const newIss = tokenEndpointResponse.claims.iss;
    const existingSub = stateData.user?.sub;
    const existingIss = stateData.user?.iss;

    const subMismatch = newSub !== undefined && existingSub !== undefined && newSub !== existingSub;
    const issMismatch = newIss !== undefined && existingIss !== undefined && newIss !== existingIss;

    if (subMismatch || issMismatch) {
      stateData = undefined;
    }
  }

  if (stateData) {
    const isNewTokenSet = !stateData.tokenSets.some(
      (tokenSet) => tokenSet.audience === audience && tokenSet.scope === tokenEndpointResponse.scope
    );

    const tokenSets = isNewTokenSet
      ? [...stateData.tokenSets, createUpdatedTokenSet(audience, tokenEndpointResponse)]
      : stateData.tokenSets.map((tokenSet) =>
          tokenSet.audience === audience && tokenSet.scope === tokenEndpointResponse.scope
            ? createUpdatedTokenSet(audience, tokenEndpointResponse)
            : tokenSet
        );

    // The `session_expiry` ceiling is intentionally NOT derived here. It is stamped once at the
    // login sites (interactive login, backchannel login, MFA verify) and preserved across every
    // refresh via the `...stateData` spread below. A refresh-token grant must never overwrite the
    // ceiling — even when a Post-Login Action stamps `session_expiry` on the refreshed ID token —
    // because that would let the session outlive the bound asserted at the original login.
    return {
      ...stateData,
      idToken: tokenEndpointResponse.idToken ?? stateData.idToken,
      refreshToken: tokenEndpointResponse.refreshToken ?? stateData.refreshToken,
      tokenSets,
      domain: context?.domain ?? stateData.domain,
    };
  } else {
    const user = tokenEndpointResponse.claims;
    return {
      user,
      idToken: tokenEndpointResponse.idToken,
      refreshToken: tokenEndpointResponse.refreshToken,
      tokenSets: [createUpdatedTokenSet(audience, tokenEndpointResponse)],
      domain: context?.domain,
      internal: {
        sid: user?.sid as string,
        createdAt: Math.floor(Date.now() / 1000),
      },
    };
  }
}

export function updateStateDataForConnectionTokenSet(
  options: AccessTokenForConnectionOptions,
  stateData: StateData,
  tokenEndpointResponse: TokenResponse
) {
  stateData.connectionTokenSets = stateData.connectionTokenSets || [];

  const isNewTokenSet = !stateData.connectionTokenSets.some(
    (tokenSet) =>
      tokenSet.connection === options.connection && (!options.loginHint || tokenSet.loginHint === options.loginHint)
  );

  const connectionTokenSet = {
    connection: options.connection,
    loginHint: options.loginHint,
    accessToken: tokenEndpointResponse.accessToken,
    scope: tokenEndpointResponse.scope,
    expiresAt: tokenEndpointResponse.expiresAt,
  };

  const connectionTokenSets = isNewTokenSet
    ? [...stateData.connectionTokenSets, connectionTokenSet]
    : stateData.connectionTokenSets.map((tokenSet) =>
        tokenSet.connection === options.connection && (!options.loginHint || tokenSet.loginHint === options.loginHint)
          ? connectionTokenSet
          : tokenSet
      );

  return {
    ...stateData,
    connectionTokenSets,
  };
}
