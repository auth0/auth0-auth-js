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
 * Reads the IPSIE `session_expiry` claim (absolute Unix seconds) from ID token claims.
 *
 * Fail-open by design: returns `undefined` (meaning "no ceiling") unless the value is a
 * positive integer. A missing or malformed claim MUST NEVER be treated as an already-expired
 * session — a platform glitch must not lock out every enterprise user.
 *
 * @param claims The decoded ID token claims, or undefined.
 * @returns The ceiling in Unix seconds, or undefined when absent/invalid.
 */
export function extractSessionExpiry(claims: TokenResponse['claims'] | undefined): number | undefined {
  const value = claims?.session_expiry;
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : undefined;
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

    return {
      ...stateData,
      idToken: tokenEndpointResponse.idToken ?? stateData.idToken,
      refreshToken: tokenEndpointResponse.refreshToken ?? stateData.refreshToken,
      tokenSets,
      domain: context?.domain ?? stateData.domain,
      sessionExpiresAt: extractSessionExpiry(tokenEndpointResponse.claims) ?? stateData.sessionExpiresAt,
    };
  } else {
    const user = tokenEndpointResponse.claims;
    const sessionExpiresAt = extractSessionExpiry(tokenEndpointResponse.claims);

    // Lockout guard: never persist a session that is already past its ceiling at login.
    if (sessionExpiresAt !== undefined) {
      const iatOrNow = typeof user?.iat === 'number' ? user.iat : Math.floor(Date.now() / 1000);
      if (sessionExpiresAt <= iatOrNow) {
        throw new SessionExpiredError(
          'The upstream identity provider session_expiry is at or before the issued-at time; refusing to create an already-expired session.'
        );
      }
    }

    return {
      user,
      idToken: tokenEndpointResponse.idToken,
      refreshToken: tokenEndpointResponse.refreshToken,
      tokenSets: [createUpdatedTokenSet(audience, tokenEndpointResponse)],
      domain: context?.domain,
      sessionExpiresAt,
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
