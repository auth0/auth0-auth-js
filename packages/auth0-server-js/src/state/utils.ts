import type { AccessTokenForConnectionOptions, StateData } from '../types.js';
import { TokenResponse } from '@auth0/auth0-auth-js';

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
  tokenEndpointResponse: TokenResponse
): StateData {
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
    };
  } else {
    const user = tokenEndpointResponse.claims;
    return {
      user,
      idToken: tokenEndpointResponse.idToken,
      refreshToken: tokenEndpointResponse.refreshToken,
      tokenSets: [
        createUpdatedTokenSet(audience, tokenEndpointResponse),
      ],
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
