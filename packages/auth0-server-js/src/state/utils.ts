import type { AccessTokenForConnectionOptions, StateData } from '../types.js';
import { TokenResponse } from '@auth0/auth0-auth-js';

/**
 * Utility function to update the state with a new response from the token endpoint
 * @param audience The audience of the token endpoint response
 * @param stateDate The existing state data to update, or undefined if no state data available.
 * @param tokenEndpointResponse The response from the token endpoint.
 * @returns Updated state data.
 */
export function updateStateData(
  audience: string,
  stateDate: StateData | undefined,
  tokenEndpointResponse: TokenResponse
): StateData {
  if (stateDate) {
    const isNewTokenSet = !stateDate.tokenSets.some(
      (tokenSet) => tokenSet.audience === audience && tokenSet.scope === tokenEndpointResponse.scope
    );

    const createUpdatedTokenSet = (response: TokenResponse) => ({
      audience,
      accessToken: response.accessToken,
      scope: response.scope,
      expiresAt: Math.floor(Date.now() / 1000) + Number(response.expiresAt),
    });

    const tokenSets = isNewTokenSet
      ? [...stateDate.tokenSets, createUpdatedTokenSet(tokenEndpointResponse)]
      : stateDate.tokenSets.map((tokenSet) =>
          tokenSet.audience === audience && tokenSet.scope === tokenEndpointResponse.scope
            ? createUpdatedTokenSet(tokenEndpointResponse)
            : tokenSet
        );

    return {
      ...stateDate,
      idToken: tokenEndpointResponse.idToken,
      refreshToken: tokenEndpointResponse.refreshToken ?? stateDate.refreshToken,
      tokenSets,
    };
  } else {
    const user = tokenEndpointResponse.claims;
    return {
      user,
      idToken: tokenEndpointResponse.idToken,
      refreshToken: tokenEndpointResponse.refreshToken,
      tokenSets: [
        {
          audience,
          accessToken: tokenEndpointResponse.accessToken,
          scope: tokenEndpointResponse.scope,
          expiresAt:tokenEndpointResponse.expiresAt,
        },
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
  stateDate: StateData,
  tokenEndpointResponse: TokenResponse
) {
  stateDate.connectionTokenSets = stateDate.connectionTokenSets || [];

  const isNewTokenSet = !stateDate.connectionTokenSets.some(
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
    ? [...stateDate.connectionTokenSets, connectionTokenSet]
    : stateDate.connectionTokenSets.map((tokenSet) =>
        tokenSet.connection === options.connection &&
        (!options.loginHint || tokenSet.loginHint === options.loginHint)
          ? connectionTokenSet
          : tokenSet
      );

  return {
    ...stateDate,
    connectionTokenSets,
  };
}
