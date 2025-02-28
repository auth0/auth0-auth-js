import type { TokenEndpointResponse, TokenEndpointResponseHelpers } from 'openid-client';
import type { AccessTokenForConnectionOptions, StateData } from '../types.js';

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
  tokenEndpointResponse: TokenEndpointResponse & TokenEndpointResponseHelpers
): StateData {
  if (stateDate) {
    const isNewTokenSet = !stateDate.tokenSets.some(
      (tokenSet) => tokenSet.audience === audience && tokenSet.scope === tokenEndpointResponse.scope
    );

    const createUpdatedTokenSet = (response: TokenEndpointResponse) => ({
      audience,
      accessToken: response.access_token,
      scope: response.scope,
      expiresAt: Math.floor(Date.now() / 1000) + Number(response.expires_in),
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
      idToken: tokenEndpointResponse.id_token,
      refreshToken: tokenEndpointResponse.refresh_token ?? stateDate.refreshToken,
      tokenSets,
    };
  } else {
    const user = tokenEndpointResponse.claims();
    return {
      user,
      idToken: tokenEndpointResponse.id_token,
      refreshToken: tokenEndpointResponse.refresh_token,
      tokenSets: [
        {
          audience,
          accessToken: tokenEndpointResponse.access_token,
          scope: tokenEndpointResponse.scope,
          expiresAt: Math.floor(Date.now() / 1000) + Number(tokenEndpointResponse.expires_in),
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
  tokenEndpointResponse: TokenEndpointResponse
) {
  stateDate.connectionTokenSets = stateDate.connectionTokenSets || [];

  const isNewTokenSet = !stateDate.connectionTokenSets.some(
    (tokenSet) =>
      tokenSet.connection === options.connection && (!options.loginHint || tokenSet.loginHint === options.loginHint)
  );

  const connectionTokenSet = {
    connection: options.connection,
    loginHint: options.loginHint,
    accessToken: tokenEndpointResponse.access_token,
    scope: tokenEndpointResponse.scope,
    expiresAt: Math.floor(Date.now() / 1000) + Number(tokenEndpointResponse.expires_in),
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
