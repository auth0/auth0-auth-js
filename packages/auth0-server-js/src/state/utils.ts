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

    const createUpdatedTokenSet = (response: TokenEndpointResponse, refresh_token?: string) => ({
      audience,
      access_token: response.access_token,
      refresh_token: response.refresh_token ?? refresh_token,
      scope: response.scope,
      expires_at: Math.floor(Date.now() / 1000) + Number(response.expires_in),
    });

    const tokenSets = isNewTokenSet
      ? [...stateDate.tokenSets, createUpdatedTokenSet(tokenEndpointResponse)]
      : stateDate.tokenSets.map((tokenSet) =>
          tokenSet.audience === audience && tokenSet.scope === tokenEndpointResponse.scope
            ? createUpdatedTokenSet(tokenEndpointResponse, stateDate.refresh_token)
            : tokenSet
        );

    return {
      ...stateDate,
      id_token: tokenEndpointResponse.id_token,
      refresh_token: tokenEndpointResponse.refresh_token ?? stateDate.refresh_token,
      tokenSets,
    };
  } else {
    const user = tokenEndpointResponse.claims();
    return {
      user,
      id_token: tokenEndpointResponse.id_token,
      refresh_token: tokenEndpointResponse.refresh_token,
      tokenSets: [
        {
          audience,
          access_token: tokenEndpointResponse.access_token,
          scope: tokenEndpointResponse.scope,
          expires_at: Math.floor(Date.now() / 1000) + Number(tokenEndpointResponse.expires_in),
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
      tokenSet.connection === options.connection && (!options.login_hint || tokenSet.login_hint === options.login_hint)
  );

  const connectionTokenSet = {
    connection: options.connection,
    login_hint: options.login_hint,
    access_token: tokenEndpointResponse.access_token,
    scope: tokenEndpointResponse.scope,
    expires_at: Math.floor(Date.now() / 1000) + Number(tokenEndpointResponse.expires_in),
  };

  const connectionTokenSets = isNewTokenSet
    ? [...stateDate.connectionTokenSets, connectionTokenSet]
    : stateDate.connectionTokenSets.map((tokenSet) =>
        tokenSet.connection === options.connection &&
        (!options.login_hint || tokenSet.login_hint === options.login_hint)
          ? connectionTokenSet
          : tokenSet
      );

  return {
    ...stateDate,
    connectionTokenSets,
  };
}
