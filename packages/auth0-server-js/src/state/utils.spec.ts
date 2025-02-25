import { expect, test } from 'vitest';
import type { StateData } from '../types.js';
import type { IDToken, TokenEndpointResponse, TokenEndpointResponseHelpers } from 'openid-client';
import { updateStateData, updateStateDataForConnectionTokenSet } from './utils.js';

test('updateStateData - should add when state undefined', () => {
  const response = {
    id_token: '<id_token>',
    access_token: '<access_token>',
    refresh_token: '<refresh_token>',
    expires_in: 500,
    token_type: 'bearer',
    scope: '<scope>',
    claims: () =>
      ({ iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 } as IDToken),
  } as TokenEndpointResponse & TokenEndpointResponseHelpers;

  const updatedState = updateStateData('<audience>', undefined, response);

  expect(updatedState.id_token).toBe('<id_token>');
  expect(updatedState.refresh_token).toBe('<refresh_token>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.scope).toBe('<scope>');
  expect(updatedState.tokenSets[0]!.access_token).toBe('<access_token>');
});

test('updateStateData - should add when tokenSets are empty', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    access_token: '<access_token>',
    expires_in: 500,
    token_type: 'bearer',
    claims: () =>
      ({ iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 } as IDToken),
  } as TokenEndpointResponse & TokenEndpointResponseHelpers;

  const updatedState = updateStateData('<audience>', initialState, response);
  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.access_token).toBe('<access_token>');
});

test('updateStateData - should update when tokenSets does contain a token for same audience and scope - without refresh token', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        access_token: '<access_token>',
        scope: '<scope>',
        audience: '<audience>',
        expires_at: Date.now() + 500,
      },
    ],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    id_token: '<id_token_2>',
    access_token: '<access_token_2>',
    expires_in: 500,
    token_type: 'bearer',
    scope: '<scope>',
    claims: () =>
      ({ iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 } as IDToken),
  } as TokenEndpointResponse & TokenEndpointResponseHelpers;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.id_token).toBe('<id_token_2>');
  expect(updatedState.refresh_token).toBe('<refresh_token>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.scope).toBe('<scope>');
  expect(updatedState.tokenSets[0]!.access_token).toBe('<access_token_2>');
});

test('updateStateData - should update when tokenSets does contain a token for same audience and scope - with refresh token', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [
      {
        access_token: '<access_token>',
        scope: '<scope>',
        audience: '<audience>',
        expires_at: Date.now() + 500,
      },
      {
        access_token: '<access_token>',
        scope: '<scope_2>',
        audience: '<audience_2>',
        expires_at: Date.now() + 500,
      },
    ],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    id_token: '<id_token_2>',
    access_token: '<access_token_2>',
    refresh_token: '<refresh_token_2>',
    expires_in: 500,
    token_type: 'bearer',
    scope: '<scope>',
    claims: () =>
      ({ iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 } as IDToken),
  } as TokenEndpointResponse & TokenEndpointResponseHelpers;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.id_token).toBe('<id_token_2>');
  expect(updatedState.refresh_token).toBe('<refresh_token_2>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(2);

  const updatedTokenSet = updatedState.tokenSets.find(
    (tokenSet) => tokenSet.audience === '<audience>' && tokenSet.scope === '<scope>'
  );
  expect(updatedTokenSet!.audience).toBe('<audience>');
  expect(updatedTokenSet!.scope).toBe('<scope>');
  expect(updatedTokenSet!.access_token).toBe('<access_token_2>');
});

test('updateStateDataForConnectionTokenSet - should add when connectionTokenSets are empty', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response: TokenEndpointResponse = {
    access_token: '<access_token_for_connection>',
    expires_in: 500,
    token_type: 'bearer',
  };

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(1);
  expect(updatedState.connectionTokenSets[0]!.connection).toBe('<connection>');
  expect(updatedState.connectionTokenSets[0]!.access_token).toBe('<access_token_for_connection>');
});

test('updateStateDataForConnectionTokenSet - should add when connectionTokenSets are undefined', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: undefined,
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response: TokenEndpointResponse = {
    access_token: '<access_token_for_connection>',
    expires_in: 500,
    token_type: 'bearer',
  };

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(1);
  expect(updatedState.connectionTokenSets[0]!.connection).toBe('<connection>');
  expect(updatedState.connectionTokenSets[0]!.access_token).toBe('<access_token_for_connection>');
});

test('updateStateDataForConnectionTokenSet - should add when connectionTokenSets does not contain a token for same connection', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection_2>',
        access_token: '<access_token_for_connection_2>',
        expires_at: Date.now() + 500,
        scope: '<scope>',
      },
    ],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response: TokenEndpointResponse = {
    access_token: '<access_token_for_connection>',
    expires_in: 500,
    token_type: 'bearer',
  };

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(2);

  const insertedConnectionTokenSet = updatedState.connectionTokenSets.find(
    (tokenSet) => tokenSet.connection === '<connection>'
  );
  expect(insertedConnectionTokenSet!.connection).toBe('<connection>');
  expect(insertedConnectionTokenSet!.access_token).toBe('<access_token_for_connection>');
});

test('updateStateDataForConnectionTokenSet - should update when connectionTokenSets does contain a token for same connection', () => {
  const initialState: StateData = {
    id_token: '<id_token>',
    refresh_token: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        access_token: '<access_token_for_connection>',
        expires_at: Date.now() + 500,
        scope: '<scope>',
      },
      {
        connection: '<another_connection>',
        access_token: '<another_access_token_for_connection>',
        expires_at: Date.now() + 500,
        scope: '<scope>',
      },
    ],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response: TokenEndpointResponse = {
    access_token: '<access_token_for_connection_2>',
    expires_in: 500,
    token_type: 'bearer',
  };

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(2);
  const updatedConnectionTokenSet = updatedState.connectionTokenSets.find(
    (tokenSet) => tokenSet.connection === '<connection>'
  );

  expect(updatedConnectionTokenSet!.connection).toBe('<connection>');
  expect(updatedConnectionTokenSet!.access_token).toBe('<access_token_for_connection_2>');
});

test('updateStateDataForConnectionTokenSet - should update when connectionTokenSets does contain a token for same connection and login_hint', () => {
    const initialState: StateData = {
      id_token: '<id_token>',
      refresh_token: '<refresh_token>',
      tokenSets: [],
      connectionTokenSets: [
        {
          connection: '<connection>',
          login_hint: '<login_hint>',
          access_token: '<access_token_for_connection>',
          expires_at: Date.now() + 500,
          scope: '<scope>',
        },
        {
          connection: '<connection>',
          login_hint: '<another_login_hint>',
          access_token: '<another_access_token_for_connection>',
          expires_at: Date.now() + 500,
          scope: '<scope>',
        },
      ],
      user: { sub: '<sub>' },
      internal: { sid: '<sid>', createdAt: Date.now() },
    };
    const response: TokenEndpointResponse = {
      access_token: '<access_token_for_connection_2>',
      expires_in: 500,
      token_type: 'bearer',
    };
  
    const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>', login_hint: '<login_hint>' }, initialState, response);
    expect(updatedState.connectionTokenSets.length).toBe(2);
    const updatedConnectionTokenSet = updatedState.connectionTokenSets.find(
      (tokenSet) => tokenSet.connection === '<connection>' && tokenSet.login_hint === '<login_hint>'
    );
  
    expect(updatedConnectionTokenSet!.connection).toBe('<connection>');
    expect(updatedConnectionTokenSet!.access_token).toBe('<access_token_for_connection_2>');
  });
