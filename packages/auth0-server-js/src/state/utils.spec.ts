import { expect, test } from 'vitest';
import type { StateData } from '../types.js';
import { updateStateData, updateStateDataForConnectionTokenSet } from './utils.js';
import { TokenResponse } from '../../../auth0-auth-js/dist/types.js';

test('updateStateData - should add when state undefined', () => {
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', undefined, response);

  expect(updatedState.idToken).toBe('<id_token>');
  expect(updatedState.refreshToken).toBe('<refresh_token>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.scope).toBe('<scope>');
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token>');
});

test('updateStateData - should add when tokenSets are empty', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    accessToken: '<access_token>',
    expiresAt: Date.now() / 1000 + 500,
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);
  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token>');
});

test('updateStateData - should update when tokenSets does contain a token for same audience and scope - without refresh token', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        accessToken: '<access_token>',
        scope: '<scope>',
        audience: '<audience>',
        expiresAt: Date.now() + 500,
      },
    ],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_2>',
    accessToken: '<access_token_2>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.idToken).toBe('<id_token_2>');
  expect(updatedState.refreshToken).toBe('<refresh_token>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.scope).toBe('<scope>');
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token_2>');
});

test('updateStateData - should update when tokenSets does contain a token for same audience and scope - with refresh token', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        accessToken: '<access_token>',
        scope: '<scope>',
        audience: '<audience>',
        expiresAt: Date.now() + 500,
      },
      {
        accessToken: '<access_token>',
        scope: '<scope_2>',
        audience: '<audience_2>',
        expiresAt: Date.now() + 500,
      },
    ],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_2>',
    accessToken: '<access_token_2>',
    refreshToken: '<refresh_token_2>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.idToken).toBe('<id_token_2>');
  expect(updatedState.refreshToken).toBe('<refresh_token_2>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(2);

  const updatedTokenSet = updatedState.tokenSets.find(
    (tokenSet) => tokenSet.audience === '<audience>' && tokenSet.scope === '<scope>'
  );
  expect(updatedTokenSet!.audience).toBe('<audience>');
  expect(updatedTokenSet!.scope).toBe('<scope>');
  expect(updatedTokenSet!.accessToken).toBe('<access_token_2>');
});

test('updateStateDataForConnectionTokenSet - should add when connectionTokenSets are empty', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    accessToken: '<access_token_for_connection>',
    expiresAt: Date.now() / 1000 + 500,
  } as TokenResponse;

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(1);
  expect(updatedState.connectionTokenSets[0]!.connection).toBe('<connection>');
  expect(updatedState.connectionTokenSets[0]!.accessToken).toBe('<access_token_for_connection>');
});

test('updateStateDataForConnectionTokenSet - should add when connectionTokenSets are undefined', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: undefined,
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response = {
    accessToken: '<access_token_for_connection>',
    expiresAt: Date.now() / 1000 + 500,
  } as TokenResponse;

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(1);
  expect(updatedState.connectionTokenSets[0]!.connection).toBe('<connection>');
  expect(updatedState.connectionTokenSets[0]!.accessToken).toBe('<access_token_for_connection>');
});

test('updateStateDataForConnectionTokenSet - should add when connectionTokenSets does not contain a token for same connection', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection_2>',
        accessToken: '<access_token_for_connection_2>',
        expiresAt: Date.now() + 500,
        scope: '<scope>',
      },
    ],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    accessToken: '<access_token_for_connection>',
    expiresAt: Date.now() / 1000 + 500,
  } as TokenResponse;

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(2);

  const insertedConnectionTokenSet = updatedState.connectionTokenSets.find(
    (tokenSet) => tokenSet.connection === '<connection>'
  );
  expect(insertedConnectionTokenSet!.connection).toBe('<connection>');
  expect(insertedConnectionTokenSet!.accessToken).toBe('<access_token_for_connection>');
});

test('updateStateDataForConnectionTokenSet - should update when connectionTokenSets does contain a token for same connection', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        accessToken: '<access_token_for_connection>',
        expiresAt: Date.now() + 500,
        scope: '<scope>',
      },
      {
        connection: '<another_connection>',
        accessToken: '<another_access_token_for_connection>',
        expiresAt: Date.now() + 500,
        scope: '<scope>',
      },
    ],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response = {
    accessToken: '<access_token_for_connection_2>',
    expiresAt: Date.now() / 1000 + 500,
  } as TokenResponse;

  const updatedState = updateStateDataForConnectionTokenSet({ connection: '<connection>' }, initialState, response);
  expect(updatedState.connectionTokenSets.length).toBe(2);
  const updatedConnectionTokenSet = updatedState.connectionTokenSets.find(
    (tokenSet) => tokenSet.connection === '<connection>'
  );

  expect(updatedConnectionTokenSet!.connection).toBe('<connection>');
  expect(updatedConnectionTokenSet!.accessToken).toBe('<access_token_for_connection_2>');
});

test('updateStateDataForConnectionTokenSet - should update when connectionTokenSets does contain a token for same connection and login_hint', () => {
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    connectionTokenSets: [
      {
        connection: '<connection>',
        loginHint: '<login_hint>',
        accessToken: '<access_token_for_connection>',
        expiresAt: Date.now() + 500,
        scope: '<scope>',
      },
      {
        connection: '<connection>',
        loginHint: '<another_login_hint>',
        accessToken: '<another_access_token_for_connection>',
        expiresAt: Date.now() + 500,
        scope: '<scope>',
      },
    ],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };
  const response = {
    accessToken: '<access_token_for_connection_2>',
    expiresAt: Date.now() / 1000 + 500,
  } as TokenResponse;

  const updatedState = updateStateDataForConnectionTokenSet(
    { connection: '<connection>', loginHint: '<login_hint>' },
    initialState,
    response
  );
  expect(updatedState.connectionTokenSets.length).toBe(2);
  const updatedConnectionTokenSet = updatedState.connectionTokenSets.find(
    (tokenSet) => tokenSet.connection === '<connection>' && tokenSet.loginHint === '<login_hint>'
  );

  expect(updatedConnectionTokenSet!.connection).toBe('<connection>');
  expect(updatedConnectionTokenSet!.accessToken).toBe('<access_token_for_connection_2>');
});
