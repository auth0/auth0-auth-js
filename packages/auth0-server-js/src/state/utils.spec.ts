import { expect, test } from 'vitest';
import { TokenResponse } from '@auth0/auth0-auth-js';
import type { StateData } from '../types.js';
import { updateStateData, updateStateDataForConnectionTokenSet } from './utils.js';

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

test('updateStateData - should add when state undefined - and correctly set expiresAt', () => {
  const expiresAt = Date.now() / 1000 + 500;
  const expiresAtDate = new Date(expiresAt * 1000);

  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    expiresAt: expiresAt,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', undefined, response);

   const updatedExpiresAt = updatedState.tokenSets[0]!.expiresAt;
  const updatedExpiresAtDate = new Date(updatedExpiresAt * 1000);

  expect(updatedExpiresAtDate.toISOString()).toBe(expiresAtDate.toISOString());
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

test('updateStateData - should update when tokenSets does contain a token for same audience and scope - and correctly set expiresAt', () => {
  const expiresAt = Date.now() / 1000 + 3600;
  const expiresAtDate = new Date(expiresAt * 1000);

  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [
      {
        accessToken: '<access_token>',
        scope: '<scope>',
        audience: '<audience>',
        expiresAt: Date.now() / 1000 + 500,
      },
    ],
    connectionTokenSets: [],
    user: { sub: '<sub>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_2>',
    accessToken: '<access_token_2>',
    expiresAt: expiresAt,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  const updatedExpiresAt = updatedState.tokenSets[0]!.expiresAt;
  const updatedExpiresAtDate = new Date(updatedExpiresAt * 1000);

  expect(updatedExpiresAtDate.toISOString()).toBe(expiresAtDate.toISOString());
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

test('updateStateData - should persist issuer and domain for new sessions', () => {
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', undefined, response, {
    issuer: 'https://issuer.example/',
    domain: 'auth0.local',
  });

  expect(updatedState.issuer).toBe('https://issuer.example/');
  expect(updatedState.domain).toBe('auth0.local');
});

test('updateStateData - should retain or override issuer and domain for existing sessions', () => {
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
    issuer: 'https://issuer.example/',
    domain: 'auth0.local',
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_2>',
    accessToken: '<access_token_2>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const retained = updateStateData('<audience>', initialState, response);
  expect(retained.issuer).toBe('https://issuer.example/');
  expect(retained.domain).toBe('auth0.local');

  const overridden = updateStateData('<audience>', initialState, response, {
    issuer: 'https://issuer.override/',
    domain: 'auth0.override',
  });
  expect(overridden.issuer).toBe('https://issuer.override/');
  expect(overridden.domain).toBe('auth0.override');
});
