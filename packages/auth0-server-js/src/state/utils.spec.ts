import { expect, test } from 'vitest';
import { TokenResponse } from '@auth0/auth0-auth-js';
import type { StateData } from '../types.js';
import { SessionExpiredError } from '../errors.js';
import {
  updateStateData,
  updateStateDataForConnectionTokenSet,
  extractSessionExpiry,
  isSessionExpiryReached,
  SESSION_EXPIRY_LEEWAY,
} from './utils.js';

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

test('updateStateData - should preserve existing idToken when response does not include one', () => {
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
    accessToken: '<access_token_2>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.idToken).toBe('<id_token>');
  expect(updatedState.refreshToken).toBe('<refresh_token>');
  expect(updatedState.user!.sub).toBe('<sub>');

  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.audience).toBe('<audience>');
  expect(updatedState.tokenSets[0]!.scope).toBe('<scope>');
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token_2>');
});

test('updateStateData - should wipe state and create fresh session when sub does not match', () => {
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
    user: { sub: '<sub>', iss: '<iss>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_new>',
    accessToken: '<access_token_new>',
    refreshToken: '<refresh_token_new>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<different_sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  // Should be a fresh session for the new user, not merged with the old one
  expect(updatedState.user!.sub).toBe('<different_sub>');
  expect(updatedState.idToken).toBe('<id_token_new>');
  expect(updatedState.refreshToken).toBe('<refresh_token_new>');
  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token_new>');
});

test('updateStateData - should wipe state and create fresh session when iss does not match', () => {
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
    user: { sub: '<sub>', iss: '<iss>' },
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_new>',
    accessToken: '<access_token_new>',
    refreshToken: '<refresh_token_new>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<different_iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  // Should be a fresh session for the new issuer, not merged with the old one
  expect(updatedState.user!.sub).toBe('<sub>');
  expect(updatedState.user!.iss).toBe('<different_iss>');
  expect(updatedState.idToken).toBe('<id_token_new>');
  expect(updatedState.refreshToken).toBe('<refresh_token_new>');
  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token_new>');
});

test('updateStateData - should merge state when iss and sub both match', () => {
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
    user: { sub: '<sub>', iss: '<iss>' },
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

  // Same user, should merge (update token set in place)
  expect(updatedState.user!.sub).toBe('<sub>');
  expect(updatedState.tokenSets.length).toBe(1);
  expect(updatedState.tokenSets[0]!.accessToken).toBe('<access_token_2>');
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

test('updateStateData - should persist domain for new sessions', () => {
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as TokenResponse;

  const updatedState = updateStateData('<audience>', undefined, response, {
    domain: 'auth0.local',
  });

  expect(updatedState.domain).toBe('auth0.local');
});

test('updateStateData - should retain or override domain for existing sessions', () => {
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
  expect(retained.domain).toBe('auth0.local');

  const overridden = updateStateData('<audience>', initialState, response, {
    domain: 'auth0.override',
  });
  expect(overridden.domain).toBe('auth0.override');
});

test('extractSessionExpiry - returns the value for a positive integer', () => {
  expect(extractSessionExpiry({ session_expiry: 1748566800 } as never)).toBe(1748566800);
});

test('extractSessionExpiry - returns undefined when the claim is absent', () => {
  expect(extractSessionExpiry({ sub: '<sub>' } as never)).toBeUndefined();
  expect(extractSessionExpiry(undefined)).toBeUndefined();
});

test('extractSessionExpiry - returns undefined for invalid shapes (fail-open)', () => {
  expect(extractSessionExpiry({ session_expiry: '1748566800' } as never)).toBeUndefined(); // string
  expect(extractSessionExpiry({ session_expiry: 1748566800.5 } as never)).toBeUndefined(); // float
  expect(extractSessionExpiry({ session_expiry: 0 } as never)).toBeUndefined(); // zero
  expect(extractSessionExpiry({ session_expiry: -5 } as never)).toBeUndefined(); // negative
  expect(extractSessionExpiry({ session_expiry: Number.NaN } as never)).toBeUndefined(); // NaN
});

test('extractSessionExpiry - accepts a far-future integer (documents the milliseconds limitation: ms values look like valid far-future seconds and are NOT rejected)', () => {
  const millisecondsLikeValue = 1748566800000;
  expect(extractSessionExpiry({ session_expiry: millisecondsLikeValue } as never)).toBe(millisecondsLikeValue);
});

test('isSessionExpiryReached - undefined ceiling means no ceiling (never reached)', () => {
  expect(isSessionExpiryReached(undefined)).toBe(false);
});

test('isSessionExpiryReached - false when now is well before the ceiling', () => {
  const now = 1_000_000;
  expect(isSessionExpiryReached(now + 3600, now)).toBe(false);
});

test('isSessionExpiryReached - true when now is past the ceiling', () => {
  const now = 1_000_000;
  expect(isSessionExpiryReached(now - 1, now)).toBe(true);
});

test('isSessionExpiryReached - true within the negative leeway window (expires early for clock skew)', () => {
  const now = 1_000_000;
  // ceiling is 10s in the future, but leeway is 30s, so it is already considered reached
  expect(isSessionExpiryReached(now + 10, now)).toBe(true);
});

test('isSessionExpiryReached - true exactly at ceiling minus leeway (boundary inclusive)', () => {
  const now = 1_000_000;
  expect(isSessionExpiryReached(now + SESSION_EXPIRY_LEEWAY, now)).toBe(true);
});

test('isSessionExpiryReached - false just before the leeway boundary', () => {
  const now = 1_000_000;
  expect(isSessionExpiryReached(now + SESSION_EXPIRY_LEEWAY + 1, now)).toBe(false);
});

test('updateStateData - stamps sessionExpiresAt on a fresh login when the claim is present', () => {
  const iat = Math.floor(Date.now() / 1000);
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    expiresAt: iat + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat, exp: iat + 500, session_expiry: iat + 3600 },
  } as unknown as TokenResponse;

  const updatedState = updateStateData('<audience>', undefined, response);

  expect(updatedState.sessionExpiresAt).toBe(iat + 3600);
});

test('updateStateData - leaves sessionExpiresAt undefined on a fresh login when the claim is absent (non-breaking)', () => {
  const iat = Math.floor(Date.now() / 1000);
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    expiresAt: iat + 500,
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat, exp: iat + 500 },
  } as unknown as TokenResponse;

  const updatedState = updateStateData('<audience>', undefined, response);

  expect(updatedState.sessionExpiresAt).toBeUndefined();
});

test('updateStateData - throws SessionExpiredError when session_expiry is at or before iat (lockout guard)', () => {
  const iat = Math.floor(Date.now() / 1000);
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    expiresAt: iat + 500,
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat, exp: iat + 500, session_expiry: iat },
  } as unknown as TokenResponse;

  expect(() => updateStateData('<audience>', undefined, response)).toThrow(SessionExpiredError);
});

test('updateStateData - lockout guard falls back to now when iat is absent', () => {
  const now = Math.floor(Date.now() / 1000);
  const response = {
    idToken: '<id_token>',
    accessToken: '<access_token>',
    expiresAt: now + 500,
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', exp: now + 500, session_expiry: now - 10 },
  } as unknown as TokenResponse;

  expect(() => updateStateData('<audience>', undefined, response)).toThrow(SessionExpiredError);
});

test('updateStateData - preserves stored sessionExpiresAt across a refresh that lacks the claim', () => {
  const stored = Math.floor(Date.now() / 1000) + 3600;
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [{ accessToken: '<access_token>', scope: '<scope>', audience: '<audience>', expiresAt: Date.now() + 500 }],
    connectionTokenSets: [],
    user: { sub: '<sub>', iss: '<iss>' },
    sessionExpiresAt: stored,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_2>',
    accessToken: '<access_token_2>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: Date.now(), exp: Date.now() + 500 },
  } as unknown as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.sessionExpiresAt).toBe(stored);
});

test('updateStateData - updates sessionExpiresAt when a same-user re-login carries a new claim', () => {
  const stored = 1_000_000;
  const next = 2_000_000;
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [{ accessToken: '<access_token>', scope: '<scope>', audience: '<audience>', expiresAt: Date.now() + 500 }],
    connectionTokenSets: [],
    user: { sub: '<sub>', iss: '<iss>' },
    sessionExpiresAt: stored,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_2>',
    accessToken: '<access_token_2>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: 1_000, exp: Date.now() + 500, session_expiry: next },
  } as unknown as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.sessionExpiresAt).toBe(next);
});

test('updateStateData - different-user re-login yields a fresh ceiling, not the stale one', () => {
  const stale = 1_000_000;
  const fresh = 2_000_000;
  const initialState: StateData = {
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [{ accessToken: '<access_token>', scope: '<scope>', audience: '<audience>', expiresAt: Date.now() + 500 }],
    connectionTokenSets: [],
    user: { sub: '<sub>', iss: '<iss>' },
    sessionExpiresAt: stale,
    internal: { sid: '<sid>', createdAt: Date.now() },
  };

  const response = {
    idToken: '<id_token_new>',
    accessToken: '<access_token_new>',
    refreshToken: '<refresh_token_new>',
    expiresAt: Date.now() / 1000 + 500,
    scope: '<scope>',
    claims: { iss: '<iss>', aud: '<audience>', sub: '<different_sub>', iat: 1_000, exp: Date.now() + 500, session_expiry: fresh },
  } as unknown as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  expect(updatedState.user!.sub).toBe('<different_sub>');
  expect(updatedState.sessionExpiresAt).toBe(fresh);
});
