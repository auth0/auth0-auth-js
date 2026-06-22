import { expect, test } from 'vitest';
import { TokenResponse } from '@auth0/auth0-auth-js';
import type { StateData } from '../types.js';
import { SessionExpiredError } from '../errors.js';
import {
  updateStateData,
  updateStateDataForConnectionTokenSet,
  extractSessionExpiry,
  isSessionExpiryReached,
  isSessionExpiryInPast,
  applySessionExpiryAtLogin,
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

test('extractSessionExpiry - rejects a millisecond-scale value (would otherwise be a far-future seconds ceiling that never triggers)', () => {
  const millisecondsLikeValue = 1748566800000;
  expect(extractSessionExpiry({ session_expiry: millisecondsLikeValue } as never)).toBeUndefined();
});

test('extractSessionExpiry - accepts a plausible far-future seconds value just below the bound', () => {
  const farFutureSeconds = 9_999_999_999; // < 1e10 (10,000,000,000), year ~2286
  expect(extractSessionExpiry({ session_expiry: farFutureSeconds } as never)).toBe(farFutureSeconds);
});

test('extractSessionExpiry - rejects exactly the bound (10,000,000,000) and above', () => {
  expect(extractSessionExpiry({ session_expiry: 10_000_000_000 } as never)).toBeUndefined();
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

// --- updateStateData: the ceiling is preserve-only here; stamping/lockout live at login sites ---

test('updateStateData - does NOT stamp sessionExpiresAt on a fresh login (stamping happens at the login site)', () => {
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

  // updateStateData no longer derives the ceiling; applySessionExpiryAtLogin does.
  expect(updatedState.sessionExpiresAt).toBeUndefined();
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

test('updateStateData - preserves stored sessionExpiresAt across a refresh EVEN WHEN the response carries a session_expiry (write-once; never re-derived on refresh)', () => {
  const stored = 1_700_000_000;
  const laterCeiling = 1_900_000_000; // an Action could stamp this on a refresh grant — must be ignored
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
    claims: { iss: '<iss>', aud: '<audience>', sub: '<sub>', iat: 1_000, exp: Date.now() + 500, session_expiry: laterCeiling },
  } as unknown as TokenResponse;

  const updatedState = updateStateData('<audience>', initialState, response);

  // The refresh response's session_expiry must NOT push the ceiling out.
  expect(updatedState.sessionExpiresAt).toBe(stored);
});

// --- isSessionExpiryInPast: the login-site lockout predicate ---

test('isSessionExpiryInPast - undefined ceiling is never in the past', () => {
  expect(isSessionExpiryInPast(undefined)).toBe(false);
  expect(isSessionExpiryInPast(undefined, 1000)).toBe(false);
});

test('isSessionExpiryInPast - ceiling at or before iat is in the past (born expired)', () => {
  const iat = 1_000_000;
  expect(isSessionExpiryInPast(iat, iat)).toBe(true);
  expect(isSessionExpiryInPast(iat - 1, iat)).toBe(true);
});

test('isSessionExpiryInPast - ceiling within the leeway window of iat counts as past', () => {
  const iat = 1_000_000;
  expect(isSessionExpiryInPast(iat + SESSION_EXPIRY_LEEWAY, iat)).toBe(true);
  expect(isSessionExpiryInPast(iat + SESSION_EXPIRY_LEEWAY + 1, iat)).toBe(false);
});

test('isSessionExpiryInPast - falls back to now when iat is in milliseconds (a bad iat cannot manufacture a lockout)', () => {
  const now = Math.floor(Date.now() / 1000);
  // ms iat would, if trusted, make any seconds ceiling look "in the past"; it must fall back to now.
  expect(isSessionExpiryInPast(now + 3600, Date.now())).toBe(false);
});

// --- applySessionExpiryAtLogin: extract + lockout + stamp, used by the login sites ---

const loginState = (sub = '<sub>'): StateData => ({
  idToken: '<id_token>',
  refreshToken: '<refresh_token>',
  tokenSets: [{ accessToken: '<access_token>', scope: '<scope>', audience: '<audience>', expiresAt: Date.now() + 500 }],
  connectionTokenSets: [],
  user: { sub, iss: '<iss>' },
  internal: { sid: '<sid>', createdAt: Date.now() },
});

test('applySessionExpiryAtLogin - stamps sessionExpiresAt from the claim', () => {
  const iat = Math.floor(Date.now() / 1000);
  const stamped = applySessionExpiryAtLogin(loginState(), {
    iss: '<iss>',
    aud: '<audience>',
    sub: '<sub>',
    iat,
    exp: iat + 500,
    session_expiry: iat + 3600,
  } as never);

  expect(stamped.sessionExpiresAt).toBe(iat + 3600);
});

test('applySessionExpiryAtLogin - leaves sessionExpiresAt undefined when the claim is absent (non-breaking)', () => {
  const iat = Math.floor(Date.now() / 1000);
  const stamped = applySessionExpiryAtLogin(loginState(), {
    iss: '<iss>',
    aud: '<audience>',
    sub: '<sub>',
    iat,
    exp: iat + 500,
  } as never);

  expect(stamped.sessionExpiresAt).toBeUndefined();
});

test('applySessionExpiryAtLogin - throws SessionExpiredError when session_expiry is at or before iat', () => {
  const iat = Math.floor(Date.now() / 1000);
  expect(() =>
    applySessionExpiryAtLogin(loginState(), {
      iss: '<iss>',
      aud: '<audience>',
      sub: '<sub>',
      iat,
      exp: iat + 500,
      session_expiry: iat,
    } as never)
  ).toThrow(SessionExpiredError);
});

test('applySessionExpiryAtLogin - throws falling back to now when iat is absent', () => {
  const now = Math.floor(Date.now() / 1000);
  expect(() =>
    applySessionExpiryAtLogin(loginState(), {
      iss: '<iss>',
      aud: '<audience>',
      sub: '<sub>',
      exp: now + 500,
      session_expiry: now - 10,
    } as never)
  ).toThrow(SessionExpiredError);
});

test('applySessionExpiryAtLogin - re-login UPDATES a preserved ceiling (login site overwrites)', () => {
  const stored = 1_700_000_000;
  const next = 1_900_000_000;
  // simulate the login-site composition: updateStateData (preserves stored) then stamp from new claim
  const preserved = { ...loginState(), sessionExpiresAt: stored };
  const restamped = applySessionExpiryAtLogin(preserved, {
    iss: '<iss>',
    aud: '<audience>',
    sub: '<sub>',
    iat: 1_000,
    exp: Date.now() + 500,
    session_expiry: next,
  } as never);

  expect(restamped.sessionExpiresAt).toBe(next);
});

test('applySessionExpiryAtLogin - re-login through a no-ceiling connection CLEARS a preserved ceiling', () => {
  const stored = 1_900_000_000;
  const preserved = { ...loginState(), sessionExpiresAt: stored };
  const restamped = applySessionExpiryAtLogin(preserved, {
    iss: '<iss>',
    aud: '<audience>',
    sub: '<sub>',
    iat: 1_000,
    exp: Date.now() + 500,
    // no session_expiry — the new login asserts no ceiling
  } as never);

  expect(restamped.sessionExpiresAt).toBeUndefined();
});

test('updateStateData + applySessionExpiryAtLogin - different-user re-login yields a fresh ceiling, not the stale one', () => {
  const stale = 1_000_000;
  const fresh = 1_900_000_000;
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

  // login-site composition: updateStateData wipes on sub mismatch, then the claim is stamped
  const merged = updateStateData('<audience>', initialState, response);
  const updatedState = applySessionExpiryAtLogin(merged, response.claims);

  expect(updatedState.user!.sub).toBe('<different_sub>');
  expect(updatedState.sessionExpiresAt).toBe(fresh);
});
