import { describe, expect, test } from 'vitest';

import { InvalidRequestError } from './errors.js';
import { getCurrentActor, getDelegationChain } from './act.js';
import type { VerifiedAccessTokenClaims } from './types.js';

describe('act helpers', () => {
  test('getCurrentActor returns undefined when act is missing', () => {
    const claims: VerifiedAccessTokenClaims = {
      sub: 'auth0|user123',
    };

    expect(getCurrentActor(claims)).toBeUndefined();
  });

  test('getDelegationChain returns an empty array when act is missing', () => {
    const claims: VerifiedAccessTokenClaims = {
      sub: 'auth0|user123',
    };

    expect(getDelegationChain(claims)).toEqual([]);
  });

  test('getCurrentActor returns the outermost act.sub', () => {
    const claims: VerifiedAccessTokenClaims = {
      sub: 'auth0|user123',
      act: {
        sub: 'mcp_server_2_client_id',
        act: {
          sub: 'mcp_server_1_client_id',
          act: {
            sub: 'spa_client_id',
          },
        },
      },
    };

    expect(getCurrentActor(claims)).toBe('mcp_server_2_client_id');
  });

  test('getDelegationChain returns actors from newest to oldest', () => {
    const claims: VerifiedAccessTokenClaims = {
      sub: 'auth0|user123',
      act: {
        sub: 'mcp_server_2_client_id',
        act: {
          sub: 'mcp_server_1_client_id',
          act: {
            sub: 'spa_client_id',
          },
        },
      },
    };

    expect(getDelegationChain(claims)).toEqual([
      'mcp_server_2_client_id',
      'mcp_server_1_client_id',
      'spa_client_id',
    ]);
  });

  test('throws when act is not an object', () => {
    expect(() =>
      getCurrentActor({
        act: 'invalid',
      } as unknown as VerifiedAccessTokenClaims)
    ).toThrowError(InvalidRequestError);
  });

  test('throws when act.sub is missing', () => {
    expect(() =>
      getCurrentActor({
        act: {},
      } as unknown as VerifiedAccessTokenClaims)
    ).toThrowError('Invalid "act" claim: "act.sub" must be a non-empty string');
  });

  test('throws when nested act is malformed', () => {
    expect(() =>
      getDelegationChain({
        act: {
          sub: 'mcp_server_client_id',
          act: [],
        },
      } as unknown as VerifiedAccessTokenClaims)
    ).toThrowError('Invalid "act" claim: "act.act" must be an object');
  });

  test('throws when act contains a circular structure', () => {
    const act = { sub: 'mcp_server_client_id' } as { sub: string; act?: unknown };
    act.act = act;

    expect(() =>
      getDelegationChain({
        act,
      } as unknown as VerifiedAccessTokenClaims)
    ).toThrowError('Invalid "act" claim: circular structures are not supported');
  });
});
