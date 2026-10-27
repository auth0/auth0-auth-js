import { describe, expect, test } from 'vitest';

import * as pkg from './index.js';
import { ApiClient as DirectApiClient } from './api-client.js';
import { getCurrentActor as directGetCurrentActor, getDelegationChain as directGetDelegationChain } from './act.js';
import { getToken as directGetToken } from './token.js';
import {
  MissingClientAuthError as BaseMissingClientAuthError,
  TokenExchangeError as BaseTokenExchangeError,
  InvalidScopeError as BaseInvalidScopeError,
} from '@auth0/auth0-auth-js';
import {
  InvalidRequestError,
  MissingTransactionError,
  VerifyAccessTokenError,
} from './errors.js';
import { ProtectedResourceMetadataBuilder, BearerMethod } from './protected-resource-metadata.js';
import type {
  CachedToken,
  IndexedTokenStore,
  OnBehalfOfTokenContext,
  OboCacheKeyIdentity,
  TokenIndexMember,
  TokenSet,
  TokenStore,
  VerifiedToken,
} from './index.js';

describe('index exports', () => {
  test('re-exports ApiClient', () => {
    expect(pkg.ApiClient).toBe(DirectApiClient);
  });

  test('re-exports getToken', () => {
    expect(pkg.getToken).toBe(directGetToken);
    expect(typeof pkg.getToken).toBe('function');
  });

  test('re-exports act helpers', () => {
    expect(pkg.getCurrentActor).toBe(directGetCurrentActor);
    expect(pkg.getDelegationChain).toBe(directGetDelegationChain);
  });

  test('re-exports InvalidScopeError from auth0-auth-js', () => {
    expect(pkg.InvalidScopeError).toBe(BaseInvalidScopeError);
  });

  test('re-exports errors from this package', () => {
    expect(pkg.InvalidRequestError).toBe(InvalidRequestError);
    expect(pkg.MissingTransactionError).toBe(MissingTransactionError);
    expect(pkg.VerifyAccessTokenError).toBe(VerifyAccessTokenError);
  });

  test('MissingTransactionError uses default message', () => {
    const err = new MissingTransactionError();
    expect(err.message).toBe('The transaction is missing.');
    expect(err.code).toBe('missing_transaction_error');
  });

  test('re-exports auth0-auth-js errors', () => {
    expect(pkg.MissingClientAuthError).toBe(BaseMissingClientAuthError);
    expect(pkg.TokenExchangeError).toBe(BaseTokenExchangeError);
  });

  test('re-exports protected resource metadata helpers', () => {
    expect(pkg.ProtectedResourceMetadataBuilder).toBe(ProtectedResourceMetadataBuilder);
    expect(pkg.BearerMethod).toBe(BearerMethod);
  });

  describe('on behalf of cache surface', () => {
    const identity: OboCacheKeyIdentity = {
      exchangeTenant: 'https://tenant.example.com',
      exchangeClientId: 'client-id',
      exchangeAudience: 'https://api.example.com',
      verified: {
        accessToken: 'subject-token',
        claims: { iss: 'https://tenant.example.com/', sub: 'user-1' },
      },
      requestedAudience: 'https://downstream.example.com',
    };

    test('exports the scope and key helpers as functions', () => {
      expect(typeof pkg.normalizeScopes).toBe('function');
      expect(typeof pkg.buildOboTokenKey).toBe('function');
      expect(typeof pkg.buildOboIndexKey).toBe('function');
    });

    test('normalizeScopes is callable through the entry point', () => {
      expect(pkg.normalizeScopes('b a')).toEqual(['a', 'b']);
    });

    test('buildOboTokenKey is callable through the entry point', async () => {
      const key = await pkg.buildOboTokenKey({ ...identity, layout: 'strict', scope: 'b a' });
      expect(typeof key).toBe('string');
      expect(key).toMatch(/^a0\.obo\.v1\.strict\./);
    });

    test('buildOboIndexKey is callable through the entry point', async () => {
      const key = await pkg.buildOboIndexKey(identity);
      expect(typeof key).toBe('string');
      expect(key).toMatch(/^a0\.obo\.index\.v1\./);
    });
  });

  // The assignments below are compile-time shape checks. They are verified by `tsc`, not
  // by the runtime assertions, so a field that is renamed or dropped from the public type
  // fails the typecheck. `TokenSet` is declared once and exported explicitly while
  // `export * from './types.js'` is also present, so a second declaration of the same name
  // would change the public shape without any error at the entry point.
  describe('public type shapes', () => {
    test('TokenSet carries accessToken, expiresAt, scope and tokenType', () => {
      const tokenSet: TokenSet = {
        accessToken: 'access-token',
        expiresAt: 1_700_000_000,
        scope: 'read:data',
        tokenType: 'bearer',
      };
      expect(tokenSet.accessToken).toBe('access-token');
    });

    test('CachedToken extends TokenSet with grantedScopes and issuedTokenType', () => {
      const cached: CachedToken = {
        accessToken: 'access-token',
        expiresAt: 1_700_000_000,
        scope: 'read:data',
        tokenType: 'bearer',
        grantedScopes: ['read:data'],
        issuedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      };
      const asTokenSet: TokenSet = cached;
      expect(asTokenSet.accessToken).toBe('access-token');
    });

    test('VerifiedToken carries accessToken and claims', () => {
      const verified: VerifiedToken = { accessToken: 'access-token', claims: { sub: 'user-1' } };
      expect(verified.claims.sub).toBe('user-1');
    });

    test('TokenStore has get, set and delete', () => {
      const store: TokenStore = {
        get: async () => undefined,
        set: async () => undefined,
        delete: async () => undefined,
      };
      expect(typeof store.get).toBe('function');
    });

    test('IndexedTokenStore adds addIndexMember and listIndexMembers to TokenStore', () => {
      const store: IndexedTokenStore = {
        get: async () => undefined,
        set: async () => undefined,
        delete: async () => undefined,
        addIndexMember: async () => undefined,
        listIndexMembers: async () => [],
      };
      const asTokenStore: TokenStore = store;
      expect(typeof asTokenStore.get).toBe('function');
    });

    test('TokenIndexMember carries tokenKey, grantedScopes and expiresAt', () => {
      const member: TokenIndexMember = {
        tokenKey: 'a0.obo.v1.index.key',
        grantedScopes: ['read:data'],
        expiresAt: 1_700_000_000,
      };
      expect(member.tokenKey).toBe('a0.obo.v1.index.key');
    });

    test('OnBehalfOfTokenContext carries optional store and verified', () => {
      const context: OnBehalfOfTokenContext = {
        store: {
          get: async () => undefined,
          set: async () => undefined,
          delete: async () => undefined,
        },
        verified: { accessToken: 'access-token', claims: {} },
      };
      expect(context.verified?.accessToken).toBe('access-token');
    });
  });

  // These symbols were deliberately removed from this package. `OrganizationPolicy` is a
  // type, and a type has no runtime presence, so it cannot be probed here; its removal is
  // enforced by the typecheck of any consumer that still imports it.
  describe('removed exports', () => {
    test.each(['DownscopedTokenError'])(
      'does not export %s',
      (name) => {
        expect(Object.keys(pkg)).not.toContain(name);
        expect(name in pkg).toBe(false);
      }
    );
  });
});
