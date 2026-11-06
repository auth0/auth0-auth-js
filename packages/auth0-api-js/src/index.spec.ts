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
import { InvalidSessionError, PoppyUnavailableError, SessionEndedError, SignInRequiredError } from './poppy/errors.js';
import { toHttpErrorResponse } from './poppy/http-error-response.js';
import { PoppySessionStore } from './poppy/session-store.js';
import type {
  ApiClientOptions,
  CachedToken,
  HttpErrorResponse,
  IndexedTokenStore,
  OnBehalfOfTokenContext,
  OboCacheKeyIdentity,
  PoppyOptions,
  PoppySession,
  PoppySessionRecord,
  TokenIndexMember,
  TokenSet,
  TokenStore,
  VerifiedPoppyRequest,
  VerifiedToken,
  VerifyPoppyRequestOptions,
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

  describe('Poppy surface', () => {
    test('re-exports the Poppy errors, the Session store and the error mapper', () => {
      expect(pkg.InvalidSessionError).toBe(InvalidSessionError);
      expect(pkg.SessionEndedError).toBe(SessionEndedError);
      expect(pkg.SignInRequiredError).toBe(SignInRequiredError);
      expect(pkg.PoppyUnavailableError).toBe(PoppyUnavailableError);
      expect(pkg.PoppySessionStore).toBe(PoppySessionStore);
      expect(pkg.toHttpErrorResponse).toBe(toHttpErrorResponse);
    });

    test('the Poppy errors extend the exported AuthError', () => {
      const errors = [
        new pkg.InvalidSessionError('missing_session'),
        new pkg.SessionEndedError(),
        new pkg.SignInRequiredError({ scope: 'orders:write' }),
        new pkg.PoppyUnavailableError(),
      ];
      for (const error of errors) {
        expect(error).toBeInstanceOf(pkg.AuthError);
      }
    });

    test('toHttpErrorResponse is callable through the entry point', () => {
      expect(pkg.toHttpErrorResponse(new pkg.SessionEndedError())?.status).toBe(400);
      expect(pkg.toHttpErrorResponse(new Error('not an AuthError'))).toBeUndefined();
    });

    test('does not export the internal Poppy constants', () => {
      expect(Object.keys(pkg)).not.toContain('INVALID_SESSION_MESSAGES');
      expect(Object.keys(pkg)).not.toContain('ACT_CLAIMS');
    });
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

    test('PoppyOptions is accepted by both ApiClientOptions variants', () => {
      const poppy: PoppyOptions = {
        config: {
          issuer: 'https://example.auth0.com/',
          apis: [{ identifier: 'https://api.example.com', public_origin: 'https://api.example.com' }],
          agents: ['https://agent.example/agent.json'],
        },
        verifySession: true,
        agents: ['https://agent.example/agent.json'],
        agentClientIdClaims: ['client_id', 'azp'],
        iatWindow: 60,
        baseUrl: 'https://api.example.com',
        agentMetadata: {
          fetch: globalThis.fetch,
          cache: { ttl: 600, maxEntries: 100 },
          timeoutMs: 5000,
          maxBytes: 65536,
          allowPrivateAddresses: false,
        },
      };
      const withDomain: ApiClientOptions = { domain: 'example.auth0.com', audience: 'https://api.example.com', poppy };
      const withDomains: ApiClientOptions = {
        domains: ['example.auth0.com'],
        audience: 'https://api.example.com',
        poppy,
      };

      expect(withDomain.poppy).toBe(poppy);
      expect(withDomains.poppy).toBe(poppy);
    });

    test('PoppySessionStore is extended with get and set', async () => {
      class MemoryPoppySessionStore extends PoppySessionStore {
        readonly #records = new Map<string, PoppySessionRecord>();

        async get(key: string): Promise<PoppySessionRecord | undefined> {
          return this.#records.get(key);
        }

        async set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord> {
          const stored = this.#records.get(key) ?? record;
          this.#records.set(key, stored);
          return stored;
        }
      }
      const poppy: PoppyOptions = { sessionStore: new MemoryPoppySessionStore() };

      expect(poppy.sessionStore).toBeInstanceOf(PoppySessionStore);
      expect(await poppy.sessionStore?.get('unknown')).toBeUndefined();
    });

    test('VerifyPoppyRequestOptions and VerifiedPoppyRequest carry the request and the verified Session', () => {
      const request: VerifyPoppyRequestOptions = {
        method: 'POST',
        url: 'https://api.example.com/orders',
        headers: { 'poppy-session': 'a.b.c', authorization: undefined, accept: ['application/json'] },
        requireSession: true,
      };
      const poppy: PoppySession = {
        sessionId: 'Yx2b7Qd_Kp8mR3vT1nWc4A',
        key: 'opaque-key',
        userId: 'usr_Q7c1vK',
        agent: { cimdUrl: 'https://agent.example/agent.json', poppyAgentId: 'agt_1' },
        state: 'signed_in',
        source: 'header',
      };
      const verified: VerifiedPoppyRequest = { poppy, claims: { sub: 'usr_Q7c1vK' } };
      const signedOut: VerifiedPoppyRequest = {};

      expect(request.requireSession).toBe(true);
      expect(verified.poppy?.agent.cimdUrl).toBe('https://agent.example/agent.json');
      expect(signedOut.poppy).toBeUndefined();
    });

    test('HttpErrorResponse carries a status, headers and an optional body', () => {
      const response: HttpErrorResponse = {
        status: 400,
        headers: { 'x-one': 'a', 'x-many': ['a', 'b'] },
        body: { error: 'invalid_session', error_description: 'The Session is not valid.' },
      };
      const withoutBody: HttpErrorResponse = { status: 401, headers: {} };

      expect(response.body?.error).toBe('invalid_session');
      expect(withoutBody.body).toBeUndefined();
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
