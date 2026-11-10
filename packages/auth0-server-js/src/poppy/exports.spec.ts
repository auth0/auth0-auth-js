import { TokenByCodeError } from '@auth0/auth0-auth-js';
import { describe, expect, expectTypeOf, test } from 'vitest';
import * as sdk from '../index.js';
import type {
  PoppyActClaim,
  PoppyAgent,
  PoppyAgentContext,
  PoppyConfig,
  PoppyContext,
  PoppyGuestCookieOptions,
  PoppyGuestData,
  PoppyGuestStore,
  PoppyOptions,
  PoppySessionMember,
  PoppySessionState,
  PoppyVisitor,
  StatelessPoppyGuestStoreOptions,
  TokenSet,
} from '../index.js';
import { AbstractPoppyGuestStore } from './abstract-poppy-guest-store.js';
import { ServerPoppyClient } from './server-poppy-client.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';

describe('the package entry point', () => {
  test('exports ServerPoppyClient and InvalidPoppySessionError', () => {
    expect(sdk.ServerPoppyClient).toBe(ServerPoppyClient);
    expect(sdk.InvalidPoppySessionError).toBeTypeOf('function');
  });

  test('exports both guest stores', () => {
    expect(sdk.AbstractPoppyGuestStore).toBe(AbstractPoppyGuestStore);
    expect(sdk.StatelessPoppyGuestStore).toBe(StatelessPoppyGuestStore);
  });

  // An app tells a refused callback, such as a session conflict, from other errors with this class.
  test('exports TokenByCodeError', () => {
    expect(sdk.TokenByCodeError).toBe(TokenByCodeError);
  });

  test('does not export the internals', () => {
    expect(sdk).not.toHaveProperty('resolvePoppyOptions');
    expect(sdk).not.toHaveProperty('PROTOCOL_VERSION_PATTERN');
    expect(sdk).not.toHaveProperty('ACT_CLAIMS');
  });

  // Types have no runtime value: `npm run typecheck` checks these.
  test('exports the Poppy types', () => {
    expectTypeOf<PoppySessionState>().toEqualTypeOf<'signed_out' | 'signed_in'>();
    expectTypeOf<PoppyContext>().toEqualTypeOf<{ kind: 'human' } | PoppyAgentContext>();
    expectTypeOf<PoppyVisitor['kind']>().toEqualTypeOf<'none' | 'anonymous' | 'user' | 'guest'>();
    expectTypeOf<PoppyAgentContext['kind']>().toEqualTypeOf<'agent'>();
    expectTypeOf<PoppyAgentContext['agent']>().toEqualTypeOf<PoppyAgent>();
    expectTypeOf<PoppyActClaim['sub']>().toEqualTypeOf<string>();
    expectTypeOf<PoppyGuestData['tokenSets']>().toEqualTypeOf<TokenSet[]>();
    expectTypeOf<PoppyGuestStore<{ request: string }>['get']>().toEqualTypeOf<
      (identifier: string, options?: { request: string }) => Promise<PoppyGuestData | undefined>
    >();
    expectTypeOf<PoppyOptions['config']>().toEqualTypeOf<PoppyConfig>();
    expectTypeOf<PoppyOptions['agentSessionMaxAge']>().toEqualTypeOf<number | undefined>();
    expectTypeOf<PoppySessionMember>().toEqualTypeOf<
      'act.sub' | 'act.poppy_sid' | 'act.poppy_user_id' | 'act.poppy_agent_id'
    >();
    expectTypeOf<StatelessPoppyGuestStoreOptions['cookie']>().toEqualTypeOf<PoppyGuestCookieOptions | undefined>();
    expectTypeOf<PoppyGuestCookieOptions['sameSite']>().toEqualTypeOf<'strict' | 'lax' | 'none' | undefined>();
  });
});

describe('InvalidPoppySessionError', () => {
  test('sets name and code', () => {
    const error = new sdk.InvalidPoppySessionError('act.sub');

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('InvalidPoppySessionError');
    expect(error.code).toBe('invalid_poppy_session');
  });

  test.each(['act.sub', 'act.poppy_sid', 'act.poppy_user_id', 'act.poppy_agent_id'] as const)(
    'names %s in a fixed message',
    (member) => {
      expect(new sdk.InvalidPoppySessionError(member).message).toBe(
        `The ID token's act claim does not hold a well-formed Poppy Session: ${member} is invalid.`
      );
    }
  );
});
