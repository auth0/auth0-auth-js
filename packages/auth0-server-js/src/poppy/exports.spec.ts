import { TokenByCodeError } from '@auth0/auth0-auth-js';
import { describe, expect, expectTypeOf, test } from 'vitest';
import * as sdk from '../index.js';
import type {
  PoppyActClaim,
  PoppyAgentContext,
  PoppyConfig,
  PoppyContext,
  PoppyError,
  PoppyErrorCode,
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
import { createPoppyFile } from '../test-utils/poppy.js';
import { AbstractPoppyGuestStore } from './abstract-poppy-guest-store.js';
import { ServerPoppyClient } from './server-poppy-client.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';

describe('the package entry point', () => {
  test('exports ServerPoppyClient and InvalidPoppySessionError', () => {
    expect(sdk.ServerPoppyClient).toBe(ServerPoppyClient);
    expect(sdk.InvalidPoppySessionError).toBeTypeOf('function');
  });

  test('exports PoppyError and its codes', () => {
    expect(sdk.PoppyError).toBeTypeOf('function');
    expect(sdk.PoppyErrorCode).toStrictEqual({
      INVALID_GUEST: 'invalid_poppy_guest',
      INVALID_AGENT: 'invalid_poppy_agent',
      GUEST_NOT_SUPPORTED: 'poppy_guest_not_supported',
      SIGN_IN_REQUIRED: 'poppy_sign_in_required',
    });
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
    expect(sdk).not.toHaveProperty('HOST_NAME_PATTERN');
    expect(sdk).not.toHaveProperty('BROWSER_SIGN_IN_SCOPE');
    expect(sdk).not.toHaveProperty('ACT_CLAIMS');
  });

  // Types have no runtime value: `npm run typecheck` checks these.
  test('exports the Poppy types', () => {
    expectTypeOf<PoppySessionState>().toEqualTypeOf<'guest' | 'signed_in'>();
    expectTypeOf<PoppyContext>().toEqualTypeOf<{ kind: 'human' } | PoppyAgentContext>();
    expectTypeOf<PoppyVisitor['kind']>().toEqualTypeOf<'none' | 'anonymous' | 'user' | 'guest'>();
    expectTypeOf<PoppyAgentContext['kind']>().toEqualTypeOf<'agent'>();
    expectTypeOf<PoppyAgentContext['state']>().toEqualTypeOf<PoppySessionState>();
    expectTypeOf<PoppyAgentContext['sub']>().toEqualTypeOf<string>();
    expectTypeOf<PoppyAgentContext['sub_profile']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<PoppyAgentContext['act']>().toEqualTypeOf<
      PoppyActClaim & { poppy_sid: string; poppy_user_id: string }
    >();
    expectTypeOf<PoppyAgentContext['scopes']>().toEqualTypeOf<string[]>();
    expectTypeOf<PoppyAgentContext['key']>().toEqualTypeOf<string>();
    expectTypeOf<keyof PoppyAgentContext>().toEqualTypeOf<
      'kind' | 'state' | 'sub' | 'sub_profile' | 'act' | 'scopes' | 'key'
    >();
    expectTypeOf<PoppyActClaim['sub']>().toEqualTypeOf<string>();
    expectTypeOf<PoppyGuestData['tokenSets']>().toEqualTypeOf<TokenSet[]>();
    expectTypeOf<PoppyGuestData['sub']>().toEqualTypeOf<string>();
    expectTypeOf<PoppyGuestData['sub_profile']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<PoppyGuestData['act']>().toEqualTypeOf<PoppyActClaim>();
    expectTypeOf<PoppyGuestStore<{ request: string }>['get']>().toEqualTypeOf<
      (identifier: string, options?: { request: string }) => Promise<PoppyGuestData | undefined>
    >();
    expectTypeOf<PoppyOptions['config']>().toEqualTypeOf<PoppyConfig>();
    expectTypeOf<PoppyOptions['agentSessionMaxAge']>().toEqualTypeOf<number | undefined>();
    expectTypeOf<PoppySessionMember>().toEqualTypeOf<
      'act.sub' | 'act.poppy_sid' | 'act.poppy_user_id' | 'act.poppy_agent_id' | 'sub' | 'exp'
    >();
    expectTypeOf<PoppyErrorCode>().toEqualTypeOf<
      'invalid_poppy_guest' | 'invalid_poppy_agent' | 'poppy_guest_not_supported' | 'poppy_sign_in_required'
    >();
    expectTypeOf<PoppyError['code']>().toEqualTypeOf<PoppyErrorCode>();
    expectTypeOf<PoppyError['reason']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<StatelessPoppyGuestStoreOptions['cookie']>().toEqualTypeOf<PoppyGuestCookieOptions | undefined>();
    expectTypeOf<PoppyGuestCookieOptions['sameSite']>().toEqualTypeOf<'strict' | 'lax' | 'none' | undefined>();
  });
});

// The config is the file that `auth0 poppy config` writes. An app imports it or parses it, and passes it as it is.
describe('the PoppyConfig type', () => {
  test('accepts the imported JSON file of the CLI as it is, with no cast', () => {
    // `createPoppyFile()` is typed by TypeScript from the JSON file, as an import of the file is. The next line has no
    // cast: `npm run typecheck` fails when the type does not accept the file.
    const imported = createPoppyFile();
    const config: PoppyConfig = imported;

    expectTypeOf(imported).toMatchTypeOf<PoppyConfig>();
    expect(config).toBe(imported);
  });

  test('types the two members that the package reads, and nothing else', () => {
    expectTypeOf<PoppyConfig['organization']['domain']>().toEqualTypeOf<string>();
    expectTypeOf<PoppyConfig['auth']['issuer']>().toEqualTypeOf<string>();
    expectTypeOf<PoppyConfig['organization']['name']>().toEqualTypeOf<unknown>();
    expectTypeOf<PoppyConfig['auth']['scopes']>().toEqualTypeOf<unknown>();
    expectTypeOf<PoppyConfig['protocol_version']>().toEqualTypeOf<unknown>();
    expectTypeOf<PoppyConfig['web']>().toEqualTypeOf<unknown>();
  });

  // A type-level test: the `@ts-expect-error` lines are the assertions, and `npm run typecheck` enforces them. A
  // plain `vitest run` only checks that the list has five entries.
  test('needs organization.domain and auth.issuer', () => {
    const configs: PoppyConfig[] = [
      { organization: { domain: 'zepto.example' }, auth: { issuer: 'https://auth.zepto.example/' } },
      // @ts-expect-error organization.domain is required
      { organization: {}, auth: { issuer: 'https://auth.zepto.example/' } },
      // @ts-expect-error auth.issuer is required
      { organization: { domain: 'zepto.example' }, auth: {} },
      // @ts-expect-error auth is required
      { organization: { domain: 'zepto.example' } },
      // @ts-expect-error the domain is a string
      { organization: { domain: 1 }, auth: { issuer: 'https://auth.zepto.example/' } },
    ];

    expect(configs).toHaveLength(5);
  });
});

describe('InvalidPoppySessionError', () => {
  test('sets name and code', () => {
    const error = new sdk.InvalidPoppySessionError('act.sub');

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('InvalidPoppySessionError');
    expect(error.code).toBe('invalid_poppy_session');
  });

  test.each(['act.sub', 'act.poppy_sid', 'act.poppy_user_id', 'act.poppy_agent_id', 'sub', 'exp'] as const)(
    'keeps the claim it names as member %s',
    (member) => {
      expect(new sdk.InvalidPoppySessionError(member).member).toBe(member);
    }
  );

  test.each(['act.sub', 'act.poppy_sid', 'act.poppy_user_id', 'act.poppy_agent_id', 'sub', 'exp'] as const)(
    'names %s in a fixed message',
    (member) => {
      expect(new sdk.InvalidPoppySessionError(member).message).toBe(
        `The ID token does not hold a well-formed Poppy Session: ${member} is invalid.`
      );
    }
  );
});
