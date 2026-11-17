import { describe, expect, test } from 'vitest';
import { CIMD_URL, GUEST_SUB, SESSION_KEY, agentAct, agentContext } from '../test-utils/poppy.js';
import { buildAgentContext, splitScopes } from './agent-context.js';
import type { PoppySessionAct } from './claims.js';

const act = (overrides: Record<string, unknown> = {}) => agentAct(overrides) as PoppySessionAct;

describe('splitScopes', () => {
  test.each([
    { name: 'one scope', scope: 'openid', scopes: ['openid'] },
    {
      name: 'scopes in the order that the string has them',
      scope: 'orders:read openid checkout',
      scopes: ['orders:read', 'openid', 'checkout'],
    },
    { name: 'a double space, without an empty scope', scope: 'openid  profile', scopes: ['openid', 'profile'] },
    { name: 'a space at either end, without an empty scope', scope: ' openid profile ', scopes: ['openid', 'profile'] },
    { name: 'an empty string', scope: '', scopes: [] },
    { name: 'a string of spaces', scope: '   ', scopes: [] },
    { name: 'no scope', scope: undefined, scopes: [] },
  ])('gives $scopes for $name', ({ scope, scopes }) => {
    expect(splitScopes(scope)).toStrictEqual(scopes);
  });

  test('gives a new list on each call', () => {
    expect(splitScopes('openid')).not.toBe(splitScopes('openid'));
    expect(splitScopes(undefined)).not.toBe(splitScopes(undefined));
  });
});

describe('buildAgentContext', () => {
  test('builds the context of a guest from the claims of the join, with the key of the Session', async () => {
    const context = await buildAgentContext(
      'guest',
      { sub: GUEST_SUB, sub_profile: 'urn:auth0:anonymous_user', act: act() },
      []
    );

    expect(context).toStrictEqual(agentContext('guest'));
    expect(context.key).toBe(SESSION_KEY);
  });

  test('builds the context of a signed-in agent with the scopes that it is given', async () => {
    const context = await buildAgentContext('signed_in', { sub: 'auth0|ana', act: act() }, ['openid', 'profile']);

    expect(context).toStrictEqual(agentContext('signed_in'));
  });

  test('keeps the whole act, with the members that it does not know and an act inside it', async () => {
    const whole = act({ client_id: 'web_app_client', extension: { tags: ['a'] }, act: { sub: CIMD_URL } });

    const context = await buildAgentContext('signed_in', { sub: 'auth0|ana', act: whole }, []);

    expect(context.act).toStrictEqual(whole);
  });

  test('copies the act and the scopes, so a change to the context reaches neither', async () => {
    const source = { sub: 'auth0|ana', act: act({ extension: { tags: ['a'] } }) };
    const scopes = ['openid'];

    const context = await buildAgentContext('signed_in', source, scopes);
    context.act.sub = 'https://evil.example/agent.json';
    (context.act.extension as { tags: string[] }).tags.push('b');
    context.scopes.push('admin');

    expect(source.act).toStrictEqual(act({ extension: { tags: ['a'] } }));
    expect(scopes).toStrictEqual(['openid']);
  });

  test.each([
    { name: 'a string', subProfile: 'urn:example:member', kept: true },
    { name: 'a list', subProfile: ['urn:example:member'], kept: false },
    { name: 'a number', subProfile: 7, kept: false },
    { name: 'null', subProfile: null, kept: false },
    { name: 'undefined', subProfile: undefined, kept: false },
  ])('has the sub_profile only when it is a string: $name', async ({ subProfile, kept }) => {
    const context = await buildAgentContext('signed_in', { sub: 'auth0|ana', sub_profile: subProfile, act: act() }, []);

    // No key at all when it is left out, and not a key with the value `undefined`.
    expect(Object.keys(context)).toEqual(
      kept
        ? ['kind', 'state', 'sub', 'sub_profile', 'act', 'scopes', 'key']
        : ['kind', 'state', 'sub', 'act', 'scopes', 'key']
    );
    expect(context.sub_profile).toBe(kept ? subProfile : undefined);
  });
});
