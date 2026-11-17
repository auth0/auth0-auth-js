import { describe, expect, test } from 'vitest';
import { InvalidPoppySessionError } from '../errors.js';
import type { PoppySessionMember } from '../errors.js';
import { CIMD_URL, GUEST_SUB, OTHER_SESSION_ID, SESSION_ID, USER_ID, agentAct } from '../test-utils/poppy.js';
import { classifyLogin } from './classify-login.js';

type Claims = Record<string, unknown>;

const EXP = 1_790_000_000;
const ANONYMOUS = 'urn:auth0:anonymous_user';
const PERSON = 'auth0|ana';

// The claims of the ID token of a guest. `more` replaces claims, and a claim set to `undefined` is left out, as JSON has
// no `undefined`.
function claimsOf(base: Claims, more: Claims = {}): Claims {
  const claims = { ...base, ...more };

  for (const [name, value] of Object.entries(claims)) {
    if (value === undefined) {
      delete claims[name];
    }
  }

  return claims;
}

const guestClaims = (more: Claims = {}) =>
  claimsOf({ sub: GUEST_SUB, sub_profile: ANONYMOUS, act: agentAct(), exp: EXP }, more);

const agentClaims = (more: Claims = {}) => claimsOf({ sub: PERSON, act: agentAct(), exp: EXP }, more);

// The `act` as a token holds it, with members left out when they are set to `undefined`.
function actWith(overrides: Claims = {}): Claims {
  return claimsOf(agentAct(), overrides);
}

// What `classifyLogin` throws for the claims.
function failureOf(claims: Claims): unknown {
  try {
    classifyLogin(claims);
  } catch (error) {
    return error;
  }

  return undefined;
}

function expectInvalidSession(claims: Claims, member: PoppySessionMember): void {
  const error = failureOf(claims);

  expect(error).toBeInstanceOf(InvalidPoppySessionError);
  expect((error as InvalidPoppySessionError).message).toBe(new InvalidPoppySessionError(member).message);
}

describe('classifyLogin | a person', () => {
  // `poppy_sid` belongs to the prototype here, not to the claim. JSON has no such member.
  const inheritedSid = Object.assign(Object.create({ poppy_sid: SESSION_ID }) as Claims, { sub: CIMD_URL });

  const rows: Array<{ name: string; claims: Claims | undefined }> = [
    { name: 'no claims', claims: undefined },
    { name: 'a user and no act', claims: { sub: PERSON, exp: EXP } },
    { name: 'an act that is a string', claims: { sub: PERSON, exp: EXP, act: 'x' } },
    { name: 'an act that is null', claims: { sub: PERSON, exp: EXP, act: null } },
    { name: 'an act that is a list', claims: { sub: PERSON, exp: EXP, act: Object.assign([], agentAct()) } },
    // The `act` that an Action sets for a person who acts for a customer has no `poppy_sid`.
    { name: 'an act without poppy_sid', claims: { sub: PERSON, exp: EXP, act: { sub: CIMD_URL } } },
    { name: 'an act that only inherits poppy_sid', claims: { sub: PERSON, exp: EXP, act: inheritedSid } },
    // A person's claims need no `exp` or `sub` of their own to be a person's.
    { name: 'no exp and no sub', claims: {} },
    // The profile has to be one whole token, written exactly. A sub that only has the guest start inside is a user's.
    { name: 'a sub_profile that only starts with the profile', claims: { sub: PERSON, sub_profile: `${ANONYMOUS}_x` } },
    { name: 'a sub_profile with text in front of the profile', claims: { sub: PERSON, sub_profile: `x-${ANONYMOUS}` } },
    { name: 'a sub_profile in capital letters', claims: { sub: PERSON, sub_profile: ANONYMOUS.toUpperCase() } },
    { name: 'a list with an entry that only starts with the profile', claims: { sub_profile: [`${ANONYMOUS}_x`] } },
    { name: 'a sub that only has the guest start inside', claims: { sub: `auth0|${GUEST_SUB}` } },
    { name: 'a sub_profile that is a number', claims: { sub: PERSON, sub_profile: 42 } },
  ];

  test.each(rows)('is human with $name', ({ claims }) => {
    expect(classifyLogin(claims)).toStrictEqual({ kind: 'human' });
  });
});

describe('classifyLogin | a signed-in agent', () => {
  test('has the login and the exp', () => {
    expect(classifyLogin(agentClaims())).toStrictEqual({
      kind: 'agent',
      login: { sub: PERSON, act: agentAct() },
      exp: EXP,
    });
  });

  test('has the sub_profile of the token, when it is a string', () => {
    expect(classifyLogin(agentClaims({ sub_profile: 'urn:example:profile' }))).toMatchObject({
      kind: 'agent',
      login: { sub_profile: 'urn:example:profile' },
    });
    expect(classifyLogin(agentClaims({ sub_profile: ['urn:example:profile'] }))).toMatchObject({ kind: 'agent' });
    expect(classifyLogin(agentClaims({ sub_profile: ['urn:example:profile'] }))).not.toHaveProperty(
      'login.sub_profile'
    );
  });

  test('has no poppy_agent_id when the act has none', () => {
    const result = classifyLogin(agentClaims({ act: actWith({ poppy_agent_id: undefined }) }));

    expect(result).toMatchObject({ kind: 'agent' });
    expect(result.kind === 'agent' && result.login.act).not.toHaveProperty('poppy_agent_id');
  });

  test('has a copy of the act, with the members that the package does not know', () => {
    const act = { ...actWith({ x_other: { nested: [1] } }) };
    const result = classifyLogin(agentClaims({ act }));

    expect(result).toMatchObject({ kind: 'agent', login: { act } });
    expect(result.kind === 'agent' && result.login.act).not.toBe(act);
  });

  test.each([
    // The profile of a person that is not the anonymous one, in the token of a signed-in agent.
    { name: 'a sub_profile that only starts with the anonymous profile', claims: { sub_profile: `${ANONYMOUS}_x` } },
    { name: 'a sub_profile in capital letters', claims: { sub_profile: ANONYMOUS.toUpperCase() } },
  ])('is an agent for $name with a valid Poppy act', ({ claims }) => {
    expect(classifyLogin(agentClaims(claims)).kind).toBe('agent');
  });
});

describe('classifyLogin | a guest', () => {
  test('has the login and the exp', () => {
    expect(classifyLogin(guestClaims())).toStrictEqual({
      kind: 'guest',
      login: { sub: GUEST_SUB, sub_profile: ANONYMOUS, act: agentAct() },
      exp: EXP,
    });
  });

  // The profile has to be one whole token. Any run of white space separates two profiles, and white space at either end
  // hides none.
  test.each([
    // What Auth0 sends for a guest: `user` and the anonymous profile in one string.
    { name: 'user and the profile, as Auth0 sends it', value: `user ${ANONYMOUS}` },
    { name: 'the profile among others', value: `urn:example:a ${ANONYMOUS}` },
    { name: 'a tab between the profiles', value: `urn:example:a\t${ANONYMOUS}` },
    { name: 'a line break between the profiles', value: `urn:example:a\n${ANONYMOUS}` },
    { name: 'a line break after the profile', value: `${ANONYMOUS}\n` },
    { name: 'a tab after the profile', value: `${ANONYMOUS}\t` },
    { name: 'a list with the profile', value: [ANONYMOUS] },
    { name: 'a list with the profile among others', value: ['urn:example:a', ANONYMOUS] },
    { name: 'a list entry that holds two profiles', value: [`urn:example:a ${ANONYMOUS}`] },
    { name: 'a list entry with a tab between two profiles', value: [`urn:example:a\t${ANONYMOUS}`] },
  ])('is a guest with $name as the sub_profile', ({ value }) => {
    expect(classifyLogin(guestClaims({ sub_profile: value })).kind).toBe('guest');
  });

  test('has no sub_profile in the login when the claim is a list', () => {
    const result = classifyLogin(guestClaims({ sub_profile: [ANONYMOUS] }));

    expect(result.kind).toBe('guest');
    expect(result.kind === 'guest' && result.login).not.toHaveProperty('sub_profile');
  });

  test('does not need a poppy_agent_id', () => {
    expect(classifyLogin(guestClaims({ act: actWith({ poppy_agent_id: undefined }) })).kind).toBe('guest');
  });
});

describe('classifyLogin | a login that looks like a guest but is not one', () => {
  // The reason names the claims. It shows no value, except `sub_profile`, which is a short label.
  const rows: Array<{ name: string; claims: Claims; reason: string }> = [
    // One marker alone.
    {
      name: 'the guest sub and no sub_profile',
      claims: guestClaims({ sub_profile: undefined }),
      reason: 'sub starts with anon_poppy@, but sub_profile is missing',
    },
    {
      name: 'the guest sub and a sub_profile that is user',
      claims: guestClaims({ sub_profile: 'user' }),
      reason: 'sub starts with anon_poppy@, but sub_profile is "user" and does not hold urn:auth0:anonymous_user',
    },
    {
      name: 'the guest sub and another sub_profile',
      claims: guestClaims({ sub_profile: 'urn:example:other' }),
      reason:
        'sub starts with anon_poppy@, but sub_profile is "urn:example:other" and does not hold urn:auth0:anonymous_user',
    },
    {
      name: 'the guest sub and a sub_profile that holds the profile in capital letters',
      claims: guestClaims({ sub_profile: ANONYMOUS.toUpperCase() }),
      reason: `sub starts with anon_poppy@, but sub_profile is "${ANONYMOUS.toUpperCase()}" and does not hold urn:auth0:anonymous_user`,
    },
    {
      name: 'the guest sub and a sub_profile that only starts with the profile',
      claims: guestClaims({ sub_profile: `${ANONYMOUS}_x` }),
      reason: `sub starts with anon_poppy@, but sub_profile is "${ANONYMOUS}_x" and does not hold urn:auth0:anonymous_user`,
    },
    {
      name: 'the guest sub and a sub_profile list without the profile',
      claims: guestClaims({ sub_profile: ['user', 42] }),
      reason: 'sub starts with anon_poppy@, but sub_profile does not hold urn:auth0:anonymous_user',
    },
    {
      name: 'the guest sub and a sub_profile that is a number',
      claims: guestClaims({ sub_profile: 42 }),
      reason: 'sub starts with anon_poppy@, but sub_profile does not hold urn:auth0:anonymous_user',
    },
    {
      name: 'the anonymous profile and a user sub',
      claims: guestClaims({ sub: PERSON }),
      reason: 'sub_profile marks an anonymous user, but sub does not start with anon_poppy@',
    },
    {
      name: 'the anonymous profile and no sub',
      claims: guestClaims({ sub: undefined }),
      reason: 'sub_profile marks an anonymous user, but sub does not start with anon_poppy@',
    },
    {
      name: 'the anonymous profile and a sub that is a number',
      claims: guestClaims({ sub: 42 }),
      reason: 'sub_profile marks an anonymous user, but sub does not start with anon_poppy@',
    },
    {
      name: 'the anonymous profile and a sub that only has the guest start inside',
      claims: guestClaims({ sub: `auth0|${GUEST_SUB}` }),
      reason: 'sub_profile marks an anonymous user, but sub does not start with anon_poppy@',
    },
    // Both markers, and the agent state is not valid.
    { name: 'no act', claims: guestClaims({ act: undefined }), reason: 'act is missing or is not an object' },
    { name: 'an act that is null', claims: guestClaims({ act: null }), reason: 'act is missing or is not an object' },
    {
      name: 'an act that is a string',
      claims: guestClaims({ act: 'x' }),
      reason: 'act is missing or is not an object',
    },
    { name: 'an act that is a list', claims: guestClaims({ act: [] }), reason: 'act is missing or is not an object' },
    {
      name: 'an act with no poppy_sid',
      claims: guestClaims({ act: { sub: CIMD_URL } }),
      reason: 'act.poppy_sid is missing or invalid',
    },
    {
      name: 'no act.sub',
      claims: guestClaims({ act: actWith({ sub: undefined }) }),
      reason: 'act.sub is missing or invalid',
    },
    {
      name: 'an empty act.sub',
      claims: guestClaims({ act: actWith({ sub: '' }) }),
      reason: 'act.sub is missing or invalid',
    },
    {
      name: 'an act.sub that is a list',
      claims: guestClaims({ act: actWith({ sub: ['secret-sub'] }) }),
      reason: 'act.sub is missing or invalid',
    },
    {
      name: 'a poppy_sid with a character that is not base64url',
      claims: guestClaims({ act: actWith({ poppy_sid: 'secret+sid' }) }),
      reason: 'act.poppy_sid is missing or invalid',
    },
    {
      name: 'a poppy_sid that is a number',
      claims: guestClaims({ act: actWith({ poppy_sid: 42 }) }),
      reason: 'act.poppy_sid is missing or invalid',
    },
    {
      name: 'a poppy_sid of 257 characters',
      claims: guestClaims({ act: actWith({ poppy_sid: 'a'.repeat(257) }) }),
      reason: 'act.poppy_sid is missing or invalid',
    },
    {
      name: 'no poppy_user_id',
      claims: guestClaims({ act: actWith({ poppy_user_id: undefined }) }),
      reason: 'act.poppy_user_id is missing or invalid',
    },
    {
      name: 'an empty poppy_user_id',
      claims: guestClaims({ act: actWith({ poppy_user_id: '' }) }),
      reason: 'act.poppy_user_id is missing or invalid',
    },
    {
      name: 'a poppy_user_id that is a list',
      claims: guestClaims({ act: actWith({ poppy_user_id: ['secret-user'] }) }),
      reason: 'act.poppy_user_id is missing or invalid',
    },
    {
      name: 'an empty poppy_agent_id',
      claims: guestClaims({ act: actWith({ poppy_agent_id: '' }) }),
      reason: 'act.poppy_agent_id is missing or invalid',
    },
    {
      name: 'a poppy_agent_id that is a number',
      claims: guestClaims({ act: actWith({ poppy_agent_id: 7 }) }),
      reason: 'act.poppy_agent_id is missing or invalid',
    },
    // `exp` is required: there is no deadline to fall back to.
    { name: 'no exp', claims: guestClaims({ exp: undefined }), reason: 'exp is missing or invalid' },
    { name: 'an exp that is null', claims: guestClaims({ exp: null }), reason: 'exp is missing or invalid' },
    { name: 'an exp that is a string', claims: guestClaims({ exp: `${EXP}` }), reason: 'exp is missing or invalid' },
    { name: 'an exp that is NaN', claims: guestClaims({ exp: NaN }), reason: 'exp is missing or invalid' },
    { name: 'an exp that is infinite', claims: guestClaims({ exp: Infinity }), reason: 'exp is missing or invalid' },
    { name: 'an exp that is zero', claims: guestClaims({ exp: 0 }), reason: 'exp is missing or invalid' },
    { name: 'an exp that is negative', claims: guestClaims({ exp: -5 }), reason: 'exp is missing or invalid' },
    {
      name: 'an exp in milliseconds',
      claims: guestClaims({ exp: EXP * 1000 }),
      reason: 'exp is missing or invalid',
    },
    { name: 'an exp that is a list', claims: guestClaims({ exp: [EXP] }), reason: 'exp is missing or invalid' },
  ];

  test.each(rows)('is invalid_guest with $name', ({ claims, reason }) => {
    expect(classifyLogin(claims)).toStrictEqual({ kind: 'invalid_guest', reason });
  });

  test('is never read as a signed-in agent or a person, whatever else is wrong', () => {
    for (const { claims } of rows) {
      expect(classifyLogin(claims).kind).toBe('invalid_guest');
    }
  });

  // The first check that fails is the one that is named.
  test('names the markers first, then the act, then the exp', () => {
    const bad = { sub: PERSON, act: undefined, exp: undefined };

    expect(classifyLogin(guestClaims(bad))).toMatchObject({ reason: expect.stringContaining('sub_profile marks') });
    expect(classifyLogin(guestClaims({ ...bad, sub: GUEST_SUB }))).toMatchObject({
      reason: 'act is missing or is not an object',
    });
    expect(classifyLogin(guestClaims({ ...bad, sub: GUEST_SUB, act: agentAct() }))).toMatchObject({
      reason: 'exp is missing or invalid',
    });
  });

  test('shows no value of the token in the reason, except the sub_profile label', () => {
    const secrets = [
      guestClaims({ sub: 'anon_poppy@secret-sub', sub_profile: undefined }),
      guestClaims({ sub: 'secret-sub' }),
      guestClaims({ act: actWith({ sub: ['secret-act-sub'] }) }),
      guestClaims({ act: actWith({ poppy_sid: 'secret+sid' }) }),
      guestClaims({ act: actWith({ poppy_user_id: ['secret-user'] }) }),
      guestClaims({ act: actWith({ poppy_agent_id: ['secret-agent'] }) }),
      guestClaims({ act: 'secret-act' }),
      guestClaims({ exp: 'secret-exp' }),
      guestClaims({ sub_profile: ['secret-profile'] }),
    ];

    for (const claims of secrets) {
      const result = classifyLogin(claims);

      expect(result.kind).toBe('invalid_guest');
      expect(JSON.stringify(result)).not.toContain('secret');
    }
  });

  test('shows the sub_profile as a short label: quoted, with line breaks escaped, and cut at 64 characters', () => {
    const long = classifyLogin(guestClaims({ sub_profile: `x${'y'.repeat(100)}` }));
    const lines = classifyLogin(guestClaims({ sub_profile: 'a\nb' }));

    expect(long.kind === 'invalid_guest' && long.reason).toBe(
      `sub starts with anon_poppy@, but sub_profile is "x${'y'.repeat(63)}..." and does not hold ${ANONYMOUS}`
    );
    expect(lines.kind === 'invalid_guest' && lines.reason).toContain('"a\\nb"');
    expect(lines.kind === 'invalid_guest' && lines.reason).not.toContain('\n');
  });
});

describe('classifyLogin | a Poppy Session that is not well formed, with no guest marker', () => {
  const rows: Array<{ name: string; overrides: Claims; member: PoppySessionMember }> = [
    { name: 'no act.sub', overrides: { sub: undefined }, member: 'act.sub' },
    { name: 'an act.sub of spaces only', overrides: { sub: '   ' }, member: 'act.sub' },
    { name: 'a poppy_sid that is a number', overrides: { poppy_sid: 42 }, member: 'act.poppy_sid' },
    { name: 'a poppy_sid with a space', overrides: { poppy_sid: 'has space' }, member: 'act.poppy_sid' },
    { name: 'no poppy_user_id', overrides: { poppy_user_id: undefined }, member: 'act.poppy_user_id' },
    { name: 'an empty poppy_user_id', overrides: { poppy_user_id: '' }, member: 'act.poppy_user_id' },
    { name: 'an empty poppy_agent_id', overrides: { poppy_agent_id: '' }, member: 'act.poppy_agent_id' },
  ];

  test.each(rows)('throws InvalidPoppySessionError for $name, and names $member', ({ overrides, member }) => {
    expectInvalidSession(agentClaims({ act: actWith(overrides) }), member);
  });

  test.each([
    { name: 'no sub', claims: agentClaims({ sub: undefined }), member: 'sub' as const },
    { name: 'an empty sub', claims: agentClaims({ sub: '' }), member: 'sub' as const },
    { name: 'a sub that is a number', claims: agentClaims({ sub: 42 }), member: 'sub' as const },
    { name: 'no exp', claims: agentClaims({ exp: undefined }), member: 'exp' as const },
    { name: 'an exp that is null', claims: agentClaims({ exp: null }), member: 'exp' as const },
    { name: 'an exp that is a string', claims: agentClaims({ exp: `${EXP}` }), member: 'exp' as const },
    { name: 'an exp that is NaN', claims: agentClaims({ exp: NaN }), member: 'exp' as const },
    { name: 'an exp that is infinite', claims: agentClaims({ exp: Infinity }), member: 'exp' as const },
    { name: 'an exp that is zero', claims: agentClaims({ exp: 0 }), member: 'exp' as const },
    { name: 'an exp that is negative', claims: agentClaims({ exp: -1 }), member: 'exp' as const },
    { name: 'an exp in milliseconds', claims: agentClaims({ exp: EXP * 1000 }), member: 'exp' as const },
  ])('throws InvalidPoppySessionError for $name, and names $member', ({ claims, member }) => {
    expectInvalidSession(claims, member);
  });

  test('checks the act first, then the sub, then the exp', () => {
    const bad = { sub: undefined, exp: undefined, act: actWith({ poppy_sid: 'has space' }) };

    expectInvalidSession(agentClaims(bad), 'act.poppy_sid');
    expectInvalidSession(agentClaims({ ...bad, act: agentAct() }), 'sub');
    expectInvalidSession(agentClaims({ ...bad, act: agentAct(), sub: PERSON }), 'exp');
  });

  test('shows no value of the token in the error', () => {
    const error = failureOf(agentClaims({ act: actWith({ poppy_user_id: ['secret-user'] }), exp: 'secret-exp' }));

    expect(error).toBeInstanceOf(InvalidPoppySessionError);
    expect(`${(error as Error).message} ${JSON.stringify(error)}`).not.toContain('secret');
  });
});

describe('classifyLogin | the claims', () => {
  test('classifyLogin does not change the claims it reads', () => {
    const claims = guestClaims({ act: actWith({ x_other: { nested: true } }) });
    const before = structuredClone(claims);

    classifyLogin(claims);
    classifyLogin(agentClaims());

    expect(claims).toStrictEqual(before);
  });

  test('gives a login whose act is a copy', () => {
    const claims = agentClaims({ act: actWith({ x_other: { nested: [1] } }) });
    const result = classifyLogin(claims);

    (result as unknown as { login: { act: { x_other: { nested: number[] } } } }).login.act.x_other.nested.push(2);

    expect((claims.act as { x_other: { nested: number[] } }).x_other.nested).toEqual([1]);
  });

  test('tells two Sessions of the same agent apart by poppy_sid', () => {
    const first = classifyLogin(guestClaims({ act: actWith({ poppy_sid: SESSION_ID }) }));
    const second = classifyLogin(
      guestClaims({ act: actWith({ poppy_sid: OTHER_SESSION_ID, poppy_user_id: USER_ID }) })
    );

    expect(first.kind === 'guest' && first.login.act.poppy_sid).toBe(SESSION_ID);
    expect(second.kind === 'guest' && second.login.act.poppy_sid).toBe(OTHER_SESSION_ID);
  });
});
