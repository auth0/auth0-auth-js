import { describe, expect, test } from 'vitest';
import { InvalidPoppySessionError, type PoppySessionMember } from '../errors.js';
import { AGENT_ID, CIMD_URL, GUEST_SUB, SESSION_ID, USER_ID, agentAct } from '../test-utils/poppy.js';
import { agentSessionDeadline, holdsPoppySession, readAgentLogin } from './claims.js';

type Claims = Record<string, unknown>;

const OTHER_CIMD_URL = 'https://other.example/agent.json';

// The claims of an ID token. `act` can be anything here, as it is anything in a token. `more` replaces claims.
const claimsWith = (act: unknown, more: Claims = {}): Claims => ({ sub: 'auth0|ana', act, ...more });

// An `act` claim as a token holds it. JSON has no `undefined`, so a member set to `undefined` is left out.
function actWith(overrides: Claims = {}): Claims {
  const act = agentAct(overrides);

  for (const [name, value] of Object.entries(act)) {
    if (value === undefined) {
      delete act[name];
    }
  }

  return act;
}

// What `readAgentLogin` throws for the claims, or `undefined` when it throws nothing.
function failureOf(claims: Claims): unknown {
  try {
    readAgentLogin(claims);
  } catch (error) {
    return error;
  }

  return undefined;
}

// The error is the one for this member. Its message is a fixed text, so it names the member and nothing else.
function expectInvalid(claims: Claims, member: PoppySessionMember): void {
  const error = failureOf(claims);

  expect(error).toBeInstanceOf(InvalidPoppySessionError);
  expect((error as InvalidPoppySessionError).message).toBe(new InvalidPoppySessionError(member).message);
}

describe('holdsPoppySession and readAgentLogin | claims that hold no Poppy Session', () => {
  // `poppy_sid` belongs to the prototype here, not to the claim. JSON has no such member.
  const inheritedSid = Object.assign(Object.create({ poppy_sid: SESSION_ID }) as Claims, {
    sub: CIMD_URL,
    poppy_user_id: USER_ID,
  });

  const rows: Array<{ name: string; claims: Claims | undefined }> = [
    { name: 'no claims', claims: undefined },
    { name: 'no act', claims: { sub: 'auth0|ana' } },
    { name: 'an act that is a string', claims: claimsWith('x') },
    { name: 'an act that is a number', claims: claimsWith(42) },
    { name: 'an act that is null', claims: claimsWith(null) },
    { name: 'an act that is an empty list', claims: claimsWith([]) },
    // A list is not an object claim, even when it has the members of a Session as properties.
    { name: 'an act that is a list with the Session members', claims: claimsWith(Object.assign([], agentAct())) },
    { name: 'an act without poppy_sid', claims: claimsWith(actWith({ poppy_sid: undefined })) },
    { name: 'an act that only inherits poppy_sid', claims: claimsWith(inheritedSid) },
    { name: 'a poppy_sid outside act', claims: { sub: 'auth0|ana', poppy_sid: SESSION_ID, act: { sub: CIMD_URL } } },
  ];

  test.each(rows)('finds no Session in $name', ({ claims }) => {
    expect(holdsPoppySession(claims)).toBe(false);
    expect(readAgentLogin(claims)).toBeUndefined();
  });
});

describe('readAgentLogin | claims that hold a Poppy Session', () => {
  test('reads the Session, the user, the agent and the end of the Session from act', () => {
    const act = agentAct();
    const claims = claimsWith(act);

    expect(holdsPoppySession(claims)).toBe(true);
    // `toStrictEqual`: a member set to `undefined`, and a member that is not named here, both fail.
    expect(readAgentLogin(claims)).toStrictEqual({
      sessionId: SESSION_ID,
      userId: USER_ID,
      agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
      isGuest: false,
      sessionExp: act.poppy_session_exp,
    });
  });

  test('has no poppyAgentId in the agent when the act has no poppy_agent_id', () => {
    const login = readAgentLogin(claimsWith(actWith({ poppy_agent_id: undefined })));

    expect(login?.agent).toStrictEqual({ cimdUrl: CIMD_URL });
    expect(Object.keys(login?.agent ?? {})).toEqual(['cimdUrl']);
  });

  test('reads the outermost act, and not an act inside it', () => {
    const act = agentAct({ act: { sub: OTHER_CIMD_URL, poppy_sid: 'inner_sid', poppy_user_id: 'inner_user' } });

    expect(readAgentLogin(claimsWith(act))).toMatchObject({
      sessionId: SESSION_ID,
      userId: USER_ID,
      agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
    });
  });

  test('does not change the claims it reads', () => {
    const claims = Object.freeze(claimsWith(Object.freeze(agentAct())));

    expect(() => readAgentLogin(claims)).not.toThrow();
  });

  test.each([
    { name: 'the whole alphabet', sid: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' },
    { name: 'one character', sid: 'a' },
    { name: 'the longest id, 256 characters', sid: 'a'.repeat(256) },
  ])('accepts $name as poppy_sid', ({ sid }) => {
    expect(readAgentLogin(claimsWith(actWith({ poppy_sid: sid })))?.sessionId).toBe(sid);
  });
});

describe('readAgentLogin | claims whose Poppy Session is malformed', () => {
  const rows: Array<{ name: string; overrides: Claims; member: PoppySessionMember }> = [
    { name: 'no sub', overrides: { sub: undefined }, member: 'act.sub' },
    { name: 'an empty sub', overrides: { sub: '' }, member: 'act.sub' },
    { name: 'a sub of spaces only', overrides: { sub: '   ' }, member: 'act.sub' },
    { name: 'a sub that is a number', overrides: { sub: 42 }, member: 'act.sub' },
    { name: 'a sub that is null', overrides: { sub: null }, member: 'act.sub' },
    { name: 'a poppy_sid that is a number', overrides: { poppy_sid: 42 }, member: 'act.poppy_sid' },
    { name: 'a poppy_sid that is null', overrides: { poppy_sid: null }, member: 'act.poppy_sid' },
    // `RegExp.test` turns a list of one string into that string, so the type has to be checked first.
    {
      name: 'a poppy_sid that is a list of one valid id',
      overrides: { poppy_sid: [SESSION_ID] },
      member: 'act.poppy_sid',
    },
    { name: 'an empty poppy_sid', overrides: { poppy_sid: '' }, member: 'act.poppy_sid' },
    { name: 'a poppy_sid with a space', overrides: { poppy_sid: 'has space' }, member: 'act.poppy_sid' },
    { name: 'a poppy_sid with base64 characters', overrides: { poppy_sid: 'ab+/cd==' }, member: 'act.poppy_sid' },
    { name: 'a poppy_sid of 257 characters', overrides: { poppy_sid: 'a'.repeat(257) }, member: 'act.poppy_sid' },
    // `$` in a JavaScript pattern does not match before a final line break.
    {
      name: 'a poppy_sid with a final line break',
      overrides: { poppy_sid: `${SESSION_ID}\n` },
      member: 'act.poppy_sid',
    },
    { name: 'no poppy_user_id', overrides: { poppy_user_id: undefined }, member: 'act.poppy_user_id' },
    { name: 'an empty poppy_user_id', overrides: { poppy_user_id: '' }, member: 'act.poppy_user_id' },
    { name: 'a poppy_user_id that is a number', overrides: { poppy_user_id: 7 }, member: 'act.poppy_user_id' },
    { name: 'a poppy_user_id that is null', overrides: { poppy_user_id: null }, member: 'act.poppy_user_id' },
    { name: 'a poppy_user_id that is a list', overrides: { poppy_user_id: [USER_ID] }, member: 'act.poppy_user_id' },
    { name: 'an empty poppy_agent_id', overrides: { poppy_agent_id: '' }, member: 'act.poppy_agent_id' },
    { name: 'a poppy_agent_id that is a number', overrides: { poppy_agent_id: 7 }, member: 'act.poppy_agent_id' },
    { name: 'a poppy_agent_id that is null', overrides: { poppy_agent_id: null }, member: 'act.poppy_agent_id' },
    {
      name: 'a poppy_agent_id that is a list',
      overrides: { poppy_agent_id: [AGENT_ID] },
      member: 'act.poppy_agent_id',
    },
  ];

  // The act still holds a Session, so the login must be refused. It must not fall back to a login without an agent.
  test.each(rows)('throws for $name, and names $member', ({ overrides, member }) => {
    const claims = claimsWith(actWith(overrides));

    expect(holdsPoppySession(claims)).toBe(true);
    expectInvalid(claims, member);
  });

  test('checks the members in this order: sub, poppy_sid, poppy_user_id, poppy_agent_id', () => {
    const allWrong = { sub: undefined, poppy_sid: 'has space', poppy_user_id: '', poppy_agent_id: '' };

    expectInvalid(claimsWith(actWith(allWrong)), 'act.sub');
    expectInvalid(claimsWith(actWith({ ...allWrong, sub: CIMD_URL })), 'act.poppy_sid');
    expectInvalid(claimsWith(actWith({ ...allWrong, sub: CIMD_URL, poppy_sid: SESSION_ID })), 'act.poppy_user_id');
    expectInvalid(
      claimsWith(actWith({ ...allWrong, sub: CIMD_URL, poppy_sid: SESSION_ID, poppy_user_id: USER_ID })),
      'act.poppy_agent_id'
    );
  });

  test.each([
    { member: 'act.sub', overrides: { sub: ['secret-sub'] } },
    { member: 'act.poppy_sid', overrides: { poppy_sid: 'secret+sid' } },
    { member: 'act.poppy_user_id', overrides: { poppy_user_id: ['secret-user'] } },
    { member: 'act.poppy_agent_id', overrides: { poppy_agent_id: ['secret-agent'] } },
  ])('shows no value of the token in the error for $member', ({ overrides }) => {
    const error = failureOf(claimsWith(actWith(overrides)));

    expect(error).toBeInstanceOf(InvalidPoppySessionError);
    // The message, and the properties that the error carries.
    expect(`${(error as Error).message} ${JSON.stringify(error)}`).not.toContain('secret');
  });
});

describe('readAgentLogin | poppy_session_exp', () => {
  const keptLogin = {
    sessionId: SESSION_ID,
    userId: USER_ID,
    agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
    isGuest: false,
  };

  test.each([
    { name: 'a time in Unix seconds', value: 1790907300, sessionExp: 1790907300 },
    { name: 'the largest time below the bound for milliseconds', value: 9_999_999_999, sessionExp: 9_999_999_999 },
    // A platform that does not round the time must not lose the bound. It is rounded down, which is the earlier time,
    // as the `exp` of the ID token is.
    { name: 'a fraction, rounded down', value: 1790907300.9, sessionExp: 1790907300 },
    { name: 'a fraction just below a whole second, rounded down', value: 1790907300.999, sessionExp: 1790907300 },
    {
      name: 'the largest fraction below the bound for milliseconds, rounded down',
      value: 9_999_999_999.9,
      sessionExp: 9_999_999_999,
    },
    // As for the `exp` of the ID token, a time that rounds down to 0 is a time in the past, and the login is refused.
    { name: 'a fraction below 1, which rounds down to 0', value: 0.5, sessionExp: 0 },
  ])('keeps $name', ({ value, sessionExp }) => {
    expect(readAgentLogin(claimsWith(actWith({ poppy_session_exp: value })))).toStrictEqual({
      ...keptLogin,
      sessionExp,
    });
  });

  test.each([
    { name: 'no value', value: undefined },
    { name: 'null', value: null },
    { name: 'a string', value: '1790907300' },
    { name: 'a string with a fraction', value: '1790907300.5' },
    { name: 'a time in milliseconds', value: 1790907300000 },
    { name: 'a time in milliseconds with a fraction', value: 1790907300000.5 },
    { name: 'the bound for milliseconds itself', value: 1e10 },
    { name: 'zero', value: 0 },
    { name: 'minus zero', value: -0 },
    { name: 'a negative number', value: -1 },
    { name: 'a negative fraction', value: -1.5 },
    { name: 'not a number', value: NaN },
    { name: 'an infinite number', value: Infinity },
    { name: 'a negative infinite number', value: -Infinity },
    { name: 'an object', value: { seconds: 1790907300 } },
    { name: 'a list of one time', value: [1790907300] },
  ])('leaves sessionExp out for $name, and still reads the login', ({ value }) => {
    expect(readAgentLogin(claimsWith(actWith({ poppy_session_exp: value })))).toStrictEqual(keptLogin);
  });
});

describe('readAgentLogin | isGuest', () => {
  const rows: Array<{ name: string; claims: Claims; isGuest: boolean }> = [
    {
      name: 'a sub_profile that is the anonymous user profile',
      claims: { sub_profile: 'urn:auth0:anonymous_user' },
      isGuest: true,
    },
    {
      name: 'a sub_profile string with the profile among others',
      claims: { sub_profile: 'urn:example:a urn:auth0:anonymous_user' },
      isGuest: true,
    },
    {
      name: 'a sub_profile list with the profile',
      claims: { sub_profile: ['urn:auth0:anonymous_user'] },
      isGuest: true,
    },
    {
      name: 'a sub_profile list with the profile among others',
      claims: { sub_profile: ['urn:example:a', 'urn:auth0:anonymous_user'] },
      isGuest: true,
    },
    // Any white space separates two profiles, and white space at either end hides none.
    {
      name: 'a sub_profile string with a tab between the profiles',
      claims: { sub_profile: 'urn:example:a\turn:auth0:anonymous_user' },
      isGuest: true,
    },
    {
      name: 'a sub_profile string with a line break between the profiles',
      claims: { sub_profile: 'urn:example:a\nurn:auth0:anonymous_user' },
      isGuest: true,
    },
    {
      name: 'a sub_profile string with a line break after the profile',
      claims: { sub_profile: 'urn:auth0:anonymous_user\n' },
      isGuest: true,
    },
    {
      name: 'a sub_profile string with a tab after the profile',
      claims: { sub_profile: 'urn:auth0:anonymous_user\t' },
      isGuest: true,
    },
    // An entry of a list is split in the same way.
    {
      name: 'a sub_profile list entry that holds two profiles',
      claims: { sub_profile: ['urn:example:a urn:auth0:anonymous_user'] },
      isGuest: true,
    },
    {
      name: 'a sub_profile list entry with a tab between two profiles',
      claims: { sub_profile: ['urn:example:a\turn:auth0:anonymous_user'] },
      isGuest: true,
    },
    { name: 'a guest sub and no sub_profile', claims: { sub: GUEST_SUB }, isGuest: true },
    // A tenant can send `user` as the `sub_profile` of a guest, so the `sub` alone marks the guest.
    { name: 'a guest sub and a sub_profile that is user', claims: { sub: GUEST_SUB, sub_profile: 'user' }, isGuest: true },
    { name: 'a guest sub and a sub_profile list of user', claims: { sub: GUEST_SUB, sub_profile: ['user'] }, isGuest: true },
    {
      name: 'a guest sub and another sub_profile',
      claims: { sub: GUEST_SUB, sub_profile: 'urn:example:other' },
      isGuest: true,
    },
    {
      name: 'a sub_profile that only starts with the profile',
      claims: { sub: 'auth0|ana', sub_profile: 'urn:auth0:anonymous_user_x' },
      isGuest: false,
    },
    {
      name: 'a sub_profile list with an entry that only starts with the profile',
      claims: { sub_profile: ['urn:auth0:anonymous_user_x'] },
      isGuest: false,
    },
    {
      name: 'a sub_profile list without the profile',
      claims: { sub_profile: ['urn:example:other', 42] },
      isGuest: false,
    },
    // The profile is one whole token, written exactly: neither the case nor the text around it may differ.
    {
      name: 'a sub_profile with the profile in capital letters',
      claims: { sub_profile: 'URN:AUTH0:ANONYMOUS_USER' },
      isGuest: false,
    },
    {
      name: 'a sub_profile with text in front of the profile',
      claims: { sub_profile: 'x-urn:auth0:anonymous_user' },
      isGuest: false,
    },
    { name: 'a sub that only has the guest start inside', claims: { sub: `auth0|${GUEST_SUB}` }, isGuest: false },
    { name: 'a sub that is a number', claims: { sub: 42 }, isGuest: false },
    { name: 'a user sub and no sub_profile', claims: { sub: 'auth0|ana' }, isGuest: false },
    {
      name: 'a user sub and a sub_profile that is a number',
      claims: { sub: 'auth0|ana', sub_profile: 42 },
      isGuest: false,
    },
  ];

  test.each(rows)('gives isGuest $isGuest for $name', ({ claims, isGuest }) => {
    expect(readAgentLogin(claimsWith(agentAct(), claims))?.isGuest).toBe(isGuest);
  });
});

describe('agentSessionDeadline', () => {
  const NOW = 1000;
  const MAX_AGE = 7200;
  // The longest an agent's session lasts, which the other candidates are measured against.
  const END_OF_MAX_AGE = 8200;

  const deadlineFor = (input: { exp?: unknown; sessionExp?: number; sessionExpiry?: number }): number =>
    agentSessionDeadline({ now: NOW, maxAge: MAX_AGE, exp: undefined, ...input });

  test.each([
    {
      name: 'the earliest of exp, sessionExp and sessionExpiry',
      input: { exp: 5000, sessionExp: 4000, sessionExpiry: 3000 },
      deadline: 3000,
    },
    {
      name: 'exp, when it is the earliest',
      input: { exp: 2000, sessionExp: 4000, sessionExpiry: 3000 },
      deadline: 2000,
    },
    { name: 'sessionExp, when it is the earliest', input: { exp: 5000, sessionExp: 4000 }, deadline: 4000 },
    { name: 'sessionExpiry, when it is the earliest', input: { exp: 5000, sessionExpiry: 3000 }, deadline: 3000 },
    { name: 'exp alone', input: { exp: 5000 }, deadline: 5000 },
    { name: 'exp rounded down', input: { exp: 5000.7 }, deadline: 5000 },
    { name: 'the max age, when exp is later', input: { exp: 9000 }, deadline: END_OF_MAX_AGE },
    {
      name: 'the max age, when sessionExp and sessionExpiry are later',
      input: { sessionExp: 9000, sessionExpiry: 9500 },
      deadline: END_OF_MAX_AGE,
    },
    { name: 'the max age, when exp is not a number', input: { exp: 'x' }, deadline: END_OF_MAX_AGE },
  ])('gives $name: $deadline', ({ input, deadline }) => {
    expect(deadlineFor(input)).toBe(deadline);
  });

  test.each([
    { name: 'missing', exp: undefined },
    { name: 'null', exp: null },
    { name: 'a string of digits', exp: '5000' },
    { name: 'not a number', exp: NaN },
    { name: 'zero', exp: 0 },
    { name: 'a negative number', exp: -5 },
  ])('does not use an exp that is $name', ({ exp }) => {
    expect(deadlineFor({ exp })).toBe(END_OF_MAX_AGE);
  });

  test('does not use an exp that is at or above the bound for milliseconds', () => {
    // A max age so long that these values would be the earliest candidate, if they were used.
    const input = { now: NOW, maxAge: 2e10, sessionExp: undefined, sessionExpiry: undefined };

    expect(agentSessionDeadline({ ...input, exp: 1e10 })).toBe(NOW + 2e10);
    expect(agentSessionDeadline({ ...input, exp: 1.5e10 })).toBe(NOW + 2e10);
    expect(agentSessionDeadline({ ...input, exp: 9_999_999_999 })).toBe(9_999_999_999);
  });
});
