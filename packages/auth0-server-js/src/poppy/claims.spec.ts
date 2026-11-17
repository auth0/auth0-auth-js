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
  test('reads the sub and the act of the claims', () => {
    const claims = claimsWith(agentAct());

    expect(holdsPoppySession(claims)).toBe(true);
    // `toStrictEqual`: a member set to `undefined`, and a member that is not named here, both fail.
    expect(readAgentLogin(claims)).toStrictEqual({
      sub: 'auth0|ana',
      act: { sub: CIMD_URL, poppy_sid: SESSION_ID, poppy_user_id: USER_ID, poppy_agent_id: AGENT_ID },
    });
  });

  test('has no poppy_agent_id in the act when the token has none', () => {
    const login = readAgentLogin(claimsWith(actWith({ poppy_agent_id: undefined })));

    expect(login?.act).toStrictEqual({ sub: CIMD_URL, poppy_sid: SESSION_ID, poppy_user_id: USER_ID });
    expect(Object.keys(login?.act ?? {})).toEqual(['sub', 'poppy_sid', 'poppy_user_id']);
  });

  test('reads the outermost act, and keeps the act inside it as a member of the claim', () => {
    const inner = { sub: OTHER_CIMD_URL, poppy_sid: 'inner_sid', poppy_user_id: 'inner_user' };
    const claims = claimsWith(agentAct({ act: inner }));

    expect(readAgentLogin(claims)?.act).toStrictEqual({
      sub: CIMD_URL,
      poppy_sid: SESSION_ID,
      poppy_user_id: USER_ID,
      poppy_agent_id: AGENT_ID,
      act: inner,
    });
  });

  test('keeps the whole act, with the members that it does not know', () => {
    const act = agentAct({
      client_id: 'web_app_client',
      iss: 'https://auth.zepto.example/',
      extension: { tags: ['a'] },
    });

    expect(readAgentLogin(claimsWith(act))?.act).toStrictEqual(act);
  });

  test('gives a copy of the act, so a change to it reaches neither the claims nor the next login', () => {
    const claims = claimsWith(agentAct({ extension: { tags: ['a'] } }));
    const before = structuredClone(claims);

    const login = readAgentLogin(claims)!;

    expect(login.act).not.toBe(claims.act);
    expect(login.act.extension).not.toBe((claims.act as Claims).extension);

    login.act.sub = 'https://evil.example/agent.json';
    (login.act.extension as { tags: string[] }).tags.push('b');

    expect(claims).toStrictEqual(before);
    expect(readAgentLogin(claims)?.act).toStrictEqual(before.act);
  });

  test.each([
    { name: 'a string', subProfile: 'urn:example:member', expected: { sub_profile: 'urn:example:member' } },
    { name: 'a list', subProfile: ['urn:example:member'], expected: {} },
    { name: 'a number', subProfile: 7, expected: {} },
    { name: 'null', subProfile: null, expected: {} },
    { name: 'missing', subProfile: undefined, expected: {} },
  ])('has the sub_profile of the claims only when it is a string: $name', ({ subProfile, expected }) => {
    const login = readAgentLogin(claimsWith(agentAct(), { sub_profile: subProfile }));

    // The login has no `sub_profile` key, and not one with the value `undefined`.
    expect(login).toStrictEqual({ sub: 'auth0|ana', act: agentAct(), ...expected });
  });

  test('has the sub of the claims, which is not the sub of the agent', () => {
    const login = readAgentLogin(claimsWith(agentAct(), { sub: GUEST_SUB }));

    expect(login?.sub).toBe(GUEST_SUB);
    expect(login?.act.sub).toBe(CIMD_URL);
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
    expect(readAgentLogin(claimsWith(actWith({ poppy_sid: sid })))?.act.poppy_sid).toBe(sid);
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
  // Auth0 does not send it any more, and nothing reads it. A build that still sends it is one more member of the act, as
  // any member that this package does not know, and it changes nothing else.
  test.each([
    { name: 'a time in Unix seconds', value: 1790907300 },
    { name: 'a time in the past', value: 1 },
    { name: 'a string', value: '1790907300' },
    { name: 'null', value: null },
  ])('does not read it: the login is the same with $name', ({ value }) => {
    const login = readAgentLogin(claimsWith(actWith({ poppy_session_exp: value })));

    expect(login).toStrictEqual({
      sub: 'auth0|ana',
      act: { ...agentAct(), poppy_session_exp: value },
    });
  });
});

describe('agentSessionDeadline', () => {
  const NOW = 1000;
  const MAX_AGE = 7200;
  // The longest an agent's session lasts, which the other candidates are measured against.
  const END_OF_MAX_AGE = 8200;

  // `exp` is required: a login that has none is refused before a deadline is asked for (see `classifyLogin`).
  const deadlineFor = (input: { exp: number; sessionExpiry?: number }): number =>
    agentSessionDeadline({ now: NOW, maxAge: MAX_AGE, ...input });

  test.each([
    {
      name: 'the earlier of exp and sessionExpiry: sessionExpiry',
      input: { exp: 5000, sessionExpiry: 3000 },
      deadline: 3000,
    },
    { name: 'the earlier of exp and sessionExpiry: exp', input: { exp: 2000, sessionExpiry: 3000 }, deadline: 2000 },
    { name: 'exp alone', input: { exp: 5000 }, deadline: 5000 },
    { name: 'exp rounded down', input: { exp: 5000.7 }, deadline: 5000 },
    { name: 'the max age, when exp is later', input: { exp: 9000 }, deadline: END_OF_MAX_AGE },
    {
      name: 'the max age, when exp and sessionExpiry are later',
      input: { exp: 9000, sessionExpiry: 9500 },
      deadline: END_OF_MAX_AGE,
    },
    // Not a fallback: the exp has the last word when it is the earliest, and it is never left out.
    { name: 'exp that is in the past', input: { exp: 500 }, deadline: 500 },
  ])('gives $name: $deadline', ({ input, deadline }) => {
    expect(deadlineFor(input)).toBe(deadline);
  });

  test('rounds an exp below 1 down to 0, which is a time in the past', () => {
    expect(deadlineFor({ exp: 0.5 })).toBe(0);
  });
});
