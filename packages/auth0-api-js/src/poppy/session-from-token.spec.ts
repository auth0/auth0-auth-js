import { afterEach, describe, expect, test, vi } from 'vitest';

import * as actModule from '../act.js';
import { InvalidRequestError } from '../errors.js';
import type { VerifiedAccessTokenClaims } from '../types.js';
import { InvalidSessionError } from './errors.js';
import { sessionFromToken } from './session-from-token.js';

const CIMD_URL = 'https://agent.example/agent.json';
const OTHER_AGENT_URL = 'https://other.example/agent.json';
const SID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
const USER_ID = 'usr_test';
const AGENT_ID = 'travel';

// The text of the error, word for word. It names the `act` claim of the access token, and it is fixed: no value of the
// token is in it.
const MESSAGE = "The access token's act claim does not hold a well-formed Session.";

/** The claims of a verified access token of a web app. `act` can be anything here, as it is anything in a token. */
function claimsWith(act?: unknown): VerifiedAccessTokenClaims {
  return {
    iss: 'https://example.auth0.com/',
    sub: 'auth0|ana',
    aud: 'https://api.zepto.example',
    ...(act === undefined ? {} : { act }),
  } as VerifiedAccessTokenClaims;
}

/** An `act` claim that holds a whole Session. A member set to `undefined` is left out. */
function sessionAct(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const act: Record<string, unknown> = {
    sub: CIMD_URL,
    poppy_sid: SID,
    poppy_user_id: USER_ID,
    poppy_agent_id: AGENT_ID,
    ...overrides,
  };
  for (const [name, value] of Object.entries(act)) {
    if (value === undefined) {
      delete act[name];
    }
  }
  return act;
}

/** What `sessionFromToken` throws for `act`, or `undefined` when it throws nothing. */
function failureOf(act: unknown): unknown {
  try {
    sessionFromToken(claimsWith(act));
  } catch (error) {
    return error;
  }
  return undefined;
}

function expectMalformed(error: unknown, cause: string): void {
  expect(error).toBeInstanceOf(InvalidSessionError);
  const refused = error as InvalidSessionError;
  expect(refused.reason).toBe('malformed_session');
  expect(refused.code).toBe('invalid_session');
  expect(refused.statusCode).toBe(400);
  expect(refused.message).toBe(MESSAGE);
  expect(refused.cause).toEqual({ code: cause });
}

describe('sessionFromToken | a token that holds no Session', () => {
  test('gives undefined for a token without an act claim', () => {
    expect(sessionFromToken(claimsWith())).toBeUndefined();
  });

  test.each([
    { name: 'an act that is a delegation of RFC 8693 and has only a sub', act: { sub: 'service-a' } },
    {
      name: 'an act with the other members of a Session, but not poppy_sid',
      act: sessionAct({ poppy_sid: undefined }),
    },
    { name: 'an act with other members', act: { sub: CIMD_URL, scope: 'read:cart', client_id: 'abc' } },
    { name: 'an empty act', act: {} },
    { name: 'a nested act that holds the Session while the outer one does not', act: { sub: 'a', act: sessionAct() } },
  ])('gives undefined for $name', ({ act }) => {
    expect(sessionFromToken(claimsWith(act))).toBeUndefined();
  });

  test.each([
    { name: 'a string', act: 'poppy_sid' },
    { name: 'a number', act: 42 },
    { name: 'true', act: true },
    { name: 'null', act: null },
    { name: 'an array', act: [sessionAct()] },
  ])('gives undefined for an act that is $name, and not an object', ({ act }) => {
    // `claimsWith` leaves out an `act` of `undefined`, so `null` is the only form of a missing value that gets here.
    expect(sessionFromToken(claimsWith(act))).toBeUndefined();
  });

  test('does not read poppy_sid from the top level of the claims', () => {
    const claims = { ...claimsWith({ sub: CIMD_URL }), poppy_sid: SID, poppy_user_id: USER_ID };

    expect(sessionFromToken(claims)).toBeUndefined();
  });

  test('does not read a poppy_sid that the act inherits', () => {
    // A member of a prototype is not a member of the claim. JSON has none, so only a polluted prototype has one.
    const act = Object.create({ poppy_sid: SID, poppy_user_id: USER_ID }) as Record<string, unknown>;
    act.sub = CIMD_URL;

    expect(sessionFromToken(claimsWith(act))).toBeUndefined();
  });
});

describe('sessionFromToken | a token that holds a Session', () => {
  test('maps the claims of act to the Session', () => {
    const result = sessionFromToken(claimsWith(sessionAct()));

    // `toStrictEqual`: a member with the value `undefined`, and a member that is not named here, both fail.
    expect(result).toStrictEqual({
      sessionId: SID,
      userId: USER_ID,
      agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
    });
  });

  test('has no poppyAgentId in the agent when the token has no poppy_agent_id', () => {
    const result = sessionFromToken(claimsWith(sessionAct({ poppy_agent_id: undefined })));

    expect(result).toStrictEqual({ sessionId: SID, userId: USER_ID, agent: { cimdUrl: CIMD_URL } });
    expect(Object.keys(result?.agent ?? {})).toEqual(['cimdUrl']);
  });

  test('takes the agent URL from the sub of the outermost act', () => {
    const act = sessionAct({ act: { sub: OTHER_AGENT_URL, poppy_sid: 'inner-sid', poppy_user_id: 'usr_inner' } });

    const result = sessionFromToken(claimsWith(act));

    expect(result).toStrictEqual({
      sessionId: SID,
      userId: USER_ID,
      agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
    });
  });

  test('ignores the members of the act that are not Session claims', () => {
    const result = sessionFromToken(claimsWith(sessionAct({ scope: 'read:cart', jti: 'abc' })));

    expect(result).toStrictEqual({
      sessionId: SID,
      userId: USER_ID,
      agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
    });
  });

  test('does not change the claims it reads', () => {
    const act = Object.freeze(sessionAct());
    const claims = Object.freeze(claimsWith(act));

    expect(() => sessionFromToken(claims)).not.toThrow();
  });

  test.each([
    {
      name: 'the whole alphabet of a Session ID',
      sid: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-',
    },
    { name: 'one character', sid: 'a' },
    { name: 'the longest Session ID, 256 characters', sid: 'a'.repeat(256) },
  ])('accepts $name as poppy_sid', ({ sid }) => {
    expect(sessionFromToken(claimsWith(sessionAct({ poppy_sid: sid })))?.sessionId).toBe(sid);
  });
});

describe('sessionFromToken | a token with a Session that is malformed', () => {
  test.each([
    { name: 'no sub', act: { sub: undefined }, cause: 'act_sub' },
    { name: 'a sub that is a number', act: { sub: 42 }, cause: 'act_sub' },
    { name: 'a sub that is null', act: { sub: null }, cause: 'act_sub' },
    { name: 'a sub that is an object', act: { sub: { id: CIMD_URL } }, cause: 'act_sub' },
    { name: 'an empty sub', act: { sub: '' }, cause: 'act_sub' },
    { name: 'a sub of spaces only', act: { sub: '   ' }, cause: 'act_sub' },
    { name: 'a poppy_sid with a plus sign', act: { poppy_sid: 'abc+def' }, cause: 'poppy_sid' },
    { name: 'a poppy_sid with a slash', act: { poppy_sid: 'abc/def' }, cause: 'poppy_sid' },
    { name: 'a poppy_sid with a padding sign', act: { poppy_sid: 'abcdef==' }, cause: 'poppy_sid' },
    { name: 'a poppy_sid with a space', act: { poppy_sid: 'abc def' }, cause: 'poppy_sid' },
    { name: 'a poppy_sid with a line break at the end', act: { poppy_sid: `${SID}\n` }, cause: 'poppy_sid' },
    { name: 'an empty poppy_sid', act: { poppy_sid: '' }, cause: 'poppy_sid' },
    { name: 'a poppy_sid of 257 characters', act: { poppy_sid: 'a'.repeat(257) }, cause: 'poppy_sid' },
    { name: 'a poppy_sid that is a number', act: { poppy_sid: 12345 }, cause: 'poppy_sid' },
    { name: 'a poppy_sid that is null', act: { poppy_sid: null }, cause: 'poppy_sid' },
    // `RegExp.test` turns an array of one string into that string, so the type must be checked first.
    { name: 'a poppy_sid that is a list of one valid ID', act: { poppy_sid: [SID] }, cause: 'poppy_sid' },
    { name: 'no poppy_user_id', act: { poppy_user_id: undefined }, cause: 'poppy_user_id' },
    { name: 'an empty poppy_user_id', act: { poppy_user_id: '' }, cause: 'poppy_user_id' },
    { name: 'a poppy_user_id that is a number', act: { poppy_user_id: 42 }, cause: 'poppy_user_id' },
    { name: 'a poppy_user_id that is null', act: { poppy_user_id: null }, cause: 'poppy_user_id' },
    { name: 'an empty poppy_agent_id', act: { poppy_agent_id: '' }, cause: 'poppy_agent_id' },
    { name: 'a poppy_agent_id that is a number', act: { poppy_agent_id: 7 }, cause: 'poppy_agent_id' },
    { name: 'a poppy_agent_id that is null', act: { poppy_agent_id: null }, cause: 'poppy_agent_id' },
    { name: 'a poppy_agent_id that is a list', act: { poppy_agent_id: [AGENT_ID] }, cause: 'poppy_agent_id' },
  ])('gives malformed_session for $name', ({ act, cause }) => {
    expectMalformed(failureOf(sessionAct(act)), cause);
  });

  test('gives malformed_session, and not the InvalidRequestError of getCurrentActor, for an unusable sub', () => {
    const error = failureOf(sessionAct({ sub: undefined }));

    expect(error).not.toBeInstanceOf(InvalidRequestError);
    expectMalformed(error, 'act_sub');
  });

  test('names the act claim of the access token, and not the Poppy-Session header', () => {
    const error = failureOf(sessionAct({ poppy_user_id: undefined })) as InvalidSessionError;

    expect(error.message).toContain('act claim');
    expect(error.message).not.toContain('Poppy-Session');
  });

  test('checks the members in this order: sub, poppy_sid, poppy_user_id, poppy_agent_id', () => {
    const allWrong = { sub: undefined, poppy_sid: 'a+b', poppy_user_id: '', poppy_agent_id: '' };

    expectMalformed(failureOf(sessionAct(allWrong)), 'act_sub');
    expectMalformed(failureOf(sessionAct({ ...allWrong, sub: CIMD_URL })), 'poppy_sid');
    expectMalformed(failureOf(sessionAct({ ...allWrong, sub: CIMD_URL, poppy_sid: SID })), 'poppy_user_id');
    expectMalformed(
      failureOf(sessionAct({ ...allWrong, sub: CIMD_URL, poppy_sid: SID, poppy_user_id: USER_ID })),
      'poppy_agent_id'
    );
  });

  test('puts no value of the token into the message or the cause', () => {
    const act = sessionAct({ poppy_sid: 'secret+sid', poppy_user_id: 'secret-user', poppy_agent_id: 'secret-agent' });

    const error = failureOf(act) as InvalidSessionError;

    expect(JSON.stringify([error.message, error.cause])).not.toMatch(/secret/);
    expect(error.message).toBe(MESSAGE);
  });

  test('gives a new error each time, so that no stack or cause is shared', () => {
    const act = sessionAct({ poppy_user_id: undefined });

    const first = failureOf(act);
    const second = failureOf(act);

    expect(first).not.toBe(second);
    expect((first as InvalidSessionError).cause).not.toBe((second as InvalidSessionError).cause);
  });
});

describe('sessionFromToken | an error of getCurrentActor', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('reports an InvalidRequestError as a Session that is not well formed: act_sub', () => {
    vi.spyOn(actModule, 'getCurrentActor').mockImplementation(() => {
      throw new InvalidRequestError('Invalid "act" claim');
    });

    expectMalformed(failureOf(sessionAct()), 'act_sub');
  });

  test.each([
    { name: 'a TypeError', error: new TypeError('Cannot read properties of undefined') },
    { name: 'a RangeError', error: new RangeError('Maximum call stack size exceeded') },
    {
      name: 'an error of the SDK that is not an InvalidRequestError',
      error: new InvalidSessionError('missing_session'),
    },
    { name: 'a value that is not an error', error: 'boom' },
  ])('lets $name through as it is, because it is a bug and not a malformed Session', ({ error }) => {
    vi.spyOn(actModule, 'getCurrentActor').mockImplementation(() => {
      throw error;
    });

    expect(failureOf(sessionAct())).toBe(error);
  });
});
