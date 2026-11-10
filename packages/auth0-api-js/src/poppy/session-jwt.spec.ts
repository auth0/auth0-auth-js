import {
  SignJWT,
  base64url,
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  generateKeyPair,
  jwtVerify,
  type JWK,
} from 'jose';
import { beforeAll, describe, expect, expectTypeOf, test } from 'vitest';

import {
  DELEGATION_JWT_TYP,
  MAX_SESSION_ID_LENGTH,
  MAX_SESSION_JWT_LENGTH,
  MAX_URL_LENGTH,
  SESSION_JWT_ALGORITHMS,
  SESSION_JWT_TYP,
} from './constants.js';
import { InvalidSessionError } from './errors.js';
import { readPoppyRequestHeaders } from './request-headers.js';
import { normalizeTyp, parseSessionJwt, type UnverifiedSessionJwt } from './session-jwt.js';
import { createTestAgent } from './testing/test-agent.js';
import type { TestAgent, TestSessionJwtDefect, TestSessionJwtOptions } from './testing/test-agent.js';

const CIMD_URL = 'https://agent.example/agent.json';
const AUD = 'https://example.auth0.com/';
const HTU = 'https://api.example.com/orders';
const SID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
const JTI = 'e1j3V_bKic8-LAEBq7Rw2g';
const IAT = 1790900000;
// The SHA-256 hash of the access token `abc`, base64url-encoded.
const ATH_OF_ABC = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

// The messages of the errors, word for word. They say which check failed and nothing else: no value of the JWT is in
// them, so the same text comes back for every bad value of a check.
const MESSAGES = {
  shape: 'The Session JWT must be in compact form: three parts of base64url characters, separated by dots.',
  tooLong: `The Session JWT must be at most ${MAX_SESSION_JWT_LENGTH} characters.`,
  header: 'The Session JWT header must be a base64url-encoded JSON object.',
  payload: 'The Session JWT payload must be a base64url-encoded JSON object.',
  typ: 'The Session JWT typ header must be poppy-session+jwt.',
  alg: 'The Session JWT alg header must be ES256.',
  kid: 'The Session JWT kid header must be a non-empty string.',
  delegation: 'The Session JWT poppy_dlg header must be a JWT in compact form.',
  iss: 'The Session JWT iss claim must be the https URL of an agent.',
  aud: 'The Session JWT aud claim must be a single string.',
  sid: 'The Session JWT sid claim must be 1 to 256 characters of the base64url alphabet.',
  sub: 'The Session JWT sub claim must be a non-empty string.',
  jti: 'The Session JWT jti claim must be a non-empty string.',
  htm: 'The Session JWT htm claim must be a string.',
  htu: 'The Session JWT htu claim must be a string.',
  iat: 'The Session JWT iat claim must be a finite number.',
  agentId: 'The Session JWT agent_id claim must be left out or be a non-empty string.',
  ath: 'The Session JWT ath claim must be left out or be a non-empty string.',
} as const;

type Build = () => unknown;

/** The error `parseSessionJwt` throws for `jwt`. Fails the test when it does not throw. */
function rejectionOf(jwt: unknown): InvalidSessionError {
  try {
    parseSessionJwt(jwt as string);
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidSessionError);
    return error as InvalidSessionError;
  }
  throw new Error('Expected parseSessionJwt to throw.');
}

function expectMalformed(jwt: unknown, message: string): void {
  const error = rejectionOf(jwt);

  expect(error.reason).toBe('malformed_session');
  expect(error.code).toBe('invalid_session');
  expect(error.statusCode).toBe(400);
  expect(error.message).toBe(message);
  // Nothing else in the error can carry a part of the JWT.
  expect(error.cause).toBeUndefined();
  expect(error.headers).toBeUndefined();
}

function partOf(jwt: string, index: 0 | 1 | 2): string {
  return jwt.split('.')[index] ?? '';
}

/** The header or the payload of a JWT, as the JSON text it was made from. */
function textOf(jwt: string, index: 0 | 1): string {
  return new TextDecoder().decode(base64url.decode(partOf(jwt, index)));
}

/** `jwt` with one part replaced, so its signature no longer matches. The header and the payload are given as text. */
function withPart(jwt: string, index: 0 | 1 | 2, value: string): string {
  const parts = jwt.split('.');
  parts[index] = index === 2 ? value : base64url.encode(value);
  return parts.join('.');
}

/** `jwt` with its header changed. A value replaces the parameter, and `undefined` removes it. */
function withHeader(jwt: string, changes: Record<string, unknown>): string {
  const header = { ...(JSON.parse(textOf(jwt, 0)) as Record<string, unknown>), ...changes };
  return withPart(jwt, 0, JSON.stringify(header));
}

/** `jwt` with a signature of filler, so the whole JWT has exactly `length` characters. */
function withLength(jwt: string, length: number): string {
  const [header, payload] = [partOf(jwt, 0), partOf(jwt, 1)];
  return `${header}.${payload}.${'A'.repeat(length - header.length - payload.length - 2)}`;
}

describe('parseSessionJwt', () => {
  let agent: TestAgent;
  let valid: string;

  /** A valid Session JWT for `POST https://api.example.com/orders`, with the options and the overrides given. */
  function mint(options: Partial<TestSessionJwtOptions> = {}): Promise<string> {
    return agent.createSessionJwt({ aud: AUD, htm: 'POST', htu: HTU, sid: SID, jti: JTI, iat: IAT, ...options });
  }

  beforeAll(async () => {
    agent = await createTestAgent({ cimdUrl: CIMD_URL });
    valid = await mint();
  });

  describe('a valid Session JWT', () => {
    test('is read to its exact values', async () => {
      const jwt = await mint({ sub: 'usr_Q7c1vK', agentId: 'travel', accessToken: 'abc' });
      const delegation = decodeProtectedHeader(jwt).poppy_dlg as string;
      // The `kid` is the thumbprint of the key the delegation vouches for (RFC 7638).
      const { jwk } = (decodeJwt(delegation) as unknown as { cnf: { jwk: JWK } }).cnf;

      expect(parseSessionJwt(jwt)).toStrictEqual({
        jwt,
        header: {
          typ: 'poppy-session+jwt',
          alg: 'ES256',
          kid: await calculateJwkThumbprint(jwk),
          poppy_dlg: delegation,
        },
        claims: {
          iss: CIMD_URL,
          aud: AUD,
          sid: SID,
          sub: 'usr_Q7c1vK',
          agent_id: 'travel',
          htm: 'POST',
          htu: HTU,
          iat: IAT,
          jti: JTI,
          ath: ATH_OF_ABC,
        },
      });
    });

    // The check and the type are made from one list, so adding an algorithm to it changes both, and the type cannot
    // stay behind. The type checker reads these lines, and `npm run typecheck` is what fails when they are wrong.
    test('has an alg that is typed from the list of Session JWT algorithms', () => {
      expectTypeOf<UnverifiedSessionJwt['header']['alg']>().toEqualTypeOf<(typeof SESSION_JWT_ALGORITHMS)[number]>();
      expectTypeOf<UnverifiedSessionJwt['header']['alg']>().toEqualTypeOf<'ES256'>();
      expect(SESSION_JWT_ALGORITHMS).toEqual(['ES256']);
    });

    test('leaves agent_id and ath out of the result when the JWT has none', () => {
      const { claims } = parseSessionJwt(valid);

      expect(claims).not.toHaveProperty('agent_id');
      expect(claims).not.toHaveProperty('ath');
      expect(Object.keys(claims).sort()).toEqual(['aud', 'htm', 'htu', 'iat', 'iss', 'jti', 'sid', 'sub']);
    });

    test.each<[string, string]>([
      ['the type alone', 'poppy-session+jwt'],
      ['the type with application/ before it', 'application/poppy-session+jwt'],
      ['the type in capitals', 'POPPY-SESSION+JWT'],
      ['the type with capitals in some letters', 'Poppy-Session+Jwt'],
      ['the type with application/ in capitals', 'APPLICATION/POPPY-SESSION+JWT'],
      ['the type with Application/ before it', 'Application/poppy-session+jwt'],
    ])('accepts a typ that is %s, and returns it as it came', async (_label, typ) => {
      const parsed = parseSessionJwt(await mint({ header: { typ } }));

      expect(parsed.header.typ).toBe(typ);
    });

    test('reads the same JWT to equal results, in objects that share nothing', () => {
      const first = parseSessionJwt(valid);
      const second = parseSessionJwt(valid);

      expect(second).toStrictEqual(first);
      expect(second).not.toBe(first);
      expect(second.header).not.toBe(first.header);
      expect(second.claims).not.toBe(first.claims);

      first.claims.sid = 'changed';
      first.header.kid = 'changed';

      expect(parseSessionJwt(valid).claims.sid).toBe(SID);
      expect(parseSessionJwt(valid).header.kid).not.toBe('changed');
    });

    test('returns only the documented members, whatever else the JWT carries', async () => {
      const jwt = await mint({
        agentId: 'travel',
        accessToken: 'abc',
        header: {
          jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
          jku: 'https://evil.example/jwks.json',
          x5u: 'https://evil.example/cert',
          x5c: ['AAAA'],
          cty: 'JWT',
          custom: { nested: true },
        },
        claims: { exp: 1, nbf: 2, cnf: { jwk: {} }, scope: 'admin', custom: [1, 2, 3] },
      });

      const parsed = parseSessionJwt(jwt);

      expect(Object.keys(parsed).sort()).toEqual(['claims', 'header', 'jwt']);
      expect(Object.keys(parsed.header).sort()).toEqual(['alg', 'kid', 'poppy_dlg', 'typ']);
      expect(Object.keys(parsed.claims).sort()).toEqual([
        'agent_id',
        'ath',
        'aud',
        'htm',
        'htu',
        'iat',
        'iss',
        'jti',
        'sid',
        'sub',
      ]);
    });

    test('does not let a __proto__ member of the JWT change the result', () => {
      const header = textOf(valid, 0).replace('{', '{"__proto__":{"alg":"none","polluted":true},');
      const payload = textOf(valid, 1).replace('{', '{"__proto__":{"iss":"https://evil.example/x","polluted":true},');

      const parsed = parseSessionJwt(withPart(withPart(valid, 0, header), 1, payload));

      expect(parsed.header.alg).toBe('ES256');
      expect(parsed.claims.iss).toBe(CIMD_URL);
      expect(parsed.header).not.toHaveProperty('polluted');
      expect(parsed.claims).not.toHaveProperty('polluted');
      expect(Object.getPrototypeOf(parsed.header)).toBe(Object.prototype);
      expect(Object.getPrototypeOf(parsed.claims)).toBe(Object.prototype);
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });

    test('uses the last of two members with the same name, as JSON.parse and jose do', () => {
      const payload = textOf(valid, 1).replace('{', '{"sid":"first-sid",');

      expect(parseSessionJwt(withPart(valid, 1, payload)).claims.sid).toBe(SID);
    });

    test('ignores a deeply nested member that nothing reads', () => {
      const nested = `{"deep":${'{"a":'.repeat(1500)}1${'}'.repeat(1500)},`;

      const parsed = parseSessionJwt(withPart(valid, 1, textOf(valid, 1).replace('{', nested)));

      expect(parsed.claims.sid).toBe(SID);
    });

    // Parsing checks the shape of what the JWT says and nothing else. The checks of the delegation and of the
    // signature come later, and the ones that only they can make must not happen here: they need the keys of the agent.
    const DEFECT_MESSAGES: Record<TestSessionJwtDefect, string | undefined> = {
      missing_delegation: MESSAGES.delegation,
      signed_with_agent_key: MESSAGES.delegation,
      expired_delegation: undefined,
      delegation_too_long: undefined,
      delegation_from_future: undefined,
      delegation_iss_mismatch: undefined,
      delegation_wrong_typ: undefined,
      delegation_unknown_kid: undefined,
      delegation_private_cnf: undefined,
      session_wrong_typ: MESSAGES.typ,
      session_wrong_kid: undefined,
      session_bad_signature: undefined,
    };

    test.each(Object.entries(DEFECT_MESSAGES) as [TestSessionJwtDefect, string | undefined][])(
      'handles a Session JWT made with the test agent defect %s',
      async (defect, message) => {
        const jwt = await mint({ defect });

        if (message === undefined) {
          expect(parseSessionJwt(jwt).claims.iss).toBe(CIMD_URL);
        } else {
          expectMalformed(jwt, message);
        }
      }
    );

    test.each<[string, Partial<TestSessionJwtOptions>]>([
      [
        'a kid that is not a thumbprint, because the thumbprint is checked with the signature',
        { header: { kid: 'x' } },
      ],
      [
        'a poppy_dlg that is not a delegation, because the delegation is verified later',
        { header: { poppy_dlg: 'a.b.c' } },
      ],
      ['a sid of one character', { sid: 'a' }],
      ['a sid of 256 characters', { sid: 'a'.repeat(256) }],
      ['a sid with every kind of character', { sid: 'AZaz09-_' }],
      [
        'an agent on localhost, because the address is checked later',
        { claims: { iss: 'https://localhost:8443/agent.json' } },
      ],
      [
        'an agent on an IP address, because the address is checked later',
        { claims: { iss: 'https://127.0.0.1/agent.json' } },
      ],
      ['an iat of zero', { iat: 0 }],
      ['a negative iat', { iat: -5 }],
      ['an iat that has a fraction', { iat: 1790900000.5 }],
      ['a method in lower case, which the claim checks compare without case', { htm: 'post' }],
      ['a URL with a query, which the claim checks compare without it', { htu: `${HTU}?a=1#f` }],
      ['a URL that is not the URL of the request, which the claim checks refuse', { htu: 'http://other.example/x' }],
      ['an empty method and an empty URL, which the claim checks refuse', { htm: '', htu: '' }],
      ['an aud that is not the Company, which the claim checks refuse', { aud: 'https://other.example/' }],
      ['an empty aud, which the claim checks refuse', { aud: '' }],
      ['a sub and a jti of one space', { sub: ' ', jti: ' ' }],
    ])('accepts %s', async (_label, options) => {
      expect(parseSessionJwt(await mint(options)).claims.iss).toMatch(/^https:\/\//);
    });

    test('accepts a JWT of exactly the longest length, and rejects one character more', () => {
      const longest = withLength(valid, MAX_SESSION_JWT_LENGTH);

      expect(longest).toHaveLength(MAX_SESSION_JWT_LENGTH);
      expect(parseSessionJwt(longest).claims.sid).toBe(SID);
      expectMalformed(withLength(valid, MAX_SESSION_JWT_LENGTH + 1), MESSAGES.tooLong);
    });
  });

  describe('rejects', () => {
    describe('a JWT that is not three parts of base64url characters', () => {
      test.each<[string, Build]>([
        ['an empty string', () => ''],
        ['one part', () => 'abcdef'],
        ['two parts', () => 'abc.def'],
        ['four parts, with a part after the signature', () => `${valid}.abc`],
        ['five parts, as a JWE has', () => 'a.b.c.d.e'],
        ['only dots', () => '..'],
        ['an empty header', () => `.${partOf(valid, 1)}.${partOf(valid, 2)}`],
        ['an empty payload', () => `${partOf(valid, 0)}..${partOf(valid, 2)}`],
        ['an empty signature', () => `${partOf(valid, 0)}.${partOf(valid, 1)}.`],
        ['a space before the JWT', () => ` ${valid}`],
        ['a space after the JWT', () => `${valid} `],
        ['a tab before the JWT', () => `\t${valid}`],
        ['a line feed after the JWT', () => `${valid}\n`],
        ['a carriage return and a line feed after the JWT', () => `${valid}\r\n`],
        ['a null character after the JWT', () => `${valid}\u0000`],
        [
          'a space inside the header, which a lenient decoder would skip',
          () =>
            `${partOf(valid, 0).slice(0, 10)} ${partOf(valid, 0).slice(10)}.${partOf(valid, 1)}.${partOf(valid, 2)}`,
        ],
        [
          'a space inside the payload, which a lenient decoder would skip',
          () =>
            `${partOf(valid, 0)}.${partOf(valid, 1).slice(0, 10)} ${partOf(valid, 1).slice(10)}.${partOf(valid, 2)}`,
        ],
        ['padding after the header', () => `${partOf(valid, 0)}=.${partOf(valid, 1)}.${partOf(valid, 2)}`],
        ['padding after the signature', () => `${valid}=`],
        ['the plus sign of standard base64 in the signature', () => `${partOf(valid, 0)}.${partOf(valid, 1)}.ab+cd`],
        ['the slash of standard base64 in the signature', () => `${partOf(valid, 0)}.${partOf(valid, 1)}.ab/cd`],
        ['a letter that is not ASCII in the signature', () => `${partOf(valid, 0)}.${partOf(valid, 1)}.abc\u00e9`],
        ['a letter that looks like a Latin one', () => `${valid.slice(0, 5)}\uff41${valid.slice(6)}`],
        ['a JSON object instead of a JWT', () => '{"typ":"poppy-session+jwt"}'],
        ['the Bearer scheme before the JWT', () => `Bearer ${valid}`],
        ['the JWT in quotes', () => `"${valid}"`],
        ['two JWTs joined with a comma', () => `${valid},${valid}`],
        ['two JWTs joined with a comma and a space', () => `${valid}, ${valid}`],
        ['two JWTs joined with a space', () => `${valid} ${valid}`],
        ['undefined', () => undefined],
        ['null', () => null],
        ['a number', () => 42],
        ['an array that holds the JWT', () => [valid]],
        ['an object', () => ({ jwt: valid })],
        ['a String object that holds the JWT', () => new String(valid)],
      ])('%s', async (_label, build) => {
        expectMalformed(await build(), MESSAGES.shape);
      });

      test('a long run of base64url characters that ends in a character that is not', () => {
        expectMalformed(`${'a'.repeat(MAX_SESSION_JWT_LENGTH - 10)}.${'b'.repeat(5)}.!`, MESSAGES.shape);
        expectMalformed(`${'a.'.repeat(Math.floor(MAX_SESSION_JWT_LENGTH / 2))}`, MESSAGES.shape);
      });
    });

    describe('a JWT longer than MAX_SESSION_JWT_LENGTH', () => {
      test.each<[string, Build]>([
        ['one character over the limit', () => withLength(valid, MAX_SESSION_JWT_LENGTH + 1)],
        [
          'a claim that is as long as the limit',
          () => mint({ claims: { padding: 'x'.repeat(MAX_SESSION_JWT_LENGTH) } }),
        ],
        ['letters only', () => 'a'.repeat(MAX_SESSION_JWT_LENGTH + 1)],
        ['dots only', () => '.'.repeat(MAX_SESSION_JWT_LENGTH + 1)],
        ['a million characters', () => `${valid.slice(0, 10)}${'a'.repeat(1_000_000)}`],
      ])('%s', async (_label, build) => {
        expectMalformed(await build(), MESSAGES.tooLong);
      });
    });

    describe('a header or a payload that cannot be decoded to a JSON object', () => {
      const BAD_TEXTS: [string, string][] = [
        ['text that is not JSON', 'not json'],
        ['JSON that stops early', '{"typ":"poppy-session+jwt"'],
        ['an array', '[1,2]'],
        ['an array of one object', '[{"typ":"poppy-session+jwt"}]'],
        ['a string', '"text"'],
        ['a number', '123'],
        ['null', 'null'],
        ['true', 'true'],
        ['an array nested 3000 deep', `${'['.repeat(3000)}${']'.repeat(3000)}`],
      ];

      test.each<[string, Build]>([
        ...BAD_TEXTS.map(([label, text]): [string, Build] => [
          `a header that is ${label}`,
          () => withPart(valid, 0, text),
        ]),
        [
          'a header of one character, which is not a whole number of bytes',
          () => `a.${partOf(valid, 1)}.${partOf(valid, 2)}`,
        ],
        ['a header of five characters', () => `abcde.${partOf(valid, 1)}.${partOf(valid, 2)}`],
      ])('%s', async (_label, build) => {
        expectMalformed(await build(), MESSAGES.header);
      });

      test.each<[string, Build]>([
        ...BAD_TEXTS.map(([label, text]): [string, Build] => [
          `a payload that is ${label}`,
          () => withPart(valid, 1, text),
        ]),
        [
          'a payload of one character, which is not a whole number of bytes',
          () => `${partOf(valid, 0)}.a.${partOf(valid, 2)}`,
        ],
        ['a payload of five characters', () => `${partOf(valid, 0)}.abcde.${partOf(valid, 2)}`],
      ])('%s', async (_label, build) => {
        expectMalformed(await build(), MESSAGES.payload);
      });

      test('checks the header before the payload', () => {
        expectMalformed(withPart(withPart(valid, 0, 'not json'), 1, 'not json'), MESSAGES.header);
      });
    });

    describe('a typ that is not poppy-session+jwt', () => {
      test.each<[string, unknown]>([
        ['JWT', 'JWT'],
        ['the typ of a delegation', 'poppy-delegation+jwt'],
        ['the typ of a delegation with application/', 'application/poppy-delegation+jwt'],
        ['more text after the type', 'poppy-session+jwt+extra'],
        ['text before the type', 'my-poppy-session+jwt'],
        ['another top-level type', 'text/poppy-session+jwt'],
        ['application/ twice', 'application/application/poppy-session+jwt'],
        ['a space before the type', ' poppy-session+jwt'],
        ['a space after the type', 'poppy-session+jwt '],
        ['a media type parameter', 'poppy-session+jwt; charset=utf-8'],
        ['a slash after the type', 'poppy-session+jwt/'],
        ['a slash before the type', '/poppy-session+jwt'],
        ['an empty string', ''],
        ['only application/', 'application/'],
        ['a number', 123],
        ['null', null],
        ['true', true],
        ['an array that holds the type', ['poppy-session+jwt']],
        ['an object', { typ: 'poppy-session+jwt' }],
        ['no typ', undefined],
      ])('%s', async (_label, typ) => {
        expectMalformed(await mint({ header: { typ } }), MESSAGES.typ);
      });
    });

    describe('an alg that is not ES256', () => {
      test.each<[string, unknown]>([
        ['ES384', 'ES384'],
        ['ES512', 'ES512'],
        ['RS256', 'RS256'],
        ['PS256', 'PS256'],
        ['PS384, which a delegation can use and a Session JWT cannot', 'PS384'],
        ['HS256', 'HS256'],
        ['HS512', 'HS512'],
        ['none', 'none'],
        ['None', 'None'],
        ['es256 in lower case', 'es256'],
        ['ES256 with a space after it', 'ES256 '],
        ['an empty string', ''],
        ['a number', 256],
        ['null', null],
        ['an array that holds ES256', ['ES256']],
        ['no alg', undefined],
      ])('%s', async (_label, alg) => {
        expectMalformed(withHeader(valid, { alg }), MESSAGES.alg);
      });

      test('checks the typ before the alg', () => {
        expectMalformed(withHeader(valid, { typ: 'JWT', alg: 'none' }), MESSAGES.typ);
      });
    });

    describe('a kid that is missing or empty', () => {
      test.each<[string, unknown]>([
        ['no kid', undefined],
        ['an empty string', ''],
        ['a number', 123],
        ['null', null],
        ['true', true],
        ['an array that holds a string', ['x']],
        ['an object', {}],
      ])('%s', async (_label, kid) => {
        expectMalformed(await mint({ header: { kid } }), MESSAGES.kid);
      });
    });

    describe('a poppy_dlg that is missing or is not three parts', () => {
      test.each<[string, unknown]>([
        ['no poppy_dlg', undefined],
        ['an empty string', ''],
        ['one part', 'abc'],
        ['two parts', 'a.b'],
        ['four parts', 'a.b.c.d'],
        ['an empty part in the middle', 'a..c'],
        ['an empty first part', '.b.c'],
        ['an empty signature', 'a.b.'],
        ['a space inside', 'a b.c.d'],
        ['a line feed at the end', 'a.b.c\n'],
        ['a comma', 'a.b.c,d.e.f'],
        ['a number', 123],
        ['null', null],
        ['true', true],
        ['an array that holds a delegation', ['a.b.c']],
        ['an object', {}],
      ])('%s', async (_label, poppyDlg) => {
        expectMalformed(await mint({ header: { poppy_dlg: poppyDlg } }), MESSAGES.delegation);
      });
    });

    describe('an iss that is not an agent URL', () => {
      test.each<[string, unknown]>([
        ['http', 'http://agent.example/agent.json'],
        ['a URL with a user name and a password', 'https://u:p@agent.example/agent.json'],
        ['a URL with a fragment', 'https://agent.example/agent.json#f'],
        ['a URL with an empty fragment', 'https://agent.example/agent.json#'],
        ['a host in capitals, which is not canonical', 'https://Agent.example/agent.json'],
        ['a URL with no path, which is not canonical', 'https://agent.example'],
        ['the default port, which is not canonical', 'https://agent.example:443/agent.json'],
        ['text that is not a URL', 'not a url'],
        ['a script URL', 'javascript:alert(1)'],
        ['an empty string', ''],
        ['a URL over the length limit', `https://agent.example/${'a'.repeat(MAX_URL_LENGTH)}`],
        ['a number', 123],
        ['null', null],
        ['an array that holds the URL', [CIMD_URL]],
        ['an object', { href: CIMD_URL }],
        ['no iss', undefined],
      ])('%s', async (_label, iss) => {
        expectMalformed(await mint({ claims: { iss } }), MESSAGES.iss);
      });
    });

    describe('an aud that is not a string', () => {
      test.each<[string, unknown]>([
        ['an array of one string, because the specification wants a single string', [AUD]],
        ['an array of two strings', [AUD, 'https://other.example/']],
        ['an empty array', []],
        ['a number', 123],
        ['null', null],
        ['true', true],
        ['an object', { aud: AUD }],
        ['no aud', undefined],
      ])('%s', async (_label, aud) => {
        expectMalformed(await mint({ claims: { aud } }), MESSAGES.aud);
      });
    });

    describe('a sid that is not a Session ID', () => {
      test.each<[string, unknown]>([
        ['an empty string', ''],
        ['257 characters', 'a'.repeat(257)],
        ['a space', 'a b'],
        ['a space at the start', ' abc'],
        ['a plus sign', 'a+b'],
        ['a slash', 'a/b'],
        ['an equals sign', 'a=b'],
        ['a dot', 'a.b'],
        ['a line feed at the end', 'abc\n'],
        ['a line feed at the start', '\nabc'],
        ['a null character', 'abc\u0000'],
        ['a letter that is not ASCII', '\u00e9'],
        ['a number, which the pattern would read as text', 123],
        ['an array of one valid sid, which the pattern would read as text', ['abc']],
        ['null', null],
        ['an object', {}],
        ['no sid', undefined],
      ])('%s', async (_label, sid) => {
        expectMalformed(await mint({ claims: { sid } }), MESSAGES.sid);
      });

      test('accepts a sid of 256 characters and rejects one of 257, with the limit in the message', async () => {
        // 256 is the limit that the specification sets for the IDs of section 8.2, and the SDK applies it to a sid. The
        // pattern and the message are made from the one constant, and this test holds the constant to that number.
        expect(MAX_SESSION_ID_LENGTH).toBe(256);

        expect(parseSessionJwt(await mint({ sid: 'a'.repeat(256) })).claims.sid).toHaveLength(256);
        expectMalformed(await mint({ claims: { sid: 'a'.repeat(257) } }), MESSAGES.sid);
        expect(MESSAGES.sid).toContain('1 to 256 characters');
      });
    });

    describe.each<[string, 'sub' | 'jti', string]>([
      ['sub', 'sub', MESSAGES.sub],
      ['jti', 'jti', MESSAGES.jti],
    ])('a %s that is not a non-empty string', (_name, claim, message) => {
      test.each<[string, unknown]>([
        ['an empty string', ''],
        ['a number', 123],
        ['zero', 0],
        ['null', null],
        ['true', true],
        ['false', false],
        ['an array that holds a string', ['x']],
        ['an object', {}],
        [`no ${claim}`, undefined],
      ])('%s', async (_label, value) => {
        expectMalformed(await mint({ claims: { [claim]: value } }), message);
      });
    });

    describe.each<[string, 'htm' | 'htu', string]>([
      ['htm', 'htm', MESSAGES.htm],
      ['htu', 'htu', MESSAGES.htu],
    ])('an %s that is not a string', (_name, claim, message) => {
      test.each<[string, unknown]>([
        ['a number', 123],
        ['null', null],
        ['true', true],
        ['an array that holds a string', ['POST']],
        ['an object', {}],
        [`no ${claim}`, undefined],
      ])('%s', async (_label, value) => {
        expectMalformed(await mint({ claims: { [claim]: value } }), message);
      });
    });

    describe('an iat that is not a finite number', () => {
      test.each<[string, unknown]>([
        ['a string of digits', '1790900000'],
        ['an empty string', ''],
        ['null, which is what JSON makes of NaN', null],
        ['true', true],
        ['an array that holds a number', [IAT]],
        ['an object', {}],
        ['no iat', undefined],
      ])('%s', async (_label, iat) => {
        expectMalformed(await mint({ claims: { iat } }), MESSAGES.iat);
      });

      test.each<[string, string]>([
        ['1e999, which JSON.parse reads as Infinity', '1e999'],
        ['-1e999, which JSON.parse reads as minus Infinity', '-1e999'],
      ])('%s', (_label, literal) => {
        const payload = textOf(valid, 1).replace(`"iat":${IAT}`, `"iat":${literal}`);

        expect(payload).toContain(literal);
        expectMalformed(withPart(valid, 1, payload), MESSAGES.iat);
      });
    });

    describe.each<[string, 'agent_id' | 'ath', string]>([
      ['agent_id', 'agent_id', MESSAGES.agentId],
      ['ath', 'ath', MESSAGES.ath],
    ])('an %s that is there and is not a non-empty string', (_name, claim, message) => {
      test.each<[string, unknown]>([
        ['an empty string', ''],
        ['a number', 123],
        ['zero', 0],
        ['null, because the claim is there', null],
        ['true', true],
        ['false', false],
        ['an array that holds a string', ['x']],
        ['an object', {}],
      ])('%s', async (_label, value) => {
        expectMalformed(await mint({ claims: { [claim]: value } }), message);
      });
    });

    test('a JWT that the agent signed with its own key, and not with a delegated key', async () => {
      // There is no delegation, and the specification says the Company must reject such a JWT.
      expectMalformed(await mint({ defect: 'signed_with_agent_key' }), MESSAGES.delegation);
      expectMalformed(await mint({ defect: 'missing_delegation' }), MESSAGES.delegation);
    });

    test('runs the checks in a fixed order, so the first one that fails gives the message', async () => {
      // The typ is wrong, and so are the alg, the kid, the delegation and the claims.
      const everythingWrong = await mint({
        header: { typ: 'JWT', kid: '', poppy_dlg: undefined },
        claims: { iss: 'x', sid: '' },
      });

      expectMalformed(withHeader(everythingWrong, { alg: 'none' }), MESSAGES.typ);
      expectMalformed(withHeader(everythingWrong, { alg: 'none', typ: SESSION_JWT_TYP }), MESSAGES.alg);
      expectMalformed(withHeader(everythingWrong, { typ: SESSION_JWT_TYP }), MESSAGES.kid);
      expectMalformed(withHeader(everythingWrong, { typ: SESSION_JWT_TYP, kid: 'k' }), MESSAGES.delegation);
      expectMalformed(
        withHeader(everythingWrong, { typ: SESSION_JWT_TYP, kid: 'k', poppy_dlg: 'a.b.c' }),
        MESSAGES.iss
      );
    });
  });

  describe('the error', () => {
    test('is an InvalidSessionError with reason malformed_session, status 400 and code invalid_session', () => {
      const error = rejectionOf('not a jwt');

      expect(error.name).toBe('InvalidSessionError');
      expect(error.reason).toBe('malformed_session');
      expect(error.code).toBe('invalid_session');
      expect(error.statusCode).toBe(400);
    });

    test('has the same message for different bad values of the same check', async () => {
      const first = rejectionOf(await mint({ claims: { sid: 'secret-value-one!' } }));
      const second = rejectionOf(await mint({ claims: { sid: 'another secret value' } }));

      expect(first.message).toBe(second.message);
      expect(first.message).not.toContain('secret');
    });

    test('never contains a part of the JWT or of what it carries', async () => {
      const marker = 'leak-me-4f9c1d';
      const inputs: unknown[] = [
        `${valid}.${marker}`,
        `${marker}${valid}`,
        withPart(valid, 0, marker),
        withPart(valid, 1, JSON.stringify({ marker })),
        withHeader(valid, { typ: marker }),
        withHeader(valid, { alg: marker }),
        await mint({ header: { kid: 7, typ: marker } }),
        await mint({ claims: { iss: `https://${marker}.example/x#f` } }),
        await mint({ claims: { aud: [marker] } }),
        await mint({ claims: { sid: `${marker} ` } }),
        await mint({ claims: { sub: [marker] } }),
        await mint({ claims: { htm: [marker], htu: [marker] } }),
        await mint({ claims: { iat: marker } }),
        await mint({ claims: { agent_id: [marker] } }),
        await mint({ claims: { ath: [marker] } }),
        await mint({ header: { poppy_dlg: `${marker}.x` } }),
        marker,
      ];

      for (const input of inputs) {
        const { message, stack } = rejectionOf(input);

        expect(message.toLowerCase()).not.toContain(marker);
        // The stack starts with the name and the message, and holds paths and nothing of the JWT.
        expect(stack ?? '').not.toContain(marker);
        expect(stack ?? '').not.toContain(partOf(valid, 2));
      }
    });
  });

  // The pipeline reads the header first and parses what it returns, so the two have to agree on every form of header.
  describe('the value that readPoppyRequestHeaders returns', () => {
    test.each<[string, (jwt: string) => Record<string, string | string[] | undefined>]>([
      ['the usual name', (jwt) => ({ 'Poppy-Session': jwt })],
      ['lower case and an array of one', (jwt) => ({ 'poppy-session': [jwt] })],
      ['upper case with spaces and tabs around the value', (jwt) => ({ 'POPPY-SESSION': ` \t${jwt}\t ` })],
      ['a Fetch API Headers object', (jwt) => Object.fromEntries(new Headers({ 'Poppy-Session': jwt }))],
    ])('is parsed from %s', (_label, toHeaders) => {
      const { session, sessionMalformed } = readPoppyRequestHeaders(toHeaders(valid));

      expect(sessionMalformed).toBe(false);
      expect(parseSessionJwt(session as string).jwt).toBe(valid);
    });

    test('is not there when the header was sent twice, whatever the form, so nothing is parsed', () => {
      const twice = [
        { 'poppy-session': [valid, valid] },
        { 'Poppy-Session': valid, 'poppy-session': valid },
        { 'poppy-session': `${valid}, ${valid}` },
        Object.fromEntries(
          new Headers([
            ['Poppy-Session', valid],
            ['poppy-session', valid],
          ])
        ),
      ];

      for (const headers of twice) {
        expect(readPoppyRequestHeaders(headers)).toMatchObject({ session: undefined, sessionMalformed: true });
      }
    });
  });

  describe('every input', () => {
    // The pipeline answers 400 for an InvalidSessionError and 500 for anything else, so nothing else may come out.
    test('gives a result or an InvalidSessionError with reason malformed_session, for any change to the JWT', () => {
      const replacements = ['A', '9', '-', '_', '.', '=', ' ', '\u00e9'];
      let parsed = 0;
      let rejected = 0;
      // Collected and checked once at the end, because about 20 000 calls make this loop cheap, and an assertion for
      // each one would not be.
      const unexpected: unknown[] = [];

      const attempt = (jwt: string): void => {
        try {
          parseSessionJwt(jwt);
          parsed += 1;
        } catch (error) {
          if (error instanceof InvalidSessionError && error.reason === 'malformed_session') {
            rejected += 1;
          } else {
            unexpected.push(error);
          }
        }
      };

      for (let index = 0; index < valid.length; index += 1) {
        attempt(valid.slice(0, index));
        for (const replacement of replacements) {
          attempt(`${valid.slice(0, index)}${replacement}${valid.slice(index + 1)}`);
          attempt(`${valid.slice(0, index)}${replacement}${valid.slice(index)}`);
        }
        attempt(`${valid.slice(0, index)}${valid.slice(index + 1)}`);
      }

      expect(unexpected).toEqual([]);
      // The loop reaches both outcomes, so it tests something. A change to the signature still parses, because the
      // signature is checked later and not here.
      expect(parsed).toBeGreaterThan(50);
      expect(rejected).toBeGreaterThan(1000);
    });
  });
});

describe('normalizeTyp', () => {
  test.each<[string, string]>([
    ['poppy-session+jwt', 'poppy-session+jwt'],
    ['application/poppy-session+jwt', 'poppy-session+jwt'],
    ['Application/Poppy-Session+JWT', 'poppy-session+jwt'],
    ['APPLICATION/JWT', 'jwt'],
    ['JWT', 'jwt'],
    ['application/application/jwt', 'application/jwt'],
    ['text/plain', 'text/plain'],
    ['application/', ''],
    ['', ''],
    [' application/jwt', ' application/jwt'],
    ['xapplication/jwt', 'xapplication/jwt'],
    ['application/jwt/', 'jwt/'],
    ['application', 'application'],
  ])('%j becomes %j', (typ, normalized) => {
    expect(normalizeTyp(typ)).toBe(normalized);
  });

  // The rule is the way jose compares a `typ`: lower case, and `application/` can be left out. One table checks both
  // JWT kinds against jose itself, so the two cannot drift.
  describe('compares typ the way jose does', () => {
    const TYPS = [
      'poppy-session+jwt',
      'Poppy-Session+JWT',
      'application/poppy-session+jwt',
      'APPLICATION/POPPY-SESSION+JWT',
      'application/application/poppy-session+jwt',
      'text/poppy-session+jwt',
      ' poppy-session+jwt',
      'poppy-session+jwt ',
      'poppy-session+jwt/',
      'poppy-session',
      'poppy-delegation+jwt',
      'Poppy-Delegation+JWT',
      'application/poppy-delegation+jwt',
      'application//poppy-delegation+jwt',
      '/poppy-delegation+jwt',
      'JWT',
      'application/',
      'application/jwt',
      '',
    ];
    let privateKey: CryptoKey;
    let publicKey: CryptoKey;

    beforeAll(async () => {
      ({ privateKey, publicKey } = await generateKeyPair('ES256'));
    });

    test.each([
      ['a Session JWT', SESSION_JWT_TYP],
      ['a delegation', DELEGATION_JWT_TYP],
    ])('for %s', async (_label, expected) => {
      let accepted = 0;
      for (const typ of TYPS) {
        const jws = await new SignJWT({ a: 1 }).setProtectedHeader({ alg: 'ES256', typ }).sign(privateKey);
        const joseAccepts = await jwtVerify(jws, publicKey, { typ: expected }).then(
          () => true,
          () => false
        );

        expect({ typ, accepted: normalizeTyp(typ) === expected }).toStrictEqual({ typ, accepted: joseAccepts });
        accepted += joseAccepts ? 1 : 0;
      }

      // The table has typs that jose accepts and typs it refuses.
      expect(accepted).toBeGreaterThanOrEqual(3);
      expect(accepted).toBeLessThan(TYPS.length / 2);
    });
  });
});
