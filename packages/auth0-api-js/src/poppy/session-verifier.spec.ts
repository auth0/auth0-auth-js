import { createHash } from 'node:crypto';

import { CompactSign, base64url, decodeJwt, type CompactJWSHeaderParameters } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';

import { InvalidConfigurationError, InvalidRequestError } from '../errors.js';
import { rejectionOf } from '../test-utils/poppy.js';
import type { InvalidSessionReason } from '../types.js';
import { AgentMetadataFetcher } from './agent-metadata.js';
import { DEFAULT_DELEGATION_CACHE_MAX_ENTRIES, SESSION_JWT_TYP } from './constants.js';
import { DelegationVerifier, type VerifiedDelegation } from './delegation.js';
import { InvalidSessionError } from './errors.js';
import { parseSessionJwt, type UnverifiedSessionJwt } from './session-jwt.js';
import {
  checkSessionClaims,
  computeAth,
  computeSessionKey,
  expectedRequestUrl,
  verifySessionSignature,
} from './session-verifier.js';
import { createTestAgent, type TestAgent, type TestSessionJwtOptions } from './testing/test-agent.js';

const CIMD_URL = 'https://agent.example/agent.json';
const AUD = 'https://example.auth0.com/';
const PUBLIC_ORIGIN = 'https://api.zepto.example';
const HTU = `${PUBLIC_ORIGIN}/orders`;
const SID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
const START = Date.UTC(2026, 10, 6, 12, 0, 0);
const START_SECONDS = START / 1000;
const NOW = 1_790_900_000;
const IAT_WINDOW_SECONDS = 60;
// The SHA-256 hash of the access token `abc`, base64url-encoded.
const ATH_OF_ABC = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';
// The SHA-256 hash of the text `<agent URL>\n<SID>`, base64url-encoded, computed with another implementation.
const SESSION_KEY_OF_AGENT_AND_SID = 'TCKalJy8Oz7hl1YTKAJt86LQcaiaLsYmFX-cLwiaJ4c';

// The messages of the errors, word for word. They say which check failed and nothing else: no value of the JWT or of
// the request is in them, so the same text comes back for every bad value of a check.
const MESSAGES = {
  session_kid: 'The Session JWT kid is not the thumbprint of the delegated key.',
  session_signature: 'The Session JWT could not be verified with the delegated key.',
  aud: 'The Session JWT aud is not the identifier of your Company.',
  htm: 'The Session JWT htm is not the method of the request.',
  htu: 'The Session JWT htu is not the URL of the request, or is not an https URL.',
  iat: 'The Session JWT iat is outside the accepted window.',
  url: 'The request URL must be an absolute URL or a path that starts with "/".',
  noOrigin:
    'Invalid poppy configuration: the URL of the request must be a full URL, such as https://api.example.com/orders, ' +
    'when the public origin of the API is not known. Pass the full URL, or set poppy.baseUrl, or set the ' +
    'public_origin of the API in poppy.config.',
} as const;

type SessionCause = 'session_kid' | 'session_signature';
type ClaimCause = 'aud' | 'htm' | 'htu' | 'iat';

// Pins `Date` only: the clock of the caches and of `jose` moves, and the timers of the runtime keep working.
function pinClock(): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
}

function expectRefusal(
  action: () => unknown,
  reason: InvalidSessionReason,
  cause: SessionCause | ClaimCause
): InvalidSessionError {
  let thrown: unknown;
  try {
    action();
  } catch (error) {
    thrown = error;
  }
  return expectRefused(thrown, reason, cause);
}

function expectRefused(error: unknown, reason: InvalidSessionReason, cause: SessionCause | ClaimCause) {
  expect(error).toBeInstanceOf(InvalidSessionError);
  const refused = error as InvalidSessionError;
  expect(refused.reason).toBe(reason);
  expect(refused.code).toBe('invalid_session');
  expect(refused.statusCode).toBe(400);
  expect(refused.cause).toEqual({ code: cause });
  expect(refused.message).toBe(MESSAGES[cause]);
  return refused;
}

function partsOf(jwt: string): [string, string, string] {
  const [header = '', payload = '', signature = ''] = jwt.split('.');
  return [header, payload, signature];
}

/** The header or the payload of a JWT, as the JSON text it was made from. */
function textOf(jwt: string, index: 0 | 1): string {
  return new TextDecoder().decode(base64url.decode(partsOf(jwt)[index]));
}

/** `jwt` with one part replaced, so its signature no longer matches. The header and the payload are given as text. */
function withPart(jwt: string, index: 0 | 1 | 2, value: string): string {
  const parts = partsOf(jwt);
  parts[index] = index === 2 ? value : base64url.encode(value);
  return parts.join('.');
}

/** `jwt` with the header or the payload changed. A value replaces the member, and `undefined` removes it. */
function withMember(jwt: string, index: 0 | 1, changes: Record<string, unknown>): string {
  const current = JSON.parse(textOf(jwt, index)) as Record<string, unknown>;
  for (const [name, value] of Object.entries(changes)) {
    if (value === undefined) {
      delete current[name];
    } else {
      current[name] = value;
    }
  }
  return withPart(jwt, index, JSON.stringify(current));
}

describe('session-verifier', () => {
  let agent: TestAgent;

  beforeAll(async () => {
    agent = await createTestAgent({ cimdUrl: CIMD_URL });
  });

  beforeEach(() => {
    pinClock();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** A Session JWT of the test agent for `POST https://api.zepto.example/orders`, as text. */
  function mintJwt(options: Partial<TestSessionJwtOptions> = {}): Promise<string> {
    return agent.createSessionJwt({ aud: AUD, htm: 'POST', htu: HTU, sid: SID, ...options });
  }

  /** The same, parsed. Do not use it for a defect that the parser refuses. */
  async function mint(options: Partial<TestSessionJwtOptions> = {}): Promise<UnverifiedSessionJwt> {
    return parseSessionJwt(await mintJwt(options));
  }

  /** The delegation of a Session JWT, verified by the real verifier over the test agent. */
  function verifyDelegation(session: UnverifiedSessionJwt): Promise<VerifiedDelegation> {
    const fetcher = new AgentMetadataFetcher({
      fetch: agent.fetch,
      ttlMs: 600_000,
      maxEntries: 100,
      timeoutMs: 5000,
      maxBytes: 65_536,
      allowPrivateAddresses: false,
    });
    const verifier = new DelegationVerifier(fetcher, {
      iatWindowSeconds: IAT_WINDOW_SECONDS,
      cacheMaxEntries: DEFAULT_DELEGATION_CACHE_MAX_ENTRIES,
      ttlMs: 600_000,
    });
    return verifier.verify(session.header.poppy_dlg, session.claims.iss);
  }

  describe('verifySessionSignature', () => {
    test('passes for a Session JWT that the delegated key signed', async () => {
      const session = await mint();
      const delegation = await verifyDelegation(session);

      await expect(verifySessionSignature(session, delegation)).resolves.toBeUndefined();
    });

    test.each(['Poppy-Session+JWT', 'application/poppy-session+jwt'])(
      'passes with the typ %s, as the parser takes it',
      async (typ) => {
        const session = await mint({ header: { typ } });
        const delegation = await verifyDelegation(session);

        await expect(verifySessionSignature(session, delegation)).resolves.toBeUndefined();
      }
    );

    test('passes for a Session JWT with an exp that has not passed and an nbf that has', async () => {
      const session = await mint({ claims: { exp: START_SECONDS + 600, nbf: START_SECONDS - 600 } });
      const delegation = await verifyDelegation(session);

      await expect(verifySessionSignature(session, delegation)).resolves.toBeUndefined();
    });

    test('passes for every Session JWT of one User, with the one delegation', async () => {
      const first = await mint({ sid: 'sid-one' });
      const second = await mint({ sid: 'sid-two', htm: 'GET' });
      const delegation = await verifyDelegation(first);

      await expect(verifySessionSignature(first, delegation)).resolves.toBeUndefined();
      await expect(verifySessionSignature(second, delegation)).resolves.toBeUndefined();
    });

    test('refuses session_bad_signature, a signature of another key', async () => {
      const session = await mint({ defect: 'session_bad_signature' });
      const delegation = await verifyDelegation(session);

      // The kid is right, and the key that signed is not the delegated key.
      expect(session.header.kid).toBe(delegation.sessionKeyThumbprint);
      expectRefused(
        await rejectionOf(verifySessionSignature(session, delegation)),
        'signature_invalid',
        'session_signature'
      );
    });

    test('refuses session_wrong_kid, a kid that is not the thumbprint of the delegated key', async () => {
      const session = await mint({ defect: 'session_wrong_kid' });
      const delegation = await verifyDelegation(session);

      // The delegated key signed the JWT, so only the kid is wrong.
      expectRefused(await rejectionOf(verifySessionSignature(session, delegation)), 'signature_invalid', 'session_kid');
    });

    test('refuses session_wrong_typ, a typ of JWT, that the parser would refuse before this step', async () => {
      const good = await mint();
      const delegation = await verifyDelegation(good);
      const wrongTyp = await mintJwt({ defect: 'session_wrong_typ' });
      expect(() => parseSessionJwt(wrongTyp)).toThrow(InvalidSessionError);

      // The JWT is signed with the delegated key, so only the typ is wrong.
      const session: UnverifiedSessionJwt = { ...good, jwt: wrongTyp };
      expectRefused(
        await rejectionOf(verifySessionSignature(session, delegation)),
        'signature_invalid',
        'session_signature'
      );
    });

    test('checks the kid before the signature', async () => {
      const session = await mint({ defect: 'session_wrong_kid' });
      const delegation = await verifyDelegation(session);
      const unsigned: UnverifiedSessionJwt = { ...session, jwt: withPart(session.jwt, 2, 'c2ln') };

      expectRefused(
        await rejectionOf(verifySessionSignature(unsigned, delegation)),
        'signature_invalid',
        'session_kid'
      );
    });

    test('refuses a Session JWT that carries the delegation of another User', async () => {
      const mine = await mint({ sub: 'usr_mine' });
      const other = await mint({ sub: 'usr_other' });
      const stolen = await mint({ sub: 'usr_mine', header: { poppy_dlg: other.header.poppy_dlg } });
      const delegation = await verifyDelegation(stolen);

      // The delegation is a valid one, for the key of the other User.
      expect(delegation.sessionKeyThumbprint).toBe(other.header.kid);
      expect(delegation.sessionKeyThumbprint).not.toBe(mine.header.kid);
      expectRefused(await rejectionOf(verifySessionSignature(stolen, delegation)), 'signature_invalid', 'session_kid');
    });

    test.each([
      { name: 'the htu', index: 1 as const, changes: { htu: 'https://api.zepto.example/other' } },
      { name: 'the sub', index: 1 as const, changes: { sub: 'usr_someone_else' } },
      { name: 'the aud', index: 1 as const, changes: { aud: 'https://other.auth0.com/' } },
      { name: 'an added claim', index: 1 as const, changes: { extra: true } },
      { name: 'an added header', index: 0 as const, changes: { cty: 'JWT' } },
    ])('refuses a Session JWT after a change of $name', async ({ index, changes }) => {
      const session = await mint();
      const delegation = await verifyDelegation(session);
      const changed: UnverifiedSessionJwt = { ...session, jwt: withMember(session.jwt, index, changes) };

      expectRefused(
        await rejectionOf(verifySessionSignature(changed, delegation)),
        'signature_invalid',
        'session_signature'
      );
    });

    test('refuses a signature that is missing, too short, or made of zeros', async () => {
      const session = await mint();
      const delegation = await verifyDelegation(session);

      for (const signature of ['', 'c2ln', base64url.encode(new Uint8Array(64))]) {
        const changed: UnverifiedSessionJwt = { ...session, jwt: withPart(session.jwt, 2, signature) };
        expectRefused(
          await rejectionOf(verifySessionSignature(changed, delegation)),
          'signature_invalid',
          'session_signature'
        );
      }
    });

    test.each(['ES384', 'ES512', 'RS256', 'PS256', 'HS256', 'EdDSA', 'none', 'es256', ''])(
      'refuses the alg %j with the right kid',
      async (alg) => {
        const session = await mint();
        const delegation = await verifyDelegation(session);
        const changed: UnverifiedSessionJwt = { ...session, jwt: withMember(session.jwt, 0, { alg }) };

        expectRefused(
          await rejectionOf(verifySessionSignature(changed, delegation)),
          'signature_invalid',
          'session_signature'
        );
      }
    );

    test('refuses a Session JWT signed with HMAC, with the public key of the delegated key as the secret', async () => {
      const session = await mint();
      const delegation = await verifyDelegation(session);
      // The classic confusion: the public key, which anyone can read in the delegation, is used as the HMAC secret.
      const publicJwk = (decodeJwt(session.header.poppy_dlg).cnf as { jwk: object }).jwk;
      const secret = new TextEncoder().encode(JSON.stringify(publicJwk));
      const [, payload] = partsOf(session.jwt);
      const header = {
        alg: 'HS256',
        typ: SESSION_JWT_TYP,
        kid: session.header.kid,
        poppy_dlg: session.header.poppy_dlg,
      };
      const forged = await new CompactSign(base64url.decode(payload))
        .setProtectedHeader(header as CompactJWSHeaderParameters)
        .sign(secret);

      expectRefused(
        await rejectionOf(verifySessionSignature({ ...session, jwt: forged }, delegation)),
        'signature_invalid',
        'session_signature'
      );
    });

    test('refuses a Session JWT whose exp has passed, or whose nbf is still ahead', async () => {
      const expired = await mint({ claims: { exp: START_SECONDS - 1 } });
      const early = await mint({ claims: { nbf: START_SECONDS + 600 } });
      const delegation = await verifyDelegation(expired);

      expectRefused(
        await rejectionOf(verifySessionSignature(expired, delegation)),
        'signature_invalid',
        'session_signature'
      );
      expectRefused(
        await rejectionOf(verifySessionSignature(early, delegation)),
        'signature_invalid',
        'session_signature'
      );
    });

    test('leaves no value of the JWT in the message or the cause of the error', async () => {
      const session = await mint({ defect: 'session_wrong_kid' });
      const delegation = await verifyDelegation(session);

      const error = (await rejectionOf(verifySessionSignature(session, delegation))) as InvalidSessionError;

      for (const secret of [session.jwt, session.header.kid, session.header.poppy_dlg, SID, CIMD_URL]) {
        expect(error.message).not.toContain(secret);
        expect(JSON.stringify(error.cause)).not.toContain(secret);
      }
    });
  });

  describe('expectedRequestUrl', () => {
    test.each([
      {
        name: 'a URL that a proxy rewrote, with a query',
        url: 'http://10.0.0.5:8080/orders?x=1',
        origin: PUBLIC_ORIGIN,
        expected: `${PUBLIC_ORIGIN}/orders`,
      },
      { name: 'a path', url: '/orders', origin: PUBLIC_ORIGIN, expected: `${PUBLIC_ORIGIN}/orders` },
      { name: 'a path with a query and a fragment', url: '/orders?x=1#top', origin: PUBLIC_ORIGIN, expected: HTU },
      { name: 'a path with an empty query', url: '/orders?', origin: PUBLIC_ORIGIN, expected: HTU },
      { name: 'the root path', url: '/', origin: PUBLIC_ORIGIN, expected: `${PUBLIC_ORIGIN}/` },
      {
        name: 'an absolute URL with a fragment',
        url: 'https://internal.example/orders#top',
        origin: PUBLIC_ORIGIN,
        expected: HTU,
      },
      {
        name: 'an absolute URL with a user name and a password',
        url: 'http://user:secret@10.0.0.5/orders',
        origin: PUBLIC_ORIGIN,
        expected: HTU,
      },
      {
        name: 'a path with escapes, which stay as they are',
        url: '/a%7eb/c%2Fd?q=%7e',
        origin: PUBLIC_ORIGIN,
        expected: `${PUBLIC_ORIGIN}/a%7eb/c%2Fd`,
      },
      {
        name: 'a path that starts with two slashes, which stays a path',
        url: '//evil.example/x',
        origin: PUBLIC_ORIGIN,
        expected: `${PUBLIC_ORIGIN}//evil.example/x`,
      },
      {
        name: 'a path that starts with a slash and a backslash',
        url: '/\\evil.example/x',
        origin: PUBLIC_ORIGIN,
        expected: `${PUBLIC_ORIGIN}//evil.example/x`,
      },
      {
        name: 'a path with a scheme and an authority in it',
        url: '/https://evil.example/x',
        origin: PUBLIC_ORIGIN,
        expected: `${PUBLIC_ORIGIN}/https://evil.example/x`,
      },
      { name: 'a path with dot segments', url: '/a/../b', origin: PUBLIC_ORIGIN, expected: `${PUBLIC_ORIGIN}/b` },
      {
        name: 'an origin with a port',
        url: '/orders',
        origin: `${PUBLIC_ORIGIN}:8443`,
        expected: `${PUBLIC_ORIGIN}:8443/orders`,
      },
      {
        name: 'an absolute URL on the host of the public origin',
        url: `${HTU}?x=1`,
        origin: PUBLIC_ORIGIN,
        expected: HTU,
      },
    ])('with a public origin, gives the origin and the path of $name', ({ url, origin, expected }) => {
      expect(expectedRequestUrl(url, origin)).toBe(expected);
    });

    test.each([
      'http://10.0.0.5:8080/orders?x=1',
      'https://api.zepto.example/orders?x=1#top',
      'https://api.zepto.example/a%7eb',
    ])('without a public origin, gives the absolute URL %s as it is', (url) => {
      expect(expectedRequestUrl(url, undefined)).toBe(url);
    });

    test.each(['/orders', '/orders?token=secret-value', '//host/orders', 'orders', '', '*'])(
      'without a public origin, refuses %j with an error about the setup',
      (url) => {
        let thrown: unknown;
        try {
          expectedRequestUrl(url, undefined);
        } catch (error) {
          thrown = error;
        }

        expect(thrown).toBeInstanceOf(InvalidConfigurationError);
        const error = thrown as InvalidConfigurationError;
        expect(error.code).toBe('invalid_configuration_error');
        expect(error.message).toBe(MESSAGES.noOrigin);
        expect(error.message).toContain('poppy.baseUrl');
        expect(error.message).toContain('public_origin');
        expect(error.message).not.toContain('secret-value');
      }
    );

    test.each([
      'orders',
      '',
      '*',
      'ht!tp://host/orders?token=secret-value',
      'mailto:someone@example.com',
      'data:text/plain,secret-value',
      'javascript:alert(1)',
      'a:b',
      'https://',
    ])('with a public origin, refuses %j, which is neither a path nor an absolute URL with a path', (url) => {
      let thrown: unknown;
      try {
        expectedRequestUrl(url, PUBLIC_ORIGIN);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(InvalidRequestError);
      const error = thrown as InvalidRequestError;
      expect(error.code).toBe('invalid_request');
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe(MESSAGES.url);
      expect(error.message).not.toContain('secret-value');
    });

    test('keeps a request behind a proxy working, which the host the server sees would break', async () => {
      const session = await mint({ htm: 'GET', htu: 'https://api.zepto.example/orders' });
      const seenByServer = 'http://10.0.0.5:8080/orders?x=1';
      const expected = { audiences: [AUD], method: 'GET', iatWindowSeconds: IAT_WINDOW_SECONDS };

      expect(() =>
        checkSessionClaims(session, { ...expected, url: expectedRequestUrl(seenByServer, PUBLIC_ORIGIN) })
      ).not.toThrow();
      expectRefusal(
        () => checkSessionClaims(session, { ...expected, url: expectedRequestUrl(seenByServer, undefined) }),
        'claim_mismatch',
        'htu'
      );
    });
  });

  describe('checkSessionClaims', () => {
    interface Row {
      name: string;
      /** The claims of the Session JWT. */
      claims?: { aud?: string; htm?: string; htu?: string; iat?: number };
      /** What the request says. */
      expected?: { audiences?: readonly string[]; method?: string; url?: string; iatWindowSeconds?: number };
    }

    interface Failing extends Row {
      reason: InvalidSessionReason;
      cause: ClaimCause;
    }

    async function check(row: Row): Promise<void> {
      const session = await mint({ iat: NOW, ...row.claims });
      checkSessionClaims(session, {
        audiences: [AUD],
        method: 'POST',
        url: HTU,
        iatWindowSeconds: IAT_WINDOW_SECONDS,
        now: NOW,
        ...row.expected,
      });
    }

    test.each<Row>([
      { name: 'aud is the one audience' },
      {
        name: 'aud is in a list of audiences',
        expected: { audiences: ['https://a.example/', AUD, 'https://b.example/'] },
      },
      { name: 'htm is in lower case', claims: { htm: 'post' } },
      { name: 'htm is in mixed case', claims: { htm: 'PoSt' } },
      { name: 'the method is in lower case', expected: { method: 'post' } },
      { name: 'htu has a query', claims: { htu: `${HTU}?x=1&y=2` } },
      { name: 'htu has a fragment', claims: { htu: `${HTU}#top` } },
      { name: 'htu has a query and a fragment', claims: { htu: `${HTU}?x=1#top` } },
      { name: 'the request URL has a query', expected: { url: `${HTU}?x=1` } },
      { name: 'htu has the default port', claims: { htu: 'https://api.zepto.example:443/orders' } },
      { name: 'htu has a host in capital letters', claims: { htu: 'https://API.Zepto.Example/orders' } },
      { name: 'htu has a scheme in capital letters', claims: { htu: 'HTTPS://api.zepto.example/orders' } },
      {
        name: 'htu has an escape of an unreserved character, and the URL has the character',
        claims: { htu: 'https://api.zepto.example/a%7eb' },
        expected: { url: 'https://api.zepto.example/a~b' },
      },
      {
        name: 'htu has the character, and the URL has the escape',
        claims: { htu: 'https://api.zepto.example/a~b' },
        expected: { url: 'https://api.zepto.example/a%7Eb' },
      },
      {
        name: 'htu has a lower case escape of a reserved character, and the URL has the upper case one',
        claims: { htu: 'https://api.zepto.example/a%2fb' },
        expected: { url: 'https://api.zepto.example/a%2Fb' },
      },
      { name: 'iat is now', claims: { iat: NOW } },
      { name: 'iat is exactly the window behind', claims: { iat: NOW - IAT_WINDOW_SECONDS } },
      { name: 'iat is exactly the window ahead', claims: { iat: NOW + IAT_WINDOW_SECONDS } },
      { name: 'iat is now, and the window is 0', claims: { iat: NOW }, expected: { iatWindowSeconds: 0 } },
      {
        name: 'iat is 5 seconds ahead, and the window is 5',
        claims: { iat: NOW + 5 },
        expected: { iatWindowSeconds: 5 },
      },
    ])('passes when $name', async (row) => {
      await expect(check(row)).resolves.toBeUndefined();
    });

    test.each<Failing>([
      {
        name: 'aud has no slash at the end, where the audience has one',
        claims: { aud: 'https://example.auth0.com' },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'aud has a slash at the end, where the audience has none',
        claims: { aud: 'https://example.auth0.com/' },
        expected: { audiences: ['https://example.auth0.com'] },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'aud differs by one character',
        claims: { aud: 'https://example.auth0.con/' },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'aud is in capital letters',
        claims: { aud: 'HTTPS://EXAMPLE.AUTH0.COM/' },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'aud has a space at the end',
        claims: { aud: `${AUD} ` },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'aud is the start of an audience',
        claims: { aud: 'https://example.auth0.com' },
        expected: { audiences: ['https://example.auth0.com/'] },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'there is no audience',
        expected: { audiences: [] },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      {
        name: 'aud is not one of several audiences',
        expected: { audiences: ['https://a.example/', 'https://b.example/'] },
        reason: 'claim_mismatch',
        cause: 'aud',
      },
      { name: 'htm is GET and the method is POST', claims: { htm: 'GET' }, reason: 'claim_mismatch', cause: 'htm' },
      {
        name: 'htm is POST and the method is GET',
        expected: { method: 'GET' },
        reason: 'claim_mismatch',
        cause: 'htm',
      },
      { name: 'htm is empty', claims: { htm: '' }, reason: 'claim_mismatch', cause: 'htm' },
      { name: 'htm has a space', claims: { htm: 'POST ' }, reason: 'claim_mismatch', cause: 'htm' },
      {
        name: 'htu is another path',
        claims: { htu: 'https://api.zepto.example/other' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu has a slash at the end, and the URL has none',
        claims: { htu: `${HTU}/` },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu has a deeper path',
        claims: { htu: `${HTU}/1` },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu has another host',
        claims: { htu: 'https://other.zepto.example/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu has another port',
        claims: { htu: 'https://api.zepto.example:8443/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu has an escape of a reserved character, and the URL has the character',
        claims: { htu: 'https://api.zepto.example/a%2Fb' },
        expected: { url: 'https://api.zepto.example/a/b' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu and the URL are http',
        claims: { htu: 'http://api.zepto.example/orders' },
        expected: { url: 'http://api.zepto.example/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu is http and the URL is https',
        claims: { htu: 'http://api.zepto.example/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'htu is https and the URL is http',
        expected: { url: 'http://api.zepto.example/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      { name: 'htu is not a URL', claims: { htu: 'not a url' }, reason: 'claim_mismatch', cause: 'htu' },
      { name: 'htu is a path', claims: { htu: '/orders' }, reason: 'claim_mismatch', cause: 'htu' },
      { name: 'htu is empty', claims: { htu: '' }, reason: 'claim_mismatch', cause: 'htu' },
      {
        name: 'htu has another scheme',
        claims: { htu: 'ftp://api.zepto.example/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'the request URL is a path and not a URL, so the URL normalization throws',
        expected: { url: '/orders' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      {
        name: 'the request URL has a URL in its path, so the URL normalization throws',
        claims: { htu: 'https://api.zepto.example/https://evil.example/' },
        expected: { url: 'https://api.zepto.example/https://evil.example/' },
        reason: 'claim_mismatch',
        cause: 'htu',
      },
      { name: 'iat is 61 seconds behind', claims: { iat: NOW - 61 }, reason: 'iat_out_of_window', cause: 'iat' },
      { name: 'iat is 61 seconds ahead', claims: { iat: NOW + 61 }, reason: 'iat_out_of_window', cause: 'iat' },
      { name: 'iat is an hour behind', claims: { iat: NOW - 3600 }, reason: 'iat_out_of_window', cause: 'iat' },
      {
        name: 'iat is a second ahead, and the window is 0',
        claims: { iat: NOW + 1 },
        expected: { iatWindowSeconds: 0 },
        reason: 'iat_out_of_window',
        cause: 'iat',
      },
      {
        name: 'iat is a second behind, and the window is 0',
        claims: { iat: NOW - 1 },
        expected: { iatWindowSeconds: 0 },
        reason: 'iat_out_of_window',
        cause: 'iat',
      },
    ])('refuses when $name', async (row) => {
      const session = await mint({ iat: NOW, ...row.claims });

      expectRefusal(
        () =>
          checkSessionClaims(session, {
            audiences: [AUD],
            method: 'POST',
            url: HTU,
            iatWindowSeconds: IAT_WINDOW_SECONDS,
            now: NOW,
            ...row.expected,
          }),
        row.reason,
        row.cause
      );
    });

    test('uses the current time when it is not given one', async () => {
      const expected = { audiences: [AUD], method: 'POST', url: HTU, iatWindowSeconds: IAT_WINDOW_SECONDS };
      const edgeBehind = await mint({ iat: START_SECONDS - IAT_WINDOW_SECONDS });
      const edgeAhead = await mint({ iat: START_SECONDS + IAT_WINDOW_SECONDS });
      const tooOld = await mint({ iat: START_SECONDS - IAT_WINDOW_SECONDS - 1 });
      const tooNew = await mint({ iat: START_SECONDS + IAT_WINDOW_SECONDS + 1 });

      expect(() => checkSessionClaims(edgeBehind, expected)).not.toThrow();
      expect(() => checkSessionClaims(edgeAhead, expected)).not.toThrow();
      expectRefusal(() => checkSessionClaims(tooOld, expected), 'iat_out_of_window', 'iat');
      expectRefusal(() => checkSessionClaims(tooNew, expected), 'iat_out_of_window', 'iat');

      // Part of a second later it is still the same second, as for a DPoP proof: the edge that passed still passes.
      vi.setSystemTime(START + 999);
      expect(() => checkSessionClaims(edgeBehind, expected)).not.toThrow();

      // A second later, the edge that passed is out.
      vi.setSystemTime(START + 1000);
      expectRefusal(() => checkSessionClaims(edgeBehind, expected), 'iat_out_of_window', 'iat');
    });

    test('checks aud first, then htm, then htu, then iat', async () => {
      const allWrong = await mint({
        aud: 'https://x.example/',
        htm: 'GET',
        htu: 'https://x.example/',
        iat: NOW - 3600,
      });
      const expected = { audiences: [AUD], method: 'POST', url: HTU, iatWindowSeconds: IAT_WINDOW_SECONDS, now: NOW };

      expectRefusal(() => checkSessionClaims(allWrong, expected), 'claim_mismatch', 'aud');
      expectRefusal(
        () => checkSessionClaims({ ...allWrong, claims: { ...allWrong.claims, aud: AUD } }, expected),
        'claim_mismatch',
        'htm'
      );
      expectRefusal(
        () => checkSessionClaims({ ...allWrong, claims: { ...allWrong.claims, aud: AUD, htm: 'POST' } }, expected),
        'claim_mismatch',
        'htu'
      );
      expectRefusal(
        () =>
          checkSessionClaims(
            { ...allWrong, claims: { ...allWrong.claims, aud: AUD, htm: 'POST', htu: HTU } },
            expected
          ),
        'iat_out_of_window',
        'iat'
      );
    });

    test('leaves no value of the JWT or of the request in the message or the cause', async () => {
      const session = await mint({
        aud: 'https://secret-aud.example/',
        htu: 'https://secret-host.example/secret-path',
      });

      const error = expectRefusal(
        () =>
          checkSessionClaims(session, {
            audiences: [AUD],
            method: 'POST',
            url: `${HTU}?token=secret-query`,
            iatWindowSeconds: 60,
          }),
        'claim_mismatch',
        'aud'
      );

      for (const secret of ['secret-aud', 'secret-host', 'secret-path', 'secret-query', AUD, HTU]) {
        expect(error.message).not.toContain(secret);
        expect(JSON.stringify(error.cause)).not.toContain(secret);
      }
    });
  });

  describe('computeAth', () => {
    test('gives the known value for abc', async () => {
      await expect(computeAth('abc')).resolves.toBe(ATH_OF_ABC);
    });

    test.each([
      'abc',
      '',
      'a.b.c',
      'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl',
      'token with spaces and +/= characters',
      'ünïcödé',
      ' padded token \n',
    ])('gives the base64url SHA-256 hash of %j, as node:crypto does', async (token) => {
      const expected = createHash('sha256').update(token, 'utf8').digest('base64url');

      await expect(computeAth(token)).resolves.toBe(expected);
    });

    test('gives 43 characters of the base64url alphabet, with no padding', async () => {
      // Hashes whose standard base64 has `+`, `/` and `=`: one that the loop below finds is enough to show it.
      const hashes = await Promise.all(Array.from({ length: 64 }, (_, index) => computeAth(`token-${index}`)));

      for (const hash of hashes) {
        expect(hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
      }
      expect(hashes.some((hash) => hash.includes('-') || hash.includes('_'))).toBe(true);
    });

    test('gives the ath that the test agent puts in a Session JWT', async () => {
      const session = await mint({ accessToken: 'an-access-token' });

      expect(session.claims.ath).toBe(await computeAth('an-access-token'));
    });
  });

  describe('computeSessionKey', () => {
    test('is the base64url SHA-256 hash of the agent URL, a newline and the Session ID', async () => {
      const expected = createHash('sha256').update(`${CIMD_URL}\n${SID}`, 'utf8').digest('base64url');

      await expect(computeSessionKey(CIMD_URL, SID)).resolves.toBe(expected);
    });

    test('gives the known value, which the formula gives in every SDK', async () => {
      await expect(computeSessionKey(CIMD_URL, SID)).resolves.toBe(SESSION_KEY_OF_AGENT_AND_SID);
    });

    test('gives 43 characters of the base64url alphabet, with no padding', async () => {
      await expect(computeSessionKey(CIMD_URL, SID)).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    test('gives another key for another agent and for another Session ID', async () => {
      const keys = await Promise.all([
        computeSessionKey(CIMD_URL, SID),
        computeSessionKey('https://other.example/agent.json', SID),
        computeSessionKey(CIMD_URL, 'another-sid'),
      ]);

      expect(new Set(keys).size).toBe(3);
    });

    test('keeps the agent URL and the Session ID apart, so two pairs never give one text', async () => {
      // Without the newline, both would be hashed as `https://a.example/xy`.
      const first = await computeSessionKey('https://a.example/x', 'y');
      const second = await computeSessionKey('https://a.example/', 'xy');

      expect(first).not.toBe(second);
      expect(first).toBe(createHash('sha256').update('https://a.example/x\ny', 'utf8').digest('base64url'));
    });

    test('depends on the agent that signed and the sid, and on nothing else of the Session JWT', async () => {
      const first = await mint({ sid: SID, sub: 'usr_one', htm: 'GET' });
      const second = await mint({ sid: SID, sub: 'usr_two', htm: 'POST', agentId: 'travel' });

      await expect(computeSessionKey(first.claims.iss, first.claims.sid)).resolves.toBe(
        await computeSessionKey(second.claims.iss, second.claims.sid)
      );
    });
  });

  describe('the whole chain', () => {
    test('verifies a Session JWT of the test agent from its delegation to its claims', async () => {
      const session = await mint({ accessToken: 'abc' });

      const delegation = await verifyDelegation(session);
      await verifySessionSignature(session, delegation);
      checkSessionClaims(session, { audiences: [AUD], method: 'POST', url: HTU, iatWindowSeconds: IAT_WINDOW_SECONDS });

      expect(session.claims.ath).toBe(ATH_OF_ABC);
      await expect(computeSessionKey(session.claims.iss, session.claims.sid)).resolves.toBe(
        SESSION_KEY_OF_AGENT_AND_SID
      );
    });
  });
});
