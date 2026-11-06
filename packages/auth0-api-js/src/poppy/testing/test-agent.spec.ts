import * as jose from 'jose';
import { afterEach, describe, expect, test, vi } from 'vitest';

import {
  DEFAULT_IAT_WINDOW_SECONDS,
  MAX_DELEGATION_LIFETIME_SECONDS,
  MAX_URL_LENGTH,
  SESSION_ID_PATTERN,
} from '../constants.js';
import * as testing from '../../testing.js';
// The types come from the public entry point on purpose: this file does not compile if one of them is not exported.
import type { CreateTestAgentOptions, TestAgent, TestSessionJwtDefect, TestSessionJwtOptions } from '../../testing.js';
import { isAgentUrl } from '../url-rules.js';
import { createTestAgent } from './test-agent.js';

const CIMD_URL = 'https://agent.example/agent.json';
const JWKS_URI = 'https://agent.example/jwks.json';
const AUD = 'https://example.auth0.com/';
const REQUEST: TestSessionJwtOptions = { aud: AUD, htm: 'POST', htu: 'https://api.example.com/orders' };
// 2026-11-06T12:00:00Z, for the tests that pin the clock.
const NOW = Date.UTC(2026, 10, 6, 12, 0, 0) / 1000;
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

// A record, not an array, so this file does not compile when a defect is added and not tested here.
const DEFECTS: Record<TestSessionJwtDefect, true> = {
  missing_delegation: true,
  signed_with_agent_key: true,
  expired_delegation: true,
  delegation_too_long: true,
  delegation_from_future: true,
  delegation_iss_mismatch: true,
  delegation_wrong_typ: true,
  delegation_unknown_kid: true,
  delegation_private_cnf: true,
  session_wrong_typ: true,
  session_wrong_kid: true,
  session_bad_signature: true,
};
const DEFECT_NAMES = Object.keys(DEFECTS) as TestSessionJwtDefect[];

afterEach(() => {
  vi.useRealTimers();
});

// Pins `Date` only, so the clock of the agent is fixed and the timers of the runtime keep working.
function pinClock(seconds: number = NOW): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(seconds * 1000);
}

interface Delegation {
  jwt: string;
  header: jose.ProtectedHeaderParameters;
  payload: { iss: string; iat: number; exp: number; jti: string; cnf: { jwk: jose.JWK } };
}

function delegationOf(sessionJwt: string): Delegation {
  const { poppy_dlg: jwt } = jose.decodeProtectedHeader(sessionJwt);
  if (typeof jwt !== 'string') {
    throw new Error('Expected the Session JWT to carry a delegation.');
  }
  return {
    jwt,
    header: jose.decodeProtectedHeader(jwt),
    payload: jose.decodeJwt(jwt) as unknown as Delegation['payload'],
  };
}

function agentKeyOf(agent: TestAgent): jose.JWK {
  const [key] = agent.jwks.keys;
  if (!key) {
    throw new Error('Expected the agent to publish a key.');
  }
  return key;
}

// The delegated key of a Session JWT, to verify with. It drops `d`, so it works for a private `cnf.jwk` too.
function delegatedKeyOf(sessionJwt: string) {
  const { kty, crv, x, y } = delegationOf(sessionJwt).payload.cnf.jwk;
  return jose.importJWK({ kty, crv, x, y }, 'ES256');
}

async function verifies(jws: string, key: Awaited<ReturnType<typeof jose.importJWK>>): Promise<boolean> {
  try {
    await jose.compactVerify(jws, key);
    return true;
  } catch {
    return false;
  }
}

function deviationsOf(checks: [deviation: string, deviates: boolean][]): string[] {
  return checks.filter(([, deviates]) => deviates).map(([deviation]) => deviation);
}

// An independent check of what the specification asks of a Session JWT and its delegation (sections 5.2 and 5.3).
// It lists every deviation it finds, named after the defect that causes it, so a JWT made with one defect must
// list exactly the deviations of that defect, which is that one defect unless its description says more.
async function findDeviations(agent: TestAgent, sessionJwt: string, now: number): Promise<string[]> {
  const sessionHeader = jose.decodeProtectedHeader(sessionJwt);
  const agentKey = agentKeyOf(agent);
  // What the header of every Session JWT must have, with a delegation or without.
  const headerChecks: [string, boolean][] = [
    ['session_wrong_typ', sessionHeader.typ !== 'poppy-session+jwt'],
    ['session_wrong_alg', sessionHeader.alg !== 'ES256'],
  ];

  if (typeof sessionHeader.poppy_dlg !== 'string') {
    // Without a delegation the JWT was signed either with the key from the key set, or with a delegated key. There is
    // no cnf.jwk to check the kid and the signature against, so the header checks are all that is left.
    const withoutDelegation = sessionHeader.kid === agentKey.kid ? 'signed_with_agent_key' : 'missing_delegation';
    return [withoutDelegation, ...deviationsOf(headerChecks)];
  }

  const delegation = delegationOf(sessionJwt);
  const { iss, iat, exp, cnf } = delegation.payload;
  const delegatedJwk = { kty: cnf.jwk.kty, crv: cnf.jwk.crv, x: cnf.jwk.x, y: cnf.jwk.y };

  const checks: [deviation: string, deviates: boolean][] = [
    ['delegation_wrong_typ', delegation.header.typ !== 'poppy-delegation+jwt'],
    ['delegation_unknown_kid', delegation.header.kid !== agentKey.kid],
    ['delegation_iss_mismatch', iss !== agent.cimdUrl],
    ['expired_delegation', exp <= now],
    ['delegation_too_long', exp - iat > MAX_DELEGATION_LIFETIME_SECONDS],
    ['delegation_from_future', iat > now + DEFAULT_IAT_WINDOW_SECONDS],
    ['delegation_private_cnf', 'd' in cnf.jwk],
    ['delegation_bad_signature', !(await verifies(delegation.jwt, await jose.importJWK(agentKey, agentKey.alg)))],
    ...headerChecks,
    ['session_wrong_kid', sessionHeader.kid !== (await jose.calculateJwkThumbprint(delegatedJwk))],
    ['session_bad_signature', !(await verifies(sessionJwt, await jose.importJWK(delegatedJwk, 'ES256')))],
  ];
  return deviationsOf(checks);
}

// A PS384 agent signs the `signed_with_agent_key` JWT with PS384, so that JWT also breaks the rule that a Session JWT
// uses ES256. Every other defect is the one deviation that its name says.
function expectedDeviations(defect: TestSessionJwtDefect, delegationAlg: 'ES256' | 'PS384'): string[] {
  return defect === 'signed_with_agent_key' && delegationAlg === 'PS384' ? [defect, 'session_wrong_alg'] : [defect];
}

describe('createTestAgent', () => {
  describe('with the defaults', () => {
    test('describes an agent at https://agent.example', async () => {
      const agent = await createTestAgent();

      expect(agent.cimdUrl).toBe(CIMD_URL);
      expect(agent.jwksUri).toBe(JWKS_URI);
      expect(agent.metadata).toEqual({
        client_id: CIMD_URL,
        client_name: expect.any(String),
        jwks_uri: JWKS_URI,
        token_endpoint_auth_method: 'private_key_jwt',
      });
      expect(agent.metadata.client_id).toBe(agent.cimdUrl);
      expect(agent.metadata.jwks_uri).toBe(agent.jwksUri);
    });

    test('publishes one ES256 key whose kid is its thumbprint, without private members', async () => {
      const agent = await createTestAgent();
      const key = agentKeyOf(agent);

      expect(agent.jwks.keys).toHaveLength(1);
      expect(key).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256' });
      expect(key.kid).toBe(await jose.calculateJwkThumbprint(key));
      for (const member of PRIVATE_MEMBERS) {
        expect(key).not.toHaveProperty(member);
      }
    });

    test('gives every agent its own keys', async () => {
      const [first, second] = await Promise.all([createTestAgent(), createTestAgent()]);

      expect(agentKeyOf(first).kid).not.toBe(agentKeyOf(second).kid);
    });
  });

  describe('options', () => {
    test('builds jwksUri from the origin of cimdUrl', async () => {
      const cimdUrl = 'https://my-agent.test:8443/some/path/agent.json';
      const agent = await createTestAgent({ cimdUrl });

      expect(agent.cimdUrl).toBe(cimdUrl);
      expect(agent.jwksUri).toBe('https://my-agent.test:8443/jwks.json');
      expect(agent.metadata.client_id).toBe(cimdUrl);
      expect(agent.metadata.jwks_uri).toBe(agent.jwksUri);
      expect(jose.decodeJwt(await agent.createSessionJwt(REQUEST)).iss).toBe(cimdUrl);
      expect((await agent.fetch(cimdUrl)).status).toBe(200);
      expect((await agent.fetch(agent.jwksUri)).status).toBe(200);
    });

    test.each<[string, CreateTestAgentOptions]>([
      ['an http: URL', { cimdUrl: 'http://agent.example/agent.json' }],
      ['a URL with another scheme', { cimdUrl: 'ftp://agent.example/agent.json' }],
      ['text that is not a URL', { cimdUrl: 'agent.example/agent.json' }],
      ['an empty string', { cimdUrl: '' }],
    ])('rejects a cimdUrl that is %s with a TypeError', async (_description, options) => {
      const result = createTestAgent(options);

      await expect(result).rejects.toBeInstanceOf(TypeError);
      await expect(result).rejects.toThrow(/cimdUrl.*https/);
    });

    // A verifier compares an agent URL character by character, so it accepts one spelling only: the one that
    // `new URL(url).href` gives. Another spelling would make every Session JWT of the agent fail with
    // `malformed_session`, which does not point at the `cimdUrl` that caused it.
    const NOT_CANONICAL: Array<[string, string]> = [
      ['a host in upper case', 'https://Agent.Example/agent.json'],
      ['no path', 'https://agent.example'],
      ['the default port', 'https://agent.example:443/agent.json'],
      ['a fragment', 'https://agent.example/agent.json#keys'],
      ['an empty fragment', 'https://agent.example/agent.json#'],
      ['a user name and a password', 'https://user:secret@agent.example/agent.json'],
      ['a user name', 'https://user@agent.example/agent.json'],
      ['an empty user name', 'https://@agent.example/agent.json'],
      ['a dot segment', 'https://agent.example/a/../agent.json'],
      ['a space', 'https://agent.example/my agent.json'],
      ['a Unicode host', 'https://bücher.example/agent.json'],
      ['a leading space', ' https://agent.example/agent.json'],
      ['a trailing new line', 'https://agent.example/agent.json\n'],
      ['more characters than the limit for an agent URL', `https://agent.example/${'a'.repeat(MAX_URL_LENGTH)}`],
    ];
    const CANONICAL: Array<[string, string]> = [
      ['the default', CIMD_URL],
      ['a port that is not the default one and a path', 'https://my-agent.test:8443/some/path/agent.json'],
      ['the root path', 'https://agent.example/'],
      ['a query', 'https://agent.example/agent.json?x=1'],
      ['a punycode host', 'https://xn--bcher-kva.example/agent.json'],
      ['localhost', 'https://localhost:8443/agent.json'],
      ['an IP address', 'https://10.0.0.7/agent.json'],
      ['a name in the .test domain', 'https://my-agent.test/agent.json'],
    ];

    test.each(NOT_CANONICAL)(
      'rejects a cimdUrl with %s with a TypeError that says what a canonical URL is',
      async (_description, cimdUrl) => {
        const result = createTestAgent({ cimdUrl });

        await expect(result).rejects.toBeInstanceOf(TypeError);
        await expect(result).rejects.toThrow(
          'createTestAgent: cimdUrl must be an https: URL in canonical form, which is how a verifier compares agent URLs: ' +
            'a host in lower case, no default port, a path of at least "/", no fragment, no user name or password, and ' +
            `at most ${MAX_URL_LENGTH} characters. It must equal new URL(cimdUrl).href.`
        );
      }
    );

    // A URL can hold a user name and a password, and a test runner prints the message in the log of a CI job. So the
    // message is a fixed text, whichever check refuses the URL, and nothing of the URL is in it. The user name is not
    // `user`, because the text for a URL that is not canonical says "no user name or password" in its own words.
    test.each([
      ['an https: URL', 'https://alice:hunter2@agent.example/agent.json'],
      ['an http: URL', 'http://alice:hunter2@agent.example/agent.json'],
    ])('puts nothing of a user name, a password or a host in the message for %s', async (_description, cimdUrl) => {
      const result = createTestAgent({ cimdUrl });

      await expect(result).rejects.toBeInstanceOf(TypeError);
      await expect(result).rejects.not.toThrow(/alice|hunter2|agent\.example/);
    });

    test.each(CANONICAL)('accepts a cimdUrl with %s', async (_description, cimdUrl) => {
      const agent = await createTestAgent({ cimdUrl });

      expect(agent.cimdUrl).toBe(cimdUrl);
      expect(new URL(agent.cimdUrl).href).toBe(agent.cimdUrl);
      expect(jose.decodeJwt(await agent.createSessionJwt(REQUEST)).iss).toBe(cimdUrl);
    });

    test('accepts a cimdUrl exactly when a verifier accepts it as an agent URL', async () => {
      for (const [, cimdUrl] of [...CANONICAL, ...NOT_CANONICAL]) {
        const accepted = await createTestAgent({ cimdUrl }).then(
          () => true,
          () => false
        );

        expect(accepted, cimdUrl).toBe(isAgentUrl(cimdUrl));
      }
    });

    test.each<[string, number]>([
      ['zero', 0],
      ['negative', -1],
      ['not an integer', 1.5],
      ['more than 24 hours', MAX_DELEGATION_LIFETIME_SECONDS + 1],
      ['NaN', NaN],
      ['a string', '3600' as unknown as number],
    ])('rejects a lifetime that is %s with a RangeError', async (_description, delegationLifetimeSeconds) => {
      const result = createTestAgent({ delegationLifetimeSeconds });

      await expect(result).rejects.toBeInstanceOf(RangeError);
      await expect(result).rejects.toThrow(/delegationLifetimeSeconds.*1 to 86400/);
    });

    test.each([1, 86400])('accepts a delegationLifetimeSeconds of %i', async (delegationLifetimeSeconds) => {
      const agent = await createTestAgent({ delegationLifetimeSeconds });
      const { payload } = delegationOf(await agent.createSessionJwt(REQUEST));

      expect(payload.exp - payload.iat).toBe(delegationLifetimeSeconds);
    });
  });

  describe('fetch', () => {
    test('serves the client metadata as JSON for cimdUrl', async () => {
      const agent = await createTestAgent();

      const response = await agent.fetch(CIMD_URL);

      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toContain('application/json');
      expect(await response.json()).toEqual(agent.metadata);
    });

    test('serves the key set as JSON for jwksUri, given a URL', async () => {
      const agent = await createTestAgent();

      const response = await agent.fetch(new URL(JWKS_URI));

      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toContain('application/json');
      expect(await response.json()).toEqual(agent.jwks);
    });

    test('serves both documents, given a Request', async () => {
      const agent = await createTestAgent();

      expect(await (await agent.fetch(new Request(CIMD_URL))).json()).toEqual(agent.metadata);
      expect(await (await agent.fetch(new Request(JWKS_URI))).json()).toEqual(agent.jwks);
    });

    test.each([
      'https://agent.example/other',
      'https://agent.example/agent.json?x=1',
      'https://other.example/agent.json',
      'http://agent.example/agent.json',
    ])('answers 404 for %s', async (url) => {
      const agent = await createTestAgent();

      expect((await agent.fetch(url)).status).toBe(404);
      expect((await agent.fetch(new URL(url))).status).toBe(404);
      expect((await agent.fetch(new Request(url))).status).toBe(404);
    });

    test('works as a bare function that uses no this', async () => {
      const { fetch: bareFetch } = await createTestAgent();

      const response = await bareFetch(CIMD_URL);

      expect(response.status).toBe(200);
    });

    test('accepts the init that a metadata fetcher sends', async () => {
      const agent = await createTestAgent();

      const response = await agent.fetch(JWKS_URI, {
        method: 'GET',
        redirect: 'manual',
        headers: { accept: 'application/json' },
        signal: new AbortController().signal,
      });

      expect(response.status).toBe(200);
    });

    test('builds a new response on every call, so a body can be read each time', async () => {
      const agent = await createTestAgent();

      const first = await agent.fetch(CIMD_URL);
      const second = await agent.fetch(CIMD_URL);

      expect(await first.json()).toEqual(agent.metadata);
      expect(await second.json()).toEqual(agent.metadata);
    });

    test('serves the metadata and the key set as they are when it is called', async () => {
      const agent = await createTestAgent();

      agent.metadata.client_name = 'Renamed Agent';
      agent.jwks.keys.push({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'extra' });

      expect(await (await agent.fetch(CIMD_URL)).json()).toMatchObject({ client_name: 'Renamed Agent' });
      const servedKeys = await (await agent.fetch(JWKS_URI)).json();
      expect(servedKeys).toEqual({ keys: [agentKeyOf(agent), expect.objectContaining({ kid: 'extra' })] });
    });
  });

  describe('createSessionJwt', () => {
    test('makes a Session JWT with a delegation, as the specification describes it', async () => {
      pinClock();
      const agent = await createTestAgent();

      const sessionJwt = await agent.createSessionJwt(REQUEST);
      const delegation = delegationOf(sessionJwt);

      expect(jose.decodeProtectedHeader(sessionJwt)).toEqual({
        typ: 'poppy-session+jwt',
        alg: 'ES256',
        kid: await jose.calculateJwkThumbprint(delegation.payload.cnf.jwk),
        poppy_dlg: delegation.jwt,
      });
      expect(delegation.header).toEqual({ alg: 'ES256', typ: 'poppy-delegation+jwt', kid: agentKeyOf(agent).kid });
      expect(delegation.payload).toEqual({
        iss: CIMD_URL,
        cnf: { jwk: { kty: 'EC', crv: 'P-256', x: expect.any(String), y: expect.any(String) } },
        iat: NOW,
        exp: NOW + 3600,
        jti: expect.any(String),
      });
      expect(jose.decodeJwt(sessionJwt)).toEqual({
        iss: CIMD_URL,
        aud: AUD,
        sid: expect.stringMatching(SESSION_ID_PATTERN),
        sub: 'usr_test',
        htm: 'POST',
        htu: 'https://api.example.com/orders',
        iat: NOW,
        jti: expect.any(String),
      });
    });

    test('makes a delegation that verifies with the key set of the agent', async () => {
      const agent = await createTestAgent();
      const { jwt } = delegationOf(await agent.createSessionJwt(REQUEST));

      const { payload, protectedHeader } = await jose.jwtVerify(jwt, jose.createLocalJWKSet(agent.jwks), {
        typ: 'poppy-delegation+jwt',
        issuer: CIMD_URL,
        algorithms: ['ES256'],
      });

      expect(protectedHeader.kid).toBe(agentKeyOf(agent).kid);
      expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    test('makes a Session JWT that verifies with cnf.jwk, and its kid is the thumbprint of cnf.jwk', async () => {
      const agent = await createTestAgent();
      const sessionJwt = await agent.createSessionJwt(REQUEST);
      const { cnf } = delegationOf(sessionJwt).payload;

      const { protectedHeader } = await jose.jwtVerify(sessionJwt, await jose.importJWK(cnf.jwk, 'ES256'), {
        typ: 'poppy-session+jwt',
        issuer: CIMD_URL,
        audience: AUD,
        algorithms: ['ES256'],
      });

      expect(protectedHeader.kid).toBe(await jose.calculateJwkThumbprint(cnf.jwk));
      expect(Object.keys(cnf.jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    });

    test('leaves out ath and agent_id unless they are asked for', async () => {
      const agent = await createTestAgent();

      const payload = jose.decodeJwt(await agent.createSessionJwt(REQUEST));

      expect(payload).not.toHaveProperty('ath');
      expect(payload).not.toHaveProperty('agent_id');
    });

    test('sets ath to the base64url SHA-256 hash of the access token', async () => {
      const agent = await createTestAgent();

      const payload = jose.decodeJwt(await agent.createSessionJwt({ ...REQUEST, accessToken: 'abc' }));

      expect(payload.ath).toBe('ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
    });

    test('uses the sid, sub, agentId, iat and jti it is given', async () => {
      const agent = await createTestAgent();

      const payload = jose.decodeJwt(
        await agent.createSessionJwt({
          ...REQUEST,
          sid: 'sid_1',
          sub: 'usr_1',
          agentId: 'agt_1',
          iat: NOW - 30,
          jti: 'jti_1',
        })
      );

      expect(payload).toEqual({
        iss: CIMD_URL,
        aud: AUD,
        sid: 'sid_1',
        sub: 'usr_1',
        agent_id: 'agt_1',
        htm: 'POST',
        htu: 'https://api.example.com/orders',
        iat: NOW - 30,
        jti: 'jti_1',
      });
    });

    test('picks a new random sid and jti of 22 characters for each JWT', async () => {
      const agent = await createTestAgent();

      const jwts = await Promise.all([agent.createSessionJwt(REQUEST), agent.createSessionJwt(REQUEST)]);
      const [first, second] = jwts.map((jwt) => jose.decodeJwt(jwt));

      for (const value of [first?.sid, first?.jti, second?.sid, second?.jti]) {
        expect(value).toMatch(SESSION_ID_PATTERN);
        expect(value).toHaveLength(22);
      }
      expect(first?.sid).not.toBe(second?.sid);
      expect(first?.jti).not.toBe(second?.jti);
    });

    test('reads the clock on every call', async () => {
      pinClock();
      const agent = await createTestAgent();

      const first = jose.decodeJwt(await agent.createSessionJwt(REQUEST));
      vi.setSystemTime((NOW + 10) * 1000);
      const second = jose.decodeJwt(await agent.createSessionJwt(REQUEST));

      expect(first.iat).toBe(NOW);
      expect(second.iat).toBe(NOW + 10);
    });

    test('merges claims last: a value overrides a claim and undefined removes it', async () => {
      const agent = await createTestAgent();

      const claims = { aud: 'x', jti: undefined, sub: 'usr_2', extra: 1 };

      const payload = jose.decodeJwt(await agent.createSessionJwt({ ...REQUEST, sub: 'usr_1', claims }));

      expect(payload.aud).toBe('x');
      expect(payload).not.toHaveProperty('jti');
      expect(payload.sub).toBe('usr_2');
      expect(payload.extra).toBe(1);
      expect(payload.htm).toBe('POST');
    });

    test('merges header last: a value overrides a parameter and undefined removes it', async () => {
      const agent = await createTestAgent();

      const header = jose.decodeProtectedHeader(
        await agent.createSessionJwt({ ...REQUEST, header: { typ: 'JWT', poppy_dlg: undefined, extra: 'x' } })
      );

      expect(header.typ).toBe('JWT');
      expect(header).not.toHaveProperty('poppy_dlg');
      expect(header.extra).toBe('x');
      expect(header.alg).toBe('ES256');
    });

    test('does not change the options it is given', async () => {
      const agent = await createTestAgent();
      const options = Object.freeze({
        ...REQUEST,
        claims: Object.freeze({ jti: undefined }),
        header: Object.freeze({ typ: 'JWT' }),
      });

      await expect(agent.createSessionJwt(options)).resolves.toEqual(expect.any(String));
    });
  });

  describe('delegations', () => {
    test('uses one delegated key and one delegation for a sub', async () => {
      const agent = await createTestAgent();

      const first = await agent.createSessionJwt(REQUEST);
      const second = await agent.createSessionJwt({ ...REQUEST, sid: 'sid_2', htu: 'https://api.example.com/cart' });

      expect(jose.decodeProtectedHeader(second)).toEqual(jose.decodeProtectedHeader(first));
      expect(delegationOf(second)).toEqual(delegationOf(first));
    });

    test('gives each sub its own delegated key and delegation', async () => {
      const agent = await createTestAgent();

      const first = await agent.createSessionJwt({ ...REQUEST, sub: 'usr_1' });
      const second = await agent.createSessionJwt({ ...REQUEST, sub: 'usr_2' });

      expect(jose.decodeProtectedHeader(second).kid).not.toBe(jose.decodeProtectedHeader(first).kid);
      expect(delegationOf(second).jwt).not.toBe(delegationOf(first).jwt);
      expect(delegationOf(second).payload.jti).not.toBe(delegationOf(first).payload.jti);
    });

    test('uses one delegated key and one delegation when the first calls for a sub run together', async () => {
      const agent = await createTestAgent();

      const jwts = await Promise.all([1, 2, 3].map(() => agent.createSessionJwt(REQUEST)));

      const headers = jwts.map((jwt) => jose.decodeProtectedHeader(jwt));
      expect(new Set(headers.map((header) => header.kid)).size).toBe(1);
      expect(new Set(headers.map((header) => header.poppy_dlg)).size).toBe(1);
    });

    test('gives a delegation the lifetime it is configured with', async () => {
      const agent = await createTestAgent({ delegationLifetimeSeconds: 120 });

      const { payload } = delegationOf(await agent.createSessionJwt(REQUEST));

      expect(payload.exp - payload.iat).toBe(120);
    });

    test('keeps a delegation until its exp, then issues a new one for the same delegated key', async () => {
      pinClock();
      const agent = await createTestAgent({ delegationLifetimeSeconds: 600 });

      const first = await agent.createSessionJwt(REQUEST);
      vi.setSystemTime((NOW + 599) * 1000);
      const lastSecond = await agent.createSessionJwt(REQUEST);
      vi.setSystemTime((NOW + 600) * 1000);
      const renewed = await agent.createSessionJwt(REQUEST);

      expect(delegationOf(lastSecond).jwt).toBe(delegationOf(first).jwt);
      expect(delegationOf(renewed).jwt).not.toBe(delegationOf(first).jwt);
      expect(delegationOf(renewed).payload).toMatchObject({ iat: NOW + 600, exp: NOW + 1200 });
      expect(delegationOf(renewed).payload.jti).not.toBe(delegationOf(first).payload.jti);
      expect(delegationOf(renewed).payload.cnf).toEqual(delegationOf(first).payload.cnf);
      expect(jose.decodeProtectedHeader(renewed).kid).toBe(jose.decodeProtectedHeader(first).kid);
    });

    test('issues a new delegation when the clock goes back before the one it has', async () => {
      pinClock();
      const agent = await createTestAgent();
      const first = await agent.createSessionJwt(REQUEST);

      vi.setSystemTime((NOW - 100) * 1000);
      const earlier = await agent.createSessionJwt(REQUEST);

      expect(delegationOf(earlier).payload.iat).toBe(NOW - 100);
      expect(delegationOf(earlier).payload.cnf).toEqual(delegationOf(first).payload.cnf);
    });
  });

  describe('with delegationAlg PS384', () => {
    test('publishes an RSA key of 2048 bits whose kid is its thumbprint, without private members', async () => {
      const agent = await createTestAgent({ delegationAlg: 'PS384' });
      const key = agentKeyOf(agent);

      expect(agent.jwks.keys).toHaveLength(1);
      expect(key).toMatchObject({ kty: 'RSA', alg: 'PS384' });
      expect(jose.base64url.decode(key.n ?? '')).toHaveLength(256);
      expect(key.kid).toBe(await jose.calculateJwkThumbprint(key));
      for (const member of PRIVATE_MEMBERS) {
        expect(key).not.toHaveProperty(member);
      }
    });

    test('signs delegations with PS384, and the Session JWT stays ES256', async () => {
      const agent = await createTestAgent({ delegationAlg: 'PS384' });
      const sessionJwt = await agent.createSessionJwt(REQUEST);
      const delegation = delegationOf(sessionJwt);

      expect(delegation.header).toEqual({ alg: 'PS384', typ: 'poppy-delegation+jwt', kid: agentKeyOf(agent).kid });
      await jose.jwtVerify(delegation.jwt, jose.createLocalJWKSet(agent.jwks), { algorithms: ['PS384'] });
      expect(jose.decodeProtectedHeader(sessionJwt).alg).toBe('ES256');
      await jose.jwtVerify(sessionJwt, await jose.importJWK(delegation.payload.cnf.jwk, 'ES256'), {
        algorithms: ['ES256'],
      });
    });
  });

  describe('defect', () => {
    // A Session JWT without a defect and the agent that made it, with the clock pinned.
    async function setUp(options: CreateTestAgentOptions = {}) {
      pinClock();
      const agent = await createTestAgent(options);
      const valid = await agent.createSessionJwt(REQUEST);
      const withDefect = (defect: TestSessionJwtDefect) => agent.createSessionJwt({ ...REQUEST, defect });
      return { agent, valid, withDefect };
    }

    test('missing_delegation leaves out poppy_dlg and signs with the delegated key', async () => {
      const { valid, withDefect } = await setUp();

      const jwt = await withDefect('missing_delegation');

      const header = jose.decodeProtectedHeader(jwt);
      expect(header).not.toHaveProperty('poppy_dlg');
      expect(header.kid).toBe(jose.decodeProtectedHeader(valid).kid);
      await jose.jwtVerify(jwt, await delegatedKeyOf(valid));
    });

    test('signed_with_agent_key leaves out poppy_dlg and signs with the key from jwks_uri', async () => {
      const { agent, withDefect } = await setUp();

      const jwt = await withDefect('signed_with_agent_key');

      const header = jose.decodeProtectedHeader(jwt);
      expect(header).not.toHaveProperty('poppy_dlg');
      expect(header).toMatchObject({ typ: 'poppy-session+jwt', alg: 'ES256', kid: agentKeyOf(agent).kid });
      await jose.jwtVerify(jwt, jose.createLocalJWKSet(agent.jwks));
    });

    test('signed_with_agent_key of a PS384 agent has alg PS384, so it also breaks the ES256 rule', async () => {
      const { agent, withDefect } = await setUp({ delegationAlg: 'PS384' });

      const jwt = await withDefect('signed_with_agent_key');

      expect(jose.decodeProtectedHeader(jwt)).toMatchObject({ alg: 'PS384', kid: agentKeyOf(agent).kid });
      await jose.jwtVerify(jwt, jose.createLocalJWKSet(agent.jwks));
      expect(await findDeviations(agent, jwt, NOW)).toEqual(['signed_with_agent_key', 'session_wrong_alg']);
    });

    test('expired_delegation makes a delegation that ended an hour ago and lasted an hour', async () => {
      const { agent, withDefect } = await setUp();

      const { jwt, payload } = delegationOf(await withDefect('expired_delegation'));

      expect(payload).toMatchObject({ iat: NOW - 7200, exp: NOW - 3600 });
      await expect(jose.jwtVerify(jwt, jose.createLocalJWKSet(agent.jwks))).rejects.toMatchObject({
        code: 'ERR_JWT_EXPIRED',
      });
      const justBeforeExp = new Date((payload.exp - 1) * 1000);
      await jose.jwtVerify(jwt, jose.createLocalJWKSet(agent.jwks), { currentDate: justBeforeExp });
    });

    test('expired_delegation keeps its lifetime within 24 hours when the agent makes the longest', async () => {
      pinClock();
      const agent = await createTestAgent({ delegationLifetimeSeconds: MAX_DELEGATION_LIFETIME_SECONDS });

      const { payload } = delegationOf(await agent.createSessionJwt({ ...REQUEST, defect: 'expired_delegation' }));

      expect(payload.exp).toBe(NOW - 3600);
      expect(payload.exp - payload.iat).toBe(MAX_DELEGATION_LIFETIME_SECONDS);
    });

    test('delegation_too_long makes a delegation that ends 24 hours and 1 second after it was issued', async () => {
      const { withDefect } = await setUp();

      const { payload } = delegationOf(await withDefect('delegation_too_long'));

      expect(payload.iat).toBe(NOW);
      expect(payload.exp - payload.iat).toBe(86401);
    });

    test('delegation_from_future makes a delegation issued an hour from now', async () => {
      const { withDefect } = await setUp();

      const { payload } = delegationOf(await withDefect('delegation_from_future'));

      expect(payload.iat).toBeGreaterThanOrEqual(NOW + 3600);
      expect(payload.exp).toBe(payload.iat + 3600);
    });

    test('delegation_iss_mismatch names another agent as the issuer of the delegation', async () => {
      const { agent, withDefect } = await setUp();

      const jwt = await withDefect('delegation_iss_mismatch');

      expect(delegationOf(jwt).payload.iss).toBe('https://other.example/agent.json');
      expect(jose.decodeJwt(jwt).iss).toBe(agent.cimdUrl);
    });

    test.each([CIMD_URL, 'https://other.example/agent.json', 'https://another.example/agent.json'])(
      'delegation_iss_mismatch names an agent other than %s, even when that is the usual other agent',
      async (cimdUrl) => {
        const { agent, withDefect } = await setUp({ cimdUrl });

        const jwt = await withDefect('delegation_iss_mismatch');

        const { iss } = delegationOf(jwt).payload;
        expect(iss).not.toBe(agent.cimdUrl);
        expect(new URL(iss).href).not.toBe(new URL(agent.cimdUrl).href);
        expect(await findDeviations(agent, jwt, NOW)).toEqual(['delegation_iss_mismatch']);
      }
    );

    test('delegation_wrong_typ gives the delegation the typ JWT and leaves the Session JWT typ alone', async () => {
      const { withDefect } = await setUp();

      const jwt = await withDefect('delegation_wrong_typ');

      expect(delegationOf(jwt).header.typ).toBe('JWT');
      expect(jose.decodeProtectedHeader(jwt).typ).toBe('poppy-session+jwt');
    });

    test('delegation_unknown_kid signs with the real key but names a kid that is not in the key set', async () => {
      const { agent, withDefect } = await setUp();

      const { jwt, header } = delegationOf(await withDefect('delegation_unknown_kid'));

      expect(agent.jwks.keys.map((key) => key.kid)).not.toContain(header.kid);
      await expect(jose.jwtVerify(jwt, jose.createLocalJWKSet(agent.jwks))).rejects.toMatchObject({
        code: 'ERR_JWKS_NO_MATCHING_KEY',
      });
      await jose.jwtVerify(jwt, await jose.importJWK(agentKeyOf(agent), 'ES256'));
    });

    test('delegation_private_cnf puts the private member d in cnf.jwk and changes nothing else', async () => {
      const { agent, withDefect } = await setUp();

      const jwt = await withDefect('delegation_private_cnf');

      const { cnf } = delegationOf(jwt).payload;
      expect(typeof cnf.jwk.d).toBe('string');
      expect(jose.decodeProtectedHeader(jwt).kid).toBe(await jose.calculateJwkThumbprint(cnf.jwk));
      await jose.jwtVerify(jwt, await delegatedKeyOf(jwt));
      await jose.jwtVerify(delegationOf(jwt).jwt, jose.createLocalJWKSet(agent.jwks), {
        currentDate: new Date(NOW * 1000),
      });
    });

    test('session_wrong_typ gives the Session JWT the typ JWT and leaves the delegation alone', async () => {
      const { valid, withDefect } = await setUp();

      const jwt = await withDefect('session_wrong_typ');

      expect(jose.decodeProtectedHeader(jwt)).toEqual({ ...jose.decodeProtectedHeader(valid), typ: 'JWT' });
      expect(delegationOf(jwt).header.typ).toBe('poppy-delegation+jwt');
    });

    test('session_wrong_kid names the thumbprint of another key, and the signature is still good', async () => {
      const { valid, withDefect } = await setUp();

      const jwt = await withDefect('session_wrong_kid');

      const { kid } = jose.decodeProtectedHeader(jwt);
      expect(kid).toEqual(expect.any(String));
      expect(kid).not.toBe(await jose.calculateJwkThumbprint(delegationOf(valid).payload.cnf.jwk));
      await jose.jwtVerify(jwt, await delegatedKeyOf(valid));
    });

    test('session_bad_signature keeps the header and signs with another key', async () => {
      const { valid, withDefect } = await setUp();

      const jwt = await withDefect('session_bad_signature');

      expect(jose.decodeProtectedHeader(jwt)).toEqual(jose.decodeProtectedHeader(valid));
      expect(jose.base64url.decode(jwt.split('.')[2] ?? '')).toHaveLength(64);
      await expect(jose.jwtVerify(jwt, await delegatedKeyOf(valid))).rejects.toMatchObject({
        code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
      });
    });

    test('merges claims and header after the defect', async () => {
      const { agent } = await setUp();

      const jwt = await agent.createSessionJwt({
        ...REQUEST,
        defect: 'missing_delegation',
        header: { poppy_dlg: 'restored' },
        claims: { iss: 'https://other.example/agent.json' },
      });

      expect(jose.decodeProtectedHeader(jwt).poppy_dlg).toBe('restored');
      expect(jose.decodeJwt(jwt).iss).toBe('https://other.example/agent.json');
    });

    test('does not stop the other Session JWTs of the sub from carrying the same delegation', async () => {
      const { agent, valid } = await setUp();

      for (const defect of DEFECT_NAMES) {
        await agent.createSessionJwt({ ...REQUEST, defect });
      }
      const after = await agent.createSessionJwt(REQUEST);

      expect(delegationOf(after)).toEqual(delegationOf(valid));
      expect(jose.decodeProtectedHeader(after)).toEqual(jose.decodeProtectedHeader(valid));
    });

    test('makes a new delegation for each call with a delegation defect', async () => {
      const { withDefect } = await setUp();

      const first = delegationOf(await withDefect('delegation_wrong_typ'));
      const second = delegationOf(await withDefect('delegation_wrong_typ'));

      expect(second.jwt).not.toBe(first.jwt);
      expect(second.payload.jti).not.toBe(first.payload.jti);
      expect(second.payload.cnf).toEqual(first.payload.cnf);
    });

    describe.each(['ES256', 'PS384'] as const)('with a %s agent', (delegationAlg) => {
      test('a Session JWT without a defect deviates in no way', async () => {
        const { agent, valid } = await setUp({ delegationAlg });

        expect(await findDeviations(agent, valid, NOW)).toEqual([]);
      });

      test.each(DEFECT_NAMES)('%s deviates in the ways it documents', async (defect) => {
        const { agent, withDefect } = await setUp({ delegationAlg });

        const jwt = await withDefect(defect);

        expect(await findDeviations(agent, jwt, NOW)).toEqual(expectedDeviations(defect, delegationAlg));
      });
    });
  });
});

describe('the @auth0/auth0-api-js/testing entry point', () => {
  test('exports createTestAgent and nothing else at runtime', () => {
    expect(Object.keys(testing)).toEqual(['createTestAgent']);
    expect(testing.createTestAgent).toBe(createTestAgent);
  });
});
