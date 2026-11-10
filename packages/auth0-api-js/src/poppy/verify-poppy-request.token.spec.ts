import { createHash } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from 'vitest';

import { ApiClient } from '../api-client.js';
import {
  InvalidConfigurationError,
  InvalidDpopProofError,
  InvalidRequestError,
  VerifyAccessTokenError,
} from '../errors.js';
import { MemoryStore, rejectionOf } from '../test-utils/poppy.js';
import { generateToken, jwks } from '../test-utils/tokens.js';
import type {
  DomainsResolver,
  InvalidSessionReason,
  PoppyOptions,
  PoppySession,
  VerifyAccessTokenOptions,
  VerifyPoppyRequestOptions,
} from '../types.js';
import { InvalidSessionError, SessionEndedError } from './errors.js';
import { toHttpErrorResponse } from './http-error-response.js';
import { createTestAgent, type TestAgent, type TestSessionJwtOptions } from './testing/test-agent.js';

const DOMAIN = 'example.auth0.com';
const ISSUER = 'https://example.auth0.com/';
const DISCOVERY_URL = `${ISSUER}.well-known/openid-configuration`;
const JWKS_URL = `${ISSUER}.well-known/jwks.json`;
const AUDIENCE = 'https://api.zepto.example';
const PUBLIC_ORIGIN = 'https://api.zepto.example';
const CART_URL = `${PUBLIC_ORIGIN}/cart`;
// What a server behind a proxy sees: not the URL that the agent signed.
const INTERNAL_CART_URL = 'http://10.0.0.5:8080/cart?x=1';
const OTHER_AGENT_URL = 'https://other.example/agent.json';
const SID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
const USER_ID = 'usr_test';
const TOKEN_SUBJECT = 'auth0|ana';
// The SHA-256 hash of the text `<agent URL>\n<SID>` for the default test agent and SID, base64url-encoded, computed
// with another implementation.
const KEY_OF_DEFAULT_AGENT_AND_SID = 'TCKalJy8Oz7hl1YTKAJt86LQcaiaLsYmFX-cLwiaJ4c';
// Two values for the Authorization header, which is not one credential.
const TWO_AUTHORIZATIONS = ['Bearer a.b.c', 'Bearer d.e.f'];

// The texts of the errors that the pipeline throws itself, word for word. They are fixed: no value of the request is
// in them.
const MESSAGES = {
  missing_session: 'This request needs a verified Session, and it has no Poppy-Session header.',
  registered_agent: "A registered agent's request needs the Poppy-Session header.",
  ath_mismatch: "The Session JWT's ath doesn't match the access token.",
  token_client_mismatch: "The access token wasn't issued to the agent named in the Session JWT.",
  session_mismatch: "The Session JWT's User ID or Agent ID doesn't match the Session.",
  token_session_malformed: "The access token's act claim does not hold a well-formed Session.",
  authorization_malformed: 'The request must carry one Authorization header with one credential.',
} as const;

// The challenges for an `invalid_request` error with no scheme, for each DPoP mode of the client (RFC 6750, section
// 3.1): the same ones that `verifyAccessToken` gives its own `invalid_request` errors.
const MALFORMED_AUTHORIZATION_CHALLENGES = {
  allowed: [
    `Bearer realm="api", error="invalid_request", error_description="${MESSAGES.authorization_malformed}"`,
    'DPoP algs="ES256"',
  ],
  required: ['DPoP algs="ES256"'],
  disabled: [`Bearer realm="api", error="invalid_request", error_description="${MESSAGES.authorization_malformed}"`],
} as const;

// Auth0 is the only host these tests serve. The requests are counted, to show when a check does not reach Auth0, and
// they are recorded, to show what a request did reach. The agent is served by its own `fetch`, and so is not recorded.
let discoveryRequests = 0;
let jwksRequests = 0;
const intercepted: string[] = [];

const server = setupServer(
  http.get(DISCOVERY_URL, () => {
    discoveryRequests += 1;
    return HttpResponse.json({ issuer: ISSUER, jwks_uri: JWKS_URL, token_endpoint: `${ISSUER}oauth/token` });
  }),
  http.get(JWKS_URL, () => {
    jwksRequests += 1;
    return HttpResponse.json({ keys: jwks });
  })
);

interface DpopKey {
  privateKey: CryptoKey;
  jwk: JWK;
  jkt: string;
}

let agent: TestAgent;
let dpopKey: DpopKey;

beforeAll(async () => {
  agent = await createTestAgent();
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  dpopKey = { privateKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
  server.events.on('request:start', ({ request }) => {
    intercepted.push(request.url);
  });
  server.listen({ onUnhandledRequest: 'error' });
});

afterEach(() => {
  server.resetHandlers();
  intercepted.length = 0;
  discoveryRequests = 0;
  jwksRequests = 0;
});

afterAll(() => server.close());

/** An `ApiClient` for `example.auth0.com` that checks the header and gets the agent from the test agent. */
function createClient(poppy: PoppyOptions = {}, dpopMode?: 'allowed' | 'required' | 'disabled'): ApiClient {
  return new ApiClient({
    domain: DOMAIN,
    audience: AUDIENCE,
    ...(dpopMode === undefined ? {} : { dpop: { mode: dpopMode } }),
    poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch }, ...poppy },
  });
}

/** A signed access token of Auth0 for the audience of the client. It is the token of the agent, unless `claims` say. */
function accessToken(
  claims: Record<string, unknown> = { azp: agent.cimdUrl },
  expiresAt?: number,
  audience = AUDIENCE
): Promise<string> {
  return generateToken(DOMAIN, TOKEN_SUBJECT, audience, undefined, undefined, expiresAt, claims);
}

function expiredAt(): number {
  return Math.floor(Date.now() / 1000) - 3600;
}

/** A Session JWT of the test agent for `GET https://api.zepto.example/cart`, for the issuer of `example.auth0.com`. */
function mint(options: Partial<TestSessionJwtOptions> = {}): Promise<string> {
  return agent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID, ...options });
}

function request(
  headers: VerifyPoppyRequestOptions['headers'],
  overrides: Partial<VerifyPoppyRequestOptions> = {}
): VerifyPoppyRequestOptions {
  return { method: 'GET', url: CART_URL, headers, ...overrides };
}

/** A request with a Bearer token and a Session JWT: the one given, or else one with the `ath` of the token. */
async function bearerRequest(
  token: string,
  overrides: Partial<VerifyPoppyRequestOptions> = {},
  session?: string
): Promise<VerifyPoppyRequestOptions> {
  const jwt = session ?? (await mint({ accessToken: token }));
  return request({ 'poppy-session': jwt, authorization: `Bearer ${token}` }, overrides);
}

/** A request with a Bearer token and no Session header. */
function tokenOnlyRequest(
  token: string,
  overrides: Partial<VerifyPoppyRequestOptions> = {}
): VerifyPoppyRequestOptions {
  return request({ authorization: `Bearer ${token}` }, overrides);
}

/**
 * A request with a DPoP token and a proof, or none when `proof` is `undefined`. It has no Session header, unless a
 * Session JWT is given.
 */
function dpopRequest(
  token: string,
  proof: string | string[] | undefined,
  overrides: Partial<VerifyPoppyRequestOptions> = {},
  session?: string
): VerifyPoppyRequestOptions {
  return request(
    {
      ...(session === undefined ? {} : { 'poppy-session': session }),
      authorization: `DPoP ${token}`,
      ...(proof === undefined ? {} : { dpop: proof }),
    },
    overrides
  );
}

function sha256Base64Url(text: string): string {
  return createHash('sha256').update(text).digest('base64url');
}

/** A DPoP proof with real keys and a real signature, for `token`, made with the key that the token is bound to. */
function dpopProof(token: string, overrides: { htm?: string; htu?: string } = {}): Promise<string> {
  return new SignJWT({
    htm: overrides.htm ?? 'GET',
    htu: overrides.htu ?? CART_URL,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ath: sha256Base64Url(token),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: dpopKey.jwk })
    .sign(dpopKey.privateKey);
}

/** An access token of the agent that is bound to the DPoP key. */
function dpopBoundToken(claims: Record<string, unknown> = {}): Promise<string> {
  return accessToken({ azp: agent.cimdUrl, cnf: { jkt: dpopKey.jkt }, ...claims });
}

/** The `act` claim of a web app's token that holds a Session, for the default test agent. */
function sessionAct(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { sub: agent.cimdUrl, poppy_sid: SID, poppy_user_id: USER_ID, ...overrides };
}

/** The Session of the default test agent and SID, for a verified access token. */
function expectedSession(overrides: Partial<PoppySession> = {}): PoppySession {
  return {
    sessionId: SID,
    key: KEY_OF_DEFAULT_AGENT_AND_SID,
    userId: USER_ID,
    agent: { cimdUrl: agent.cimdUrl },
    state: 'signed_in',
    source: 'header',
    ...overrides,
  };
}

/** Checks the class, the reason, the code, the status, and the cause or the text of an `invalid_session` error. */
function expectInvalidSession(
  error: unknown,
  reason: InvalidSessionReason,
  expected: { cause?: string; message?: string } = {}
): InvalidSessionError {
  expect(error).toBeInstanceOf(InvalidSessionError);
  const refused = error as InvalidSessionError;
  expect(refused.reason).toBe(reason);
  expect(refused.code).toBe('invalid_session');
  expect(refused.statusCode).toBe(400);
  if (expected.cause !== undefined) {
    expect(refused.cause).toEqual({ code: expected.cause });
  }
  if (expected.message !== undefined) {
    expect(refused.message).toBe(expected.message);
  }
  return refused;
}

/** The `www-authenticate` challenges of an error, as a list. */
function challengesOf(error: unknown): string[] {
  return ([] as string[]).concat(
    (error as { headers?: Record<string, string | string[]> }).headers?.['www-authenticate'] ?? []
  );
}

describe('ApiClient.verifyPoppyRequest | an access token with a Session in the header, signed in', () => {
  describe('a valid request', () => {
    test('returns the signed-in Session and the claims of the token', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      // `toStrictEqual`: a member with the value `undefined`, such as `poppyAgentId`, fails.
      expect(result.poppy).toStrictEqual(expectedSession());
      expect(Object.keys(result)).toEqual(['poppy', 'claims']);
      expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
      expect(result.claims).toMatchObject({ iss: ISSUER, aud: AUDIENCE, azp: agent.cimdUrl });
    });

    test('returns the very claims that verifyAccessToken verified, and calls it once', async () => {
      const client = createClient();
      const verified = vi.spyOn(client, 'verifyAccessToken');
      const token = await accessToken();

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(verified).toHaveBeenCalledTimes(1);
      expect(result.claims).toBe(await verified.mock.results[0]?.value);
    });

    test('gives the agent_id of the Session JWT as agent.poppyAgentId', async () => {
      const client = createClient();
      const token = await accessToken();
      const jwt = await mint({ accessToken: token, agentId: 'travel' });

      const result = await client.verifyPoppyRequest(await bearerRequest(token, {}, jwt));

      expect(result.poppy).toStrictEqual(
        expectedSession({ agent: { cimdUrl: agent.cimdUrl, poppyAgentId: 'travel' } })
      );
    });

    test('gives the sub and the sid of the Session JWT, and not the subject of the token', async () => {
      const client = createClient();
      const token = await accessToken();
      const jwt = await mint({ accessToken: token, sub: 'usr_other', sid: 'another-sid_01' });

      const result = await client.verifyPoppyRequest(await bearerRequest(token, {}, jwt));

      expect(result.poppy?.userId).toBe('usr_other');
      expect(result.poppy?.sessionId).toBe('another-sid_01');
      expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
    });

    test('gives the same key as the header alone gives for the same agent and Session ID', async () => {
      const client = createClient();
      const token = await accessToken();

      const signedOut = await client.verifyPoppyRequest(request({ 'poppy-session': await mint() }));
      const signedIn = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(signedOut.poppy?.state).toBe('signed_out');
      expect(signedIn.poppy?.state).toBe('signed_in');
      expect(signedIn.poppy?.key).toBe(signedOut.poppy?.key);
      expect(signedIn.poppy?.key).toBe(KEY_OF_DEFAULT_AGENT_AND_SID);
    });

    test.each([
      {
        name: 'a lower-case name',
        headers: (jwt: string, token: string) => ({ 'poppy-session': jwt, authorization: `Bearer ${token}` }),
      },
      {
        name: 'a Title-Case name',
        headers: (jwt: string, token: string) => ({ 'Poppy-Session': jwt, Authorization: `Bearer ${token}` }),
      },
      {
        name: 'an upper-case name',
        headers: (jwt: string, token: string) => ({ 'POPPY-SESSION': jwt, AUTHORIZATION: `Bearer ${token}` }),
      },
      {
        name: 'a list of one value',
        headers: (jwt: string, token: string) => ({ 'poppy-session': [jwt], authorization: [`Bearer ${token}`] }),
      },
      {
        name: 'spaces and a tab around the value',
        headers: (jwt: string, token: string) => ({ 'poppy-session': jwt, authorization: `  Bearer ${token}\t` }),
      },
      {
        name: 'a scheme in lower case',
        headers: (jwt: string, token: string) => ({ 'poppy-session': jwt, authorization: `bearer ${token}` }),
      },
      {
        name: 'a scheme in upper case',
        headers: (jwt: string, token: string) => ({ 'poppy-session': jwt, authorization: `BEARER ${token}` }),
      },
    ])('reads the headers from $name', async ({ headers }) => {
      const client = createClient();
      const token = await accessToken();

      const result = await client.verifyPoppyRequest(request(headers(await mint({ accessToken: token }), token)));

      expect(result.poppy).toStrictEqual(expectedSession());
    });

    test('calls Auth0 for the token, and for nothing else: the discovery document and the key set', async () => {
      const client = createClient();
      const token = await accessToken();

      await client.verifyPoppyRequest(await bearerRequest(token));

      // The agent is served by its own `fetch`, so Auth0 is the only host the requests reach.
      expect(intercepted).toEqual([DISCOVERY_URL, JWKS_URL]);
    });

    test('fetches the metadata and keys of the agent once, and the keys of Auth0 once, for every request', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });

      for (const sid of ['first-sid', 'second-sid', 'third-sid']) {
        const token = await accessToken();
        await client.verifyPoppyRequest(await bearerRequest(token, {}, await mint({ accessToken: token, sid })));
      }

      expect(agentFetch.mock.calls.map(([input]) => String(input))).toEqual([agent.cimdUrl, agent.jwksUri]);
      expect(discoveryRequests).toBe(1);
      expect(jwksRequests).toBe(1);
    });
  });

  describe('the agent that the token was issued to', () => {
    test('accepts a token whose client_id is the agent, though its azp is another client', async () => {
      const client = createClient();
      const token = await accessToken({ client_id: agent.cimdUrl, azp: 'another-client' });

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession());
    });

    test('refuses a client_id of another client though the azp is the agent: the first claim counts', async () => {
      const client = createClient();
      const token = await accessToken({ client_id: 'another-client', azp: agent.cimdUrl });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expectInvalidSession(error, 'token_client_mismatch', { message: MESSAGES.token_client_mismatch });
    });

    test('refuses a token with neither a client_id nor an azp', async () => {
      const client = createClient();
      const token = await accessToken({});

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expectInvalidSession(error, 'token_client_mismatch', { message: MESSAGES.token_client_mismatch });
    });

    test('refuses the token of a web app with a Session in its act claim: its client is not the agent', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      // The `act` claim is not read when the request has the header, and the token was not issued to the agent.
      expectInvalidSession(error, 'token_client_mismatch', { message: MESSAGES.token_client_mismatch });
    });

    test('refuses a token of another agent', async () => {
      const client = createClient();
      const token = await accessToken({ azp: OTHER_AGENT_URL });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expectInvalidSession(error, 'token_client_mismatch');
    });

    test('compares the claim with the agent URL character by character', async () => {
      const client = createClient();
      const token = await accessToken({ azp: `${agent.cimdUrl}/` });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expectInvalidSession(error, 'token_client_mismatch');
    });

    test.each([
      { name: 'a number', value: 42 },
      { name: 'null', value: null },
      { name: 'a list', value: ['x'] },
    ])('skips a first claim that is $name, and takes the next one that is a string', async ({ value }) => {
      const client = createClient();
      const token = await accessToken({ client_id: value, azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession());
    });

    test('refuses a token whose only client claim is not a string', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 42 });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expectInvalidSession(error, 'token_client_mismatch');
    });
  });

  describe('the ath of the Session JWT', () => {
    test('is refused with ath_mismatch when it is the hash of another token', async () => {
      const client = createClient();
      const token = await accessToken();
      const otherToken = await accessToken({ azp: agent.cimdUrl, jti: 'another-token' });

      const error = await rejectionOf(
        client.verifyPoppyRequest(await bearerRequest(token, {}, await mint({ accessToken: otherToken })))
      );

      expectInvalidSession(error, 'ath_mismatch', { message: MESSAGES.ath_mismatch });
    });

    test('is refused with ath_mismatch when the Session JWT has none', async () => {
      const client = createClient();
      const token = await accessToken();

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, await mint())));

      expectInvalidSession(error, 'ath_mismatch', { message: MESSAGES.ath_mismatch });
    });

    test('is refused with ath_mismatch when it is the hash of the token with one character changed', async () => {
      const client = createClient();
      const token = await accessToken();
      const hash = sha256Base64Url(token);
      const changed = `${hash.slice(0, -1)}${hash.endsWith('A') ? 'B' : 'A'}`;

      const error = await rejectionOf(
        client.verifyPoppyRequest(await bearerRequest(token, {}, await mint({ claims: { ath: changed } })))
      );

      expectInvalidSession(error, 'ath_mismatch');
    });

    test('is checked with the hash of the token as it came, and not of the token with its scheme', async () => {
      const client = createClient();
      const token = await accessToken();

      const error = await rejectionOf(
        client.verifyPoppyRequest(await bearerRequest(token, {}, await mint({ accessToken: `Bearer ${token}` })))
      );

      expectInvalidSession(error, 'ath_mismatch');
    });
  });

  describe('the errors of the token', () => {
    test('rejects an expired token with the VerifyAccessTokenError, with status 401 and the challenges', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl }, expiredAt());

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
      expect((error as VerifyAccessTokenError).statusCode).toBe(401);
      const response = toHttpErrorResponse(error);
      expect(response?.status).toBe(401);
      expect(response?.body).toBeUndefined();
      const challenges = response?.headers['www-authenticate'] as string[];
      expect(challenges).toHaveLength(2);
      expect(challenges[0]).toMatch(/^Bearer realm="api", error="invalid_token", error_description=".+"$/);
      expect(challenges[1]).toBe('DPoP algs="ES256"');
    });

    test('gives the error of verifyAccessToken as it is, for a token of another audience', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl }, undefined, 'https://other.example');

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
      expect(challengesOf(error)[0]).toMatch(/error="invalid_token"/);
    });

    test('gives the error of verifyAccessToken as it is, for a token that is not a JWT', async () => {
      const client = createClient();
      const token = 'not-a-jwt';

      const error = await rejectionOf(
        client.verifyPoppyRequest(await bearerRequest(token, {}, await mint({ accessToken: token })))
      );

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
      expect((error as VerifyAccessTokenError).statusCode).toBe(401);
    });

    test('lets a Session error come first: a wrong htu with an expired token gives the Session error', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl }, expiredAt());
      const jwt = await mint({ accessToken: token, htu: `${PUBLIC_ORIGIN}/other` });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, jwt)));

      expectInvalidSession(error, 'claim_mismatch', { cause: 'htu' });
    });

    test.each([
      { defect: 'session_bad_signature', reason: 'signature_invalid' },
      { defect: 'expired_delegation', reason: 'delegation_invalid' },
    ] as const)(
      'lets a Session error come first: the defect $defect with an expired token',
      async ({ defect, reason }) => {
        const client = createClient();
        const token = await accessToken({ azp: agent.cimdUrl }, expiredAt());
        const jwt = await mint({ accessToken: token, defect });

        const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, jwt)));

        expectInvalidSession(error, reason);
      }
    );

    test('lets a Session error come first, whatever the token is', async () => {
      const client = createClient();
      const jwt = await mint({ htm: 'POST' });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest('not-a-jwt', {}, jwt)));

      expectInvalidSession(error, 'claim_mismatch', { cause: 'htm' });
    });

    test('lets the token error come before the check of the agent that the token was issued to', async () => {
      const client = createClient();
      const token = await accessToken({ azp: OTHER_AGENT_URL }, expiredAt());

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
    });
  });

  describe('the order of the ath and the token', () => {
    test('refuses an ath that is for another token before the token is verified, and never calls Auth0', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl }, expiredAt());
      const jwt = await mint({ accessToken: 'another-access-token' });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, jwt)));

      expectInvalidSession(error, 'ath_mismatch');
      expect(jwksRequests).toBe(0);
      expect(discoveryRequests).toBe(0);
      expect(intercepted).toEqual([]);
    });

    test('makes the same request with the right ath reach Auth0, so the count above can fail', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl }, expiredAt());

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
      expect(jwksRequests).toBe(1);
      expect(discoveryRequests).toBe(1);
    });

    test('refuses a Session JWT without ath before the token is verified, and never calls Auth0', async () => {
      const client = createClient();
      const token = await accessToken();

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, await mint())));

      expectInvalidSession(error, 'ath_mismatch');
      expect(intercepted).toEqual([]);
    });

    test.each([
      { name: 'a claim that does not match', options: { htm: 'POST' }, reason: 'claim_mismatch' },
      { name: 'a signature that is wrong', options: { defect: 'session_bad_signature' }, reason: 'signature_invalid' },
      { name: 'an agent that is not allowed', options: {}, reason: 'agent_not_allowed' },
    ] as const)('never calls Auth0 for a Session JWT with $name', async ({ options, reason }) => {
      const client = createClient(reason === 'agent_not_allowed' ? { agents: [OTHER_AGENT_URL] } : {});
      const token = await accessToken();
      const jwt = await mint({ accessToken: token, ...options });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, jwt)));

      expectInvalidSession(error, reason);
      expect(intercepted).toEqual([]);
    });
  });

  describe('the Session record', () => {
    test('shows the store the key of the Session after the token is verified, and saves the User ID', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      const token = await accessToken();

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession());
      expect(store.getCalls).toEqual([KEY_OF_DEFAULT_AGENT_AND_SID]);
      expect(store.setCalls).toStrictEqual([{ key: KEY_OF_DEFAULT_AGENT_AND_SID, record: { userId: USER_ID } }]);
    });

    test('refuses a Session that the store knows for another User with session_mismatch', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: 'usr_first' });
      const client = createClient({ sessionStore: store });
      const token = await accessToken();

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expectInvalidSession(error, 'session_mismatch', { message: MESSAGES.session_mismatch });
    });

    test('refuses a Session that has ended with SessionEndedError', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: USER_ID, ended: true });
      const client = createClient({ sessionStore: store });
      const token = await accessToken();

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

      expect(error).toBeInstanceOf(SessionEndedError);
    });

    test.each([
      {
        name: 'an expired token',
        token: () => accessToken({ azp: agent.cimdUrl }, expiredAt()),
        error: VerifyAccessTokenError,
      },
      {
        name: 'a token of another agent',
        token: () => accessToken({ azp: OTHER_AGENT_URL }),
        error: InvalidSessionError,
      },
    ])('never asks the store when the request has $name', async ({ token, error: errorClass }) => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(await token())));

      expect(error).toBeInstanceOf(errorClass);
      expect(store.getCalls).toEqual([]);
      expect(store.setCalls).toEqual([]);
    });
  });
});

describe('ApiClient.verifyPoppyRequest | DPoP', () => {
  test('accepts a DPoP-bound token and a proof for the public URL, though the server sees another URL', async () => {
    const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
    const token = await dpopBoundToken();
    const proof = await dpopProof(token, { htu: CART_URL });
    const jwt = await mint({ accessToken: token });

    const result = await client.verifyPoppyRequest(dpopRequest(token, proof, { url: INTERNAL_CART_URL }, jwt));

    expect(result.poppy).toStrictEqual(expectedSession());
    expect(result.claims?.cnf).toEqual({ jkt: dpopKey.jkt });
  });

  test('refuses a proof for the internal URL with the InvalidDpopProofError of verifyAccessToken', async () => {
    const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
    const token = await dpopBoundToken();
    const proof = await dpopProof(token, { htu: 'http://10.0.0.5:8080/cart' });
    const jwt = await mint({ accessToken: token });

    const error = await rejectionOf(
      client.verifyPoppyRequest(dpopRequest(token, proof, { url: INTERNAL_CART_URL }, jwt))
    );

    expect(error).toBeInstanceOf(InvalidDpopProofError);
    expect((error as InvalidDpopProofError).statusCode).toBe(400);
    expect(challengesOf(error)[1]).toMatch(/^DPoP error="invalid_dpop_proof", error_description=".+", algs="ES256"$/);
  });

  test('refuses a proof for a path that is not the path of the request', async () => {
    const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
    const token = await dpopBoundToken();
    const proof = await dpopProof(token, { htu: `${PUBLIC_ORIGIN}/other` });

    const error = await rejectionOf(
      client.verifyPoppyRequest(dpopRequest(token, proof, {}, await mint({ accessToken: token })))
    );

    expect(error).toBeInstanceOf(InvalidDpopProofError);
  });

  test('refuses a proof for another method', async () => {
    const client = createClient();
    const token = await dpopBoundToken();
    const proof = await dpopProof(token, { htm: 'POST' });

    const error = await rejectionOf(
      client.verifyPoppyRequest(dpopRequest(token, proof, {}, await mint({ accessToken: token })))
    );

    expect(error).toBeInstanceOf(InvalidDpopProofError);
  });

  test('accepts a proof for POST when the method of the request is written post', async () => {
    const client = createClient();
    const token = await dpopBoundToken();
    const proof = await dpopProof(token, { htm: 'POST' });
    const jwt = await mint({ accessToken: token, htm: 'POST' });

    const result = await client.verifyPoppyRequest(dpopRequest(token, proof, { method: 'post' }, jwt));

    expect(result.poppy?.state).toBe('signed_in');
  });

  test('refuses two proofs', async () => {
    const client = createClient();
    const token = await dpopBoundToken();
    const proof = await dpopProof(token);

    const error = await rejectionOf(
      client.verifyPoppyRequest(dpopRequest(token, [proof, proof], {}, await mint({ accessToken: token })))
    );

    expect(error).toBeInstanceOf(InvalidDpopProofError);
  });

  test('gives the standard DPoP challenge, with no error, to a DPoP request that has no proof', async () => {
    const client = createClient();
    const token = await dpopBoundToken();

    const error = await rejectionOf(
      client.verifyPoppyRequest(dpopRequest(token, undefined, {}, await mint({ accessToken: token })))
    );

    expect(error).toBeInstanceOf(InvalidRequestError);
    expect((error as InvalidRequestError).statusCode).toBe(400);
    expect(challengesOf(error)).toEqual(['Bearer realm="api"', 'DPoP algs="ES256"']);
  });

  test('refuses a DPoP-bound token that is sent as Bearer, as verifyAccessToken does', async () => {
    const client = createClient();
    const token = await dpopBoundToken();

    const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

    expect(error).toBeInstanceOf(VerifyAccessTokenError);
    expect((error as VerifyAccessTokenError).message).toBe(
      'DPoP-bound token requires the DPoP authentication scheme, not Bearer'
    );
  });

  test('refuses a DPoP-bound token that is sent as Bearer with a proof', async () => {
    const client = createClient();
    const token = await dpopBoundToken();
    const proof = await dpopProof(token);

    const error = await rejectionOf(
      client.verifyPoppyRequest(
        request({ 'poppy-session': await mint({ accessToken: token }), authorization: `Bearer ${token}`, dpop: proof })
      )
    );

    expect(error).toBeInstanceOf(VerifyAccessTokenError);
  });

  test('gives the InvalidRequestError of verifyAccessToken to a proof sent with an unbound token', async () => {
    const client = createClient();
    const token = await accessToken();
    const proof = await dpopProof(token);

    const error = await rejectionOf(
      client.verifyPoppyRequest(
        request({ 'poppy-session': await mint({ accessToken: token }), authorization: `Bearer ${token}`, dpop: proof })
      )
    );

    expect(error).toBeInstanceOf(InvalidRequestError);
    expect((error as InvalidRequestError).message).toBe(
      'DPoP proof requires the DPoP authentication scheme, not Bearer'
    );
  });

  test('refuses a Bearer request in the mode that requires DPoP, as verifyAccessToken does', async () => {
    const client = createClient({}, 'required');
    const token = await accessToken();

    const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token)));

    expect(error).toBeInstanceOf(InvalidRequestError);
    expect(challengesOf(error)).toEqual(['DPoP algs="ES256"']);
  });

  test('lets a Session error come first: a Session for the internal URL gives the Session error', async () => {
    const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
    const token = await dpopBoundToken();
    const proof = await dpopProof(token, { htu: 'http://10.0.0.5:8080/cart' });
    const jwt = await mint({ accessToken: token, htu: 'http://10.0.0.5:8080/cart' });

    const error = await rejectionOf(
      client.verifyPoppyRequest(dpopRequest(token, proof, { url: INTERNAL_CART_URL }, jwt))
    );

    expectInvalidSession(error, 'claim_mismatch', { cause: 'htu' });
  });

  describe('without a Session in the header', () => {
    test('accepts a DPoP-bound token and a proof for the public URL, though the server sees another URL', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const token = await dpopBoundToken();
      const proof = await dpopProof(token);

      const result = await client.verifyPoppyRequest(dpopRequest(token, proof, { url: INTERNAL_CART_URL }));

      expect(result).toStrictEqual({ claims: expect.objectContaining({ sub: TOKEN_SUBJECT }) });
    });

    test('refuses a proof for the internal URL', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const token = await dpopBoundToken();
      const proof = await dpopProof(token, { htu: 'http://10.0.0.5:8080/cart' });

      const error = await rejectionOf(client.verifyPoppyRequest(dpopRequest(token, proof, { url: INTERNAL_CART_URL })));

      expect(error).toBeInstanceOf(InvalidDpopProofError);
    });

    test('gives the Session of the token of a DPoP request', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const token = await dpopBoundToken({ act: sessionAct() });
      const proof = await dpopProof(token);

      const result = await client.verifyPoppyRequest(dpopRequest(token, proof, { url: INTERNAL_CART_URL }));

      expect(result.poppy).toStrictEqual(expectedSession({ source: 'token' }));
    });
  });
});

describe('ApiClient.verifyPoppyRequest | an access token without a Session in the header', () => {
  describe('a token that holds no Session', () => {
    test('returns the claims and nothing else', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app' });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result)).toEqual(['claims']);
      expect(result.claims).toMatchObject({ sub: TOKEN_SUBJECT, iss: ISSUER, aud: AUDIENCE, azp: 'a-web-app' });
    });

    test('returns the claims of a token with an act that is not a Session', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: { sub: 'service-a' } });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result)).toEqual(['claims']);
      expect(result.claims?.act).toEqual({ sub: 'service-a' });
    });

    test('calls Auth0 for the token, and for nothing else', async () => {
      const client = createClient();

      await client.verifyPoppyRequest(tokenOnlyRequest(await accessToken({ azp: 'a-web-app' })));

      expect(intercepted).toEqual([DISCOVERY_URL, JWKS_URL]);
    });

    test('gives missing_session when the request requires a Session', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app' });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token, { requireSession: true })));

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.missing_session });
    });

    test('gives missing_session when the request requires a Session and the checks are off', async () => {
      const client = createClient({ verifySession: false });
      const token = await accessToken({ azp: 'a-web-app' });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token, { requireSession: true })));

      expectInvalidSession(error, 'missing_session');
    });

    test('rejects an expired token with the VerifyAccessTokenError of verifyAccessToken', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app' }, expiredAt());

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
      expect(toHttpErrorResponse(error)?.status).toBe(401);
    });

    test('gives the claims with the checks off, and with no poppy option at all', async () => {
      const token = await accessToken({ azp: 'a-web-app' });
      const withChecksOff = createClient({ verifySession: false });
      const withoutOption = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

      for (const client of [withChecksOff, withoutOption]) {
        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(Object.keys(result)).toEqual(['claims']);
        expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
      }
    });
  });

  describe('a token that holds a Session in its act claim', () => {
    test('returns the Session of the token and the claims', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession({ source: 'token', state: 'signed_in' }));
      expect(Object.keys(result)).toEqual(['poppy', 'claims']);
      expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
    });

    describe('a guest, the anonymous user whom an agent joined to the web app', () => {
      // The claims of the two guests of a test tenant of Auth0, and of an Agent as Principal.
      const GUEST_SUBJECT = 'anon_poppy@b_wzya665QRXJiNwauv_Y69mOaXNyTFMFlpU54QqhHc';
      const GUEST_PROFILE = 'user urn:auth0:anonymous_user';

      function webAppToken(subject: string, claims: Record<string, unknown>): Promise<string> {
        const all = { azp: 'a-web-app', act: sessionAct(), ...claims };
        return generateToken(DOMAIN, subject, AUDIENCE, undefined, undefined, undefined, all);
      }

      test.each([
        {
          name: 'both markers, as the token of a test tenant',
          subject: GUEST_SUBJECT,
          claims: { sub_profile: GUEST_PROFILE },
        },
        { name: 'only the sub_profile', subject: TOKEN_SUBJECT, claims: { sub_profile: GUEST_PROFILE } },
        { name: 'only the sub prefix', subject: GUEST_SUBJECT, claims: {} },
        {
          name: 'the marker among other words',
          subject: TOKEN_SUBJECT,
          claims: { sub_profile: 'a urn:auth0:anonymous_user b' },
        },
      ])('gives the state signed_out for a token with $name', async ({ subject, claims }) => {
        const client = createClient();
        const token = await webAppToken(subject, claims);

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(result.poppy).toStrictEqual(expectedSession({ source: 'token', state: 'signed_out' }));
        // The claims stay as they are: the app can still read the marker.
        expect(result.claims?.sub).toBe(subject);
      });

      test.each([
        { name: 'no sub_profile, as the token of a signed-in User', claims: {} },
        { name: 'the sub_profile user, as the tokens of Agents as Principals have', claims: { sub_profile: 'user' } },
        { name: 'a word that only starts like the marker', claims: { sub_profile: 'urn:auth0:anonymous_user_x' } },
        { name: 'a sub_profile that is not a string', claims: { sub_profile: ['urn:auth0:anonymous_user'] } },
      ])('keeps the state signed_in for a token with $name', async ({ claims }) => {
        const client = createClient();
        const token = await webAppToken(TOKEN_SUBJECT, claims);

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(result.poppy).toStrictEqual(expectedSession({ source: 'token', state: 'signed_in' }));
      });

      test("keeps the state signed_in when the marker is only in act.sub_profile, which is the agent's", async () => {
        const client = createClient();
        const act = sessionAct({ sub_profile: GUEST_PROFILE });
        const token = await webAppToken(TOKEN_SUBJECT, { act });

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(result.poppy?.state).toBe('signed_in');
      });

      test('keeps the state signed_in for a sub that has the prefix after the start', async () => {
        const client = createClient();
        const token = await webAppToken('auth0|anon_poppy@x', {});

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(result.poppy?.state).toBe('signed_in');
      });

      test('gives no Session for a guest of the Anonymous Sessions feature: its token has no poppy_sid', async () => {
        const client = createClient();
        const token = await webAppToken('anon@abc', { act: undefined, sub_profile: GUEST_PROFILE });

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(result.poppy).toBeUndefined();
        expect(result.claims?.sub_profile).toBe(GUEST_PROFILE);
      });

      test('gives no Session for the token of an Agent as Principal: its act has no poppy_sid', async () => {
        const client = createClient();
        const act = { sub: 'agt_3Lp9', sub_profile: 'ai_agent', client_id: agent.cimdUrl, iss: ISSUER };
        const token = await webAppToken(TOKEN_SUBJECT, { azp: agent.cimdUrl, act, sub_profile: 'user' });

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

        expect(result.poppy).toBeUndefined();
      });
    });

    test('has the same key as the Session of the header for the same agent and Session ID', async () => {
      const client = createClient();
      const fromToken = await client.verifyPoppyRequest(
        tokenOnlyRequest(await accessToken({ azp: 'a-web-app', act: sessionAct() }))
      );
      const fromHeader = await client.verifyPoppyRequest(request({ 'poppy-session': await mint() }));

      expect(fromToken.poppy?.source).toBe('token');
      expect(fromHeader.poppy?.source).toBe('header');
      expect(fromToken.poppy?.key).toBe(fromHeader.poppy?.key);
      expect(fromToken.poppy?.key).toBe(KEY_OF_DEFAULT_AGENT_AND_SID);
    });

    test('gives the poppy_agent_id of the token as agent.poppyAgentId', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_agent_id: 'travel' }) });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(result.poppy?.agent).toStrictEqual({ cimdUrl: agent.cimdUrl, poppyAgentId: 'travel' });
    });

    test('has no poppyAgentId in the agent when the token has no poppy_agent_id', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result.poppy?.agent ?? {})).toEqual(['cimdUrl']);
    });

    test('does not fetch the agent, because the token vouches for the Session', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });

      await client.verifyPoppyRequest(tokenOnlyRequest(await accessToken({ azp: 'a-web-app', act: sessionAct() })));

      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('returns the Session of the token when the request requires a Session', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      // The literal `true` chooses the overload where `poppy` is always set.
      const result = await client.verifyPoppyRequest({ ...tokenOnlyRequest(token), requireSession: true });

      expect(result.poppy.source).toBe('token');
    });

    test('returns the Session of the token with the checks off, because it does not come from the header', async () => {
      const client = createClient({ verifySession: false });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession({ source: 'token' }));
    });

    // The act claim of a web app's token is not the header, so the checks that are off are not the ones that read it.
    test.each([
      { name: 'a poppy_user_id that is empty', overrides: { poppy_user_id: '' }, cause: 'poppy_user_id' },
      { name: 'a poppy_sid that is not a Session ID', overrides: { poppy_sid: 'a+b' }, cause: 'poppy_sid' },
      { name: 'a poppy_agent_id that is empty', overrides: { poppy_agent_id: '' }, cause: 'poppy_agent_id' },
      { name: 'no sub', overrides: { sub: undefined }, cause: 'act_sub' },
    ])('refuses a token whose act has a poppy_sid and $name, with the checks off', async ({ overrides, cause }) => {
      const store = new MemoryStore();
      const client = createClient({ verifySession: false, sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct(overrides) });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'malformed_session', { cause, message: MESSAGES.token_session_malformed });
      expect(store.getCalls).toEqual([]);
    });

    test('returns the Session of the token, and ignores a header that is no JWT, when the checks are off', async () => {
      const client = createClient({ verifySession: false });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const result = await client.verifyPoppyRequest(
        request({ 'poppy-session': 'not-a-jwt', authorization: `Bearer ${token}` })
      );

      expect(result.poppy).toStrictEqual(expectedSession({ source: 'token' }));
    });

    test('uses the Session of the header, and not the act of the token, when the checks are on', async () => {
      const client = createClient();
      const token = await accessToken({
        azp: agent.cimdUrl,
        act: sessionAct({ poppy_sid: 'sid-of-the-token', poppy_user_id: 'usr_of_the_token' }),
      });

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession({ source: 'header' }));
    });

    test('refuses a Session that is not well formed with the malformed_session of the act claim', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_sid: 'a+b' }) });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'malformed_session', {
        cause: 'poppy_sid',
        message: MESSAGES.token_session_malformed,
      });
      expect(toHttpErrorResponse(error)).toEqual({
        status: 400,
        headers: {},
        body: { error: 'invalid_session', error_description: MESSAGES.token_session_malformed },
      });
    });

    test('verifies the token before it reads the act claim', async () => {
      const client = createClient();
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_sid: 'a+b' }) }, expiredAt());

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
    });
  });

  describe('the registered agents', () => {
    const registered = (): PoppyOptions => ({ agents: [agent.cimdUrl] });

    test('refuses the token of a registered agent that has no header, with the message about the header', async () => {
      const client = createClient(registered());
      const token = await accessToken({ azp: agent.cimdUrl });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.registered_agent });
      expect(toHttpErrorResponse(error)).toEqual({
        status: 400,
        headers: {},
        body: { error: 'invalid_session', error_description: MESSAGES.registered_agent },
      });
    });

    test('refuses it when only the request requires a Session, and the checks are off', async () => {
      const client = createClient({ ...registered(), verifySession: false });
      const token = await accessToken({ azp: agent.cimdUrl });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token, { requireSession: true })));

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.registered_agent });
    });

    test('lets it pass when the checks are off and the request does not require a Session', async () => {
      const client = createClient({ ...registered(), verifySession: false });
      const token = await accessToken({ azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result)).toEqual(['claims']);
    });

    test('lets it pass when the checks are off and the request sets requireSession to false', async () => {
      const client = createClient({ ...registered(), verifySession: false });
      const token = await accessToken({ azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token, { requireSession: false }));

      expect(Object.keys(result)).toEqual(['claims']);
    });

    test('lets the token of an agent that is not in the list pass', async () => {
      const client = createClient({ agents: [OTHER_AGENT_URL] });
      const token = await accessToken({ azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result)).toEqual(['claims']);
    });

    test('lets any token pass when there is no list', async () => {
      const client = createClient();
      const token = await accessToken({ azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result)).toEqual(['claims']);
    });

    test('lets a token with no client claim pass, because it names no agent', async () => {
      const client = createClient(registered());
      const token = await accessToken({});

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(Object.keys(result)).toEqual(['claims']);
    });

    test('uses the first client claim: a listed client_id counts though the azp is another client', async () => {
      const client = createClient(registered());
      const token = await accessToken({ client_id: agent.cimdUrl, azp: 'a-web-app' });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.registered_agent });
    });

    test('refuses it even when its act claim holds a Session', async () => {
      const client = createClient(registered());
      const token = await accessToken({ azp: agent.cimdUrl, act: sessionAct() });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.registered_agent });
    });

    test('lets the Session of the token of a web app pass, because the web app is not a registered agent', async () => {
      const client = createClient(registered());
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(result.poppy?.source).toBe('token');
    });

    test('verifies the token first: an expired token of a registered agent gives the token error', async () => {
      const client = createClient(registered());
      const token = await accessToken({ azp: agent.cimdUrl }, expiredAt());

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
    });

    test('does not apply the rule to a request that has the header', async () => {
      const client = createClient(registered());
      const token = await accessToken({ azp: agent.cimdUrl });

      const result = await client.verifyPoppyRequest(await bearerRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession());
    });

    test('never asks the store about a request that the rule refuses', async () => {
      const store = new MemoryStore();
      const client = createClient({ ...registered(), sessionStore: store });

      const error = await rejectionOf(
        client.verifyPoppyRequest(tokenOnlyRequest(await accessToken({ azp: agent.cimdUrl })))
      );

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.registered_agent });
      expect(store.getCalls).toEqual([]);
      expect(store.setCalls).toEqual([]);
    });
  });

  describe('the Session record of a Session from the token', () => {
    test('shows the store the key of the Session, and saves the User ID', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(result.poppy).toStrictEqual(expectedSession({ source: 'token' }));
      expect(store.getCalls).toEqual([KEY_OF_DEFAULT_AGENT_AND_SID]);
      expect(store.setCalls).toStrictEqual([{ key: KEY_OF_DEFAULT_AGENT_AND_SID, record: { userId: USER_ID } }]);
    });

    test('saves the Agent ID too, when the token has one', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_agent_id: 'travel' }) });

      await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(store.setCalls.map((call) => call.record)).toStrictEqual([{ userId: USER_ID, poppyAgentId: 'travel' }]);
    });

    test('refuses a Session that the store knows for another User with session_mismatch', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: 'usr_first' });
      const client = createClient({ sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'session_mismatch', { message: MESSAGES.session_mismatch });
    });

    test('refuses a Session that the store knows with another Agent ID with session_mismatch', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: USER_ID, poppyAgentId: 'food' });
      const client = createClient({ sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_agent_id: 'travel' }) });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'session_mismatch');
    });

    test('refuses a Session that has ended with SessionEndedError', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: USER_ID, ended: true });
      const client = createClient({ sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expect(error).toBeInstanceOf(SessionEndedError);
    });

    test('shares the record with the Session of the header of the same agent and Session ID', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      await client.verifyPoppyRequest(request({ 'poppy-session': await mint({ sub: 'usr_first' }) }));
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_user_id: 'usr_second' }) });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'session_mismatch');
    });

    test('asks the store with the checks off, because the Session is not from the header', async () => {
      const store = new MemoryStore();
      const client = createClient({ verifySession: false, sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

      await client.verifyPoppyRequest(tokenOnlyRequest(token));

      expect(store.getCalls).toEqual([KEY_OF_DEFAULT_AGENT_AND_SID]);
    });

    test('never asks the store about a token that holds no Session', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      const result = await client.verifyPoppyRequest(tokenOnlyRequest(await accessToken({ azp: 'a-web-app' })));
      const error = await rejectionOf(
        client.verifyPoppyRequest(tokenOnlyRequest(await accessToken({ azp: 'a-web-app' }), { requireSession: true }))
      );

      expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
      expectInvalidSession(error, 'missing_session');
      expect(store.getCalls).toEqual([]);
    });

    test('never asks the store about a Session that is not well formed', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      const token = await accessToken({ azp: 'a-web-app', act: sessionAct({ poppy_user_id: '' }) });

      const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token)));

      expectInvalidSession(error, 'malformed_session', { cause: 'poppy_user_id' });
      expect(store.getCalls).toEqual([]);
    });
  });
});

describe('ApiClient.verifyPoppyRequest | the Authorization header', () => {
  describe('a header that is not one credential', () => {
    const malformed = [
      { name: 'a list of two values', authorization: TWO_AUTHORIZATIONS },
      { name: 'a list of two values of two schemes', authorization: ['Bearer a.b.c', 'DPoP d.e.f'] },
      { name: 'two values joined with a comma and a space', authorization: 'Bearer a.b.c, Bearer d.e.f' },
      { name: 'one value with a comma', authorization: 'Bearer a.b.c,d' },
    ];

    test.each(malformed)('gives the InvalidRequestError about the header for $name', async ({ authorization }) => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(request({ authorization })));

      expect(error).toBeInstanceOf(InvalidRequestError);
      const refused = error as InvalidRequestError;
      expect(refused.code).toBe('invalid_request');
      expect(refused.statusCode).toBe(400);
      expect(refused.message).toBe(MESSAGES.authorization_malformed);
      expect(refused.cause).toEqual({ code: 'authorization_malformed' });
    });

    test('gives the same error for the same name written in two cases', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ Authorization: 'Bearer a.b.c', authorization: 'Bearer d.e.f' }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect((error as InvalidRequestError).message).toBe(MESSAGES.authorization_malformed);
    });

    test.each(malformed)(
      'answers 400 with the Bearer and DPoP challenges and no body for $name',
      async ({ authorization }) => {
        const client = createClient();

        const error = await rejectionOf(client.verifyPoppyRequest(request({ authorization })));

        const response = toHttpErrorResponse(error);
        expect(response?.status).toBe(400);
        expect(response?.body).toBeUndefined();
        expect(response?.headers).toEqual({ 'www-authenticate': MALFORMED_AUTHORIZATION_CHALLENGES.allowed });
      }
    );

    test.each(['allowed', 'required', 'disabled'] as const)(
      'answers with the challenges of the %s DPoP mode of the client',
      async (mode) => {
        const client = createClient({}, mode);

        const error = await rejectionOf(client.verifyPoppyRequest(request({ authorization: TWO_AUTHORIZATIONS })));

        const response = toHttpErrorResponse(error);
        expect(response?.status).toBe(400);
        expect(response?.body).toBeUndefined();
        expect(response?.headers['www-authenticate']).toEqual(MALFORMED_AUTHORIZATION_CHALLENGES[mode]);
      }
    );

    test('gives the challenges that verifyAccessToken gives its own invalid_request errors', async () => {
      const client = createClient();
      const token = await accessToken();
      // An `invalid_request` error of `verifyAccessToken` itself: a DPoP proof that comes with a Bearer token.
      const own = await rejectionOf(
        client.verifyPoppyRequest(request({ authorization: `Bearer ${token}`, dpop: await dpopProof(token) }))
      );
      const malformedHeader = await rejectionOf(
        client.verifyPoppyRequest(request({ authorization: TWO_AUTHORIZATIONS }))
      );

      // Only the description differs.
      const withoutDescription = (error: unknown) =>
        challengesOf(error).map((challenge) => challenge.replace(/error_description="[^"]*"/, 'error_description=…'));
      expect(own).toBeInstanceOf(InvalidRequestError);
      expect(challengesOf(own)).toHaveLength(2);
      expect(withoutDescription(malformedHeader)).toEqual(withoutDescription(own));
    });

    test('gives a new error with its own challenges each time', async () => {
      const client = createClient();

      const first = await rejectionOf(client.verifyPoppyRequest(request({ authorization: 'Bearer a.b.c,d' })));
      const second = await rejectionOf(client.verifyPoppyRequest(request({ authorization: 'Bearer a.b.c,d' })));

      expect(first).not.toBe(second);
      expect((first as InvalidRequestError).headers).not.toBe((second as InvalidRequestError).headers);
      expect(challengesOf(first)).toEqual(challengesOf(second));
    });

    test('puts no part of the header in the message, the challenges or the cause', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ authorization: ['Bearer secret-a', 'Bearer secret-b'] }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      const refused = error as InvalidRequestError;
      expect(refused.headers).toBeDefined();
      expect(JSON.stringify([refused.message, refused.cause, refused.headers])).not.toMatch(/secret/);
    });

    test('calls neither Auth0 nor the agent', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ authorization: 'Bearer a.b.c, Bearer d.e.f' }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect(intercepted).toEqual([]);
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('gives the error with the checks off, because the token step runs whatever the checks are', async () => {
      const client = createClient({ verifySession: false });

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ authorization: TWO_AUTHORIZATIONS, 'poppy-session': 'not-a-jwt' }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect((error as InvalidRequestError).message).toBe(MESSAGES.authorization_malformed);
    });

    test('gives the error when the request requires a Session, and not missing_session', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ authorization: TWO_AUTHORIZATIONS }, { requireSession: true }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
    });

    test('comes after the Session checks: a Session JWT that is wrong gives the error about the Session', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(
          request({ 'poppy-session': await mint({ htm: 'POST' }), authorization: TWO_AUTHORIZATIONS })
        )
      );

      expectInvalidSession(error, 'claim_mismatch', { cause: 'htm' });
    });

    test('comes after the Session checks: a header that is not a JWT gives the error about the Session', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'poppy-session': 'not-a-jwt', authorization: 'Bearer a.b.c,d' }))
      );

      expectInvalidSession(error, 'malformed_session');
    });

    test('is given for a Session JWT that is right, and the Session is not returned', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'poppy-session': await mint(), authorization: TWO_AUTHORIZATIONS }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect((error as InvalidRequestError).message).toBe(MESSAGES.authorization_malformed);
      expect(intercepted).toEqual([]);
    });

    test('never asks the store', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'poppy-session': await mint(), authorization: TWO_AUTHORIZATIONS }))
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect(store.getCalls).toEqual([]);
    });
  });

  describe('a header that is one value, but not a Bearer or DPoP credential', () => {
    test.each([
      { name: 'the Basic scheme', authorization: 'Basic dXNlcjpwYXNz', status: 400, error: InvalidRequestError },
      { name: 'a value with no scheme', authorization: 'a.b.c', status: 400, error: InvalidRequestError },
      { name: 'the Bearer scheme with no token', authorization: 'Bearer', status: 401, error: VerifyAccessTokenError },
      { name: 'the DPoP scheme with no token', authorization: 'DPoP', status: 401, error: VerifyAccessTokenError },
    ])(
      'gives the standard error and challenges of verifyAccessToken for $name',
      async ({ authorization, status, error: errorClass }) => {
        const client = createClient();

        const error = await rejectionOf(client.verifyPoppyRequest(request({ authorization })));

        expect(error).toBeInstanceOf(errorClass);
        expect(toHttpErrorResponse(error)?.status).toBe(status);
        expect(challengesOf(error).length).toBeGreaterThan(0);
        // Neither of the two reads `Authorization` as a token, so there is no `error` in the challenge.
        expect(challengesOf(error).join(' ')).not.toMatch(/error=/);
      }
    );

    test('gives the same error after a Session that is right, without comparing the ath', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(
          request({ 'poppy-session': await mint({ accessToken: 'some-token' }), authorization: 'Basic dXNlcjpwYXNz' })
        )
      );

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect((error as InvalidRequestError).cause).toEqual({ code: 'invalid_auth_scheme' });
    });

    test('gives the standard challenge for the Bearer scheme with no token, after a right Session', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'poppy-session': await mint(), authorization: 'Bearer' }))
      );

      expect(error).toBeInstanceOf(VerifyAccessTokenError);
      expect(challengesOf(error)).toEqual(['Bearer realm="api"', 'DPoP algs="ES256"']);
    });

    test('lets a Session error come first', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(
          request({ 'poppy-session': await mint({ htm: 'POST' }), authorization: 'Basic dXNlcjpwYXNz' })
        )
      );

      expectInvalidSession(error, 'claim_mismatch', { cause: 'htm' });
    });

    test('gives the challenges of the mode that requires DPoP', async () => {
      const client = createClient({}, 'required');

      const error = await rejectionOf(client.verifyPoppyRequest(request({ authorization: 'Basic dXNlcjpwYXNz' })));

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect(challengesOf(error)).toEqual(['DPoP algs="ES256"']);
    });
  });

  describe('what verifyAccessToken is called with', () => {
    function watch(client: ApiClient) {
      return vi.spyOn(client, 'verifyAccessToken');
    }

    function firstCall(spy: ReturnType<typeof watch>): VerifyAccessTokenOptions {
      const options = spy.mock.calls[0]?.[0];
      if (options === undefined) {
        throw new Error('verifyAccessToken was not called.');
      }
      return options;
    }

    test('gives a Bearer token the scheme, the URL and the headers, and no proof and no method', async () => {
      const client = createClient();
      const spy = watch(client);
      const token = await accessToken();
      const options = await bearerRequest(token);

      await client.verifyPoppyRequest(options);

      // `toStrictEqual`: a `dpopProof` or `httpMethod` of `undefined` would fail.
      expect(firstCall(spy)).toStrictEqual({
        accessToken: token,
        scheme: 'bearer',
        httpUrl: CART_URL,
        headers: options.headers,
      });
    });

    test('gives the headers of the request as they are', async () => {
      const client = createClient();
      const spy = watch(client);
      const options = await bearerRequest(await accessToken());

      await client.verifyPoppyRequest(options);

      expect(firstCall(spy).headers).toBe(options.headers);
    });

    test('gives a DPoP token the proof, the method and the URL', async () => {
      const client = createClient();
      const spy = watch(client);
      const token = await dpopBoundToken();
      const proof = await dpopProof(token);
      const options = dpopRequest(token, proof);

      await client.verifyPoppyRequest(options);

      expect(firstCall(spy)).toStrictEqual({
        accessToken: token,
        scheme: 'dpop',
        dpopProof: proof,
        httpMethod: 'GET',
        httpUrl: CART_URL,
        headers: options.headers,
      });
    });

    test('gives a Bearer token the proof when the request has one, and still no method', async () => {
      const client = createClient();
      const spy = watch(client);
      const token = await accessToken();
      const proof = await dpopProof(token);

      await rejectionOf(client.verifyPoppyRequest(request({ authorization: `Bearer ${token}`, dpop: proof })));

      expect(firstCall(spy)).toStrictEqual({
        accessToken: token,
        scheme: 'bearer',
        headers: { authorization: `Bearer ${token}`, dpop: proof },
        dpopProof: proof,
      });
    });

    test('gives the URL that the Session JWT is checked against: the public origin and the path', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const spy = watch(client);
      const token = await accessToken();

      await client.verifyPoppyRequest(await bearerRequest(token, { url: 'http://10.0.0.5:8080/cart?x=1#top' }));

      expect(firstCall(spy).httpUrl).toBe(CART_URL);
    });

    test('gives the URL of a path, with the public origin', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const spy = watch(client);
      const token = await accessToken();

      await client.verifyPoppyRequest(await bearerRequest(token, { url: '/cart?x=1' }));

      expect(firstCall(spy).httpUrl).toBe(CART_URL);
    });

    test('gives the URL as it is when there is no public origin, as the Session JWT is checked with it', async () => {
      const client = createClient();
      const spy = watch(client);
      const token = await accessToken();

      await client.verifyPoppyRequest(await bearerRequest(token, { url: `${CART_URL}?x=1` }));

      expect(firstCall(spy).httpUrl).toBe(`${CART_URL}?x=1`);
    });

    test('is not called for a request without an Authorization header', async () => {
      const client = createClient();
      const spy = watch(client);

      await client.verifyPoppyRequest(request({ 'poppy-session': await mint() }));
      await client.verifyPoppyRequest(request({}));

      expect(spy).not.toHaveBeenCalled();
    });

    test('is not called when a Session error comes first', async () => {
      const client = createClient();
      const spy = watch(client);
      const token = await accessToken();

      const wrongMethod = await rejectionOf(
        client.verifyPoppyRequest(await bearerRequest(token, {}, await mint({ htm: 'POST' })))
      );
      const wrongAth = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, {}, await mint())));

      expectInvalidSession(wrongMethod, 'claim_mismatch');
      expectInvalidSession(wrongAth, 'ath_mismatch');
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('the URL of the request', () => {
    test('needs a URL that is absolute when there is no public origin, as for the Session JWT', async () => {
      const client = createClient();
      const token = await accessToken();

      const error = await rejectionOf(client.verifyPoppyRequest(await bearerRequest(token, { url: '/cart' })));

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect(intercepted).toEqual([]);
    });

    test('takes a path when there is a public origin', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const token = await accessToken();

      const result = await client.verifyPoppyRequest(request({ authorization: `Bearer ${token}` }, { url: '/cart' }));

      expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
    });

    test('refuses a URL that has no path to take, when there is a public origin', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const token = await accessToken();

      const error = await rejectionOf(
        client.verifyPoppyRequest(await bearerRequest(token, { url: 'mailto:someone@example.com' }))
      );

      // The URL comes from the request, so it is a 400 with no challenges, and nothing is sent to Auth0.
      expect(error).toBeInstanceOf(InvalidRequestError);
      expect(toHttpErrorResponse(error)).toEqual({ status: 400, headers: {} });
      expect(intercepted).toEqual([]);
    });

    test('needs no URL at all for a request without an Authorization header', async () => {
      const client = createClient();

      await expect(client.verifyPoppyRequest(request({}, { url: '/cart' }))).resolves.toStrictEqual({});
    });

    // The token step uses the URL for two things: the `htu` that a DPoP proof is checked against, and the `url` that a
    // `domains` function receives. A request with only an access token, and neither of those, has nothing to work out.
    describe('a request with only an access token', () => {
      test.each([
        { name: 'a path and no public origin', poppy: {}, url: '/cart' },
        { name: 'a path and a public origin', poppy: { publicOrigin: PUBLIC_ORIGIN }, url: '/cart' },
        {
          name: 'text that is not a URL, with a public origin',
          poppy: { publicOrigin: PUBLIC_ORIGIN },
          url: 'mailto:someone@example.com',
        },
        { name: 'a path, with the Session checks off', poppy: { verifySession: false }, url: '/cart' },
      ])('verifies a Bearer token without a usable URL: $name', async ({ poppy, url }) => {
        const client = createClient(poppy);
        const spy = vi.spyOn(client, 'verifyAccessToken');
        const token = await accessToken({ azp: 'a-web-app' });

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token, { url }));

        expect(result).toStrictEqual({ claims: expect.objectContaining({ sub: TOKEN_SUBJECT }) });
        // `verifyAccessToken` has no use for the URL of a Bearer token, so it is not given one.
        expect(spy.mock.calls[0]?.[0]).toStrictEqual({
          accessToken: token,
          scheme: 'bearer',
          headers: { authorization: `Bearer ${token}` },
        });
      });

      test('reads the Session of the token without a usable URL', async () => {
        const client = createClient();
        const token = await accessToken({ azp: 'a-web-app', act: sessionAct() });

        const result = await client.verifyPoppyRequest(tokenOnlyRequest(token, { url: '/cart' }));

        expect(result.poppy).toStrictEqual(expectedSession({ source: 'token' }));
      });

      test('still refuses a token that fails verification, without a usable URL', async () => {
        const client = createClient();
        const token = await accessToken({ azp: 'a-web-app' }, expiredAt());

        const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token, { url: '/cart' })));

        expect(error).toBeInstanceOf(VerifyAccessTokenError);
      });

      test('answers a malformed Authorization header before it looks at the URL', async () => {
        const client = createClient();
        const token = await accessToken({ azp: 'a-web-app' });

        const error = await rejectionOf(
          client.verifyPoppyRequest(
            request({ authorization: [`Bearer ${token}`, `Bearer ${token}`] }, { url: '/cart' })
          )
        );

        expect(error).toBeInstanceOf(InvalidRequestError);
        expect(challengesOf(error)).toEqual(MALFORMED_AUTHORIZATION_CHALLENGES.allowed);
      });

      test('still needs a usable URL for a DPoP request, because the proof is checked against it', async () => {
        const client = createClient();
        const token = await dpopBoundToken();
        const proof = await dpopProof(token);

        const error = await rejectionOf(client.verifyPoppyRequest(dpopRequest(token, proof, { url: '/cart' })));

        expect(error).toBeInstanceOf(InvalidConfigurationError);
        expect(intercepted).toEqual([]);
      });

      describe('with a domains function', () => {
        function resolverClient(domains: DomainsResolver, poppy: PoppyOptions = {}): ApiClient {
          return new ApiClient({
            audience: AUDIENCE,
            domains,
            poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch }, ...poppy },
          });
        }

        test('gives the function the public origin and the path of the request', async () => {
          const resolver = vi.fn<DomainsResolver>(() => [ISSUER]);
          const client = resolverClient(resolver, { publicOrigin: PUBLIC_ORIGIN });
          const token = await accessToken({ azp: 'a-web-app' });

          const result = await client.verifyPoppyRequest(tokenOnlyRequest(token, { url: INTERNAL_CART_URL }));

          expect(result.claims?.sub).toBe(TOKEN_SUBJECT);
          expect(resolver).toHaveBeenCalledTimes(1);
          expect(resolver).toHaveBeenCalledWith({
            url: CART_URL,
            headers: { authorization: `Bearer ${token}` },
            unverifiedIss: ISSUER,
          });
        });

        test('still needs a usable URL, because the function receives it', async () => {
          const resolver = vi.fn<DomainsResolver>(() => [ISSUER]);
          const client = resolverClient(resolver);
          const token = await accessToken({ azp: 'a-web-app' });

          const error = await rejectionOf(client.verifyPoppyRequest(tokenOnlyRequest(token, { url: '/cart' })));

          expect(error).toBeInstanceOf(InvalidConfigurationError);
          expect(resolver).not.toHaveBeenCalled();
          expect(intercepted).toEqual([]);
        });
      });
    });
  });
});
