import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, expectTypeOf, test, vi } from 'vitest';

import { ApiClient } from '../api-client.js';
import { AuthError, InvalidConfigurationError, InvalidRequestError } from '../errors.js';
import { MemoryStore, rejectionOf } from '../test-utils/poppy.js';
import type {
  ApiClientOptions,
  DomainsResolver,
  InvalidSessionReason,
  PoppyOptions,
  PoppySession,
  PoppySessionRecord,
  VerifiedPoppyRequest,
  VerifyPoppyRequestOptions,
} from '../types.js';
import { InvalidSessionError, PoppyUnavailableError, SessionEndedError } from './errors.js';
import { toHttpErrorResponse } from './http-error-response.js';
import { computeSessionKey } from './session-verifier.js';
import {
  createTestAgent,
  type TestAgent,
  type TestSessionJwtDefect,
  type TestSessionJwtOptions,
} from './testing/test-agent.js';

const DOMAIN = 'example.auth0.com';
const ISSUER = 'https://example.auth0.com/';
const AUDIENCE = 'https://api.zepto.example';
const PUBLIC_ORIGIN = 'https://api.zepto.example';
const CART_URL = `${PUBLIC_ORIGIN}/cart`;
const OTHER_AGENT_URL = 'https://other.example/agent.json';
const SID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
const USER_ID = 'usr_test';
// The SHA-256 hash of the text `<agent URL>\n<SID>` for the default test agent and SID, base64url-encoded, computed
// with another implementation.
const KEY_OF_DEFAULT_AGENT_AND_SID = 'TCKalJy8Oz7hl1YTKAJt86LQcaiaLsYmFX-cLwiaJ4c';

// The default texts of the errors that the pipeline throws itself, word for word. They are fixed: no value of the
// request is in them.
const MESSAGES = {
  malformed_session: 'The Poppy-Session header is not a well-formed Session JWT.',
  missing_session: 'This request needs a verified Session, and it has no Poppy-Session header.',
  agent_not_allowed: 'The agent named in the Session JWT is not allowed.',
  ath_mismatch: "The Session JWT's ath doesn't match the access token.",
  session_mismatch: "The Session JWT's User ID or Agent ID doesn't match the Session.",
  session_ended: 'The Session has ended. Start a new Session with a new sid and send the request again.',
} as const;

// The messages for a `domains` function that returns something that cannot be a list of issuers.
const DOMAINS_MESSAGES = {
  notArray: 'Invalid poppy configuration: the "domains" function must return an array of domain strings',
  notString: 'Invalid poppy configuration: each domain that the "domains" function returns must be a non-blank string',
  invalid: (reason: string) =>
    `Invalid poppy configuration: the "domains" function returned a domain that is not valid: ${reason}`,
} as const;

// No handlers. A test that uses the `fetch` of the test agent proves with this server that verifying a signed-out
// Session makes no network call at all, Auth0 included: a request that reaches it is recorded below, and fails.
const server = setupServer();
const intercepted: string[] = [];

let agent: TestAgent;

beforeAll(async () => {
  agent = await createTestAgent();
  server.events.on('request:start', ({ request }) => {
    intercepted.push(request.url);
  });
  server.listen({ onUnhandledRequest: 'error' });
});

afterEach(() => {
  server.resetHandlers();
  intercepted.length = 0;
});

afterAll(() => server.close());

/** An `ApiClient` for `example.auth0.com` that checks the header and gets the agent from the test agent. */
function createClient(poppy: PoppyOptions = {}): ApiClient {
  return new ApiClient({
    domain: DOMAIN,
    audience: AUDIENCE,
    poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch }, ...poppy },
  });
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

function sessionRequest(jwt: string, overrides: Partial<VerifyPoppyRequestOptions> = {}): VerifyPoppyRequestOptions {
  return request({ 'poppy-session': jwt }, overrides);
}

/** What a request with the Session of `mint()` returns, in full. */
async function signedOutResult(overrides: Partial<PoppySession> = {}): Promise<{ poppy: PoppySession }> {
  return {
    poppy: {
      sessionId: SID,
      key: await computeSessionKey(agent.cimdUrl, SID),
      userId: USER_ID,
      agent: { cimdUrl: agent.cimdUrl },
      state: 'signed_out',
      source: 'header',
      ...overrides,
    },
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

/**
 * A store that makes `expected` first requests wait until all of them have read the record. They then all see no
 * record, as two first requests of one Session do in a real database, and race to save one.
 */
class RacingStore extends MemoryStore {
  #reads = 0;
  readonly #everyoneHasRead: Promise<void>;
  #release!: () => void;

  constructor(private readonly expected: number) {
    super();
    this.#everyoneHasRead = new Promise((resolve) => {
      this.#release = resolve;
    });
  }

  async get(key: string): Promise<PoppySessionRecord | undefined> {
    const record = await super.get(key);
    this.#reads += 1;
    if (this.#reads >= this.expected) {
      this.#release();
    }
    await this.#everyoneHasRead;
    return record;
  }
}

describe('ApiClient.verifyPoppyRequest | a Session in the header, signed out', () => {
  // Every test in this block uses the `fetch` of the test agent, so none of them may reach the network.
  afterEach(() => {
    expect(intercepted).toEqual([]);
  });

  describe('a valid header', () => {
    test('returns exactly the signed-out Session, with the hash of the agent and the Session ID as key', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(sessionRequest(await mint()));

      // `toStrictEqual`: a member with the value `undefined`, such as `poppyAgentId`, or an extra `claims` fails.
      expect(result).toStrictEqual({
        poppy: {
          sessionId: SID,
          key: KEY_OF_DEFAULT_AGENT_AND_SID,
          userId: USER_ID,
          agent: { cimdUrl: agent.cimdUrl },
          state: 'signed_out',
          source: 'header',
        },
      });
      expect(result.poppy?.key).toBe(await computeSessionKey(agent.cimdUrl, SID));
      expect(Object.keys(result)).toEqual(['poppy']);
      expect(Object.keys(result.poppy?.agent ?? {})).toEqual(['cimdUrl']);
    });

    test('gives the agent_id of the Session JWT as agent.poppyAgentId', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(sessionRequest(await mint({ agentId: 'travel' })));

      expect(result).toStrictEqual(
        await signedOutResult({ agent: { cimdUrl: agent.cimdUrl, poppyAgentId: 'travel' } })
      );
    });

    test('gives the sub and the sid of the Session JWT as the userId and the sessionId', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(
        sessionRequest(await mint({ sub: 'usr_other', sid: 'another-sid_01' }))
      );

      expect(result).toStrictEqual(
        await signedOutResult({
          userId: 'usr_other',
          sessionId: 'another-sid_01',
          key: await computeSessionKey(agent.cimdUrl, 'another-sid_01'),
        })
      );
    });

    test('gives another key to another agent that picked the same Session ID', async () => {
      const otherAgent = await createTestAgent({ cimdUrl: OTHER_AGENT_URL });
      const client = new ApiClient({
        domain: DOMAIN,
        audience: AUDIENCE,
        poppy: { verifySession: true, agentMetadata: { fetch: otherAgent.fetch } },
      });
      const jwt = await otherAgent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });

      const result = await client.verifyPoppyRequest(sessionRequest(jwt));

      expect(result.poppy?.sessionId).toBe(SID);
      expect(result.poppy?.agent.cimdUrl).toBe(OTHER_AGENT_URL);
      expect(result.poppy?.key).toBe(await computeSessionKey(OTHER_AGENT_URL, SID));
      expect(result.poppy?.key).not.toBe(KEY_OF_DEFAULT_AGENT_AND_SID);
    });

    test('takes the method from the request in any letter case', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(sessionRequest(await mint({ htm: 'POST' }), { method: 'post' }));

      expect(result).toStrictEqual(await signedOutResult());
    });

    // Header names arrive in any case, as one string or as a list of one, and with spaces around the value.
    test.each([
      { name: 'a lower-case name', headers: (jwt: string) => ({ 'poppy-session': jwt }) },
      { name: 'a Title-Case name', headers: (jwt: string) => ({ 'Poppy-Session': jwt }) },
      { name: 'an upper-case name', headers: (jwt: string) => ({ 'POPPY-SESSION': jwt }) },
      { name: 'a list of one value', headers: (jwt: string) => ({ 'poppy-session': [jwt] }) },
      { name: 'spaces and a tab around the value', headers: (jwt: string) => ({ 'poppy-session': `  ${jwt}\t` }) },
      {
        name: 'other headers around it, some with no value',
        headers: (jwt: string) => ({
          accept: 'application/json',
          'content-type': undefined,
          'x-poppy-session': 'not-a-jwt',
          'Poppy-Session': jwt,
          'x-forwarded-for': ['10.0.0.1', '10.0.0.2'],
        }),
      },
    ])('reads the header from $name', async ({ headers }) => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(request(headers(await mint())));

      expect(result).toStrictEqual(await signedOutResult());
    });

    test('treats an Authorization header with no value as no access token', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(request({ 'poppy-session': await mint(), authorization: '' }));

      expect(result).toStrictEqual(await signedOutResult());
    });

    test('fetches the metadata and the keys of an agent once, for every request that follows', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });

      await client.verifyPoppyRequest(sessionRequest(await mint()));
      await client.verifyPoppyRequest(sessionRequest(await mint({ sid: 'second-sid' })));
      await client.verifyPoppyRequest(sessionRequest(await mint({ sub: 'usr_second' })));

      // The client metadata and the key set, once. The caches belong to the client and are built once.
      expect(agentFetch.mock.calls.map(([input]) => String(input))).toEqual([agent.cimdUrl, agent.jwksUri]);
    });

    test('works as the example of createTestAgent shows', async () => {
      // The example of `createTestAgent` word for word, with the names of this file.
      const exampleAgent = await createTestAgent();
      const apiClient = new ApiClient({
        domain: 'example.auth0.com',
        audience: 'https://api.example.com/',
        poppy: { verifySession: true, agentMetadata: { fetch: exampleAgent.fetch } },
      });

      const sessionJwt = await exampleAgent.createSessionJwt({
        aud: 'https://example.auth0.com/',
        htm: 'POST',
        htu: 'https://api.example.com/orders',
      });
      const result = await apiClient.verifyPoppyRequest({
        method: 'POST',
        url: 'https://api.example.com/orders',
        headers: { 'poppy-session': sessionJwt },
      });

      expect(result.poppy?.state).toBe('signed_out');
      expect(result.poppy?.source).toBe('header');
      expect(result.poppy?.agent.cimdUrl).toBe(exampleAgent.cimdUrl);
    });

    describe('the example of verifyPoppyRequest', () => {
      // The body of `handle` in the example of `verifyPoppyRequest`, word for word. The example has one `apiClient` at
      // the top of the file, and here each test passes in its own.
      const createHandler = (apiClient: ApiClient) =>
        async function handle(request: Request) {
          try {
            const { poppy } = await apiClient.verifyPoppyRequest({
              method: request.method,
              url: request.url,
              headers: Object.fromEntries(request.headers),
            });

            // Key the state of this Session, such as its cart, by `poppy.key`. Never use `poppy.sessionId` alone.
            return { status: 200, body: { session: poppy?.key ?? null } };
          } catch (error) {
            // The status, the headers (such as `retry-after`) and the JSON body that the specification asks for.
            const failure = toHttpErrorResponse(error);
            if (!failure) {
              throw error; // Not a failure of the request: let your framework answer 500.
            }
            return failure;
          }
        };

      const exampleClient = (poppy: PoppyOptions = {}) =>
        new ApiClient({
          domain: 'example.auth0.com',
          audience: 'https://api.example.com',
          poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch }, ...poppy },
        });

      function exampleRequest(path: string, jwt?: string): Request {
        const init = jwt === undefined ? {} : { headers: { 'poppy-session': jwt } };
        return new Request(`https://api.example.com${path}`, init);
      }

      /** A Session JWT for `GET https://api.example.com/orders`. */
      const exampleJwt = () =>
        agent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: 'https://api.example.com/orders', sid: SID });

      test('answers with the key of the Session, or with no Session', async () => {
        const handle = createHandler(exampleClient());
        const jwt = await exampleJwt();

        expect(await handle(exampleRequest('/orders', jwt))).toStrictEqual({
          status: 200,
          body: { session: KEY_OF_DEFAULT_AGENT_AND_SID },
        });
        expect(await handle(exampleRequest('/orders'))).toStrictEqual({ status: 200, body: { session: null } });
      });

      test('answers with the status and the JSON body of a failed check', async () => {
        const handle = createHandler(exampleClient());
        const jwt = await exampleJwt();

        // The Session is for /orders, and the request is for /other.
        expect(await handle(exampleRequest('/other', jwt))).toStrictEqual({
          status: 400,
          headers: {},
          body: {
            error: 'invalid_session',
            error_description: 'The Session JWT htu is not the URL of the request, or is not an https URL.',
          },
        });
      });

      test('answers with the retry-after header when the host of the agent is down', async () => {
        const handle = createHandler(
          exampleClient({ agentMetadata: { fetch: async () => new Response('down', { status: 503 }) } })
        );
        const jwt = await exampleJwt();

        const answer = await handle(exampleRequest('/orders', jwt));

        expect(answer).toMatchObject({
          status: 503,
          headers: { 'retry-after': '30' },
          body: { error: 'temporarily_unavailable' },
        });
      });

      test('lets an error that is not a failure of the request go', async () => {
        const failure = new Error('db down');
        class FailingStore extends MemoryStore {
          async get(): Promise<PoppySessionRecord | undefined> {
            throw failure;
          }
        }
        const handle = createHandler(exampleClient({ sessionStore: new FailingStore() }));
        const jwt = await exampleJwt();

        await expect(handle(exampleRequest('/orders', jwt))).rejects.toBe(failure);
      });
    });
  });

  describe('Session checks on and off', () => {
    test('ignores the header when the checks are off, and fetches nothing', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ verifySession: false, agentMetadata: { fetch: agentFetch } });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(result).toStrictEqual({});
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('ignores a header that is not a JWT at all when the checks are off', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch }, verifySession: false });

      const result = await client.verifyPoppyRequest(sessionRequest('this is not a JWT'));

      expect(result).toStrictEqual({});
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('ignores the header when verifySession is not set and the request does not require a Session', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = new ApiClient({
        domain: DOMAIN,
        audience: AUDIENCE,
        poppy: { agentMetadata: { fetch: agentFetch } },
      });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: false }));

      expect(result).toStrictEqual({});
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('verifies the header when the checks are off but the request requires a Session', async () => {
      const client = createClient({ verifySession: false });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));

      expect(result).toStrictEqual(await signedOutResult());
    });

    test('verifies the header when verifySession is on and the request does not say', async () => {
      const client = createClient({ verifySession: true });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(result).toStrictEqual(await signedOutResult());
    });

    test('verifies the header with the checks on, and requireSession set to false', async () => {
      const client = createClient({ verifySession: true });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: false }));

      expect(result).toStrictEqual(await signedOutResult());
    });

    test('counts only the value true as requireSession', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ verifySession: false, agentMetadata: { fetch: agentFetch } });
      const jwt = await mint();

      for (const requireSession of [undefined, false, 1, 'true', {}]) {
        const checked = sessionRequest(jwt, { requireSession: requireSession as unknown as boolean });

        await expect(client.verifyPoppyRequest(checked)).resolves.toStrictEqual({});
      }
      expect(agentFetch).not.toHaveBeenCalled();
    });
  });

  describe('a request with neither a header nor a token', () => {
    test('gives an empty result', async () => {
      const client = createClient();

      await expect(client.verifyPoppyRequest(request({}))).resolves.toStrictEqual({});
      await expect(client.verifyPoppyRequest(request({ accept: 'application/json' }))).resolves.toStrictEqual({});
    });

    test('gives missing_session when the request requires a Session', async () => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(request({}, { requireSession: true })));

      expectInvalidSession(error, 'missing_session', { message: MESSAGES.missing_session });
    });

    test('gives missing_session when the request requires a Session and the checks are off', async () => {
      const client = createClient({ verifySession: false });

      const error = await rejectionOf(client.verifyPoppyRequest(request({}, { requireSession: true })));

      expectInvalidSession(error, 'missing_session');
    });

    test('does not read x-poppy-session or a similar name as the header', async () => {
      const client = createClient();
      const jwt = await mint();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'x-poppy-session': jwt, 'poppy-sessions': jwt }, { requireSession: true }))
      );

      expectInvalidSession(error, 'missing_session');
    });

    test('does not read the Session from the URL', async () => {
      const client = createClient();
      const jwt = await mint();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({}, { url: `${CART_URL}?poppy-session=${jwt}`, requireSession: true }))
      );

      expectInvalidSession(error, 'missing_session');
    });
  });

  describe('headers that are not a plain object', () => {
    const MESSAGE =
      'Invalid poppy configuration: verifyPoppyRequest needs "headers" to be a plain object. ' +
      'For a Fetch API Request use Object.fromEntries(request.headers).';

    // What TypeScript refuses, and JavaScript lets through. `Object.entries` of a `Headers` or a `Map` is empty, so
    // without the check the request would read as one that has no headers at all.
    const notPlain: Array<{ name: string; value: () => unknown }> = [
      { name: 'null', value: () => null },
      { name: 'undefined', value: () => undefined },
      { name: 'a string', value: () => 'poppy-session: x.y.z' },
      { name: 'a number', value: () => 42 },
      { name: 'a boolean', value: () => true },
      { name: 'a function', value: () => () => ({}) },
      {
        name: 'a Fetch API Headers',
        value: () => new Headers({ 'poppy-session': 'x.y.z', authorization: 'Bearer abc' }),
      },
      {
        name: 'the headers of a Fetch API Request',
        value: () => new Request(CART_URL, { headers: { 'poppy-session': 'x.y.z' } }).headers,
      },
      { name: 'a Map', value: () => new Map([['poppy-session', 'x.y.z']]) },
      { name: 'an array of pairs', value: () => [['poppy-session', 'x.y.z']] },
      { name: 'an empty array', value: () => [] },
      { name: 'a Set', value: () => new Set(['poppy-session']) },
      { name: 'URLSearchParams', value: () => new URLSearchParams({ 'poppy-session': 'x.y.z' }) },
      {
        name: 'an iterable object',
        value: () => ({
          *[Symbol.iterator]() {
            yield ['poppy-session', 'x.y.z'];
          },
        }),
      },
      {
        name: 'an object with a get method',
        value: () => ({ get: (name: string) => (name === 'poppy-session' ? 'x.y.z' : null) }),
      },
      {
        name: 'a record that also has a get method',
        value: () => ({ 'poppy-session': 'x.y.z', get: () => 'x.y.z' }),
      },
    ];

    test.each(notPlain)('throws InvalidConfigurationError for $name', async ({ value }) => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });
      const verifyAccessToken = vi.spyOn(client, 'verifyAccessToken');

      const error = await rejectionOf(
        client.verifyPoppyRequest(request(value() as VerifyPoppyRequestOptions['headers']))
      );

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).message).toBe(MESSAGE);
      expect(agentFetch).not.toHaveBeenCalled();
      expect(verifyAccessToken).not.toHaveBeenCalled();
    });

    // A request with a `Headers` object must not pass as a request with no headers, whatever the checks are.
    test.each(notPlain)('throws for $name when the checks are off, too', async ({ value }) => {
      const client = createClient({ verifySession: false });

      const error = await rejectionOf(
        client.verifyPoppyRequest(request(value() as VerifyPoppyRequestOptions['headers']))
      );

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).message).toBe(MESSAGE);
    });

    test('throws for a Headers object when the client has no poppy option', async () => {
      const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });
      const headers = new Headers({ authorization: 'Bearer abc' }) as unknown as VerifyPoppyRequestOptions['headers'];

      const error = await rejectionOf(client.verifyPoppyRequest(request(headers)));

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).message).toBe(MESSAGE);
    });

    test('throws before anything else is looked at: the URL, requireSession and the options of the client', async () => {
      const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });
      const headers = new Headers() as unknown as VerifyPoppyRequestOptions['headers'];

      const error = await rejectionOf(
        client.verifyPoppyRequest(request(headers, { url: '/cart', requireSession: true }))
      );

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as InvalidConfigurationError).message).toBe(MESSAGE);
    });

    test('has a message that is fixed, and tells how to pass the headers of a Fetch API Request', async () => {
      const client = createClient();
      const secret = 'Bearer hunter2';
      const headers = new Headers({ authorization: secret }) as unknown as VerifyPoppyRequestOptions['headers'];

      const error = (await rejectionOf(client.verifyPoppyRequest(request(headers)))) as InvalidConfigurationError;

      expect(error.message).not.toContain('hunter2');
      expect(error.message).toContain('Object.fromEntries(request.headers)');
      expect(error.code).toBe('invalid_configuration_error');
      expect(toHttpErrorResponse(error)).toBeUndefined();
    });

    test.each([
      { name: 'a plain record', value: (jwt: string) => ({ 'poppy-session': jwt }) },
      {
        name: 'the lower-case record that Object.fromEntries gives for a Headers object',
        value: (jwt: string) => Object.fromEntries(new Headers({ 'Poppy-Session': jwt, Accept: 'application/json' })),
      },
      {
        name: 'the lower-case record of the headers of a Fetch API Request',
        value: (jwt: string) =>
          Object.fromEntries(new Request(CART_URL, { headers: { 'Poppy-Session': jwt } }).headers),
      },
      { name: 'arrays as values', value: (jwt: string) => ({ 'poppy-session': [jwt], accept: ['a', 'b'] }) },
      {
        name: 'a header called get, with a string value',
        value: (jwt: string) => ({ 'poppy-session': jwt, get: 'abc' }),
      },
      {
        name: 'a header called get, with a list of strings',
        value: (jwt: string) => ({ 'poppy-session': jwt, get: ['a'] }),
      },
      {
        name: 'headers called has, entries and keys, with string values',
        value: (jwt: string) => ({ 'poppy-session': jwt, has: 'a', entries: 'b', keys: 'c' }),
      },
      {
        name: 'a record with no prototype',
        value: (jwt: string) => Object.assign(Object.create(null) as Record<string, string>, { 'poppy-session': jwt }),
      },
      {
        name: 'a record with a header that has no value',
        value: (jwt: string) => ({ 'poppy-session': jwt, etag: undefined }),
      },
    ])('still reads $name', async ({ value }) => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(request(value(await mint())));

      expect(result).toStrictEqual(await signedOutResult());
    });
  });

  describe('a header that cannot be one Session JWT', () => {
    const malformed = [
      { name: 'a list of two values', value: (jwt: string) => [jwt, jwt] },
      { name: 'two values joined with a comma and a space', value: (jwt: string) => `${jwt}, ${jwt}` },
      { name: 'two values joined with a comma', value: (jwt: string) => `${jwt},${jwt}` },
      { name: 'an empty value', value: () => '' },
      { name: 'spaces and nothing else', value: () => '   ' },
    ];

    test.each(malformed)('gives malformed_session for $name, and fetches nothing', async ({ value }) => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });
      const jwt = await mint();

      const error = await rejectionOf(client.verifyPoppyRequest(request({ 'poppy-session': value(jwt) })));

      expectInvalidSession(error, 'malformed_session', { message: MESSAGES.malformed_session });
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('gives malformed_session for the same name written in two cases', async () => {
      const client = createClient();
      const jwt = await mint();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'Poppy-Session': jwt, 'poppy-session': jwt }))
      );

      expectInvalidSession(error, 'malformed_session');
    });

    test.each(malformed)('ignores $name when the checks are off', async ({ value }) => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ verifySession: false, agentMetadata: { fetch: agentFetch } });
      const jwt = await mint();

      await expect(client.verifyPoppyRequest(request({ 'poppy-session': value(jwt) }))).resolves.toStrictEqual({});
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test.each(malformed)('gives malformed_session for $name when the request requires a Session', async ({ value }) => {
      const client = createClient({ verifySession: false });
      const jwt = await mint();

      const error = await rejectionOf(
        client.verifyPoppyRequest(request({ 'poppy-session': value(jwt) }, { requireSession: true }))
      );

      expectInvalidSession(error, 'malformed_session');
    });

    test('gives malformed_session, and not missing_session, for a header that is there and is not a JWT', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest('not-a-jwt', { requireSession: true })));

      expectInvalidSession(error, 'malformed_session');
      expect(agentFetch).not.toHaveBeenCalled();
    });

    // A Session JWT that the parser refuses, and that the test agent can make, is refused before anything is fetched.
    test.each<TestSessionJwtDefect>(['missing_delegation', 'signed_with_agent_key', 'session_wrong_typ'])(
      'gives malformed_session for the defect %s, and fetches nothing',
      async (defect) => {
        const agentFetch = vi.fn(agent.fetch);
        const client = createClient({ agentMetadata: { fetch: agentFetch } });

        const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ defect }))));

        expectInvalidSession(error, 'malformed_session');
        expect(agentFetch).not.toHaveBeenCalled();
      }
    );
  });

  describe('the registered agents', () => {
    test('refuses an agent that is not in agents with agent_not_allowed, before anything is fetched', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agents: [OTHER_AGENT_URL], agentMetadata: { fetch: agentFetch } });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expectInvalidSession(error, 'agent_not_allowed', { message: MESSAGES.agent_not_allowed });
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('accepts an agent that is in agents', async () => {
      const client = createClient({ agents: [OTHER_AGENT_URL, agent.cimdUrl] });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(result).toStrictEqual(await signedOutResult());
    });

    test('compares the agent URL character by character', async () => {
      // The same URL with a capital in the path, which is another URL.
      const client = createClient({ agents: ['https://agent.example/Agent.json'] });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expectInvalidSession(error, 'agent_not_allowed');
    });

    test('accepts any agent when there is no list', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(result.poppy?.agent.cimdUrl).toBe(agent.cimdUrl);
    });

    test('does not apply the list to a header that is ignored', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({
        verifySession: false,
        agents: [OTHER_AGENT_URL],
        agentMetadata: { fetch: agentFetch },
      });

      await expect(client.verifyPoppyRequest(sessionRequest(await mint()))).resolves.toStrictEqual({});
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('applies the list when the request requires a Session and the checks are off', async () => {
      const client = createClient({ verifySession: false, agents: [OTHER_AGENT_URL] });

      const error = await rejectionOf(
        client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }))
      );

      expectInvalidSession(error, 'agent_not_allowed');
    });
  });

  describe('the audience', () => {
    test('accepts the issuer of the domain as aud', async () => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(sessionRequest(await mint({ aud: ISSUER })));

      expect(result).toStrictEqual(await signedOutResult());
    });

    // `aud` is compared character by character: nothing is normalized, not the case, not the slash, not the scheme.
    test.each([
      'https://example.auth0.com',
      'https://EXAMPLE.auth0.com/',
      'HTTPS://example.auth0.com/',
      'http://example.auth0.com/',
      'https://example.auth0.com:443/',
      'https://other.auth0.com/',
      'example.auth0.com',
      ' https://example.auth0.com/',
    ])('refuses the aud %j with claim_mismatch', async (aud) => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ aud }))));

      expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
    });

    describe('with domains', () => {
      function domainsClient(domains: string[]): ApiClient {
        return new ApiClient({
          audience: AUDIENCE,
          domains,
          poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
        });
      }

      test('accepts the issuer of any of the domains as aud', async () => {
        const client = domainsClient(['a.example.com', 'b.example.com']);

        const first = await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://a.example.com/' })));
        const second = await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })));

        expect(first.poppy?.userId).toBe(USER_ID);
        expect(second.poppy?.userId).toBe(USER_ID);
      });

      test('refuses the issuer of a domain that is not in domains', async () => {
        const client = domainsClient(['a.example.com', 'b.example.com']);

        const error = await rejectionOf(
          client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://c.example.com/' })))
        );

        expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
      });

      test('takes the domains and not the domain, as verifyAccessToken does', async () => {
        const client = new ApiClient({
          domain: DOMAIN,
          domains: ['a.example.com'],
          audience: AUDIENCE,
          poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
        });

        const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ aud: ISSUER }))));

        expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
      });

      test('normalizes the domains: a host in capitals and a scheme are the same issuer', async () => {
        const client = domainsClient(['B.Example.com', 'https://c.example.com']);

        const first = await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })));
        const second = await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://c.example.com/' })));

        expect(first.poppy?.sessionId).toBe(SID);
        expect(second.poppy?.sessionId).toBe(SID);
      });
    });

    describe('with a domains function', () => {
      function resolverClient(domains: DomainsResolver, overrides: PoppyOptions = {}): ApiClient {
        return new ApiClient({
          audience: AUDIENCE,
          domains,
          poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch }, ...overrides },
        });
      }

      test('calls the function with the url, the headers and the aud of the Session as unverifiedIss', async () => {
        const resolver = vi.fn<DomainsResolver>(async () => ['b.example.com']);
        const client = resolverClient(resolver);
        const headers = { 'poppy-session': await mint({ aud: 'https://b.example.com/' }), 'x-request-id': 'abc' };

        const result = await client.verifyPoppyRequest(request(headers, { url: CART_URL }));

        expect(result.poppy?.sessionId).toBe(SID);
        expect(resolver).toHaveBeenCalledTimes(1);
        expect(resolver).toHaveBeenCalledWith({ url: CART_URL, headers, unverifiedIss: 'https://b.example.com/' });
      });

      test('passes the url as the caller gave it, behind a proxy too', async () => {
        const resolver = vi.fn<DomainsResolver>(() => ['b.example.com']);
        const client = resolverClient(resolver, { publicOrigin: PUBLIC_ORIGIN });
        const jwt = await mint({ aud: 'https://b.example.com/' });

        await client.verifyPoppyRequest(sessionRequest(jwt, { url: 'http://10.0.0.5:8080/cart?x=1' }));

        expect(resolver.mock.calls[0]?.[0]?.url).toBe('http://10.0.0.5:8080/cart?x=1');
      });

      test('accepts the domains in the array it returns, and refuses the others', async () => {
        const client = resolverClient(() => ['b.example.com', 'C.example.com']);

        const accepted = await client.verifyPoppyRequest(
          sessionRequest(await mint({ aud: 'https://c.example.com/' }))
        );
        const error = await rejectionOf(
          client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://d.example.com/' })))
        );

        expect(accepted.poppy?.sessionId).toBe(SID);
        expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
      });

      test('is called for every request, and not once', async () => {
        const resolver = vi.fn<DomainsResolver>(() => ['b.example.com']);
        const client = resolverClient(resolver);

        await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })));
        await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })));

        expect(resolver).toHaveBeenCalledTimes(2);
      });

      test('is not called until the signature of the Session JWT has been verified', async () => {
        const resolver = vi.fn<DomainsResolver>(() => ['b.example.com']);
        const client = resolverClient(resolver);

        const error = await rejectionOf(
          client.verifyPoppyRequest(
            sessionRequest(await mint({ aud: 'https://b.example.com/', defect: 'session_bad_signature' }))
          )
        );

        expectInvalidSession(error, 'signature_invalid');
        expect(resolver).not.toHaveBeenCalled();
      });

      test('is not called for a header that is ignored', async () => {
        const resolver = vi.fn<DomainsResolver>(() => ['b.example.com']);
        const client = resolverClient(resolver, { verifySession: false });

        await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })));

        expect(resolver).not.toHaveBeenCalled();
      });

      test('lets an error of the function reach the caller as it is', async () => {
        const failure = new Error('the tenant lookup failed');
        const client = resolverClient(() => {
          throw failure;
        });

        const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

        expect(error).toBe(failure);
      });

      test('lets a rejection of the function reach the caller as it is', async () => {
        const failure = new Error('the tenant lookup failed');
        const client = resolverClient(() => Promise.reject(failure));

        const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

        expect(error).toBe(failure);
      });

      // An empty list is an answer and not a mistake: this issuer is not one of ours, so no `aud` is allowed. It is how
      // a function refuses a tenant it does not know, as `verifyAccessToken` refuses a token for one with a 401.
      test.each([
        { name: 'a list', resolve: () => [] as string[] },
        { name: 'a promise of a list', resolve: () => Promise.resolve([] as string[]) },
      ])('refuses every Session JWT when it returns an empty array, as $name', async ({ resolve }) => {
        const resolver = vi.fn<DomainsResolver>(resolve);
        const client = resolverClient(resolver);

        const error = await rejectionOf(
          client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })))
        );

        expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
        expect(resolver).toHaveBeenCalledTimes(1);
        // An error for the agent (400), and not a mistake of the setup (500).
        expect(error).toBeInstanceOf(AuthError);
        expect(toHttpErrorResponse(error)).toMatchObject({ status: 400, body: { error: 'invalid_session' } });
      });

      test('lets a function refuse the tenants it does not know by returning an empty array', async () => {
        const known = ['https://b.example.com/'];
        const client = resolverClient(({ unverifiedIss }) =>
          unverifiedIss !== undefined && known.includes(unverifiedIss) ? [unverifiedIss] : []
        );

        const accepted = await client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })));
        const error = await rejectionOf(
          client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://unknown.example.com/' })))
        );

        expect(accepted.poppy?.sessionId).toBe(SID);
        expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
      });

      test.each([
        { name: 'a string', result: 'b.example.com', message: DOMAINS_MESSAGES.notArray },
        { name: 'null', result: null, message: DOMAINS_MESSAGES.notArray },
        { name: 'undefined', result: undefined, message: DOMAINS_MESSAGES.notArray },
        { name: 'an object', result: { domains: ['b.example.com'] }, message: DOMAINS_MESSAGES.notArray },
        { name: 'an array with a number', result: [42], message: DOMAINS_MESSAGES.notString },
        { name: 'an array with null', result: ['b.example.com', null], message: DOMAINS_MESSAGES.notString },
        { name: 'an array with an empty string', result: [''], message: DOMAINS_MESSAGES.notString },
        { name: 'an array with a blank string', result: ['b.example.com', '   '], message: DOMAINS_MESSAGES.notString },
        {
          name: 'an http domain',
          result: ['http://b.example.com'],
          message: DOMAINS_MESSAGES.invalid('invalid domain URL (https required)'),
        },
        {
          name: 'a domain with a path',
          result: ['b.example.com/tenant'],
          message: DOMAINS_MESSAGES.invalid('invalid domain URL (path segments are not allowed)'),
        },
        {
          name: 'a domain with a query',
          result: ['b.example.com?tenant=1'],
          message: DOMAINS_MESSAGES.invalid('invalid domain URL (query/fragment are not allowed)'),
        },
        {
          name: 'a domain with credentials',
          result: ['https://user:secret@b.example.com'],
          message: DOMAINS_MESSAGES.invalid('invalid domain URL (credentials are not allowed)'),
        },
        {
          name: 'a domain that is no URL',
          result: ['https://'],
          message: DOMAINS_MESSAGES.invalid('invalid domain URL'),
        },
      ])(
        'throws InvalidConfigurationError, and not an error for the agent, when it returns $name',
        async ({ result, message }) => {
          const client = resolverClient(() => result as unknown as string[]);

          const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

          expect(error).toBeInstanceOf(InvalidConfigurationError);
          expect((error as Error).message).toBe(message);
          // A fixed text: nothing the function returned is in it.
          expect((error as Error).message).not.toContain('secret');
          // It is a mistake of the setup, so it is neither an error for the agent nor a token error: answer 500.
          expect(error).not.toBeInstanceOf(AuthError);
          expect(toHttpErrorResponse(error)).toBeUndefined();
        }
      );
    });
  });

  describe('the request URL', () => {
    test('takes the public origin from publicOrigin, so a server behind a proxy sees the path only', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });
      const jwt = await mint();

      const absolute = await client.verifyPoppyRequest(sessionRequest(jwt, { url: 'http://10.0.0.5:8080/cart?x=1' }));
      const path = await client.verifyPoppyRequest(sessionRequest(jwt, { url: '/cart?x=1' }));

      expect(absolute.poppy?.sessionId).toBe(SID);
      expect(path.poppy?.sessionId).toBe(SID);
    });

    test('compares the htu with the URL of the request when there is no public origin', async () => {
      const client = createClient();
      const jwt = await mint();

      const ok = await client.verifyPoppyRequest(sessionRequest(jwt, { url: `${CART_URL}?x=1#top` }));
      const error = await rejectionOf(
        client.verifyPoppyRequest(sessionRequest(jwt, { url: 'http://10.0.0.5:8080/cart?x=1' }))
      );

      expect(ok.poppy?.sessionId).toBe(SID);
      expectInvalidSession(error, 'claim_mismatch', { cause: 'htu' });
    });

    test('throws InvalidConfigurationError for a URL that is a path when there is no public origin', async () => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint(), { url: '/cart' })));

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as Error).message.startsWith('Invalid poppy configuration: ')).toBe(true);
      expect(error).not.toBeInstanceOf(AuthError);
    });

    test('throws InvalidRequestError for a URL that cannot be one when there is a public origin', async () => {
      const client = createClient({ publicOrigin: PUBLIC_ORIGIN });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint(), { url: '*' })));

      expect(error).toBeInstanceOf(InvalidRequestError);
      expect((error as InvalidRequestError).statusCode).toBe(400);
    });

    test.each([
      { name: 'the method', claims: { htm: 'POST' }, cause: 'htm' },
      { name: 'the path', claims: { htu: `${PUBLIC_ORIGIN}/orders` }, cause: 'htu' },
      { name: 'the host', claims: { htu: 'https://api.other.example/cart' }, cause: 'htu' },
      { name: 'the scheme of the URL', claims: { htu: 'http://api.zepto.example/cart' }, cause: 'htu' },
    ])('refuses a Session JWT for another request: $name', async ({ claims, cause }) => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint(claims))));

      expectInvalidSession(error, 'claim_mismatch', { cause });
    });
  });

  describe('the time of the Session JWT', () => {
    const now = () => Math.floor(Date.now() / 1000);

    test.each([-120, 120])('refuses an iat that is %i seconds from now with iat_out_of_window', async (offset) => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ iat: now() + offset }))));

      expectInvalidSession(error, 'iat_out_of_window', { cause: 'iat' });
    });

    test.each([-30, 30])('accepts an iat that is %i seconds from now, inside the default window', async (offset) => {
      const client = createClient();

      const result = await client.verifyPoppyRequest(sessionRequest(await mint({ iat: now() + offset })));

      expect(result.poppy?.sessionId).toBe(SID);
    });

    test('takes the window from iatWindow', async () => {
      const wide = createClient({ iatWindow: 300 });
      const narrow = createClient({ iatWindow: 10 });
      const jwt = await mint({ iat: now() - 120 });

      const accepted = await wide.verifyPoppyRequest(sessionRequest(jwt));
      const error = await rejectionOf(narrow.verifyPoppyRequest(sessionRequest(jwt)));

      expect(accepted.poppy?.sessionId).toBe(SID);
      expectInvalidSession(error, 'iat_out_of_window', { cause: 'iat' });
    });

    test('takes the window for the delegation from iatWindow too', async () => {
      // This delegation was issued an hour from now. The default window refuses it, and a window of two hours does not.
      const jwt = await mint({ defect: 'delegation_from_future' });
      const wide = createClient({ iatWindow: 7200 });
      const standard = createClient();

      const accepted = await wide.verifyPoppyRequest(sessionRequest(jwt));
      const error = await rejectionOf(standard.verifyPoppyRequest(sessionRequest(jwt)));

      expect(accepted.poppy?.sessionId).toBe(SID);
      expectInvalidSession(error, 'delegation_invalid', { cause: 'delegation_iat' });
    });
  });

  describe('an ath without an access token', () => {
    test('is refused with ath_mismatch', async () => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ accessToken: 'abc' }))));

      expectInvalidSession(error, 'ath_mismatch', { message: MESSAGES.ath_mismatch });
    });

    test('is refused with ath_mismatch when the Authorization header is empty', async () => {
      const client = createClient();
      const jwt = await mint({ accessToken: 'abc' });

      const error = await rejectionOf(client.verifyPoppyRequest(request({ 'poppy-session': jwt, authorization: '' })));

      expectInvalidSession(error, 'ath_mismatch');
    });

    test('is malformed_session, and not ath_mismatch, when the ath is an empty string', async () => {
      const client = createClient();

      // The parser refuses an `ath` that is not a non-empty string, before anything is fetched.
      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ claims: { ath: '' } }))));

      expectInvalidSession(error, 'malformed_session');
    });

    test('is checked after the claims of the request, so a claim error comes first', async () => {
      const client = createClient();

      const error = await rejectionOf(
        client.verifyPoppyRequest(sessionRequest(await mint({ accessToken: 'abc', htm: 'POST' })))
      );

      expectInvalidSession(error, 'claim_mismatch', { cause: 'htm' });
    });
  });

  describe('the steps before the claims reach the caller as they are', () => {
    test.each<{ defect: TestSessionJwtDefect; reason: InvalidSessionReason; cause: string }>([
      { defect: 'expired_delegation', reason: 'delegation_invalid', cause: 'delegation_expired' },
      { defect: 'delegation_too_long', reason: 'delegation_invalid', cause: 'delegation_lifetime' },
      { defect: 'delegation_from_future', reason: 'delegation_invalid', cause: 'delegation_iat' },
      { defect: 'delegation_iss_mismatch', reason: 'delegation_invalid', cause: 'delegation_iss' },
      { defect: 'delegation_wrong_typ', reason: 'delegation_invalid', cause: 'delegation_typ' },
      { defect: 'delegation_unknown_kid', reason: 'delegation_invalid', cause: 'delegation_key_unknown' },
      { defect: 'delegation_private_cnf', reason: 'delegation_invalid', cause: 'cnf_private_key' },
      { defect: 'session_bad_signature', reason: 'signature_invalid', cause: 'session_signature' },
      { defect: 'session_wrong_kid', reason: 'signature_invalid', cause: 'session_kid' },
    ])('gives $reason for the defect $defect', async ({ defect, reason, cause }) => {
      const client = createClient();

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ defect }))));

      expectInvalidSession(error, reason, { cause });
    });

    test('checks the signature before the claims', async () => {
      const client = createClient();
      const jwt = await mint({ defect: 'session_bad_signature', aud: 'https://other.auth0.com/', htm: 'POST' });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(jwt)));

      expectInvalidSession(error, 'signature_invalid');
    });

    test('gives a 503 error, not an error about the Session, when the host of the agent is down', async () => {
      const client = createClient({
        agentMetadata: { fetch: async () => new Response('Service Unavailable', { status: 503 }) },
      });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expect(error).toBeInstanceOf(PoppyUnavailableError);
      expect((error as PoppyUnavailableError).statusCode).toBe(503);
      expect((error as PoppyUnavailableError).headers).toEqual({ 'retry-after': '30' });
      expect((error as PoppyUnavailableError).cause).toEqual({ code: 'upstream_unavailable' });
    });

    test('gives agent_metadata_invalid when the agent has no client metadata', async () => {
      const client = createClient({ agentMetadata: { fetch: async () => new Response('Not found', { status: 404 }) } });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expectInvalidSession(error, 'agent_metadata_invalid', { cause: 'metadata_status' });
    });

    test('gives agent_not_allowed for an agent on a private address, with no fetch', async () => {
      const privateAgent = await createTestAgent({ cimdUrl: 'https://10.0.0.7/agent.json' });
      const agentFetch = vi.fn(privateAgent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });
      const jwt = await privateAgent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(jwt)));

      expectInvalidSession(error, 'agent_not_allowed', { cause: 'agent_address_not_allowed' });
      expect(agentFetch).not.toHaveBeenCalled();
    });

    test('accepts an agent on a private address when the setup allows it', async () => {
      const privateAgent = await createTestAgent({ cimdUrl: 'https://10.0.0.7/agent.json' });
      const client = createClient({ agentMetadata: { fetch: privateAgent.fetch, allowPrivateAddresses: true } });
      const jwt = await privateAgent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });

      const result = await client.verifyPoppyRequest(sessionRequest(jwt));

      expect(result.poppy?.agent.cimdUrl).toBe('https://10.0.0.7/agent.json');
    });
  });

  describe('the Session record', () => {
    test('shows the store the key of the Session from the first request, and saves the User ID', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      const result = await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(result).toStrictEqual(await signedOutResult());
      expect(store.getCalls).toEqual([KEY_OF_DEFAULT_AGENT_AND_SID]);
      expect(store.setCalls).toStrictEqual([{ key: KEY_OF_DEFAULT_AGENT_AND_SID, record: { userId: USER_ID } }]);
    });

    test('saves the Agent ID too, when the Session JWT has one', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      await client.verifyPoppyRequest(sessionRequest(await mint({ agentId: 'travel' })));

      expect(store.setCalls.map((call) => call.record)).toStrictEqual([{ userId: USER_ID, poppyAgentId: 'travel' }]);
    });

    test('continues a known Session of the same User without saving it again', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      await client.verifyPoppyRequest(sessionRequest(await mint()));
      const second = await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(second).toStrictEqual(await signedOutResult());
      expect(store.getCalls).toHaveLength(2);
      expect(store.setCalls).toHaveLength(1);
    });

    test('refuses a second request with the same sid and another sub with session_mismatch', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      await client.verifyPoppyRequest(sessionRequest(await mint({ sub: 'usr_first' })));

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ sub: 'usr_second' }))));

      expectInvalidSession(error, 'session_mismatch', { message: MESSAGES.session_mismatch });
      expect(store.records.get(KEY_OF_DEFAULT_AGENT_AND_SID)).toStrictEqual({ userId: 'usr_first' });
    });

    test('refuses a second request with the same sid and another agent_id with session_mismatch', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });
      await client.verifyPoppyRequest(sessionRequest(await mint({ agentId: 'travel' })));

      const other = await rejectionOf(
        client.verifyPoppyRequest(sessionRequest(await mint({ agentId: 'food' })))
      );
      const none = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expectInvalidSession(other, 'session_mismatch');
      expectInvalidSession(none, 'session_mismatch');
    });

    test('does not mix up two Sessions of the same sid from two agents', async () => {
      const store = new MemoryStore();
      const otherAgent = await createTestAgent({ cimdUrl: OTHER_AGENT_URL });
      const client = createClient({ sessionStore: store, agentMetadata: { fetch: agent.fetch } });
      const otherClient = createClient({ sessionStore: store, agentMetadata: { fetch: otherAgent.fetch } });
      const otherJwt = await otherAgent.createSessionJwt({
        aud: ISSUER,
        htm: 'GET',
        htu: CART_URL,
        sid: SID,
        sub: 'usr_of_the_other_agent',
      });

      await client.verifyPoppyRequest(sessionRequest(await mint()));
      const result = await otherClient.verifyPoppyRequest(sessionRequest(otherJwt));

      expect(result.poppy?.userId).toBe('usr_of_the_other_agent');
      expect(store.records.size).toBe(2);
    });

    test('refuses a Session that has ended with SessionEndedError', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: USER_ID, ended: true });
      const client = createClient({ sessionStore: store });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expect(error).toBeInstanceOf(SessionEndedError);
      expect((error as SessionEndedError).code).toBe('session_ended');
      expect((error as SessionEndedError).statusCode).toBe(400);
      expect((error as SessionEndedError).message).toBe(MESSAGES.session_ended);
    });

    test('refuses a Session that has ended with SessionEndedError, even for another User', async () => {
      const store = new MemoryStore();
      store.records.set(KEY_OF_DEFAULT_AGENT_AND_SID, { userId: 'usr_first', ended: true });
      const client = createClient({ sessionStore: store });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint({ sub: 'usr_second' }))));

      expect(error).toBeInstanceOf(SessionEndedError);
    });

    test('lets an error of the store reach the caller as it is', async () => {
      const failure = new Error('db down');
      class FailingStore extends MemoryStore {
        async get(): Promise<PoppySessionRecord | undefined> {
          throw failure;
        }
      }
      const client = createClient({ sessionStore: new FailingStore() });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint())));

      expect(error).toBe(failure);
    });

    test('never asks the store about a Session JWT with a signature that is wrong', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      const error = await rejectionOf(
        client.verifyPoppyRequest(sessionRequest(await mint({ defect: 'session_bad_signature' })))
      );

      expectInvalidSession(error, 'signature_invalid', { cause: 'session_signature' });
      expect(store.getCalls).toEqual([]);
      expect(store.setCalls).toEqual([]);
    });

    test.each([
      { name: 'a claim that does not match', options: { htm: 'POST' }, reason: 'claim_mismatch' },
      { name: 'an ath with no access token', options: { accessToken: 'abc' }, reason: 'ath_mismatch' },
      { name: 'an expired delegation', options: { defect: 'expired_delegation' }, reason: 'delegation_invalid' },
    ] as const)('never asks the store about a Session JWT with $name', async ({ options, reason }) => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(await mint(options))));

      expectInvalidSession(error, reason);
      expect(store.getCalls).toEqual([]);
      expect(store.setCalls).toEqual([]);
    });

    test('never asks the store about a header that is ignored', async () => {
      const store = new MemoryStore();
      const client = createClient({ verifySession: false, sessionStore: store });

      await client.verifyPoppyRequest(sessionRequest(await mint()));

      expect(store.getCalls).toEqual([]);
    });

    test('never asks the store about a request with no Session', async () => {
      const store = new MemoryStore();
      const client = createClient({ sessionStore: store });

      await client.verifyPoppyRequest(request({}));
      await rejectionOf(client.verifyPoppyRequest(request({}, { requireSession: true })));

      expect(store.getCalls).toEqual([]);
    });

    describe('two first requests that arrive together', () => {
      test('fetch the metadata and the keys of the agent once, and save one record', async () => {
        const store = new RacingStore(2);
        const agentFetch = vi.fn(agent.fetch);
        const client = createClient({ sessionStore: store, agentMetadata: { fetch: agentFetch } });
        const first = await mint({ sub: USER_ID });
        const second = await mint({ sub: USER_ID });

        const results = await Promise.all([
          client.verifyPoppyRequest(sessionRequest(first)),
          client.verifyPoppyRequest(sessionRequest(second)),
        ]);

        expect(results).toStrictEqual([await signedOutResult(), await signedOutResult()]);
        expect(agentFetch.mock.calls.map(([input]) => String(input))).toEqual([agent.cimdUrl, agent.jwksUri]);
        expect(store.getCalls).toHaveLength(2);
        expect(store.records.size).toBe(1);
        expect(store.records.get(KEY_OF_DEFAULT_AGENT_AND_SID)).toStrictEqual({ userId: USER_ID });
      });

      test('let the first record win, and refuse the request of another User', async () => {
        const store = new RacingStore(2);
        const agentFetch = vi.fn(agent.fetch);
        const client = createClient({ sessionStore: store, agentMetadata: { fetch: agentFetch } });
        const first = await mint({ sub: 'usr_a' });
        const second = await mint({ sub: 'usr_b' });

        const settled = await Promise.allSettled([
          client.verifyPoppyRequest(sessionRequest(first)),
          client.verifyPoppyRequest(sessionRequest(second)),
        ]);

        // Both read no record, and both tried to save one. The store kept the first, and the other was compared to it.
        const fulfilled = settled.filter((outcome) => outcome.status === 'fulfilled');
        const rejected = settled.filter((outcome) => outcome.status === 'rejected');
        expect(fulfilled).toHaveLength(1);
        expect(rejected).toHaveLength(1);
        expectInvalidSession(rejected[0]?.reason, 'session_mismatch');
        const winner = fulfilled[0]?.value.poppy?.userId;
        expect(['usr_a', 'usr_b']).toContain(winner);
        expect(store.records.get(KEY_OF_DEFAULT_AGENT_AND_SID)).toStrictEqual({ userId: winner });
        expect(store.setCalls).toHaveLength(2);
        expect(agentFetch.mock.calls.map(([input]) => String(input))).toEqual([agent.cimdUrl, agent.jwksUri]);
      });
    });
  });

  describe('the cache of verified delegations', () => {
    // The clock of these tests starts here. A delegation of the test agent lasts an hour, and the keys of an agent are
    // kept for ten minutes by default.
    const CLOCK_START = Date.UTC(2026, 10, 6, 12, 0, 0);

    afterEach(() => {
      vi.useRealTimers();
    });

    test('keeps a delegation for the time the keys of an agent are kept, and no longer, although it lasts an hour', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(CLOCK_START);
      // A new agent, so no delegation of an earlier test is reused, and the agent signs at the time of this test.
      const timedAgent = await createTestAgent();
      const agentFetch = vi.fn(timedAgent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch } });
      const send = async (): Promise<void> => {
        const jwt = await timedAgent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });
        await client.verifyPoppyRequest(sessionRequest(jwt));
      };

      await send();
      expect(agentFetch).toHaveBeenCalledTimes(2);

      // Inside the 600 seconds of the default: nothing is fetched, because the keys and the delegation are kept.
      vi.setSystemTime(CLOCK_START + 599_000);
      await send();
      expect(agentFetch).toHaveBeenCalledTimes(2);

      // After them the delegation is verified again, and the keys that it needs are fetched again. If the delegation
      // was kept until its exp, an hour after its start, this request would fetch nothing.
      vi.setSystemTime(CLOCK_START + 601_000);
      await send();
      expect(agentFetch.mock.calls.map(([input]) => String(input))).toEqual([
        timedAgent.cimdUrl,
        timedAgent.jwksUri,
        timedAgent.cimdUrl,
        timedAgent.jwksUri,
      ]);
    });

    test('takes the time from agentMetadata.cache.ttl', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(CLOCK_START);
      const timedAgent = await createTestAgent();
      const agentFetch = vi.fn(timedAgent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch, cache: { ttl: 30 } } });
      const send = async (): Promise<void> => {
        const jwt = await timedAgent.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });
        await client.verifyPoppyRequest(sessionRequest(jwt));
      };

      await send();
      vi.setSystemTime(CLOCK_START + 29_000);
      await send();
      expect(agentFetch).toHaveBeenCalledTimes(2);

      vi.setSystemTime(CLOCK_START + 31_000);
      await send();
      expect(agentFetch).toHaveBeenCalledTimes(4);
    });

    test('verifies every request in full when agentMetadata.cache.ttl is 0, and does not read 0 as no limit', async () => {
      const agentFetch = vi.fn(agent.fetch);
      const client = createClient({ agentMetadata: { fetch: agentFetch, cache: { ttl: 0 } } });

      await client.verifyPoppyRequest(sessionRequest(await mint()));
      await client.verifyPoppyRequest(sessionRequest(await mint()));

      // The metadata and the key set, for each of the two requests: the delegation was not kept.
      expect(agentFetch).toHaveBeenCalledTimes(4);
    });

    test('stops serving the delegations of a key that the agent removed, once that time has passed', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(CLOCK_START);
      const before = await createTestAgent();
      const after = await createTestAgent();
      let current = before;
      const client = createClient({ agentMetadata: { fetch: (input, init) => current.fetch(input, init) } });
      const jwt = await before.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });
      await client.verifyPoppyRequest(sessionRequest(jwt));

      // The agent takes the key out of its key set. The delegation that was seen is served for ten minutes more.
      current = after;
      vi.setSystemTime(CLOCK_START + 599_000);
      const sameDelegation = await before.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });
      await expect(client.verifyPoppyRequest(sessionRequest(sameDelegation))).resolves.toMatchObject({
        poppy: { sessionId: SID },
      });

      vi.setSystemTime(CLOCK_START + 601_000);
      const later = await before.createSessionJwt({ aud: ISSUER, htm: 'GET', htu: CART_URL, sid: SID });
      const error = await rejectionOf(client.verifyPoppyRequest(sessionRequest(later)));

      expectInvalidSession(error, 'delegation_invalid', { cause: 'delegation_key_unknown' });
    });
  });

  describe('the options of the client are read once', () => {
    test('keep the Poppy options as they were when the client was built', async () => {
      const failingFetch = vi.fn<typeof fetch>(async () => {
        throw new Error('The changed fetch must not be used.');
      });
      const poppy: PoppyOptions = {
        verifySession: true,
        agents: [agent.cimdUrl],
        agentMetadata: { fetch: agent.fetch },
      };
      const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE, poppy });
      const changedStore = new MemoryStore();

      // Everything the caller can still reach changes after the client is built, and before it is first used.
      poppy.verifySession = false;
      poppy.agents = [OTHER_AGENT_URL];
      poppy.agentMetadata = { fetch: failingFetch };
      poppy.iatWindow = 0;
      poppy.sessionStore = changedStore;

      // 30 seconds old: inside the default window of the client as it was built, and outside the changed window of 0.
      const jwt = await mint({ iat: Math.floor(Date.now() / 1000) - 30 });
      const result = await client.verifyPoppyRequest(sessionRequest(jwt));

      expect(result).toStrictEqual(await signedOutResult());
      expect(failingFetch).not.toHaveBeenCalled();
      expect(changedStore.getCalls).toEqual([]);
    });

    test('keep the domains as they were when the client was built', async () => {
      const domains = ['a.example.com'];
      const client = new ApiClient({
        audience: AUDIENCE,
        domains,
        poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
      });
      domains.push('b.example.com');

      const error = await rejectionOf(
        client.verifyPoppyRequest(sessionRequest(await mint({ aud: 'https://b.example.com/' })))
      );

      expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
    });
  });
});

describe('ApiClient.verifyPoppyRequest | without the poppy option', () => {
  /** Serves the metadata and the key set of the test agent, as its host would, through the global fetch. */
  function serveAgent(): void {
    server.use(
      http.get(agent.cimdUrl, () => HttpResponse.json(agent.metadata)),
      http.get(agent.jwksUri, () => HttpResponse.json(agent.jwks))
    );
  }

  test('gives an empty result for a request with neither a header nor a token, with no network call', async () => {
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    await expect(client.verifyPoppyRequest(request({}))).resolves.toStrictEqual({});

    expect(intercepted).toEqual([]);
  });

  test('gives missing_session for the same request when it requires a Session, with no network call', async () => {
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    const error = await rejectionOf(client.verifyPoppyRequest(request({}, { requireSession: true })));

    expectInvalidSession(error, 'missing_session', { message: MESSAGES.missing_session });
    expect(intercepted).toEqual([]);
  });

  test('ignores the header unless the request requires a Session, with no network call', async () => {
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    await expect(client.verifyPoppyRequest(sessionRequest(await mint()))).resolves.toStrictEqual({});
    await expect(client.verifyPoppyRequest(sessionRequest('not-a-jwt'))).resolves.toStrictEqual({});

    expect(intercepted).toEqual([]);
  });

  test('verifies the header of a request that requires a Session, through the global fetch', async () => {
    serveAgent();
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));

    expect(result).toStrictEqual(await signedOutResult());
    // The client metadata and the key set of the agent, and no call to Auth0.
    expect(intercepted).toEqual([agent.cimdUrl, agent.jwksUri]);
  });

  test('refuses a header that is malformed, when the request requires a Session', async () => {
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });
    const jwt = await mint();

    const error = await rejectionOf(
      client.verifyPoppyRequest(request({ 'poppy-session': [jwt, jwt] }, { requireSession: true }))
    );

    expectInvalidSession(error, 'malformed_session');
    expect(intercepted).toEqual([]);
  });

  test('builds the caches once: a second request does not fetch the agent again', async () => {
    serveAgent();
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));
    await client.verifyPoppyRequest(sessionRequest(await mint({ sid: 'second-sid' }), { requireSession: true }));

    expect(intercepted).toEqual([agent.cimdUrl, agent.jwksUri]);
  });

  test('accepts any agent, because there is no list', async () => {
    serveAgent();
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));

    expect(result.poppy?.agent.cimdUrl).toBe(agent.cimdUrl);
  });

  test('requires the aud to be the issuer of the domain', async () => {
    serveAgent();
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE });

    const error = await rejectionOf(
      client.verifyPoppyRequest(
        sessionRequest(await mint({ aud: 'https://other.auth0.com/' }), { requireSession: true })
      )
    );

    expectInvalidSession(error, 'claim_mismatch', { cause: 'aud' });
  });

  test('uses the customFetch of the client for the agent, as it was when the client was built', async () => {
    const options: ApiClientOptions = { domain: DOMAIN, audience: AUDIENCE, customFetch: agent.fetch };
    const client = new ApiClient(options);
    const changedFetch = vi.fn<typeof fetch>(async () => {
      throw new Error('The changed fetch must not be used.');
    });

    // The options are first used by the request below, so this change comes before they are resolved.
    options.customFetch = changedFetch;
    const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));

    expect(result).toStrictEqual(await signedOutResult());
    expect(changedFetch).not.toHaveBeenCalled();
    expect(intercepted).toEqual([]);
  });

  test('uses the global fetch when the client has no customFetch, and not one set later', async () => {
    serveAgent();
    const options: ApiClientOptions = { domain: DOMAIN, audience: AUDIENCE };
    const client = new ApiClient(options);
    const laterFetch = vi.fn<typeof fetch>(async () => {
      throw new Error('A fetch that was set later must not be used.');
    });

    options.customFetch = laterFetch;
    const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));

    expect(result).toStrictEqual(await signedOutResult());
    expect(laterFetch).not.toHaveBeenCalled();
    expect(intercepted).toEqual([agent.cimdUrl, agent.jwksUri]);
  });

  test('behaves the same with an empty poppy option', async () => {
    serveAgent();
    const client = new ApiClient({ domain: DOMAIN, audience: AUDIENCE, poppy: {} });

    await expect(client.verifyPoppyRequest(sessionRequest(await mint()))).resolves.toStrictEqual({});
    expect(intercepted).toEqual([]);
    const result = await client.verifyPoppyRequest(sessionRequest(await mint(), { requireSession: true }));

    expect(result).toStrictEqual(await signedOutResult());
    expect(intercepted).toEqual([agent.cimdUrl, agent.jwksUri]);
  });
});

describe('ApiClient.verifyPoppyRequest | the types of the overloads', () => {
  // These functions are never called. They only let the compiler choose an overload for each call, and
  // `npm run typecheck` checks the result.
  const strict = (client: ApiClient) =>
    client.verifyPoppyRequest({ method: 'GET', url: CART_URL, headers: {}, requireSession: true });
  const plain = (client: ApiClient) => client.verifyPoppyRequest({ method: 'GET', url: CART_URL, headers: {} });
  const notRequired = (client: ApiClient) =>
    client.verifyPoppyRequest({ method: 'GET', url: CART_URL, headers: {}, requireSession: false });
  const unknown = (client: ApiClient, requireSession: boolean) =>
    client.verifyPoppyRequest({ method: 'GET', url: CART_URL, headers: {}, requireSession });
  const prepared = (client: ApiClient, options: VerifyPoppyRequestOptions) => client.verifyPoppyRequest(options);

  const strictKey = async (client: ApiClient): Promise<string> => {
    const { poppy } = await client.verifyPoppyRequest({
      method: 'GET',
      url: CART_URL,
      headers: {},
      requireSession: true,
    });
    return poppy.key;
  };

  const plainKey = async (client: ApiClient): Promise<string> => {
    const { poppy } = await client.verifyPoppyRequest({ method: 'GET', url: CART_URL, headers: {} });
    // @ts-expect-error Without requireSession: true, `poppy` can be undefined.
    return poppy.key;
  };

  test('types poppy as present for a call with requireSession: true', () => {
    expectTypeOf(strict).returns.resolves.toEqualTypeOf<VerifiedPoppyRequest & { poppy: PoppySession }>();
    expectTypeOf(strictKey).returns.resolves.toBeString();

    expect(typeof strict).toBe('function');
  });

  test('types poppy as optional for every other call', () => {
    expectTypeOf(plain).returns.resolves.toEqualTypeOf<VerifiedPoppyRequest>();
    expectTypeOf(notRequired).returns.resolves.toEqualTypeOf<VerifiedPoppyRequest>();
    expectTypeOf(unknown).returns.resolves.toEqualTypeOf<VerifiedPoppyRequest>();
    expectTypeOf(prepared).returns.resolves.toEqualTypeOf<VerifiedPoppyRequest>();
    expectTypeOf(plainKey).returns.resolves.toBeString();
    expectTypeOf<VerifiedPoppyRequest['poppy']>().toEqualTypeOf<PoppySession | undefined>();

    expect(typeof plain).toBe('function');
  });

  test('has a result with a poppy at run time whenever the type says so', async () => {
    const client = createClient();

    const result = await client.verifyPoppyRequest({ ...sessionRequest(await mint()), requireSession: true });

    expect(result.poppy.key).toBe(KEY_OF_DEFAULT_AGENT_AND_SID);
  });
});
