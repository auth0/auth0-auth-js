import type { JWK } from 'jose';
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';

import { rejectionOf } from '../test-utils/poppy.js';
import type { InvalidSessionReason } from '../types.js';
import { AgentMetadataFetcher } from './agent-metadata.js';
import { DEFAULT_RETRY_AFTER_SECONDS, FAILED_FETCH_CACHE_MS, UNKNOWN_KID_REFETCH_INTERVAL_MS } from './constants.js';
import { InvalidSessionError, PoppyUnavailableError } from './errors.js';
import type { ResolvedPoppyOptions } from './options.js';
import { createTestAgent, type TestAgent } from './testing/test-agent.js';

const CIMD_URL = 'https://agent.example/agent.json';
const JWKS_URI = 'https://agent.example/jwks.json';
const OTHER_CIMD_URL = 'https://other.example/agent.json';
const OTHER_JWKS_URI = 'https://other.example/jwks.json';
const TTL_MS = 600_000;
// The public part of the key in RFC 7515, appendix A.3. The tests do not verify anything with it.
const PUBLIC_KEY: JWK = {
  kty: 'EC',
  crv: 'P-256',
  kid: 'key-1',
  alg: 'ES256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};
const ROTATED_KEY: JWK = { ...PUBLIC_KEY, kid: 'key-2' };
// The private members of RFC 7518 section 6, then `oth` of a multi-prime RSA key and `priv` of an AKP key.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth', 'priv'];
const START = Date.UTC(2026, 10, 6, 12, 0, 0);
const JWKS_INVALID_MESSAGE =
  "The agent's key set must have 1 to 100 keys. " +
  'Each key needs a kty, and its members must be strings, booleans, numbers or arrays of strings.';

type FetcherOptions = ResolvedPoppyOptions['agentMetadata'];
type Handler = (url: string, init: RequestInit | undefined) => Response | Promise<Response>;

interface FetchCall {
  /** What the fetcher passed as the first argument, as it was passed. */
  input: RequestInfo | URL;
  /** The same, as text. */
  url: string;
  init: RequestInit | undefined;
  /** What `this` was inside the call. A plain function call leaves it `undefined`. */
  receiver: unknown;
}

let agent: TestAgent;

beforeAll(async () => {
  agent = await createTestAgent({ cimdUrl: CIMD_URL });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// Pins `Date` only: the cache clock moves, and the timers of the runtime keep working.
function pinClock(): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
}

function advance(milliseconds: number): void {
  vi.setSystemTime(Date.now() + milliseconds);
}

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' }, ...init });
}

function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** The documents of an agent, built for any metadata URL the way the test agent builds them. */
function documentsOf(
  cimdUrl: string,
  keys: unknown[] = [PUBLIC_KEY]
): { metadata: Record<string, unknown>; jwks: unknown } {
  const jwksUri = new URL('/jwks.json', cimdUrl).href;
  return {
    metadata: {
      client_id: cimdUrl,
      client_name: 'Test Agent',
      jwks_uri: jwksUri,
      token_endpoint_auth_method: 'private_key_jwt',
    },
    jwks: { keys },
  };
}

interface Answers {
  metadata?: () => Response | Promise<Response>;
  jwks?: () => Response | Promise<Response>;
}

/** An agent at `CIMD_URL` that answers like a healthy host, except where `answers` says otherwise. */
function agentHandler(answers: Answers = {}): Handler {
  const documents = documentsOf(CIMD_URL);
  return (url) => {
    if (url === CIMD_URL) {
      return (answers.metadata ?? (() => json(documents.metadata)))();
    }
    if (url === JWKS_URI) {
      return (answers.jwks ?? (() => json(documents.jwks)))();
    }
    return new Response('not found', { status: 404 });
  };
}

/** Healthy hosts for several agents, each with the one key given. */
function agentsHandler(...cimdUrls: string[]): Handler {
  const byUrl = new Map<string, unknown>();
  for (const cimdUrl of cimdUrls) {
    const documents = documentsOf(cimdUrl);
    byUrl.set(cimdUrl, documents.metadata);
    byUrl.set(new URL('/jwks.json', cimdUrl).href, documents.jwks);
  }
  return (url) => (byUrl.has(url) ? json(byUrl.get(url)) : new Response('not found', { status: 404 }));
}

/** An agent whose key set is `keys`. */
function keySetHandler(keys: unknown): Handler {
  return agentHandler({ jwks: () => json({ keys }) });
}

/** An agent whose metadata is `metadata`. */
function metadataHandler(metadata: unknown): Handler {
  return agentHandler({ metadata: () => json(metadata) });
}

/** An agent whose key set is the JSON `text`, written by hand, for what `JSON.stringify` cannot write. */
function keySetTextHandler(text: string): Handler {
  return agentHandler({ jwks: () => new Response(text, { status: 200 }) });
}

/** `count` public keys that differ in their `kid`. */
function manyKeys(count: number): JWK[] {
  return Array.from({ length: count }, (_, index) => ({ ...PUBLIC_KEY, kid: `key-${index}` }));
}

function recordCalls(handler: Handler): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  // A `function` and not an arrow function, so `this` shows how the fetcher called it.
  const recording = async function (this: unknown, input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push({ input, url, init, receiver: this });
    return handler(url, init);
  };
  return { fetch: recording as typeof fetch, calls };
}

function createFetcher(handler: Handler = agentHandler(), overrides: Partial<FetcherOptions> = {}) {
  const { fetch, calls } = recordCalls(handler);
  const options: FetcherOptions = {
    fetch,
    ttlMs: TTL_MS,
    maxEntries: 100,
    timeoutMs: 5000,
    maxBytes: 65_536,
    allowPrivateAddresses: false,
    ...overrides,
  };
  return { fetcher: new AgentMetadataFetcher(options), calls };
}

/** A problem with the agent that no new try fixes: a 400 `invalid_session`. */
async function expectInvalid(
  promise: Promise<unknown>,
  cause: string | readonly string[],
  reason: InvalidSessionReason = 'agent_metadata_invalid'
): Promise<InvalidSessionError> {
  const error = await rejectionOf(promise);

  expect(error).toBeInstanceOf(InvalidSessionError);
  const invalid = error as InvalidSessionError;
  expect(invalid.reason).toBe(reason);
  expect(invalid.code).toBe('invalid_session');
  expect(invalid.statusCode).toBe(400);
  if (typeof cause === 'string') {
    expect(invalid.cause).toEqual({ code: cause });
  } else {
    // A list is for a body that two runtimes refuse for different causes.
    expect(cause.map((code) => ({ code }))).toContainEqual(invalid.cause);
  }
  return invalid;
}

// What a key set with a member nested 5,000 deep is refused for. Node parses it, and the key check refuses the member.
// The `JSON.parse` of Bun stops at a smaller depth, so there the body is refused as text that is not JSON. It is
// refused before any copy, either way.
const DEEP_MEMBER_CAUSES = ['jwks_invalid', 'metadata_not_json'] as const;

/**
 * A problem that may pass: a 503 with a `Retry-After`. A failure that was just fetched says the default. One that was
 * remembered says the seconds that are left of the time it is remembered, and the test gives them as `retryAfter`.
 */
async function expectUnavailable(
  promise: Promise<unknown>,
  cause: string,
  retryAfter: number = DEFAULT_RETRY_AFTER_SECONDS
): Promise<PoppyUnavailableError> {
  const error = await rejectionOf(promise);

  expect(error).toBeInstanceOf(PoppyUnavailableError);
  const unavailable = error as PoppyUnavailableError;
  expect(unavailable.code).toBe('temporarily_unavailable');
  expect(unavailable.statusCode).toBe(503);
  expect(unavailable.retryAfter).toBe(retryAfter);
  expect(unavailable.headers).toEqual({ 'retry-after': String(retryAfter) });
  expect(unavailable.cause).toEqual({ code: cause });
  return unavailable;
}

function urlsOf(calls: FetchCall[]): string[] {
  return calls.map((call) => call.url);
}

function initOf(call: FetchCall | undefined): RequestInit {
  if (call?.init === undefined) {
    throw new Error('Expected a call with an init.');
  }
  return call.init;
}

interface BodyWatch {
  pulls: number;
  cancels: number;
  hooks: { onPull: () => void; onCancel: () => void };
}

/** Counts how often a body stream is read from, and how often it is cancelled. */
function watchBody(): BodyWatch {
  const watch: BodyWatch = {
    pulls: 0,
    cancels: 0,
    hooks: {
      onPull: () => {
        watch.pulls += 1;
      },
      onCancel: () => {
        watch.cancels += 1;
      },
    },
  };
  return watch;
}

// The bodies below have a high water mark of 0, so nothing is pulled until something reads.
function chunkedBody(chunks: Uint8Array[], watch: BodyWatch = watchBody()): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        watch.hooks.onPull();
        const chunk = chunks[index];
        index += 1;
        if (chunk === undefined) {
          controller.close();
        } else {
          controller.enqueue(chunk);
        }
      },
      cancel: watch.hooks.onCancel,
    },
    { highWaterMark: 0 }
  );
}

/**
 * `count` chunks with no byte in them, for `chunkedBody`. A read loop that only meets chunks like these runs at the
 * speed of microtasks, and nothing else can run in between, not even a timer. So a test uses a count that ends: a
 * fetcher that does not stop on its own reads to the end and fails the test, where an endless body would hang it.
 */
function emptyChunks(count: number): Uint8Array[] {
  return Array.from({ length: count }, () => new Uint8Array(0));
}

/**
 * A body that gives `chunk` on every read, for `maxReads` reads, and then ends. It is endless for the limits of these
 * tests. A fetcher that does not stop at its limit reads it to the end and fails the test, where a body that never ends
 * would keep it in a loop that nothing can interrupt.
 */
function endlessBody(chunk: Uint8Array, watch: BodyWatch, maxReads = 200): ReadableStream<Uint8Array> {
  let reads = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        watch.hooks.onPull();
        reads += 1;
        if (reads > maxReads) {
          controller.close();
        } else {
          controller.enqueue(chunk);
        }
      },
      cancel: watch.hooks.onCancel,
    },
    { highWaterMark: 0 }
  );
}

/**
 * A body whose source reuses one buffer for every chunk it gives, as a transport with a pool of buffers does: the bytes
 * of a chunk are good until the next read, and not longer. A reader that keeps the chunks, and not their bytes, ends up
 * with the last chunk as many times as there were reads.
 */
function pooledBody(bytes: Uint8Array, chunkSize: number, watch: BodyWatch): ReadableStream<Uint8Array> {
  const pool = new Uint8Array(chunkSize);
  let offset = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        watch.hooks.onPull();
        if (offset >= bytes.byteLength) {
          controller.close();
          return;
        }
        const piece = bytes.subarray(offset, offset + chunkSize);
        offset += piece.byteLength;
        // What the last chunk held is gone: a reader that still has that chunk sees the new bytes in it.
        pool.fill(0);
        pool.set(piece);
        controller.enqueue(pool.subarray(0, piece.byteLength));
      },
      cancel: watch.hooks.onCancel,
    },
    { highWaterMark: 0 }
  );
}

/** One chunk for each byte of `bytes`. */
function oneByteChunks(bytes: Uint8Array): Uint8Array[] {
  return Array.from(bytes, (byte) => Uint8Array.of(byte));
}

/** A body that is open and never gives a byte: the headers came and the rest does not. */
function stalledBody(watch: BodyWatch): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>(
    {
      pull() {
        watch.hooks.onPull();
        return new Promise<void>(() => undefined);
      },
      cancel: watch.hooks.onCancel,
    },
    { highWaterMark: 0 }
  );
}

/**
 * A response whose `body` is `stream` itself. A runtime can wrap the stream that `new Response` is given, so this keeps
 * what a test counts, the reads and the cancels, on the stream that the fetcher really reads.
 */
function withStream(stream: ReadableStream<Uint8Array>, init: ResponseInit = { status: 200 }): Response {
  const response = new Response(null, init);
  Object.defineProperty(response, 'body', { value: stream });
  return response;
}

function opaqueRedirect(): Response {
  const response = new Response(null, { status: 200 });
  Object.defineProperty(response, 'type', { value: 'opaqueredirect' });
  Object.defineProperty(response, 'status', { value: 0 });
  return response;
}

describe('AgentMetadataFetcher', () => {
  describe('getKeys for a valid agent', () => {
    test('returns the URLs and the keys of the agent, and serves the second call from the cache', async () => {
      const { fetcher, calls } = createFetcher((url) => agent.fetch(url));

      const first = await fetcher.getKeys(CIMD_URL);
      const second = await fetcher.getKeys(CIMD_URL);

      expect(first).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: agent.jwks.keys });
      expect(second).toEqual(first);
      // The metadata and then the key set, and nothing for the second call.
      expect(urlsOf(calls)).toEqual([CIMD_URL, JWKS_URI]);
    });

    test('makes two fetch calls for five calls that run together', async () => {
      const { fetcher, calls } = createFetcher((url) => agent.fetch(url));

      const results = await Promise.all(Array.from({ length: 5 }, () => fetcher.getKeys(CIMD_URL)));

      expect(calls).toHaveLength(2);
      for (const result of results) {
        expect(result).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: agent.jwks.keys });
      }
    });

    test('loads each agent once, even when different agents are loaded together', async () => {
      const { fetcher, calls } = createFetcher(agentsHandler(CIMD_URL, OTHER_CIMD_URL));

      await Promise.all([
        fetcher.getKeys(CIMD_URL),
        fetcher.getKeys(OTHER_CIMD_URL),
        fetcher.getKeys(CIMD_URL),
        fetcher.getKeys(OTHER_CIMD_URL),
      ]);

      expect(urlsOf(calls).sort()).toEqual([CIMD_URL, JWKS_URI, OTHER_CIMD_URL, OTHER_JWKS_URI].sort());
    });

    test('asks for each document with GET, redirect manual, a signal and an accept header only', async () => {
      const { fetcher, calls } = createFetcher((url) => agent.fetch(url));

      await fetcher.getKeys(CIMD_URL);

      expect(calls).toHaveLength(2);
      for (const call of calls) {
        const init = initOf(call);
        expect(Object.keys(init).sort()).toEqual(['headers', 'method', 'redirect', 'signal']);
        expect(init.method).toBe('GET');
        expect(init.redirect).toBe('manual');
        // No cookie, no authorization and no other header, and no `credentials`.
        expect(init.headers).toEqual({ accept: 'application/json' });
        expect(init).not.toHaveProperty('credentials');
        expect(init.signal).toBeInstanceOf(AbortSignal);
      }
      // Each document has a time limit of its own.
      expect(initOf(calls[0]).signal).not.toBe(initOf(calls[1]).signal);
    });

    test('passes the URL as a string, as the agent wrote it', async () => {
      const { fetcher, calls } = createFetcher(agentsHandler('https://agent.example:8443/a/b.json'));

      await fetcher.getKeys('https://agent.example:8443/a/b.json');

      expect(urlsOf(calls)).toEqual(['https://agent.example:8443/a/b.json', 'https://agent.example:8443/jwks.json']);
      expect(calls.map((call) => typeof call.input)).toEqual(['string', 'string']);
    });

    test('calls fetch as a plain function, with no receiver', async () => {
      const { fetcher, calls } = createFetcher((url) => agent.fetch(url));

      await fetcher.getKeys(CIMD_URL);

      expect(calls.map((call) => call.receiver)).toEqual([undefined, undefined]);
    });

    test('returns copies of the keys, so a caller cannot change what the cache holds', async () => {
      const key = { ...PUBLIC_KEY, key_ops: ['verify'], x5c: ['MIIB'] };
      const { fetcher, calls } = createFetcher(keySetHandler([key]));
      const pristine = structuredClone({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [key] });

      // The first call loads, and the second one is served from the cache. Neither may hand out what the cache holds.
      const first = await fetcher.getKeys(CIMD_URL);
      const [firstKey] = first.keys;
      firstKey!.kid = 'changed';
      (firstKey!.x5c as string[]).push('extra');
      (firstKey!.key_ops as string[]).length = 0;
      first.keys.push({ kty: 'EC' });
      first.keys.length = 1;
      first.jwksUri = 'https://changed.example/';
      const second = await fetcher.getKeys(CIMD_URL);
      const [secondKey] = second.keys;
      expect(second).toEqual(pristine);
      secondKey!.kid = 'changed again';
      (secondKey!.x5c as string[]).length = 0;
      second.keys.length = 0;
      second.cimdUrl = 'https://changed.example/agent.json';
      const third = await fetcher.getKeys(CIMD_URL);

      expect(third).toEqual(pristine);
      expect(second.keys).not.toBe(first.keys);
      expect(third.keys[0]).not.toBe(secondKey);
      expect(third).not.toBe(second);
      expect(calls).toHaveLength(2);
    });

    test('copies the keys without structuredClone, which recurses and throws on data that is too deep', async () => {
      const clone = vi.spyOn(globalThis, 'structuredClone');
      const { fetcher } = createFetcher(keySetHandler([{ ...PUBLIC_KEY, key_ops: ['verify'], x5c: ['MIIB'] }]));

      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(CIMD_URL);
      await fetcher.refreshKeys(CIMD_URL);

      expect(clone).not.toHaveBeenCalled();
    });

    test('returns copies to calls that run together', async () => {
      const { fetcher } = createFetcher();

      const [first, second] = await Promise.all([fetcher.getKeys(CIMD_URL), fetcher.getKeys(CIMD_URL)]);

      expect(first).toEqual(second);
      expect(first!.keys).not.toBe(second!.keys);
      expect(first!.keys[0]).not.toBe(second!.keys[0]);
    });

    test('keeps every member of every key, and keys of any type', async () => {
      const keys = [
        PUBLIC_KEY,
        { kty: 'RSA', n: 'abc', e: 'AQAB', kid: 'rsa', use: 'sig' },
        { kty: 'OKP', crv: 'Ed25519', x: 'abc' },
      ];
      const { fetcher } = createFetcher(keySetHandler(keys));

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual(keys);
    });

    test('accepts a key set on the same host with another port, and returns its URL', async () => {
      const documents = documentsOf(CIMD_URL);
      const { fetcher, calls } = createFetcher((url) =>
        url === CIMD_URL
          ? json({ ...documents.metadata, jwks_uri: 'https://agent.example:8443/keys.json' })
          : json(documents.jwks)
      );

      const keys = await fetcher.getKeys(CIMD_URL);

      expect(keys.jwksUri).toBe('https://agent.example:8443/keys.json');
      expect(urlsOf(calls)).toEqual([CIMD_URL, 'https://agent.example:8443/keys.json']);
    });

    test('ignores the other members of the metadata and of the key set', async () => {
      const documents = documentsOf(CIMD_URL);
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () =>
            json({
              ...documents.metadata,
              redirect_uris: ['https://agent.example/cb'],
              extra: { a: [1] },
              keys: [{ kty: 'EC', kid: 'decoy' }],
            }),
          jwks: () => json({ keys: [PUBLIC_KEY], other: 'ignored' }),
        })
      );

      expect(await fetcher.getKeys(CIMD_URL)).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [PUBLIC_KEY] });
    });

    test('decodes a character that is split between two chunks', async () => {
      const documents = documentsOf(CIMD_URL);
      const bytes = bytesOf(JSON.stringify({ ...documents.metadata, client_name: 'Agent é' }));
      const split = bytes.indexOf(0xc3) + 1;
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () => new Response(chunkedBody([bytes.slice(0, split), bytes.slice(split)]), { status: 200 }),
        })
      );

      expect((await fetcher.getKeys(CIMD_URL)).jwksUri).toBe(JWKS_URI);
    });

    test('accepts a body without a content-length, and a content-length that cannot be read', async () => {
      const documents = documentsOf(CIMD_URL);
      for (const contentLength of ['abc', '-5', '10, 10', '1e9', '']) {
        const { fetcher } = createFetcher(
          agentHandler({ metadata: () => json(documents.metadata, { headers: { 'content-length': contentLength } }) })
        );

        expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      }
    });

    test('reads its options when it is built, and never again', async () => {
      const { fetch, calls } = recordCalls(agentHandler());
      const options: FetcherOptions = {
        fetch,
        ttlMs: TTL_MS,
        maxEntries: 100,
        timeoutMs: 5000,
        maxBytes: 65_536,
        allowPrivateAddresses: false,
      };
      const fetcher = new AgentMetadataFetcher(options);

      options.allowPrivateAddresses = true;
      options.maxBytes = 1;
      options.fetch = () => Promise.reject(new Error('replaced'));
      await expectInvalid(
        fetcher.getKeys('https://localhost/agent.json'),
        'agent_address_not_allowed',
        'agent_not_allowed'
      );
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(2);
    });
  });

  describe('getKeys and the agent URL', () => {
    test.each([
      ['localhost', 'https://localhost/agent.json'],
      ['localhost with a port', 'https://localhost:8443/agent.json'],
      ['localhost with a trailing dot', 'https://localhost./agent.json'],
      ['a name under .localhost', 'https://app.localhost/agent.json'],
      ['a private IPv4 address', 'https://10.0.0.1/agent.json'],
      ['a private IPv4 address of 192.168/16', 'https://192.168.1.10/agent.json'],
      ['the loopback IPv4 address', 'https://127.0.0.1/agent.json'],
      ['the address of cloud metadata services', 'https://169.254.169.254/agent.json'],
      ['the IPv6 loopback address', 'https://[::1]/agent.json'],
      ['an IPv6 unique local address', 'https://[fd00::1]/agent.json'],
      ['an IPv6 link-local address', 'https://[fe80::1]/agent.json'],
      ['an IPv4-mapped IPv6 address of a private IPv4 address', 'https://[::ffff:a00:1]/agent.json'],
      ['a name with no dot', 'https://vault/agent.json'],
      ['a name with no dot and a port', 'https://vault:8200/agent.json'],
      ['a name with no dot and a trailing dot', 'https://vault./agent.json'],
      ['a name under .local', 'https://printer.local/agent.json'],
      ['a name under .internal', 'https://metadata.google.internal/agent.json'],
      ['a name under .localdomain', 'https://localhost.localdomain/agent.json'],
      ['a name under .home.arpa', 'https://printer.home.arpa/agent.json'],
    ])('refuses %s, and makes no fetch call', async (_label, url) => {
      const { fetcher, calls } = createFetcher();

      const error = await expectInvalid(fetcher.getKeys(url), 'agent_address_not_allowed', 'agent_not_allowed');

      expect(error.message).toBe("The agent's URL is on localhost or on a private, loopback or link-local address.");
      expect(calls).toHaveLength(0);
    });

    test.each<[string, unknown]>([
      ['an http URL', 'http://agent.example/agent.json'],
      ['credentials', 'https://user:secret@agent.example/agent.json'],
      ['a fragment', 'https://agent.example/agent.json#keys'],
      ['an empty fragment', 'https://agent.example/agent.json#'],
      ['an upper-case host', 'https://Agent.example/agent.json'],
      ['no path', 'https://agent.example'],
      ['a default port', 'https://agent.example:443/agent.json'],
      ['an IPv4 address written as a number', 'https://2130706433/agent.json'],
      ['text that is not a URL', 'agent.example/agent.json'],
      ['an empty string', ''],
      ['a URL over the length limit', `https://agent.example/${'a'.repeat(2048)}`],
      ['a number', 42],
      ['undefined', undefined],
      ['an object', { href: CIMD_URL }],
    ])('refuses %s, and makes no fetch call, even with private addresses allowed', async (_label, url) => {
      const { fetcher, calls } = createFetcher(agentHandler(), { allowPrivateAddresses: true });

      const error = await expectInvalid(fetcher.getKeys(url as string), 'agent_url_invalid', 'agent_not_allowed');

      expect(error.message).toBe(
        'The agent URL must be an https URL in canonical form, without credentials or a fragment.'
      );
      expect(calls).toHaveLength(0);
    });

    test('checks the address when it loads an agent, on every call, and does not cache the refusal', async () => {
      const { fetcher, calls } = createFetcher();

      await expectInvalid(
        fetcher.getKeys('https://10.0.0.1/agent.json'),
        'agent_address_not_allowed',
        'agent_not_allowed'
      );
      await expectInvalid(
        fetcher.getKeys('https://10.0.0.1/agent.json'),
        'agent_address_not_allowed',
        'agent_not_allowed'
      );

      expect(calls).toHaveLength(0);
    });

    test('lets an agent on localhost through when private addresses are allowed', async () => {
      const localAgent = await createTestAgent({ cimdUrl: 'https://localhost:8443/agent.json' });
      const { fetcher, calls } = createFetcher((url) => localAgent.fetch(url), { allowPrivateAddresses: true });

      const keys = await fetcher.getKeys('https://localhost:8443/agent.json');

      expect(keys).toEqual({
        cimdUrl: 'https://localhost:8443/agent.json',
        jwksUri: 'https://localhost:8443/jwks.json',
        keys: localAgent.jwks.keys,
      });
      expect(calls).toHaveLength(2);
    });

    test.each([
      'https://10.0.0.1/agent.json',
      'https://[::1]/agent.json',
      'https://127.0.0.1:8443/agent.json',
      'https://vault:8200/agent.json',
      'https://printer.local/agent.json',
      'https://metadata.google.internal/agent.json',
      'https://localhost.localdomain/agent.json',
      'https://printer.home.arpa/agent.json',
    ])('fetches %s when private addresses are allowed', async (url) => {
      const { fetcher, calls } = createFetcher(() => new Response('', { status: 404 }), {
        allowPrivateAddresses: true,
      });

      await expectInvalid(fetcher.getKeys(url), 'metadata_status');

      expect(urlsOf(calls)).toEqual([url]);
    });

    test('still keeps the key set on the host of the agent when private addresses are allowed', async () => {
      const documents = documentsOf('https://localhost:8443/agent.json');
      const { fetcher, calls } = createFetcher(
        (url) =>
          url === 'https://localhost:8443/agent.json'
            ? json({ ...documents.metadata, jwks_uri: 'https://127.0.0.1:8443/jwks.json' })
            : json(documents.jwks),
        { allowPrivateAddresses: true }
      );

      await expectInvalid(fetcher.getKeys('https://localhost:8443/agent.json'), 'jwks_uri_invalid');

      expect(calls).toHaveLength(1);
    });
  });

  describe('getKeys and the response of the host', () => {
    test.each([300, 301, 302, 303, 304, 307, 308, 399])(
      'refuses a redirect with status %i, and does not follow it',
      async (status) => {
        const { fetcher, calls } = createFetcher(
          agentHandler({
            metadata: () => new Response(null, { status, headers: { location: 'https://10.9.8.7/steal' } }),
          })
        );

        const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_redirect');

        expect(error.message).toBe("The agent's metadata redirected; redirects aren't followed.");
        expect(urlsOf(calls)).toEqual([CIMD_URL]);
      }
    );

    test('refuses an opaque redirect, which a runtime with manual redirects can give', async () => {
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: opaqueRedirect }));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_redirect');

      expect(calls).toHaveLength(1);
    });

    test.each([301, 302, 307])('refuses a redirect of the key set with status %i', async (status) => {
      const { fetcher, calls } = createFetcher(
        agentHandler({
          jwks: () => new Response(null, { status, headers: { location: 'https://other.example/jwks.json' } }),
        })
      );

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_redirect');

      expect(error.message).toBe("The agent's key set redirected; redirects aren't followed.");
      expect(urlsOf(calls)).toEqual([CIMD_URL, JWKS_URI]);
    });

    test('refuses an opaque redirect of the key set', async () => {
      const { fetcher } = createFetcher(agentHandler({ jwks: opaqueRedirect }));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_redirect');
    });

    test.each([400, 401, 403, 404, 410, 201, 202, 204, 206])(
      'refuses status %i as a problem with the agent',
      async (status) => {
        const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response(null, { status }) }));

        const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_status');

        expect(error.message).toBe("The agent's metadata must be served with status 200.");
        expect(calls).toHaveLength(1);
      }
    );

    test.each([400, 404, 410, 204])('refuses status %i of the key set as a problem with the agent', async (status) => {
      const { fetcher, calls } = createFetcher(agentHandler({ jwks: () => new Response(null, { status }) }));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_status');

      expect(error.message).toBe("The agent's key set must be served with status 200.");
      expect(calls).toHaveLength(2);
    });

    test.each([429, 500, 502, 503, 504, 599])('treats status %i as a host that is down for now', async (status) => {
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response(null, { status }) }));

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');

      expect(calls).toHaveLength(1);
    });

    test.each([429, 500, 503])('treats status %i of the key set as a host that is down for now', async (status) => {
      const { fetcher, calls } = createFetcher(agentHandler({ jwks: () => new Response(null, { status }) }));

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');

      expect(calls).toHaveLength(2);
    });

    test('ignores the Retry-After of the host', async () => {
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => new Response(null, { status: 503, headers: { 'retry-after': '86400' } }) })
      );

      const error = await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');

      expect(error.retryAfter).toBe(DEFAULT_RETRY_AFTER_SECONDS);
    });

    test('does not read the body of a response it refuses, and cancels it', async () => {
      for (const status of [302, 404, 500]) {
        const watch = watchBody();
        const { fetcher } = createFetcher(
          agentHandler({ metadata: () => withStream(endlessBody(bytesOf('x'.repeat(1024)), watch), { status }) })
        );

        await rejectionOf(fetcher.getKeys(CIMD_URL));

        expect(watch).toMatchObject({ pulls: 0, cancels: 1 });
      }
    });

    test('treats a fetch that rejects as a host that is down for now', async () => {
      const { fetcher, calls } = createFetcher(() => Promise.reject(new TypeError('fetch failed')));

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_failed');

      expect(calls).toHaveLength(1);
    });

    test('treats a rejected fetch of the key set as a host that is down for now', async () => {
      const { fetcher } = createFetcher(agentHandler({ jwks: () => Promise.reject(new Error('socket hang up')) }));

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_failed');
    });

    test('treats a fetch that throws at once as a host that is down for now', async () => {
      const { fetcher } = createFetcher(agentHandler(), {
        fetch: () => {
          throw new Error('thrown at once');
        },
      });

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_failed');
    });

    test('treats an answer that is not a response as a host that is down for now', async () => {
      const { fetcher } = createFetcher(agentHandler(), {
        fetch: () => Promise.resolve(undefined as unknown as Response),
      });

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_failed');
    });

    test('treats a body that breaks off as a host that is down for now', async () => {
      const broken = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytesOf('{"client_'));
          controller.error(new Error('connection reset by peer'));
        },
      });
      const { fetcher } = createFetcher(agentHandler({ metadata: () => new Response(broken, { status: 200 }) }));

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_failed');
    });
  });

  describe('getKeys and the time limit', () => {
    test('gives up on a fetch that never answers and ignores its signal', async () => {
      const { fetcher } = createFetcher(() => new Promise<Response>(() => undefined), { timeoutMs: 50 });
      const started = performance.now();

      const error = await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      expect(performance.now() - started).toBeLessThan(1000);
      expect(error.message).toBe("The agent's client metadata or keys can't be fetched right now. Try again later.");
    });

    test('gives up on a key set that never answers', async () => {
      const { fetcher, calls } = createFetcher(agentHandler({ jwks: () => new Promise<Response>(() => undefined) }), {
        timeoutMs: 50,
      });
      const started = performance.now();

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      expect(performance.now() - started).toBeLessThan(1000);
      expect(urlsOf(calls)).toEqual([CIMD_URL, JWKS_URI]);
    });

    test('gives up on a body that never ends after the headers came, and cancels it', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => withStream(stalledBody(watch), { status: 200 }) }),
        {
          timeoutMs: 50,
        }
      );
      const started = performance.now();

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      expect(performance.now() - started).toBeLessThan(1000);
      expect(watch).toMatchObject({ pulls: 1, cancels: 1 });
    });

    test('gives up on a body that starts and then stalls, and cancels it', async () => {
      const watch = watchBody();
      let sent = false;
      const stalling = new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            watch.hooks.onPull();
            if (sent) {
              return new Promise<void>(() => undefined);
            }
            sent = true;
            controller.enqueue(bytesOf('{"client_id":'));
            return undefined;
          },
          cancel: watch.hooks.onCancel,
        },
        { highWaterMark: 0 }
      );
      const { fetcher } = createFetcher(agentHandler({ metadata: () => withStream(stalling, { status: 200 }) }), {
        timeoutMs: 50,
      });

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      expect(watch.cancels).toBe(1);
    });

    test('gives up on a body of the key set that never ends', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(agentHandler({ jwks: () => withStream(stalledBody(watch), { status: 200 }) }), {
        timeoutMs: 50,
      });

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      expect(watch.cancels).toBe(1);
    });

    test('gives up on a body that has no stream and never ends', async () => {
      const response = new Response('{}', { status: 200 });
      Object.defineProperty(response, 'body', { value: null });
      Object.defineProperty(response, 'arrayBuffer', { value: () => new Promise<ArrayBuffer>(() => undefined) });
      const { fetcher } = createFetcher(agentHandler({ metadata: () => response }), { timeoutMs: 50 });

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');
    });

    test('counts the time of a slow response toward the limit of its document', async () => {
      const documents = documentsOf(CIMD_URL);
      const slow = new Promise<Response>((resolve) => setTimeout(() => resolve(json(documents.metadata)), 200));
      const { fetcher } = createFetcher(agentHandler({ metadata: () => slow }), { timeoutMs: 50 });

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');
    });

    test('gives each of the two documents the whole time limit', async () => {
      const documents = documentsOf(CIMD_URL);
      const after = <T>(milliseconds: number, value: T): Promise<T> =>
        new Promise((resolve) => setTimeout(() => resolve(value), milliseconds));
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () => after(300, json(documents.metadata)),
          jwks: () => after(300, json(documents.jwks)),
        }),
        // Each answer takes less than the limit, and the two together take more. A slow runner has 200 ms to spare.
        { timeoutMs: 500 }
      );

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
    });

    test('lets a fetch that honours the signal stop, and reports a timeout', async () => {
      let seen: AbortSignal | null | undefined;
      const { fetcher } = createFetcher(
        (_url, init) =>
          new Promise<Response>((_resolve, reject) => {
            seen = init?.signal;
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('The operation was aborted.', 'AbortError'))
            );
          }),
        { timeoutMs: 30 }
      );

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      expect(seen?.aborted).toBe(true);
    });

    test('cancels the body of a response that arrives after the time limit', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        () =>
          new Promise<Response>((resolve) =>
            setTimeout(() => resolve(withStream(stalledBody(watch), { status: 200 })), 80)
          ),
        { timeoutMs: 20 }
      );

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');

      await vi.waitFor(() => expect(watch).toMatchObject({ pulls: 0, cancels: 1 }));
    });

    test('is not hurt by a fetch that fails after the time limit', async () => {
      const { fetcher } = createFetcher(
        () => new Promise<Response>((_resolve, reject) => setTimeout(() => reject(new Error('late failure')), 80)),
        { timeoutMs: 20 }
      );

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');
      // Time for the late failure to arrive. The run fails if it surfaces as an unhandled rejection.
      await new Promise((resolve) => setTimeout(resolve, 150));
    });

    // The options check the range of timeoutMs (see options.spec.ts), so the fetcher passes the value on as it is.
    test.each([1, 1234, 2_147_483_647])(
      'makes one AbortSignal.timeout of timeoutMs %i for each document, and does not change it',
      async (timeoutMs) => {
        // The spy answers with a signal that does not abort, so a limit of 24 days does not leave a timer behind.
        const timeout = vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => new AbortController().signal);
        const { fetcher } = createFetcher((url) => agent.fetch(url), { timeoutMs });

        await fetcher.getKeys(CIMD_URL);

        expect(timeout.mock.calls).toEqual([[timeoutMs], [timeoutMs]]);
      }
    );

    test('removes its abort listeners when a document is done, so a signal keeps nothing', async () => {
      interface Tracked {
        signal: AbortSignal;
        added: number;
        live: Set<unknown>;
      }
      const tracked: Tracked[] = [];
      vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => {
        const signal = new AbortController().signal;
        const entry: Tracked = { signal, added: 0, live: new Set() };
        const target = signal as unknown as {
          addEventListener: (type: string, listener: unknown, options?: unknown) => void;
          removeEventListener: (type: string, listener: unknown, options?: unknown) => void;
        };
        const add = target.addEventListener.bind(signal);
        const remove = target.removeEventListener.bind(signal);
        target.addEventListener = (type, listener, options) => {
          entry.added += 1;
          entry.live.add(listener);
          add(type, listener, options);
        };
        target.removeEventListener = (type, listener, options) => {
          entry.live.delete(listener);
          remove(type, listener, options);
        };
        tracked.push(entry);
        return signal;
      });
      const success = createFetcher((url) => agent.fetch(url)).fetcher;
      const failure = createFetcher(() => Promise.reject(new Error('down'))).fetcher;
      const throwing = createFetcher(agentHandler(), {
        fetch: () => {
          throw new Error('thrown at once');
        },
      }).fetcher;

      await success.getKeys(CIMD_URL);
      await rejectionOf(failure.getKeys(CIMD_URL));
      await rejectionOf(throwing.getKeys(CIMD_URL));

      // Two signals for the two documents of the success, one for the failure and one for the fetch that threw.
      expect(tracked).toHaveLength(4);
      expect(tracked.map((entry) => entry.added > 0)).toEqual([true, true, true, true]);
      expect(tracked.map((entry) => entry.live.size)).toEqual([0, 0, 0, 0]);
    });
  });

  describe('getKeys and the size limit', () => {
    test('refuses a content-length over the limit, and never reads the body', async () => {
      const watch = watchBody();
      const { fetcher, calls } = createFetcher(
        agentHandler({
          metadata: () =>
            withStream(endlessBody(bytesOf('x'), watch), { status: 200, headers: { 'content-length': '999999' } }),
        })
      );

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(error.message).toBe("The agent's metadata is larger than the size limit.");
      expect(watch).toMatchObject({ pulls: 0, cancels: 1 });
      expect(calls).toHaveLength(1);
    });

    test('refuses a content-length over the limit for the key set too', async () => {
      const { fetcher } = createFetcher(
        agentHandler({ jwks: () => json({ keys: [PUBLIC_KEY] }, { headers: { 'content-length': '70000' } }) })
      );

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(error.message).toBe("The agent's key set is larger than the size limit.");
    });

    test('refuses a content-length too long to be a number the SDK can hold', async () => {
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => json({}, { headers: { 'content-length': '9'.repeat(400) } }) })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');
    });

    test('refuses a streamed body over the limit when there is no content-length, and stops reading', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () => withStream(endlessBody(bytesOf('x'.repeat(10 * 1024)), watch), { status: 200 }),
        })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      // 64 KB is 6.4 chunks of 10 KB, so the seventh chunk is the one that goes over.
      expect(watch).toMatchObject({ pulls: 7, cancels: 1 });
    });

    test('refuses a streamed body of 70 KB in one chunk', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () => withStream(chunkedBody([bytesOf(' '.repeat(70 * 1024))], watch), { status: 200 }),
        })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(watch.cancels).toBe(1);
    });

    test('refuses a body that is longer than its content-length says', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () =>
            withStream(endlessBody(bytesOf('x'.repeat(1024)), watch), {
              status: 200,
              headers: { 'content-length': '10' },
            }),
        })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(watch.cancels).toBe(1);
    });

    test('refuses a streamed body of the key set over the limit', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({ jwks: () => withStream(endlessBody(bytesOf('x'.repeat(4096)), watch), { status: 200 }) })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(watch.cancels).toBe(1);
    });

    test('takes a body of exactly maxBytes, and refuses one byte more', async () => {
      const documents = documentsOf(CIMD_URL);
      const text = JSON.stringify(documents.metadata);
      const maxBytes = 256;
      const padded = (length: number): Uint8Array => bytesOf(text.padEnd(length, ' '));

      const exact = createFetcher(
        agentHandler({
          metadata: () =>
            new Response(chunkedBody([padded(maxBytes).slice(0, 100), padded(maxBytes).slice(100)]), { status: 200 }),
        }),
        { maxBytes }
      );
      expect((await exact.fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      const over = createFetcher(
        agentHandler({
          metadata: () =>
            new Response(chunkedBody([padded(maxBytes + 1).slice(0, 100), padded(maxBytes + 1).slice(100)]), {
              status: 200,
            }),
        }),
        { maxBytes }
      );
      await expectInvalid(over.fetcher.getKeys(CIMD_URL), 'metadata_too_large');
    });

    test('takes a content-length of exactly maxBytes, and refuses one byte more before it reads the body', async () => {
      const documents = documentsOf(CIMD_URL);
      const maxBytes = 256;
      const body = JSON.stringify(documents.metadata).padEnd(maxBytes, ' ');

      const exact = createFetcher(
        agentHandler({
          metadata: () => new Response(body, { status: 200, headers: { 'content-length': String(maxBytes) } }),
        }),
        { maxBytes }
      );
      expect((await exact.fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      const watch = watchBody();
      const over = createFetcher(
        agentHandler({
          metadata: () =>
            withStream(endlessBody(bytesOf('x'), watch), {
              status: 200,
              headers: { 'content-length': String(maxBytes + 1) },
            }),
        }),
        { maxBytes }
      );
      await expectInvalid(over.fetcher.getKeys(CIMD_URL), 'metadata_too_large');
      expect(watch.pulls).toBe(0);
    });

    test('counts bytes and not characters', async () => {
      const documents = documentsOf(CIMD_URL);
      // Each of these characters is two bytes in UTF-8.
      const text = JSON.stringify({ ...documents.metadata, client_name: 'é'.repeat(100) });
      const { fetcher } = createFetcher(agentHandler({ metadata: () => new Response(text, { status: 200 }) }), {
        maxBytes: text.length + 50,
      });

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');
    });

    test('reads a body without a stream whole, and checks its size afterwards', async () => {
      const documents = documentsOf(CIMD_URL);
      const text = JSON.stringify(documents.metadata);
      const withoutStream = (body: string): Response => {
        const response = new Response(body, { status: 200 });
        Object.defineProperty(response, 'body', { value: null });
        return response;
      };
      // The key set is about 190 bytes, so it fits in the limit that the larger metadata does not.
      const maxBytes = 300;

      const fine = createFetcher(agentHandler({ metadata: () => withoutStream(text) }), { maxBytes });
      expect((await fine.fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      const exact = createFetcher(agentHandler({ metadata: () => withoutStream(text.padEnd(maxBytes, ' ')) }), {
        maxBytes,
      });
      expect((await exact.fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      const large = createFetcher(agentHandler({ metadata: () => withoutStream(text.padEnd(maxBytes + 1, ' ')) }), {
        maxBytes,
      });
      const error = await expectInvalid(large.fetcher.getKeys(CIMD_URL), 'metadata_too_large');
      expect(error.message).toBe("The agent's metadata is larger than the size limit.");
      expect(large.calls).toHaveLength(1);
    });
  });

  describe('getKeys with a Response made from a stream', () => {
    test('gives up on a body that never ends', async () => {
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => new Response(stalledBody(watchBody()), { status: 200 }) }),
        { timeoutMs: 50 }
      );

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'fetch_timeout');
    });

    test('refuses a body that never ends and has no content-length', async () => {
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () => new Response(endlessBody(bytesOf('x'.repeat(10 * 1024)), watchBody()), { status: 200 }),
        })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');
    });

    test('refuses an endless body of the key set', async () => {
      const { fetcher } = createFetcher(
        agentHandler({ jwks: () => new Response(endlessBody(bytesOf(' '.repeat(4096)), watchBody()), { status: 200 }) })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');
    });
  });

  describe('getKeys and a body of empty chunks', () => {
    // The fetcher stops a body on its own after this many empty chunks in a row. Nothing else could: a read loop that
    // only meets empty chunks runs at the speed of microtasks, and the timer of the time limit never gets to fire.
    const IN_A_ROW = 1000;

    test('refuses a body of nothing but empty chunks, stops reading it, and settles', async () => {
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => withStream(chunkedBody(emptyChunks(50_000), watch), { status: 200 }) })
      );

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_body_invalid');

      expect(error.message).toBe("The agent's metadata body sent too many empty chunks in a row.");
      expect(watch).toMatchObject({ pulls: IN_A_ROW, cancels: 1 });
    });

    test('refuses a body of empty chunks for the key set too, and says it is the key set', async () => {
      const watch = watchBody();
      const { fetcher, calls } = createFetcher(
        agentHandler({ jwks: () => withStream(chunkedBody(emptyChunks(50_000), watch), { status: 200 }) })
      );

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_body_invalid');

      expect(error.message).toBe("The agent's key set body sent too many empty chunks in a row.");
      expect(watch).toMatchObject({ pulls: IN_A_ROW, cancels: 1 });
      expect(urlsOf(calls)).toEqual([CIMD_URL, JWKS_URI]);
    });

    test('takes one empty chunk less than the limit in a row, and refuses the limit', async () => {
      const document = bytesOf(JSON.stringify(documentsOf(CIMD_URL).metadata));
      const taken = createFetcher(
        agentHandler({
          metadata: () =>
            withStream(chunkedBody([...emptyChunks(IN_A_ROW - 1), document], watchBody()), { status: 200 }),
        })
      );
      expect((await taken.fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      const watch = watchBody();
      const refused = createFetcher(
        agentHandler({
          metadata: () => withStream(chunkedBody([...emptyChunks(IN_A_ROW), document], watch), { status: 200 }),
        })
      );
      await expectInvalid(refused.fetcher.getKeys(CIMD_URL), 'metadata_body_invalid');
      expect(watch.pulls).toBe(IN_A_ROW);
    });

    test('refuses empty chunks that come after the first bytes, too', async () => {
      const document = bytesOf(JSON.stringify(documentsOf(CIMD_URL).metadata));
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () =>
            withStream(chunkedBody([document.slice(0, 10), ...emptyChunks(50_000)], watch), { status: 200 }),
        })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_body_invalid');

      // The chunk with bytes, and then the empty chunks up to the limit.
      expect(watch).toMatchObject({ pulls: 1 + IN_A_ROW, cancels: 1 });
    });

    test('counts the empty chunks that come in a row, and starts again after a chunk with bytes', async () => {
      const document = bytesOf(JSON.stringify(documentsOf(CIMD_URL).metadata));
      const watch = watchBody();
      const body = chunkedBody(
        [
          ...emptyChunks(IN_A_ROW - 1),
          document.slice(0, 10),
          ...emptyChunks(IN_A_ROW - 1),
          document.slice(10, 20),
          ...emptyChunks(IN_A_ROW - 1),
          document.slice(20),
        ],
        watch
      );
      const { fetcher } = createFetcher(agentHandler({ metadata: () => withStream(body, { status: 200 }) }));

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      // The three runs of empty chunks add up to more than the limit, and the body was read to its end.
      expect(watch.pulls).toBe(3 * (IN_A_ROW - 1) + 3 + 1);
      expect(watch.cancels).toBe(0);
    });

    test('remembers the refusal as a failure of the agent, like the other refusals', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher(
        agentHandler({ metadata: () => withStream(chunkedBody(emptyChunks(5000), watchBody()), { status: 200 }) })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_body_invalid');
      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_body_invalid');

      expect(calls).toHaveLength(1);
    });
  });

  describe('getKeys and a body of many small chunks', () => {
    // The key set of an agent whose one key has a `kid` that is a counter text, so that every byte of the body has a
    // place that no other byte has. The JSON is exactly `size` bytes, and it is all ASCII.
    function keySetOfSize(size: number): { bytes: Uint8Array; key: JWK } {
      const base = JSON.stringify({ keys: [{ ...PUBLIC_KEY, kid: '' }] }).length;
      const counter = Array.from({ length: size }, (_, index) => index.toString(36))
        .join('')
        .slice(0, size - base);
      const key: JWK = { ...PUBLIC_KEY, kid: counter };
      const bytes = bytesOf(JSON.stringify({ keys: [key] }));
      expect(bytes.byteLength).toBe(size);
      return { bytes, key };
    }

    test('parses a body of 65,536 one-byte chunks at the default limit, and reads it to its end', async () => {
      const text = JSON.stringify(documentsOf(CIMD_URL).metadata).padEnd(65_536, ' ');
      const bytes = bytesOf(text);
      expect(bytes.byteLength).toBe(65_536);
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => withStream(chunkedBody(oneByteChunks(bytes), watch), { status: 200 }) })
      );

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      // One read for each byte, and one for the end of the body.
      expect(watch).toMatchObject({ pulls: 65_536 + 1, cancels: 0 });
    });

    test('refuses a body that goes over the limit one byte at a time, and stops at the byte that goes over', async () => {
      const maxBytes = 1024;
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () =>
            withStream(chunkedBody(oneByteChunks(bytesOf(' '.repeat(maxBytes + 500))), watch), { status: 200 }),
        }),
        { maxBytes }
      );

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(error.message).toBe("The agent's metadata is larger than the size limit.");
      expect(watch).toMatchObject({ pulls: maxBytes + 1, cancels: 1 });
    });

    test('refuses a key set that goes over the limit one byte at a time, and says it is the key set', async () => {
      const maxBytes = 512;
      const chunks = oneByteChunks(bytesOf(' '.repeat(maxBytes + 1)));
      const { fetcher } = createFetcher(
        agentHandler({ jwks: () => withStream(chunkedBody(chunks, watchBody()), { status: 200 }) }),
        { maxBytes }
      );

      // The metadata is about 150 bytes, so it fits in the limit that the key set does not.
      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

      expect(error.message).toBe("The agent's key set is larger than the size limit.");
    });

    test('does not keep the chunks it reads: a source that reuses one buffer for them gives the right keys', async () => {
      const { bytes, key } = keySetOfSize(40_000);
      const watch = watchBody();
      const { fetcher } = createFetcher(
        agentHandler({ jwks: () => withStream(pooledBody(bytes, 100, watch), { status: 200 }) })
      );

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([key]);

      expect(watch).toMatchObject({ pulls: 400 + 1, cancels: 0 });
    });

    test('does not keep the chunks of a body of one-byte chunks either', async () => {
      const { bytes, key } = keySetOfSize(2000);
      const { fetcher } = createFetcher(
        agentHandler({ jwks: () => withStream(pooledBody(bytes, 1, watchBody()), { status: 200 }) })
      );

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([key]);
    });

    // The buffer starts small and grows as the body comes, and it never grows past the limit. These sizes are on both
    // sides of its first size (16,384 bytes) and of its doublings, and a limit that is not a power of two is one of
    // them.
    test.each<[number, number]>([
      [1000, 65_536],
      [16_383, 65_536],
      [16_384, 65_536],
      [16_385, 65_536],
      [32_768, 65_536],
      [32_769, 65_536],
      [65_535, 65_536],
      [65_536, 65_536],
      [20_000, 20_000],
      [16_385, 16_385],
      [16_384, 16_384],
    ])(
      'takes a body of %i bytes with a limit of %i, in chunks that cross the growth of the buffer',
      async (size, maxBytes) => {
        const { bytes, key } = keySetOfSize(size);
        for (const chunkSize of [700, 16_384, 20_000]) {
          const { fetcher } = createFetcher(
            agentHandler({ jwks: () => withStream(pooledBody(bytes, chunkSize, watchBody()), { status: 200 }) }),
            { maxBytes }
          );

          expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([key]);
        }
      }
    );

    test.each<[number, number]>([
      [20_001, 20_000],
      [16_385, 16_384],
      [65_537, 65_536],
    ])(
      'refuses a body of %i bytes with a limit of %i, in chunks that cross the growth of the buffer',
      async (size, maxBytes) => {
        const bytes = bytesOf(' '.repeat(size));
        for (const chunkSize of [700, 16_384, 20_000]) {
          const watch = watchBody();
          const { fetcher } = createFetcher(
            agentHandler({ jwks: () => withStream(pooledBody(bytes, chunkSize, watch), { status: 200 }) }),
            { maxBytes }
          );

          await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_too_large');

          expect(watch.cancels).toBe(1);
        }
      }
    );

    test('reads a small body when the limit is huge, because the buffer grows with the body and is not sized by the limit', async () => {
      const { fetcher } = createFetcher(agentHandler(), { maxBytes: Number.MAX_SAFE_INTEGER });

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
    });

    test('takes empty chunks between the small ones', async () => {
      const bytes = bytesOf(JSON.stringify(documentsOf(CIMD_URL).metadata));
      const chunks = oneByteChunks(bytes).flatMap((chunk) => [new Uint8Array(0), chunk]);
      const { fetcher } = createFetcher(
        agentHandler({ metadata: () => withStream(chunkedBody(chunks, watchBody()), { status: 200 }) })
      );

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
    });
  });

  describe('getKeys and the body', () => {
    test.each([
      ['text that is not JSON', 'this is not json'],
      ['an empty body', ''],
      ['HTML', '<html><body>Not an agent</body></html>'],
      ['JSON that stops in the middle', '{"client_id": "https://agent.example/agent.json", '],
      ['a JSON array', '[]'],
      ['a JSON array with the metadata in it', `[${JSON.stringify(documentsOf(CIMD_URL).metadata)}]`],
      ['JSON null', 'null'],
      ['a JSON string', '"https://agent.example/agent.json"'],
      ['a JSON number', '42'],
      ['a JSON boolean', 'true'],
      ['two JSON objects', '{}{}'],
      ['a very deep array', `${'['.repeat(20000)}${']'.repeat(20000)}`],
    ])('refuses %s', async (_label, body) => {
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response(body, { status: 200 }) }));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_not_json');

      expect(error.message).toBe("The agent's metadata is not a UTF-8 encoded JSON object.");
      expect(calls).toHaveLength(1);
    });

    test.each<[string, Uint8Array]>([
      ['a byte that is not UTF-8', new Uint8Array([0xff, 0xfe, 0x7b, 0x7d])],
      ['a UTF-8 sequence that stops short', Uint8Array.from([...bytesOf('{"a":"'), 0xc3, ...bytesOf('"}')])],
      ['a byte that is never UTF-8, inside a string', Uint8Array.from([...bytesOf('{"a":"'), 0xff, ...bytesOf('"}')])],
      ['UTF-16 text', new Uint8Array([0x7b, 0x00, 0x7d, 0x00])],
    ])('refuses a body with %s', async (_label, body) => {
      const { fetcher } = createFetcher(agentHandler({ metadata: () => new Response(body, { status: 200 }) }));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_not_json');
    });

    test('refuses a key set that is not JSON, or not an object', async () => {
      for (const body of ['not json', '[]', '"keys"', 'null']) {
        const { fetcher } = createFetcher(agentHandler({ jwks: () => new Response(body, { status: 200 }) }));

        const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_not_json');

        expect(error.message).toBe("The agent's key set is not a UTF-8 encoded JSON object.");
      }
    });

    test('does not mind the content-type of the response', async () => {
      const documents = documentsOf(CIMD_URL);
      const { fetcher } = createFetcher(
        agentHandler({
          metadata: () =>
            new Response(JSON.stringify(documents.metadata), {
              status: 200,
              headers: { 'content-type': 'text/plain' },
            }),
        })
      );

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
    });
  });

  describe('getKeys and the client metadata', () => {
    const documents = documentsOf(CIMD_URL);

    test.each<[string, unknown]>([
      ['another URL', 'https://agent.example/other.json'],
      ['the URL with a slash added', `${CIMD_URL}/`],
      ['the URL in another letter case', 'HTTPS://AGENT.EXAMPLE/agent.json'],
      ['the URL with a query', `${CIMD_URL}?a=1`],
      ['the URL of another host', 'https://other.example/agent.json'],
      ['an array with the URL', [CIMD_URL]],
      ['a number', 42],
      ['null', null],
      ['an empty string', ''],
      ['nothing', undefined],
    ])('refuses a client_id that is %s', async (_label, clientId) => {
      const { fetcher, calls } = createFetcher(metadataHandler({ ...documents.metadata, client_id: clientId }));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'client_id_mismatch');

      expect(error.message).toBe("The client_id in the agent's metadata is not the URL the metadata was fetched from.");
      expect(calls).toHaveLength(1);
    });

    test.each<[string, unknown]>([
      ['an http URL', 'http://agent.example/jwks.json'],
      ['another host', 'https://other.example/jwks.json'],
      ['a subdomain of the host of the agent', 'https://keys.agent.example/jwks.json'],
      ['the host of the agent as the subdomain of another host', 'https://agent.example.other.example/jwks.json'],
      ['the host of the agent with a trailing dot', 'https://agent.example./jwks.json'],
      ['127.0.0.1', 'https://127.0.0.1/jwks.json'],
      ['localhost', 'https://localhost/jwks.json'],
      ['the address of cloud metadata services', 'https://169.254.169.254/latest/meta-data/'],
      ['credentials', 'https://user:secret@agent.example/jwks.json'],
      ['a fragment', 'https://agent.example/jwks.json#keys'],
      ['an upper-case host', 'https://AGENT.example/jwks.json'],
      ['a URL with no scheme', '//agent.example/jwks.json'],
      ['a path without a host', '/jwks.json'],
      ['an empty string', ''],
      ['a URL over the length limit', `https://agent.example/${'a'.repeat(2048)}`],
      ['a number', 42],
      ['null', null],
      ['an array with the URL', [JWKS_URI]],
      ['an object', { href: JWKS_URI }],
      ['nothing', undefined],
    ])('refuses a jwks_uri that is %s, and does not fetch it', async (_label, jwksUri) => {
      const { fetcher, calls } = createFetcher(metadataHandler({ ...documents.metadata, jwks_uri: jwksUri }));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_uri_invalid');

      expect(error.message).toBe(
        "The jwks_uri in the agent's metadata must be an https URL on the same host as its client_id."
      );
      expect(urlsOf(calls)).toEqual([CIMD_URL]);
    });

    test('checks the client_id before the jwks_uri', async () => {
      const { fetcher } = createFetcher(
        metadataHandler({ ...documents.metadata, client_id: 'https://x.example/', jwks_uri: 42 })
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'client_id_mismatch');
    });
  });

  describe('getKeys and the key set', () => {
    test.each<[string, unknown]>([
      ['nothing', undefined],
      ['an empty array', []],
      ['null', null],
      ['a string', 'keys'],
      ['an object', { 0: PUBLIC_KEY, length: 1 }],
      ['a number', 1],
    ])('refuses keys that is %s', async (_label, keys) => {
      const { fetcher } = createFetcher(keySetHandler(keys));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_invalid');

      expect(error.message).toBe(JWKS_INVALID_MESSAGE);
    });

    test.each<[string, unknown]>([
      ['null', null],
      ['a string', 'key'],
      ['a number', 42],
      ['an array', [PUBLIC_KEY]],
      ['an object with no kty', { crv: 'P-256', x: 'a', y: 'b' }],
      ['an object with a kty that is not a string', { ...PUBLIC_KEY, kty: 1 }],
      ['an object with a null kty', { ...PUBLIC_KEY, kty: null }],
      ['an object with an array as kty', { ...PUBLIC_KEY, kty: ['EC'] }],
    ])('refuses a set with a key that is %s, and a good key beside it does not save it', async (_label, key) => {
      const { fetcher } = createFetcher(keySetHandler([PUBLIC_KEY, key]));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_invalid');
    });

    test('refuses a key set that is not an object, as a JSON array of keys', async () => {
      const { fetcher } = createFetcher(agentHandler({ jwks: () => json([PUBLIC_KEY]) }));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_not_json');
    });

    test.each(PRIVATE_MEMBERS)('refuses a key with the private member %s', async (member) => {
      const { fetcher } = createFetcher(keySetHandler([{ ...PUBLIC_KEY, [member]: 'c2VjcmV0' }]));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_private_key');

      expect(error.message).toBe(
        "The agent's key set has a key with a private member. A key set must have public keys only."
      );
    });

    test.each<[string, unknown]>([
      ['an empty string', ''],
      ['null', null],
      ['false', false],
      ['0', 0],
      ['an object', {}],
    ])('refuses a private member that is %s, because its name is what counts', async (_label, value) => {
      const { fetcher } = createFetcher(keySetHandler([{ ...PUBLIC_KEY, d: value }]));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_private_key');
    });

    test('refuses a whole key set when one key of several has a private member', async () => {
      const { fetcher } = createFetcher(
        keySetHandler([PUBLIC_KEY, ROTATED_KEY, { ...PUBLIC_KEY, kid: 'leaked', d: 'c2VjcmV0' }])
      );

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_private_key');
    });

    test('refuses a symmetric key', async () => {
      const { fetcher } = createFetcher(keySetHandler([{ kty: 'oct', k: 'c2VjcmV0', kid: 'hmac' }]));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_private_key');
    });

    test('looks at the name of a private member before the value of any member', async () => {
      // `d` is an object, which is not allowed as a value either. The private key is what is reported.
      const { fetcher } = createFetcher(keySetHandler([{ ...PUBLIC_KEY, extra: ['a', 1], d: { nested: 'x' } }]));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_private_key');
    });

    test('keeps the members that are strings, booleans, numbers and arrays of strings', async () => {
      const key = {
        ...PUBLIC_KEY,
        use: 'sig',
        key_ops: ['verify'],
        ext: true,
        x5c: ['MIIB', 'MIIC'],
        x5t: 'abc',
        'x5t#S256': 'def',
        x5u: 'https://agent.example/cert.pem',
        count: 3,
        ratio: -0.5,
        none: [],
      };
      const { fetcher } = createFetcher(keySetHandler([key]));

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([key]);
    });

    test.each<[string, unknown]>([
      ['null', null],
      ['an empty object', {}],
      ['an object', { a: 'b' }],
      ['an object that only names a private member', { d: 'x' }],
      ['an array of arrays', [['a']]],
      ['an array of numbers', [1]],
      ['an array of booleans', [true]],
      ['an array of objects', [{}]],
      ['an array of strings and a null', ['a', null]],
      ['an array of strings and a number', ['a', 1]],
    ])('refuses a key with a member that is %s, and a good key beside it does not save it', async (_label, value) => {
      const { fetcher } = createFetcher(keySetHandler([PUBLIC_KEY, { ...PUBLIC_KEY, extra: value }]));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_invalid');

      expect(error.message).toBe(JWKS_INVALID_MESSAGE);
    });

    test.each<[string, string]>([
      ['an array nested 5,000 deep', `${'['.repeat(5000)}${']'.repeat(5000)}`],
      ['an object nested 5,000 deep', `${'{"a":'.repeat(5000)}1${'}'.repeat(5000)}`],
    ])('refuses a key with a member that is %s, and never copies it', async (_label, deep) => {
      // The copy of a key set that a caller gets must not be able to throw. A member this deep would break a deep copy,
      // so no member may be an object, and this one never gets as far as a copy. The 64 KB limit still allows it.
      const text = `{"keys":[${JSON.stringify(PUBLIC_KEY)},{"kty":"EC","kid":"deep","extra":${deep}}]}`;
      const { fetcher } = createFetcher(keySetTextHandler(text));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), DEEP_MEMBER_CAUSES);

      expect([JWKS_INVALID_MESSAGE, "The agent's key set is not a UTF-8 encoded JSON object."]).toContain(
        error.message
      );
    });

    test.each(['1e999', '-1e999'])('refuses a number that is not finite: %s', async (number) => {
      // The number is valid JSON, and JSON.parse reads it as Infinity.
      const { fetcher } = createFetcher(keySetTextHandler(`{"keys":[{"kty":"EC","big":${number}}]}`));

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_invalid');
    });

    test('takes 100 keys', async () => {
      const keys = manyKeys(100);
      const { fetcher } = createFetcher(keySetHandler(keys));

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual(keys);
    });

    test('refuses 101 keys', async () => {
      const { fetcher } = createFetcher(keySetHandler(manyKeys(101)));

      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'jwks_invalid');

      expect(error.message).toBe(JWKS_INVALID_MESSAGE);
    });

    test('keeps a member called __proto__ as a member of the key, in every copy', async () => {
      // JSON.parse makes it an own property. A copy that assigned it would change the prototype of the copy instead.
      const { fetcher } = createFetcher(keySetTextHandler('{"keys":[{"kty":"EC","__proto__":["x"]}]}'));

      const loaded = await fetcher.getKeys(CIMD_URL);
      const cached = await fetcher.getKeys(CIMD_URL);

      for (const { keys } of [loaded, cached]) {
        expect(Object.getPrototypeOf(keys[0])).toBe(Object.prototype);
        expect(Object.getOwnPropertyDescriptor(keys[0], '__proto__')?.value).toEqual(['x']);
      }
    });

    test('does not cache a key set with a private key', async () => {
      const { fetcher, calls } = createFetcher(keySetHandler([{ ...PUBLIC_KEY, d: 'c2VjcmV0' }]));
      pinClock();

      await rejectionOf(fetcher.getKeys(CIMD_URL));
      advance(FAILED_FETCH_CACHE_MS);
      await rejectionOf(fetcher.getKeys(CIMD_URL));

      expect(calls).toHaveLength(4);
    });
  });

  describe('getKeys and the messages of its errors', () => {
    // Everything the host or the network says is in the responses below, in the part of it that follows LEAK.
    const LEAK = /LEAK|418|10\.9\.8\.7|ECONNREFUSED|stack|secret|leak/i;

    const metadata = documentsOf(CIMD_URL).metadata;
    const scenarios: Array<[string, Handler, string]> = [
      [
        'a redirect',
        agentHandler({
          metadata: () =>
            new Response('LEAK redirect body', { status: 302, headers: { location: 'https://10.9.8.7/LEAK' } }),
        }),
        'metadata_redirect',
      ],
      [
        'a status that is refused',
        agentHandler({ metadata: () => new Response('LEAK teapot body', { status: 418, statusText: 'LEAK teapot' }) }),
        'metadata_status',
      ],
      [
        'a body that is too large',
        agentHandler({
          metadata: () => new Response('LEAK', { status: 200, headers: { 'content-length': '10000000' } }),
        }),
        'metadata_too_large',
      ],
      [
        'a body that is not JSON',
        agentHandler({ metadata: () => new Response('LEAK not json 10.9.8.7') }),
        'metadata_not_json',
      ],
      [
        'a client_id that is not the URL',
        metadataHandler({ ...metadata, client_id: 'https://LEAK.example/' }),
        'client_id_mismatch',
      ],
      [
        'a jwks_uri that is refused',
        metadataHandler({ ...metadata, jwks_uri: 'https://10.9.8.7/LEAK' }),
        'jwks_uri_invalid',
      ],
      ['a key set that is not a key set', keySetHandler('LEAK'), 'jwks_invalid'],
      [
        'a key with a member that is an object',
        keySetHandler([{ ...PUBLIC_KEY, LEAK: { LEAK: 'LEAK 418 secret' } }]),
        'jwks_invalid',
      ],
      ['a key set with a private key', keySetHandler([{ ...PUBLIC_KEY, d: 'LEAK-secret-d' }]), 'jwks_private_key'],
      [
        'a body of empty chunks',
        agentHandler({ metadata: () => withStream(chunkedBody(emptyChunks(2000), watchBody()), { status: 200 }) }),
        'metadata_body_invalid',
      ],
      [
        'a key set that redirects',
        agentHandler({
          jwks: () => new Response('LEAK', { status: 307, headers: { location: 'https://10.9.8.7/LEAK' } }),
        }),
        'metadata_redirect',
      ],
      [
        'a server error',
        agentHandler({ metadata: () => new Response('LEAK stack trace', { status: 500 }) }),
        'upstream_unavailable',
      ],
      [
        'a rate limit',
        agentHandler({ metadata: () => new Response('LEAK', { status: 429, headers: { 'retry-after': '600' } }) }),
        'upstream_unavailable',
      ],
      ['a network error', () => Promise.reject(new Error('connect ECONNREFUSED 10.9.8.7:443 LEAK')), 'fetch_failed'],
    ];

    test.each(scenarios)('says nothing of what the host or the network said for %s', async (_label, handler, cause) => {
      const { fetcher } = createFetcher(handler);

      const error = (await rejectionOf(fetcher.getKeys(CIMD_URL))) as InvalidSessionError | PoppyUnavailableError;

      expect(error.cause).toEqual({ code: cause });
      expect(error.message).not.toMatch(LEAK);
      expect(error.message).not.toContain(CIMD_URL);
      expect(JSON.stringify(error.headers ?? {})).not.toMatch(LEAK);
      expect(error.message.length).toBeLessThan(160);
    });

    test('gives a host that is down for now the standard message of the error', async () => {
      const { fetcher } = createFetcher(agentHandler({ metadata: () => new Response(null, { status: 503 }) }));

      const error = await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');

      expect(error.message).toBe(new PoppyUnavailableError().message);
    });
  });

  describe('getKeys and the failure cache', () => {
    test('remembers a host that is down, and does not fetch again within 30 seconds', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response('down', { status: 500 }) }));

      const first = await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');
      advance(FAILED_FETCH_CACHE_MS - 1);
      // One millisecond of the 30 seconds is left, and that is one second to wait.
      const second = await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable', 1);

      expect(calls).toHaveLength(1);
      expect(second).not.toBe(first);
      expect(second.message).toBe(first.message);
      expect(second.cause).toEqual(first.cause);
      expect(second.cause).not.toBe(first.cause);
    });

    test.each<[string, number, number]>([
      ['at once', 0, 30],
      ['1 millisecond later', 1, 30],
      // Less than half a second over a whole number of seconds is still rounded up.
      ['600 milliseconds later', 600, 30],
      ['1 second later', 1000, 29],
      ['1001 milliseconds later', 1001, 29],
      ['1600 milliseconds later', 1600, 29],
      ['15 seconds later', 15_000, 15],
      ['29 seconds later', 29_000, 1],
      ['29.5 seconds later', 29_500, 1],
      ['1 millisecond before it ends', 29_999, 1],
    ])('tells the caller to retry in the seconds that are left, rounded up: %s', async (_label, elapsed, expected) => {
      pinClock();
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response('down', { status: 500 }) }));
      // The error of the fetch itself has the whole window to wait.
      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable', 30);

      advance(elapsed);
      const error = await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable', expected);

      expect(error.retryAfter).toBe(expected);
      expect(error.headers).toEqual({ 'retry-after': String(expected) });
      expect(calls).toHaveLength(1);
    });

    test('tells the caller to retry in 1 second when the window ends while the error is made', async () => {
      pinClock();
      const { fetcher } = createFetcher(agentHandler({ metadata: () => new Response('down', { status: 500 }) }));
      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');
      // The first reading of the clock is the check of the cache, 1 ms before the failure expires. Every later one is
      // after it, so no seconds are left, and the answer must still be a second and not 0.
      let reads = 0;
      vi.spyOn(Date, 'now').mockImplementation(() => START + (reads++ === 0 ? FAILED_FETCH_CACHE_MS - 1 : 40_000));

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable', 1);
    });

    test('counts down the seconds for a remembered timeout and a remembered network error', async () => {
      pinClock();
      const timedOut = createFetcher(() => new Promise<Response>(() => undefined), { timeoutMs: 20 });
      await expectUnavailable(timedOut.fetcher.getKeys(CIMD_URL), 'fetch_timeout', 30);
      const broken = createFetcher(() => Promise.reject(new Error('down')));
      await expectUnavailable(broken.fetcher.getKeys(CIMD_URL), 'fetch_failed', 30);

      advance(10_000);

      await expectUnavailable(timedOut.fetcher.getKeys(CIMD_URL), 'fetch_timeout', 20);
      await expectUnavailable(broken.fetcher.getKeys(CIMD_URL), 'fetch_failed', 20);
    });

    test('says nothing of a retry for a remembered failure of the agent', async () => {
      pinClock();
      const { fetcher } = createFetcher(agentHandler({ metadata: () => new Response(null, { status: 404 }) }));
      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_status');

      advance(10_000);
      const error = await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_status');

      expect(error.headers).toBeUndefined();
      expect(error).not.toHaveProperty('retryAfter');
    });

    test('fetches again after 30 seconds', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response('down', { status: 500 }) }));

      await rejectionOf(fetcher.getKeys(CIMD_URL));
      advance(FAILED_FETCH_CACHE_MS);
      await rejectionOf(fetcher.getKeys(CIMD_URL));

      expect(calls).toHaveLength(2);
    });

    test('serves the agent again when it is up after 30 seconds', async () => {
      pinClock();
      let healthy = false;
      const { fetcher } = createFetcher((url, init) =>
        healthy ? agentHandler()(url, init) : new Response('down', { status: 503 })
      );

      await rejectionOf(fetcher.getKeys(CIMD_URL));
      healthy = true;
      advance(FAILED_FETCH_CACHE_MS);

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
    });

    test.each<[string, Handler, string]>([
      [
        'a status that is refused',
        agentHandler({ metadata: () => new Response(null, { status: 404 }) }),
        'metadata_status',
      ],
      ['a redirect', agentHandler({ metadata: () => new Response(null, { status: 302 }) }), 'metadata_redirect'],
      ['a body that is not JSON', agentHandler({ metadata: () => new Response('nope') }), 'metadata_not_json'],
      ['a client_id that does not match', metadataHandler({ client_id: 'https://x.example/' }), 'client_id_mismatch'],
      ['a key set with a private key', keySetHandler([{ ...PUBLIC_KEY, d: 'x' }]), 'jwks_private_key'],
    ])('remembers a definitive failure too: %s', async (_label, handler, cause) => {
      pinClock();
      const { fetcher, calls } = createFetcher(handler);

      const first = await expectInvalid(fetcher.getKeys(CIMD_URL), cause);
      const callsAfterFirst = calls.length;
      advance(FAILED_FETCH_CACHE_MS - 1);
      const second = await expectInvalid(fetcher.getKeys(CIMD_URL), cause);

      expect(calls).toHaveLength(callsAfterFirst);
      expect(second).not.toBe(first);
      expect(second.reason).toBe(first.reason);
      expect(second.message).toBe(first.message);
    });

    test('remembers a failure of the key set, without a fetch for the metadata either', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher(agentHandler({ jwks: () => new Response('down', { status: 502 }) }));

      await rejectionOf(fetcher.getKeys(CIMD_URL));
      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');

      expect(urlsOf(calls)).toEqual([CIMD_URL, JWKS_URI]);
    });

    test('remembers a timeout and a network error', async () => {
      pinClock();
      const stalled = createFetcher(() => new Promise<Response>(() => undefined), { timeoutMs: 20 });
      await expectUnavailable(stalled.fetcher.getKeys(CIMD_URL), 'fetch_timeout');
      await expectUnavailable(stalled.fetcher.getKeys(CIMD_URL), 'fetch_timeout');
      expect(stalled.calls).toHaveLength(1);

      const broken = createFetcher(() => Promise.reject(new Error('down')));
      await expectUnavailable(broken.fetcher.getKeys(CIMD_URL), 'fetch_failed');
      await expectUnavailable(broken.fetcher.getKeys(CIMD_URL), 'fetch_failed');
      expect(broken.calls).toHaveLength(1);
    });

    test('keeps the failures of different agents apart', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher((url, init) =>
        url.startsWith('https://other.example')
          ? new Response('down', { status: 500 })
          : agentsHandler(CIMD_URL)(url, init)
      );

      await expectUnavailable(fetcher.getKeys(OTHER_CIMD_URL), 'upstream_unavailable');
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);

      expect(urlsOf(calls)).toEqual([OTHER_CIMD_URL, CIMD_URL, JWKS_URI]);
    });

    test('gives each of the calls that run together an error of its own', async () => {
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response('down', { status: 500 }) }));

      const errors = await Promise.all(
        Array.from({ length: 3 }, () => rejectionOf(fetcher.getKeys(CIMD_URL)) as Promise<PoppyUnavailableError>)
      );

      expect(calls).toHaveLength(1);
      expect(new Set(errors).size).toBe(3);
      expect(new Set(errors.map((error) => error.headers)).size).toBe(3);
      expect(new Set(errors.map((error) => error.cause)).size).toBe(3);
      for (const error of errors) {
        expect(error).toBeInstanceOf(PoppyUnavailableError);
      }
    });

    // The cache options switch off the caching of good keys, and nothing else: a host that is down is not asked
    // again at once, whatever the cache options say. This is a guard of the SDK, and not a feature of the cache.
    test.each<[string, Partial<FetcherOptions>]>([
      ['maxEntries is 0', { maxEntries: 0 }],
      ['ttlMs is 0', { ttlMs: 0 }],
      ['both are 0', { maxEntries: 0, ttlMs: 0 }],
    ])('still remembers a failure for 30 seconds when %s', async (_label, overrides) => {
      pinClock();
      const { fetcher, calls } = createFetcher(
        agentHandler({ metadata: () => new Response('down', { status: 500 }) }),
        overrides
      );

      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');
      advance(FAILED_FETCH_CACHE_MS - 1);
      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable', 1);
      expect(calls).toHaveLength(1);

      advance(1);
      await expectUnavailable(fetcher.getKeys(CIMD_URL), 'upstream_unavailable');
      expect(calls).toHaveLength(2);
    });

    test('remembers a failure of the agent for 30 seconds when maxEntries is 0, too', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher(agentHandler({ metadata: () => new Response(null, { status: 404 }) }), {
        maxEntries: 0,
      });

      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_status');
      advance(FAILED_FETCH_CACHE_MS - 1);
      await expectInvalid(fetcher.getKeys(CIMD_URL), 'metadata_status');

      expect(calls).toHaveLength(1);
    });

    test('remembers the failures of at most max(maxEntries, 100) agents', async () => {
      pinClock();
      const agents = Array.from({ length: 101 }, (_, index) => `https://agent-${index}.example/agent.json`);
      // maxEntries of 1 is below 100, so it is 100 that counts.
      const { fetcher, calls } = createFetcher(() => new Response('down', { status: 500 }), { maxEntries: 1 });

      for (const agentUrl of agents.slice(0, 100)) {
        await rejectionOf(fetcher.getKeys(agentUrl));
      }
      expect(calls).toHaveLength(100);
      // All 100 are remembered, though maxEntries is 1. The first one is used again, so the second is the oldest.
      await rejectionOf(fetcher.getKeys(agents[0]!));
      expect(calls).toHaveLength(100);

      // A 101st agent pushes the second one out, and only that one.
      await rejectionOf(fetcher.getKeys(agents[100]!));
      expect(calls).toHaveLength(101);
      await rejectionOf(fetcher.getKeys(agents[1]!));
      expect(calls).toHaveLength(102);
      await rejectionOf(fetcher.getKeys(agents[0]!));
      await rejectionOf(fetcher.getKeys(agents[100]!));
      expect(calls).toHaveLength(102);
    });

    test('remembers more agents than 100 when maxEntries is higher', async () => {
      pinClock();
      const agents = Array.from({ length: 102 }, (_, index) => `https://agent-${index}.example/agent.json`);
      const { fetcher, calls } = createFetcher(() => new Response('down', { status: 500 }), { maxEntries: 102 });

      for (const agentUrl of agents) {
        await rejectionOf(fetcher.getKeys(agentUrl));
      }
      // The first agent is still remembered, where 100 would have pushed it out.
      await rejectionOf(fetcher.getKeys(agents[0]!));

      expect(calls).toHaveLength(102);
    });
  });

  describe('getKeys and the cache', () => {
    test('fetches again once ttlMs has passed', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher();

      await fetcher.getKeys(CIMD_URL);
      advance(TTL_MS - 1);
      await fetcher.getKeys(CIMD_URL);
      expect(calls).toHaveLength(2);

      advance(1);
      await fetcher.getKeys(CIMD_URL);
      expect(calls).toHaveLength(4);
    });

    test('shows a change of the keys after ttlMs', async () => {
      pinClock();
      let keys: unknown[] = [PUBLIC_KEY];
      const { fetcher } = createFetcher((url, init) => keySetHandler(keys)(url, init));

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      keys = [ROTATED_KEY];
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      advance(TTL_MS);

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
    });

    test('keeps the older agent out when maxEntries is 1', async () => {
      const { fetcher, calls } = createFetcher(agentsHandler(CIMD_URL, OTHER_CIMD_URL), { maxEntries: 1 });

      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(OTHER_CIMD_URL);
      expect(calls).toHaveLength(4);
      // The second agent is still in the cache.
      await fetcher.getKeys(OTHER_CIMD_URL);
      expect(calls).toHaveLength(4);
      // The first agent is not: it was pushed out.
      await fetcher.getKeys(CIMD_URL);
      expect(urlsOf(calls)).toEqual([CIMD_URL, JWKS_URI, OTHER_CIMD_URL, OTHER_JWKS_URI, CIMD_URL, JWKS_URI]);
    });

    test('keeps the agent that was used last when maxEntries is 2', async () => {
      const third = 'https://third.example/agent.json';
      const { fetcher, calls } = createFetcher(agentsHandler(CIMD_URL, OTHER_CIMD_URL, third), { maxEntries: 2 });

      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(OTHER_CIMD_URL);
      // Using the first agent again makes the second one the oldest.
      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(third);
      await fetcher.getKeys(CIMD_URL);

      expect(calls).toHaveLength(6);
      await fetcher.getKeys(OTHER_CIMD_URL);
      expect(calls).toHaveLength(8);
    });

    test('caches nothing when maxEntries is 0, and still loads once for calls that run together', async () => {
      const { fetcher, calls } = createFetcher(agentHandler(), { maxEntries: 0 });

      await Promise.all([fetcher.getKeys(CIMD_URL), fetcher.getKeys(CIMD_URL)]);
      expect(calls).toHaveLength(2);

      await fetcher.getKeys(CIMD_URL);
      expect(calls).toHaveLength(4);
    });

    test('caches nothing when ttlMs is 0', async () => {
      const { fetcher, calls } = createFetcher(agentHandler(), { ttlMs: 0 });

      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(CIMD_URL);

      expect(calls).toHaveLength(4);
    });
  });

  describe('refreshKeys', () => {
    // An agent that publishes the keys of `state.keys`, and counts nothing: the calls are recorded by createFetcher. A
    // `state.keySetText` is a key set written by hand, for what JSON.stringify cannot write, and it comes first.
    interface RotatingState {
      keys: unknown[];
      down: boolean;
      keySetText?: string;
    }
    function rotatingAgent(): { handler: Handler; state: RotatingState } {
      const state: RotatingState = { keys: [PUBLIC_KEY], down: false };
      const handler: Handler = (url, init) => {
        if (state.down) {
          return new Response('down', { status: 500 });
        }
        return state.keySetText === undefined
          ? keySetHandler(state.keys)(url, init)
          : keySetTextHandler(state.keySetText)(url, init);
      };
      return { handler, state };
    }

    test('refetches and replaces the cached keys the first time', async () => {
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      await fetcher.getKeys(CIMD_URL);
      state.keys = [ROTATED_KEY];

      const refreshed = await fetcher.refreshKeys(CIMD_URL);

      expect(refreshed).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
      expect(calls).toHaveLength(4);
      // The cache holds the new keys now, so there is no other fetch.
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
      expect(calls).toHaveLength(4);
    });

    test('refetches when there is nothing in the cache', async () => {
      const { fetcher, calls } = createFetcher();

      const refreshed = await fetcher.refreshKeys(CIMD_URL);

      expect(refreshed?.keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(2);
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(2);
    });

    test('is not held back by a call to getKeys, whether it fetched or used the cache', async () => {
      const { fetcher, calls } = createFetcher();

      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(CIMD_URL);
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeDefined();

      expect(calls).toHaveLength(4);
    });

    test('returns undefined without a fetch within 30 seconds of a refetch, and refetches after', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher();
      await fetcher.refreshKeys(CIMD_URL);
      expect(calls).toHaveLength(2);

      advance(UNKNOWN_KID_REFETCH_INTERVAL_MS - 1);
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeUndefined();
      expect(calls).toHaveLength(2);

      advance(1);
      expect((await fetcher.refreshKeys(CIMD_URL))?.keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(4);
    });

    test('makes one refetch for calls that run together, and gives each of them the keys', async () => {
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      await fetcher.getKeys(CIMD_URL);
      state.keys = [ROTATED_KEY];

      const results = await Promise.all([
        fetcher.refreshKeys(CIMD_URL),
        fetcher.refreshKeys(CIMD_URL),
        fetcher.refreshKeys(CIMD_URL),
      ]);

      expect(calls).toHaveLength(4);
      for (const result of results) {
        expect(result).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
      }
      // Each call has copies of its own.
      expect(new Set(results.map((result) => result?.keys)).size).toBe(3);
    });

    test('returns copies of the keys', async () => {
      const { fetcher } = createFetcher();

      const refreshed = await fetcher.refreshKeys(CIMD_URL);
      refreshed!.keys[0]!.kid = 'changed';
      refreshed!.keys.length = 0;

      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
    });

    test('rejects like getKeys when the refetch fails with a 500, and counts against the 30 seconds', async () => {
      pinClock();
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      await fetcher.getKeys(CIMD_URL);
      state.down = true;

      await expectUnavailable(fetcher.refreshKeys(CIMD_URL), 'upstream_unavailable');
      expect(calls).toHaveLength(3);

      advance(UNKNOWN_KID_REFETCH_INTERVAL_MS - 1);
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeUndefined();
      expect(calls).toHaveLength(3);

      advance(1);
      state.down = false;
      expect((await fetcher.refreshKeys(CIMD_URL))?.keys).toEqual([PUBLIC_KEY]);
    });

    test('rejects with the error of a definitive problem, and counts against the 30 seconds', async () => {
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      await fetcher.getKeys(CIMD_URL);
      state.keys = [{ ...PUBLIC_KEY, d: 'c2VjcmV0' }];

      await expectInvalid(fetcher.refreshKeys(CIMD_URL), 'jwks_private_key');
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeUndefined();

      expect(calls).toHaveLength(4);
    });

    test('gives the callers that run together the same failure, each with an error of its own', async () => {
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      await fetcher.getKeys(CIMD_URL);
      state.down = true;

      const errors = await Promise.all([
        rejectionOf(fetcher.refreshKeys(CIMD_URL)),
        rejectionOf(fetcher.refreshKeys(CIMD_URL)),
      ]);

      expect(calls).toHaveLength(3);
      expect(errors[0]).toBeInstanceOf(PoppyUnavailableError);
      expect(errors[1]).toBeInstanceOf(PoppyUnavailableError);
      expect(errors[0]).not.toBe(errors[1]);
    });

    test('keeps the good keys when the refetch fails', async () => {
      pinClock();
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      await fetcher.getKeys(CIMD_URL);
      state.down = true;
      await rejectionOf(fetcher.refreshKeys(CIMD_URL));
      const callsAfterFailure = calls.length;

      advance(1000);
      const keys = await fetcher.getKeys(CIMD_URL);

      expect(keys.keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(callsAfterFailure);
    });

    test.each<[string, (state: RotatingState) => void, string | readonly string[]]>([
      [
        'a key with a member nested 5,000 deep',
        (state) => {
          state.keySetText = `{"keys":[{"kty":"EC","kid":"hostile","deep":${'['.repeat(5000)}${']'.repeat(5000)}}]}`;
        },
        DEEP_MEMBER_CAUSES,
      ],
      [
        'a key with a member that is an object',
        (state) => {
          state.keys = [{ ...PUBLIC_KEY, kid: 'hostile', extra: { a: 'b' } }];
        },
        'jwks_invalid',
      ],
      [
        'more than 100 keys',
        (state) => {
          state.keys = manyKeys(101);
        },
        'jwks_invalid',
      ],
    ])('keeps the good keys when the refetch meets %s, and getKeys serves them', async (_label, hostile, cause) => {
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler);
      const good = await fetcher.getKeys(CIMD_URL);
      hostile(state);

      await expectInvalid(fetcher.refreshKeys(CIMD_URL), cause);
      expect(calls).toHaveLength(4);

      // The hostile set never reached the cache, so the good keys are still there for every call, and they still copy.
      for (let call = 0; call < 3; call += 1) {
        expect(await fetcher.getKeys(CIMD_URL)).toEqual(good);
      }
      expect(calls).toHaveLength(4);
    });

    test('writes no failure when the refetch fails, so getKeys fetches once the keys have expired', async () => {
      pinClock();
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler, { ttlMs: 5000 });
      await fetcher.getKeys(CIMD_URL);
      advance(1000);
      state.down = true;
      await rejectionOf(fetcher.refreshKeys(CIMD_URL));
      expect(calls).toHaveLength(3);

      // The keys have expired, and the host is up. The failed refetch did not leave a failure to rethrow.
      advance(5000);
      state.down = false;
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(5);
    });

    test('clears the failure that getKeys remembered when a refetch works', async () => {
      pinClock();
      const { handler, state } = rotatingAgent();
      const { fetcher, calls } = createFetcher(handler, { ttlMs: 5000 });
      state.down = true;
      await rejectionOf(fetcher.getKeys(CIMD_URL));
      expect(calls).toHaveLength(1);

      // The refetch is not held back by the failure that getKeys remembers.
      advance(1000);
      state.down = false;
      expect((await fetcher.refreshKeys(CIMD_URL))?.keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(3);

      // The keys have expired, and the failure of getKeys is still within its 30 seconds.
      advance(5000);
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(5);
    });

    test('counts the 30 seconds for each agent', async () => {
      const { fetcher, calls } = createFetcher(agentsHandler(CIMD_URL, OTHER_CIMD_URL));

      expect(await fetcher.refreshKeys(CIMD_URL)).toBeDefined();
      expect(await fetcher.refreshKeys(OTHER_CIMD_URL)).toBeDefined();
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeUndefined();
      expect(await fetcher.refreshKeys(OTHER_CIMD_URL)).toBeUndefined();

      expect(calls).toHaveLength(4);
    });

    test('checks the agent URL first, so a refusal does not use up the 30 seconds', async () => {
      const { fetcher, calls } = createFetcher();

      await expectInvalid(
        fetcher.refreshKeys('https://localhost/agent.json'),
        'agent_address_not_allowed',
        'agent_not_allowed'
      );
      await expectInvalid(
        fetcher.refreshKeys('https://localhost/agent.json'),
        'agent_address_not_allowed',
        'agent_not_allowed'
      );
      await expectInvalid(
        fetcher.refreshKeys('http://agent.example/agent.json'),
        'agent_url_invalid',
        'agent_not_allowed'
      );
      await expectInvalid(
        fetcher.refreshKeys(undefined as unknown as string),
        'agent_url_invalid',
        'agent_not_allowed'
      );

      expect(calls).toHaveLength(0);
    });

    test('lets a refetch for a local agent through when private addresses are allowed', async () => {
      const localAgent = await createTestAgent({ cimdUrl: 'https://localhost:8443/agent.json' });
      const { fetcher } = createFetcher((url) => localAgent.fetch(url), { allowPrivateAddresses: true });

      expect((await fetcher.refreshKeys('https://localhost:8443/agent.json'))?.keys).toEqual(localAgent.jwks.keys);
    });

    test('gives up on a host that never answers, and counts against the 30 seconds', async () => {
      const { fetcher, calls } = createFetcher(() => new Promise<Response>(() => undefined), { timeoutMs: 40 });

      await expectUnavailable(fetcher.refreshKeys(CIMD_URL), 'fetch_timeout');
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeUndefined();

      expect(calls).toHaveLength(1);
    });

    // The cache options switch off the caching of good keys, and nothing else: a host is not refetched more than once
    // in 30 seconds, whatever the cache options say. This is a guard of the SDK, and not a feature of the cache.
    test.each<[string, Partial<FetcherOptions>]>([
      ['maxEntries is 0', { maxEntries: 0 }],
      ['ttlMs is 0', { ttlMs: 0 }],
      ['both are 0', { maxEntries: 0, ttlMs: 0 }],
    ])('still holds a refetch back for 30 seconds when %s', async (_label, overrides) => {
      pinClock();
      const { fetcher, calls } = createFetcher(agentHandler(), overrides);

      expect(await fetcher.refreshKeys(CIMD_URL)).toBeDefined();
      advance(UNKNOWN_KID_REFETCH_INTERVAL_MS - 1);
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeUndefined();
      expect(calls).toHaveLength(2);

      advance(1);
      expect(await fetcher.refreshKeys(CIMD_URL)).toBeDefined();
      expect(calls).toHaveLength(4);
    });

    test('holds back the refetches of at most max(maxEntries, 100) agents', async () => {
      const agents = Array.from({ length: 101 }, (_, index) => `https://agent-${index}.example/agent.json`);
      // maxEntries of 1 is below 100, so it is 100 that counts.
      const { fetcher, calls } = createFetcher(agentsHandler(...agents), { maxEntries: 1 });

      for (const agentUrl of agents.slice(0, 100)) {
        expect(await fetcher.refreshKeys(agentUrl)).toBeDefined();
      }
      expect(calls).toHaveLength(200);
      // All 100 are held back, though maxEntries is 1. The first one is used again, so the second is the oldest.
      expect(await fetcher.refreshKeys(agents[0]!)).toBeUndefined();
      expect(calls).toHaveLength(200);

      // A 101st agent pushes the second one out, and only that one.
      expect(await fetcher.refreshKeys(agents[100]!)).toBeDefined();
      expect(await fetcher.refreshKeys(agents[1]!)).toBeDefined();
      expect(calls).toHaveLength(204);
      expect(await fetcher.refreshKeys(agents[0]!)).toBeUndefined();
      expect(await fetcher.refreshKeys(agents[100]!)).toBeUndefined();
      expect(calls).toHaveLength(204);
    });

    test('holds back the refetches of more agents than 100 when maxEntries is higher', async () => {
      const agents = Array.from({ length: 102 }, (_, index) => `https://agent-${index}.example/agent.json`);
      const { fetcher, calls } = createFetcher(agentsHandler(...agents), { maxEntries: 102 });

      for (const agentUrl of agents) {
        expect(await fetcher.refreshKeys(agentUrl)).toBeDefined();
      }
      // The first agent is still held back, where 100 would have pushed it out.
      expect(await fetcher.refreshKeys(agents[0]!)).toBeUndefined();

      expect(calls).toHaveLength(204);
    });

    test('gives a slower load that fails at the metadata the keys of a refetch that finished first', async () => {
      let releaseSlowLoad: () => void = () => undefined;
      const slowLoad = new Promise<void>((resolve) => {
        releaseSlowLoad = resolve;
      });
      let metadataRequests = 0;
      const { fetcher, calls } = createFetcher((url, init) => {
        if (url === CIMD_URL) {
          metadataRequests += 1;
          // The first request is the one of getKeys. It answers late, with a failure.
          if (metadataRequests === 1) {
            return slowLoad.then(() => new Response(null, { status: 503 }));
          }
        }
        return agentHandler()(url, init);
      });

      const load = fetcher.getKeys(CIMD_URL);
      const refreshed = await fetcher.refreshKeys(CIMD_URL);
      releaseSlowLoad();
      const loaded = await load;

      expect(refreshed?.keys).toEqual([PUBLIC_KEY]);
      // The load failed with a 503, but a refetch had ended with keys. The caller of the load gets those keys.
      expect(loaded.keys).toEqual([PUBLIC_KEY]);
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(3);
    });

    /**
     * An agent whose first key set is slow: it arrives when `release` is called, and `loadWaiting` says that the first
     * request for it has been made. It arrives with the old keys, or as `firstAnswer` says. Every later key set is
     * `published.keys`, the rotated keys at first, or a server error while `published.down` is set. So the tests can
     * tell the old keys, the rotated ones and later ones apart.
     */
    function agentWithSlowFirstKeySet(
      overrides: Partial<FetcherOptions> = {},
      firstAnswer: () => Response | Promise<Response> = () => json({ keys: [PUBLIC_KEY] })
    ) {
      let loadIsWaiting: () => void = () => undefined;
      const loadWaiting = new Promise<void>((resolve) => {
        loadIsWaiting = resolve;
      });
      let release: () => void = () => undefined;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      const published: { keys: JWK[]; down: boolean } = { keys: [ROTATED_KEY], down: false };
      let keySetRequests = 0;
      const { fetcher, calls } = createFetcher((url, init) => {
        if (url === JWKS_URI) {
          keySetRequests += 1;
          if (keySetRequests === 1) {
            // The first request for the key set is the one of the load. It answers late.
            loadIsWaiting();
            return released.then(firstAnswer);
          }
          return published.down ? new Response('down', { status: 500 }) : json({ keys: published.keys });
        }
        return agentHandler()(url, init);
      }, overrides);
      return { fetcher, calls, published, loadWaiting, release };
    }

    /**
     * The race of a load and a refetch. `getKeys` starts a load, and a second call joins it. The key set that the load
     * asked for is slow. A refetch of the same agent runs and finishes with the rotated keys. Then the slow key set
     * arrives, with the old keys or as `firstAnswer` says. Returns what the refetch, the load and the call that joined
     * it gave.
     */
    async function loadOvertakenByRefetch(
      overrides: Partial<FetcherOptions> = {},
      firstAnswer?: () => Response | Promise<Response>
    ) {
      const slow = agentWithSlowFirstKeySet(overrides, firstAnswer);
      const load = slow.fetcher.getKeys(CIMD_URL);
      const joinedLoad = slow.fetcher.getKeys(CIMD_URL);
      await slow.loadWaiting;
      const refreshed = await slow.fetcher.refreshKeys(CIMD_URL);
      slow.release();
      const [loaded, joined] = await Promise.all([load, joinedLoad]);
      return { ...slow, refreshed, loaded, joined };
    }

    test('gives the callers of a load that a refetch overtook the keys of the refetch, and stores none', async () => {
      const { fetcher, calls, refreshed, loaded, joined } = await loadOvertakenByRefetch();

      expect(refreshed?.keys).toEqual([ROTATED_KEY]);
      // The load fetched the old keys. Neither its caller nor a call that joined it gets them: the refetch has newer.
      expect(loaded).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
      expect(joined).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
      expect(joined.keys).not.toBe(loaded.keys);
      // The load does not store the old keys over the newer ones either, so the cache still holds the rotated keys.
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
      // One load of two documents and one refetch of two documents, and the joined call made none.
      expect(calls).toHaveLength(4);
    });

    test('hands the callers of an overtaken load copies, which cannot change what the cache holds', async () => {
      const { fetcher, loaded, joined } = await loadOvertakenByRefetch();

      loaded.keys[0]!.kid = 'changed';
      loaded.keys.length = 0;
      joined.cimdUrl = 'https://changed.example/agent.json';

      expect(await fetcher.getKeys(CIMD_URL)).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
    });

    test('gives an overtaken load the keys of the refetch also when the cache keeps no keys', async () => {
      // With maxEntries of 0 the refetch stores nothing, so the keys cannot be read back from the cache.
      const { fetcher, calls, loaded, joined } = await loadOvertakenByRefetch({ maxEntries: 0 });

      expect(loaded.keys).toEqual([ROTATED_KEY]);
      expect(joined.keys).toEqual([ROTATED_KEY]);
      expect(calls).toHaveLength(4);
      // Nothing is stored, so this call loads again.
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
      expect(calls).toHaveLength(6);
    });

    test('gives an overtaken load the keys of the last refetch when several finished while it ran', async () => {
      pinClock();
      const slow = agentWithSlowFirstKeySet();
      const thirdKey: JWK = { ...PUBLIC_KEY, kid: 'key-3' };
      const load = slow.fetcher.getKeys(CIMD_URL);
      await slow.loadWaiting;
      await slow.fetcher.refreshKeys(CIMD_URL);
      advance(UNKNOWN_KID_REFETCH_INTERVAL_MS);
      slow.published.keys = [thirdKey];
      await slow.fetcher.refreshKeys(CIMD_URL);
      slow.release();

      expect((await load).keys).toEqual([thirdKey]);
      expect((await slow.fetcher.getKeys(CIMD_URL)).keys).toEqual([thirdKey]);
    });

    test('leaves the cache alone when it gives an overtaken load the keys of the refetch', async () => {
      pinClock();
      const slow = agentWithSlowFirstKeySet();
      const load = slow.fetcher.getKeys(CIMD_URL);
      await slow.loadWaiting;
      await slow.fetcher.refreshKeys(CIMD_URL);
      advance(5000);
      slow.release();
      await load;

      // The refetch stored its keys 5 seconds before the load ended, and the load did not store them again. They expire
      // at their own time, and the next call fetches.
      advance(TTL_MS - 5000);
      expect((await slow.fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
      expect(slow.calls).toHaveLength(6);
    });

    test('forgets an overtaken load once it is done, so the next load gets and stores its own keys', async () => {
      pinClock();
      const { fetcher, calls, published } = await loadOvertakenByRefetch();
      advance(TTL_MS);
      const nextKey: JWK = { ...PUBLIC_KEY, kid: 'key-3' };
      published.keys = [nextKey];

      // The keys have expired and the agent publishes others. This load is not overtaken: it gets the keys that it
      // fetched, and not the keys of the refetch that overtook the load before it, and it stores them.
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([nextKey]);
      expect(calls).toHaveLength(6);
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([nextKey]);
      expect(calls).toHaveLength(6);
    });

    // The ways the slow key set of a load can fail, with the error that a load which no refetch overtook ends with.
    interface KeySetFailure {
      /** What the slow first key set turns into when it is released. */
      answer: () => Response | Promise<Response>;
      overrides: Partial<FetcherOptions>;
      expectError: (promise: Promise<unknown>) => Promise<unknown>;
    }
    const keySetFailures: Array<[string, KeySetFailure]> = [
      [
        'a server error',
        {
          answer: () => new Response('down', { status: 500 }),
          overrides: {},
          expectError: (promise) => expectUnavailable(promise, 'upstream_unavailable'),
        },
      ],
      [
        'a timeout',
        {
          // The answer never comes, and the time limit ends the load. It is long enough for the refetch to end first.
          answer: () => new Promise<Response>(() => undefined),
          overrides: { timeoutMs: 300 },
          expectError: (promise) => expectUnavailable(promise, 'fetch_timeout'),
        },
      ],
      [
        'a status 404',
        {
          answer: () => new Response(null, { status: 404 }),
          overrides: {},
          expectError: (promise) => expectInvalid(promise, 'metadata_status'),
        },
      ],
    ];

    test.each(keySetFailures)(
      'gives a load that fails after a refetch overtook it the keys of the refetch: %s',
      async (_label, failure) => {
        pinClock();
        const { fetcher, calls, refreshed, loaded, joined } = await loadOvertakenByRefetch(
          { ttlMs: 5000, ...failure.overrides },
          failure.answer
        );

        expect(refreshed?.keys).toEqual([ROTATED_KEY]);
        // The key set of the load failed, but a refetch had ended with newer keys. The caller of the load and the call
        // that joined it get those keys.
        expect(loaded).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
        expect(joined).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [ROTATED_KEY] });
        expect(joined.keys).not.toBe(loaded.keys);
        // A later call is served from the cache, with no other fetch.
        expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
        expect(calls).toHaveLength(4);

        // The load remembered no failure. The keys expire after 5 seconds, inside the 30 seconds of a failure, and the
        // next call fetches again. A remembered failure would be rethrown here.
        advance(6000);
        expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([ROTATED_KEY]);
        expect(calls).toHaveLength(6);
      }
    );

    test.each(keySetFailures)(
      'still fails and remembers the failure when no refetch overtook the load: %s',
      async (_label, failure) => {
        pinClock();
        const slow = agentWithSlowFirstKeySet(failure.overrides, failure.answer);
        const load = slow.fetcher.getKeys(CIMD_URL);
        const joinedLoad = slow.fetcher.getKeys(CIMD_URL);
        await slow.loadWaiting;
        slow.release();

        await failure.expectError(load);
        await failure.expectError(joinedLoad);
        // The failure is remembered for 30 seconds: a later call rethrows it, with no other fetch.
        await failure.expectError(slow.fetcher.getKeys(CIMD_URL));
        expect(slow.calls).toHaveLength(2);
      }
    );

    test('does not count a refetch that failed, so the load that fails after it still fails', async () => {
      const slow = agentWithSlowFirstKeySet({}, () => new Response(null, { status: 404 }));
      slow.published.down = true;
      const load = slow.fetcher.getKeys(CIMD_URL);
      await slow.loadWaiting;
      await expectUnavailable(slow.fetcher.refreshKeys(CIMD_URL), 'upstream_unavailable');
      slow.release();

      await expectInvalid(load, 'metadata_status');
    });

    test('lets the next load store its keys when a refetch finished while no load was running', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher();
      await fetcher.refreshKeys(CIMD_URL);
      advance(TTL_MS);

      // The keys have expired. No load ran during the refetch, so nothing was overtaken, and this load stores its keys.
      await fetcher.getKeys(CIMD_URL);
      await fetcher.getKeys(CIMD_URL);

      expect(calls).toHaveLength(4);
    });

    test('lets a load store its keys when the refetch that finished meanwhile was for another agent', async () => {
      // A refetch of another agent finishes while the load of this one runs. It says nothing about this agent.
      let release: () => void = () => undefined;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      const { fetcher, calls } = createFetcher((url, init) => {
        if (url === JWKS_URI) {
          return released.then(() => json({ keys: [PUBLIC_KEY] }));
        }
        return agentsHandler(CIMD_URL, OTHER_CIMD_URL)(url, init);
      });

      const load = fetcher.getKeys(CIMD_URL);
      await fetcher.refreshKeys(OTHER_CIMD_URL);
      release();

      // The load gives its own keys, and not the keys of the other agent, and it stores them.
      expect(await load).toEqual({ cimdUrl: CIMD_URL, jwksUri: JWKS_URI, keys: [PUBLIC_KEY] });
      expect((await fetcher.getKeys(CIMD_URL)).keys).toEqual([PUBLIC_KEY]);
      expect(calls).toHaveLength(4);
    });

    test('forgets a refetch that has finished, so a later one fetches again', async () => {
      pinClock();
      const { fetcher, calls } = createFetcher();

      const first = fetcher.refreshKeys(CIMD_URL);
      await first;
      advance(UNKNOWN_KID_REFETCH_INTERVAL_MS);
      const [second, third] = await Promise.all([fetcher.refreshKeys(CIMD_URL), fetcher.refreshKeys(CIMD_URL)]);

      expect(second).toBeDefined();
      expect(third).toBeDefined();
      expect(calls).toHaveLength(4);
    });
  });
});
