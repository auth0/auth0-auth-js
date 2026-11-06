import type { JWK } from 'jose';
import { LruCache } from '../lru-cache.js';
import {
  DEFAULT_AGENT_METADATA_CACHE_MAX_ENTRIES,
  FAILED_FETCH_CACHE_MS,
  MAX_AGENT_KEYS,
  POPPY_UNAVAILABLE_MESSAGE,
  PRIVATE_KEY_MEMBERS,
  UNKNOWN_KID_REFETCH_INTERVAL_MS,
} from './constants.js';
import { InvalidSessionError, PoppyUnavailableError } from './errors.js';
import { isRecord } from './is-record.js';
import type { ResolvedPoppyOptions } from './options.js';
import { isAgentUrl, isPublicHostname, sameHostname } from './url-rules.js';

// Fetches the client metadata of a Personal Agent and the keys it points to, and keeps them for a while.
//
// This is the one place where the SDK makes a request to a URL that the other party chose: the `iss` of a Session JWT
// is the agent's own URL, and an agent that is not trusted can aim it, and the `jwks_uri` it names, at anything. Every
// rule below is a guard against that, against a host that is slow or huge, or against keys that should not be there. It
// fails closed: whatever it cannot show to be fine is refused.
//
// Spec: https://personalagentprotocol.org/docs/0.3/spec, section 3 (HTTPS, redirects and addresses), section 4.1 (agent
// identity) and section 5.3, step 1 (the fetch), and "Fetching metadata safely" in the guides.

/**
 * The diagnostic codes of the errors that this module throws. The code is in `error.cause.code`, for logs and tests.
 *
 * The message of an error is a fixed text that says which rule failed. The status, the body and the headers of a
 * response, the text of a network error and the address a name resolved to never go into a message, because they come
 * from a host that is not trusted, and a message goes back to the agent as its `error_description`.
 *
 * Refused before anything is fetched, with the reason `agent_not_allowed`:
 * - `agent_url_invalid`: the agent URL is not an https URL in canonical form ({@link isAgentUrl}).
 * - `agent_address_not_allowed`: the host is `localhost`, a private, loopback or link-local address, or a name that
 *   only a local network can resolve (a name with no dot, or one under `.local`, `.internal`, `.localdomain` or
 *   `.home.arpa`; see {@link isPublicHostname}), and private addresses were not allowed on purpose.
 *
 * A problem with the agent that a new try does not fix, with the reason `agent_metadata_invalid`. The first five apply
 * to both documents, the client metadata and the key set, and the message says which one:
 * - `metadata_redirect`: a redirect, which the protocol never follows.
 * - `metadata_status`: a status that is not 200, and is not a redirect, a 429 or a 5xx.
 * - `metadata_too_large`: a body over the size limit, by its `content-length` or by the bytes that came.
 * - `metadata_body_invalid`: a body that gives {@link MAX_EMPTY_CHUNKS_IN_A_ROW} chunks with no byte in them, one after
 *   the other. Reading a body like this never gives the timer of the time limit a turn, so only a count can stop it.
 * - `metadata_not_json`: a body that is not UTF-8, not JSON, or not a JSON object.
 * - `client_id_mismatch`: the `client_id` of the metadata is not the URL it was fetched from.
 * - `jwks_uri_invalid`: the `jwks_uri` is not an agent URL on the same host as the `client_id`, or its host is not a
 *   public one.
 * - `jwks_invalid`: `keys` is not an array of 1 to {@link MAX_AGENT_KEYS} JSON objects that each have a string `kty`,
 *   or a key has a member that is not a string, a boolean, a finite number or an array of strings.
 * - `jwks_private_key`: a key has a private member.
 *
 * A problem that may pass, which is a {@link PoppyUnavailableError}:
 * - `upstream_unavailable`: the host answered 429 or 5xx.
 * - `fetch_timeout`: the host did not answer, or did not finish its body, within the time limit.
 * - `fetch_failed`: the fetch failed in another way, such as a refused connection or a body that broke off.
 */
type ProblemCode =
  | 'agent_url_invalid'
  | 'agent_address_not_allowed'
  | 'metadata_redirect'
  | 'metadata_status'
  | 'metadata_too_large'
  | 'metadata_body_invalid'
  | 'metadata_not_json'
  | 'client_id_mismatch'
  | 'jwks_uri_invalid'
  | 'jwks_invalid'
  | 'jwks_private_key'
  | 'upstream_unavailable'
  | 'fetch_timeout'
  | 'fetch_failed';

/** Which of the two documents of an agent a message is about. */
type DocumentName = 'metadata' | 'key set';

interface ProblemDefinition {
  /** The reason of the `invalid_session` error. `undefined` is a problem that may pass, which is a 503. */
  readonly reason?: 'agent_not_allowed' | 'agent_metadata_invalid';
  /** The fixed message. */
  readonly message: (document: DocumentName) => string;
}

const PROBLEMS: Record<ProblemCode, ProblemDefinition> = {
  agent_url_invalid: {
    reason: 'agent_not_allowed',
    message: () => 'The agent URL must be an https URL in canonical form, without credentials or a fragment.',
  },
  agent_address_not_allowed: {
    reason: 'agent_not_allowed',
    message: () => "The agent's URL is on localhost or on a private, loopback or link-local address.",
  },
  metadata_redirect: {
    reason: 'agent_metadata_invalid',
    message: (document) => `The agent's ${document} redirected; redirects aren't followed.`,
  },
  metadata_status: {
    reason: 'agent_metadata_invalid',
    message: (document) => `The agent's ${document} must be served with status 200.`,
  },
  metadata_too_large: {
    reason: 'agent_metadata_invalid',
    message: (document) => `The agent's ${document} is larger than the size limit.`,
  },
  metadata_body_invalid: {
    reason: 'agent_metadata_invalid',
    message: (document) => `The agent's ${document} body sent too many empty chunks in a row.`,
  },
  metadata_not_json: {
    reason: 'agent_metadata_invalid',
    message: (document) => `The agent's ${document} is not a UTF-8 encoded JSON object.`,
  },
  client_id_mismatch: {
    reason: 'agent_metadata_invalid',
    message: () => "The client_id in the agent's metadata is not the URL the metadata was fetched from.",
  },
  jwks_uri_invalid: {
    reason: 'agent_metadata_invalid',
    message: () => "The jwks_uri in the agent's metadata must be an https URL on the same host as its client_id.",
  },
  jwks_invalid: {
    reason: 'agent_metadata_invalid',
    message: () =>
      `The agent's key set must have 1 to ${MAX_AGENT_KEYS} keys. ` +
      'Each key needs a kty, and its members must be strings, booleans, numbers or arrays of strings.',
  },
  jwks_private_key: {
    reason: 'agent_metadata_invalid',
    message: () => "The agent's key set has a key with a private member. A key set must have public keys only.",
  },
  upstream_unavailable: { message: () => POPPY_UNAVAILABLE_MESSAGE },
  fetch_timeout: { message: () => POPPY_UNAVAILABLE_MESSAGE },
  fetch_failed: { message: () => POPPY_UNAVAILABLE_MESSAGE },
};

/** A problem, as plain data: what the failure cache keeps, and what an error is made from. */
interface Problem {
  readonly code: ProblemCode;
  readonly reason: 'agent_not_allowed' | 'agent_metadata_invalid' | undefined;
  readonly message: string;
}

function problemFor(code: ProblemCode, document: DocumentName = 'metadata'): Problem {
  const { reason, message } = PROBLEMS[code];
  return { code, reason, message: message(document) };
}

/** What the code in this module throws. It never leaves: `getKeys` and `refreshKeys` turn it into a public error. */
class ProblemError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.message);
    this.name = 'ProblemError';
    this.problem = problem;
  }
}

/**
 * A new error each time, so callers never share an error, a header object or a stack.
 *
 * @param retryAfter - The seconds a 503 tells the caller to wait. The default of {@link PoppyUnavailableError} when not
 * given. A problem of the agent has no such wait.
 */
function toError(problem: Problem, retryAfter?: number): InvalidSessionError | PoppyUnavailableError {
  const error =
    problem.reason === undefined
      ? new PoppyUnavailableError(problem.message, retryAfter)
      : new InvalidSessionError(problem.reason, problem.message);
  error.cause = { code: problem.code };
  return error;
}

/** A problem that `getKeys` remembers, and the time it was found, in milliseconds since the epoch. */
interface Failure {
  readonly problem: Problem;
  readonly at: number;
}

/**
 * The error for a failure that is served from memory. A 503 tells the caller to wait for what is left of the
 * {@link FAILED_FETCH_CACHE_MS} that the failure is remembered, in whole seconds, rounded up and at least 1. An agent
 * that is told to wait 30 seconds a second time has waited for nothing.
 */
function toRememberedError(failure: Failure): InvalidSessionError | PoppyUnavailableError {
  const secondsLeft = Math.ceil((failure.at + FAILED_FETCH_CACHE_MS - Date.now()) / 1000);
  return toError(failure.problem, Math.max(1, secondsLeft));
}

/** The public error for a problem of this module. Anything else is a bug, and is left as it is. */
function publicError(error: unknown): unknown {
  return error instanceof ProblemError ? toError(error.problem) : error;
}

/**
 * The keys of an agent, as {@link AgentMetadataFetcher.getKeys} and {@link AgentMetadataFetcher.refreshKeys} return
 * them.
 */
export interface AgentKeys {
  /** The URL of the client metadata of the agent, which is its `client_id`. */
  cimdUrl: string;
  /** The `jwks_uri` of the metadata: the URL the keys came from. */
  jwksUri: string;
  /**
   * The keys of the key set, at most {@link MAX_AGENT_KEYS}. They are public keys: a set with a private member is
   * refused. Every member of a key is a string, a boolean, a finite number or an array of strings: a key with any other
   * member is refused too. Every call gets copies, so changing them changes nothing for anyone else.
   */
  keys: JWK[];
}

// A body that gives this many empty chunks in a row is refused. A read loop that only meets empty chunks runs at the
// speed of microtasks, so the timer of the time limit never gets a turn, and the byte limit does not count them. Only a
// count of the chunks can stop it.
const MAX_EMPTY_CHUNKS_IN_A_ROW = 1000;

// A `content-length` is digits and nothing else. Anything else, such as two values joined by a comma, is not trusted.
const CONTENT_LENGTH_PATTERN = /^\d+$/;

/**
 * Settles as `work()` does, or rejects as soon as `signal` aborts, whichever comes first. A `fetch` or a body that
 * ignores the signal cannot hold the caller past it. The listener on the signal is removed once either has happened,
 * and the module makes no timer of its own, so nothing is left behind.
 *
 * @param discardLate - Called with the value of `work()` when it arrives after the abort, so it can release it.
 */
function untilAborted<T>(signal: AbortSignal, work: () => Promise<T>, discardLate?: (late: T) => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    let abortedFirst = false;
    const onAbort = (): void => {
      abortedFirst = true;
      reject(signal.reason);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    // An async function, so `work` can throw at once and it is still a rejection. Both handlers below take every
    // outcome, so a rejection that comes after the abort is never unhandled.
    (async () => work())().then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        if (abortedFirst) {
          discardLate?.(value);
        } else {
          resolve(value);
        }
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}

/** Gives up the body of a response that will not be read, so the connection is free. It never throws. */
function cancelBody(response: Response): void {
  try {
    response.body?.cancel().catch(() => undefined);
  } catch {
    // The body is unusable already, so there is nothing to give up.
  }
}

/** Stops a body that is being read, without waiting for the source to say it has stopped. It never throws. */
function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.cancel().catch(() => undefined);
  } catch {
    // The stream is unusable already, so there is nothing to stop.
  }
}

/** The problem with a response before its body is read, or `undefined` when the response can be read. */
function refusalOf(response: Response, maxBytes: number): ProblemCode | undefined {
  const { status } = response;
  // `redirect: 'manual'` gives the redirect itself in Node, Bun, Deno and Workers, and an opaque one in a browser.
  if (response.type === 'opaqueredirect' || (status >= 300 && status < 400)) {
    return 'metadata_redirect';
  }
  if (status === 429 || (status >= 500 && status < 600)) {
    return 'upstream_unavailable';
  }
  if (status !== 200) {
    return 'metadata_status';
  }
  const declared = response.headers.get('content-length');
  if (declared !== null && CONTENT_LENGTH_PATTERN.test(declared) && Number(declared) > maxBytes) {
    return 'metadata_too_large';
  }
  return undefined;
}

// The size the buffer of a body starts with, in bytes. A body that is small, as the documents of an agent are, never
// needs more.
const INITIAL_BODY_BUFFER_BYTES = 16384;

/**
 * Reads the body of a response, up to `maxBytes`. Every read waits for the signal at most, so a body that stalls does
 * not hold the caller, and a body that is over the limit, has stalled or sends only empty chunks is cancelled, and not
 * read to its end.
 *
 * Each chunk is copied into one buffer as soon as it is read, and the chunk is let go. A host chooses how it frames its
 * body, so it can send the bytes of a body in many tiny chunks, and a list of the chunks would cost an object for each
 * of them, many times the size of the body. The buffer starts small, doubles as the body comes, and never grows past
 * `maxBytes`, so what is held is about the bytes that came.
 */
async function readBody(
  response: Response,
  signal: AbortSignal,
  maxBytes: number,
  document: DocumentName
): Promise<Uint8Array> {
  const stream = response.body;
  if (!stream) {
    // A response without a body stream is read whole, and its size is checked after the fact.
    const bytes = new Uint8Array(await untilAborted(signal, () => response.arrayBuffer()));
    if (bytes.byteLength > maxBytes) {
      throw new ProblemError(problemFor('metadata_too_large', document));
    }
    return bytes;
  }

  const reader = stream.getReader();
  let buffer = new Uint8Array(Math.min(maxBytes, INITIAL_BODY_BUFFER_BYTES));
  let length = 0;
  let emptyInARow = 0;
  try {
    for (;;) {
      const { done, value } = await untilAborted(signal, () => reader.read());
      if (done) {
        break;
      }
      if (value.byteLength === 0) {
        emptyInARow += 1;
        if (emptyInARow >= MAX_EMPTY_CHUNKS_IN_A_ROW) {
          throw new ProblemError(problemFor('metadata_body_invalid', document));
        }
        continue;
      }
      emptyInARow = 0;
      const needed = length + value.byteLength;
      if (needed > maxBytes) {
        throw new ProblemError(problemFor('metadata_too_large', document));
      }
      if (needed > buffer.byteLength) {
        const grown = new Uint8Array(Math.min(maxBytes, Math.max(buffer.byteLength * 2, needed)));
        grown.set(buffer.subarray(0, length));
        buffer = grown;
      }
      buffer.set(value, length);
      length = needed;
    }
  } catch (error) {
    cancelReader(reader);
    throw error;
  }
  return buffer.subarray(0, length);
}

/** Decodes a body as UTF-8, which is checked, and parses it as JSON. `undefined` when it is not a JSON object. */
function parseJsonObject(bytes: Uint8Array): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether a member of a key can be kept: a string, a boolean, a finite number or an array of strings. That is every
 * member a JWK has (RFC 7517 section 4, RFC 7518 sections 6.2 to 6.4, RFC 8037 section 2), except `oth`, an array of
 * objects, which is a private member and is refused for that. A member is never an object and an array never holds an
 * array, so a key is two levels deep at most. Whatever walks a key, such as the copy for a caller, needs no recursion,
 * and a host that nests a member thousands of levels deep, in a few KB of JSON, cannot make that code run out of stack.
 */
function isKeyMember(value: unknown): boolean {
  return (
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value)) ||
    (Array.isArray(value) && value.every((item) => typeof item === 'string'))
  );
}

/** The keys of a key set, checked. */
function readKeys(value: unknown): JWK[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_AGENT_KEYS) {
    throw new ProblemError(problemFor('jwks_invalid'));
  }
  const keys: JWK[] = [];
  for (const key of value as unknown[]) {
    if (!isRecord(key) || typeof key.kty !== 'string') {
      throw new ProblemError(problemFor('jwks_invalid'));
    }
    // The name is what counts, and not the value: a `d` that is empty or null is still a key that has a `d`. It is
    // checked before the values, so a private member is reported as one, whatever it holds.
    if (PRIVATE_KEY_MEMBERS.some((member) => Object.hasOwn(key, member))) {
      throw new ProblemError(problemFor('jwks_private_key'));
    }
    if (!Object.values(key).every(isKeyMember)) {
      throw new ProblemError(problemFor('jwks_invalid'));
    }
    keys.push(key as JWK);
  }
  return keys;
}

/**
 * A copy that shares nothing with `keys`, not even the arrays inside a key. It goes one level into a key and no deeper,
 * because a key has nothing deeper (see {@link isKeyMember}). It does not use `structuredClone`, which recurses, and so
 * is not safe on data from a host that is not trusted. The members are defined with `fromEntries` and not assigned, so
 * a member called `__proto__` stays a member of the copy and does not change its prototype.
 */
function copyOf(keys: AgentKeys): AgentKeys {
  return {
    cimdUrl: keys.cimdUrl,
    jwksUri: keys.jwksUri,
    keys: keys.keys.map((key) =>
      Object.fromEntries(Object.entries(key).map(([name, value]) => [name, Array.isArray(value) ? [...value] : value]))
    ),
  };
}

/**
 * Fetches the client metadata of an agent and its keys, checks them, and caches them: the keys for `ttlMs`, and a
 * failure for {@link FAILED_FETCH_CACHE_MS}. Calls that run together for one agent share one load.
 *
 * What it does for every URL:
 * - Before any fetch, the agent URL must be an agent URL ({@link isAgentUrl}). Unless `allowPrivateAddresses` is on,
 *   its host must be a public one ({@link isPublicHostname}).
 * - The metadata is fetched from the agent URL, and its `client_id` must equal that URL. Its `jwks_uri` must be an
 *   agent URL on the same host, and the key set is fetched from there. Redirects are not followed, for either
 *   document.
 * - Each document has one time limit that covers the request and the whole body, and a size limit. A body is never read
 *   past its limit, and a body that only gives empty chunks is stopped. The body must be UTF-8 and a JSON object.
 * - The key set must have 1 to {@link MAX_AGENT_KEYS} keys. Every key must be a JSON object with a string `kty`, no
 *   private member, and no member but strings, booleans, finite numbers and arrays of strings, or the whole set is
 *   refused. That keeps a key shallow, so a copy of it cannot fail, and a set that is refused never reaches the cache.
 *
 * The `fetch` of the options is called as `fetch(url, { method: 'GET', redirect: 'manual', headers: { accept:
 * 'application/json' }, signal })`, and nothing else is sent: no cookie, no credentials, no authorization. It must not
 * follow redirects, and it should stop when the `signal` aborts. The time limit is kept here as well, so a `fetch` that
 * ignores the signal still cannot hold a request. It checks the text of a hostname and cannot see where a name resolves
 * to, so a name that points to an internal address needs a `fetch` or a proxy that guards against it.
 *
 * Every error is an {@link InvalidSessionError} for a problem with the agent, or a {@link PoppyUnavailableError} for a
 * problem that may pass. Each has a fixed message, and a code in `cause`. See the `ProblemCode` type for the codes.
 *
 * There are three caches. The keys are kept for `ttlMs`, and at most `maxEntries` agents have keys in the cache, the
 * least recently used going first. With `ttlMs` or `maxEntries` of 0 no keys are kept, so every call fetches again,
 * though calls that run together still share one load. The failures and the times of the refetches are two guards, and
 * the cache options do not switch them off: they always hold, for at most `max(maxEntries, 100)` agents each. A host
 * that is down is not asked again for {@link FAILED_FETCH_CACHE_MS}, and the keys of an agent are not refetched more
 * than once every {@link UNKNOWN_KID_REFETCH_INTERVAL_MS}, whatever the cache options are.
 *
 * `options.timeoutMs` goes to `AbortSignal.timeout` as it is. It must be a whole number from 1 to 2147483647, which
 * the options check when they are resolved. This class does not check it again.
 */
export class AgentMetadataFetcher {
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maxBytes: number;
  readonly #allowPrivateAddresses: boolean;
  /** The keys of the agents that were fetched, for `ttlMs`. */
  readonly #keys: LruCache<AgentKeys>;
  /** The failures of `getKeys`, for `FAILED_FETCH_CACHE_MS`. `null` is a failure that a refetch has replaced. */
  readonly #failures: LruCache<Failure | null>;
  /** The agents that were refetched lately, for `UNKNOWN_KID_REFETCH_INTERVAL_MS`, failed refetches included. */
  readonly #throttle: LruCache<true>;
  /** The loads of `getKeys` that are running, one for each agent. */
  readonly #loads = new Map<string, Promise<AgentKeys>>();
  /**
   * For each agent with a running load that a refetch has finished for since the load began: the keys of the last such
   * refetch. The load began before them, so what it brings is not newer, and a failure of it is not newer either.
   * Whether it works or fails, it gives its callers these keys and changes nothing in the caches. Only the agents with
   * a running load are in it, so it cannot grow past the loads.
   */
  readonly #overtaken = new Map<string, AgentKeys>();
  /** The refetches that are running, one for each agent. */
  readonly #refetches = new Map<string, Promise<AgentKeys>>();

  /**
   * @param options - The resolved `agentMetadata` options. They are read here, once, and not again.
   */
  constructor(options: ResolvedPoppyOptions['agentMetadata']) {
    this.#fetch = options.fetch;
    this.#timeoutMs = options.timeoutMs;
    this.#maxBytes = options.maxBytes;
    this.#allowPrivateAddresses = options.allowPrivateAddresses;
    this.#keys = new LruCache<AgentKeys>(options.ttlMs, options.maxEntries);
    // Two guards against a host that is down or slow, and not a cache of anything good. A `maxEntries` of 0 is a choice
    // not to keep keys, and must not take the guards away, so they keep room for as many agents as the default does.
    const guardEntries = Math.max(options.maxEntries, DEFAULT_AGENT_METADATA_CACHE_MAX_ENTRIES);
    this.#failures = new LruCache<Failure | null>(FAILED_FETCH_CACHE_MS, guardEntries);
    this.#throttle = new LruCache<true>(UNKNOWN_KID_REFETCH_INTERVAL_MS, guardEntries);
  }

  /**
   * Gets the keys of an agent: from the cache when they are there, and else from the agent. A failure is cached for
   * {@link FAILED_FETCH_CACHE_MS}, so a host that is down is not asked again at once, and an error of that time is
   * rethrown as a new one of the same class, with the same reason, message and cause. A 503 that is rethrown tells the
   * caller to wait for the seconds that are left of that time, rounded up, and not for the whole of it again.
   *
   * @param cimdUrl - The URL of the client metadata of the agent, which is the `iss` of its Session JWT.
   * @returns The keys, as copies.
   * @throws {InvalidSessionError} With reason `agent_not_allowed` when `cimdUrl` is not an agent URL or has a host that
   * is not allowed, and with reason `agent_metadata_invalid` when the metadata or the keys can't be used.
   * @throws {PoppyUnavailableError} When the host can't be reached in time, or answers 429 or 5xx.
   */
  async getKeys(cimdUrl: string): Promise<AgentKeys> {
    this.#assertAllowed(cimdUrl);
    const cached = this.#keys.get(cimdUrl);
    if (cached !== undefined) {
      return copyOf(cached);
    }
    const failure = this.#failures.get(cimdUrl);
    if (failure) {
      throw toRememberedError(failure);
    }
    // Calls that run together share one load. It is kept here, and not in the cache, because whether its keys are
    // stored is decided when it ends (see `#load`).
    let load = this.#loads.get(cimdUrl);
    if (load === undefined) {
      // `finally` runs after `set` below, even when `#load` fails at once, so the entries are always removed. Both go
      // in the same step, so a flag of this load cannot be taken for one of the next.
      load = this.#load(cimdUrl).finally(() => {
        this.#loads.delete(cimdUrl);
        this.#overtaken.delete(cimdUrl);
      });
      this.#loads.set(cimdUrl, load);
    }
    try {
      return copyOf(await load);
    } catch (error) {
      throw publicError(error);
    }
  }

  /**
   * Refetches the metadata and the keys of an agent, past the cache, for a key ID that is not in the keys it has. At
   * most once every {@link UNKNOWN_KID_REFETCH_INTERVAL_MS} for each agent, because anyone can send a Session JWT that
   * names a real agent and a made-up key ID, and each one would otherwise make a request to the host of that agent. A
   * refetch that fails counts too.
   *
   * Calls that run together share one refetch. A refetch that works replaces the cached keys. A load of `getKeys` that
   * is still running then changes nothing in the caches, and its callers get the keys of the refetch, whether the load
   * works or fails. A refetch that fails changes nothing: the cached keys stay, and no failure is cached, but the
   * interval still counts. The interval does not depend on the cache options.
   *
   * @param cimdUrl - The URL of the client metadata of the agent.
   * @returns The new keys as copies, or `undefined` when the last refetch of this agent was less than the interval ago.
   * @throws {InvalidSessionError} As {@link AgentMetadataFetcher.getKeys}.
   * @throws {PoppyUnavailableError} As {@link AgentMetadataFetcher.getKeys}.
   */
  async refreshKeys(cimdUrl: string): Promise<AgentKeys | undefined> {
    this.#assertAllowed(cimdUrl);
    let refetch = this.#refetches.get(cimdUrl);
    if (refetch === undefined) {
      if (this.#throttle.get(cimdUrl) !== undefined) {
        return undefined;
      }
      this.#throttle.set(cimdUrl, true);
      // `finally` runs after `set` below, even when `#refetch` fails at once, so the entry is always removed.
      refetch = this.#refetch(cimdUrl).finally(() => {
        this.#refetches.delete(cimdUrl);
      });
      this.#refetches.set(cimdUrl, refetch);
    }
    try {
      return copyOf(await refetch);
    } catch (error) {
      throw publicError(error);
    }
  }

  /** The checks that come before any fetch, which are refusals. They are cheap, so they are not cached. */
  #assertAllowed(cimdUrl: string): void {
    if (!isAgentUrl(cimdUrl)) {
      throw toError(problemFor('agent_url_invalid'));
    }
    if (!this.#allowPrivateAddresses && !isPublicHostname(new URL(cimdUrl).hostname)) {
      throw toError(problemFor('agent_address_not_allowed'));
    }
  }

  /**
   * Loads the keys for `getKeys`. When it works it stores the keys, and when it fails with a problem it remembers the
   * failure.
   *
   * When a refetch of the agent has finished while the load ran, the keys of that refetch are newer than what the load
   * brings, whether that is keys or a failure. The load then changes nothing in the caches, and gives its callers the
   * keys of the refetch. Its callers include every call that joined it. If they got the older keys, they would not find
   * a key ID that the refetch has just brought, ask for a refetch, be held back by the interval, and fail on a key that
   * the cache has. If they got the failure, they would fail although the cache has keys. A failure that was remembered
   * would also be served as soon as those keys expire, within 30 seconds of a refetch that worked. A load that no
   * refetch overtook is not changed by any of this.
   */
  async #load(cimdUrl: string): Promise<AgentKeys> {
    try {
      const keys = await this.#fetchKeys(cimdUrl);
      const newer = this.#overtaken.get(cimdUrl);
      if (newer !== undefined) {
        return newer;
      }
      this.#keys.set(cimdUrl, keys);
      return keys;
    } catch (error) {
      if (error instanceof ProblemError) {
        const newer = this.#overtaken.get(cimdUrl);
        if (newer !== undefined) {
          return newer;
        }
        this.#failures.set(cimdUrl, { problem: error.problem, at: Date.now() });
      }
      throw error;
    }
  }

  /** Loads the keys for `refreshKeys`. It keeps what the cache has when it fails, and writes no failure. */
  async #refetch(cimdUrl: string): Promise<AgentKeys> {
    const keys = await this.#fetchKeys(cimdUrl);
    this.#keys.set(cimdUrl, keys);
    // A load of `getKeys` that runs now began before these keys came, so what it brings is not newer than these, and
    // neither is a failure of it. It gives its callers these keys, and stores nothing and remembers nothing. A later
    // refetch that ends during the load replaces them.
    if (this.#loads.has(cimdUrl)) {
      this.#overtaken.set(cimdUrl, keys);
    }
    // A failure that `getKeys` remembered is older than these keys. It must not be served when the keys have expired.
    if (this.#failures.get(cimdUrl)) {
      this.#failures.set(cimdUrl, null);
    }
    return keys;
  }

  async #fetchKeys(cimdUrl: string): Promise<AgentKeys> {
    const metadata = await this.#fetchDocument(cimdUrl, 'metadata');
    if (metadata.client_id !== cimdUrl) {
      throw new ProblemError(problemFor('client_id_mismatch'));
    }
    const jwksUri = metadata.jwks_uri;
    if (!this.#isJwksUriAllowed(jwksUri, cimdUrl)) {
      throw new ProblemError(problemFor('jwks_uri_invalid'));
    }
    const jwks = await this.#fetchDocument(jwksUri, 'key set');
    return { cimdUrl, jwksUri, keys: readKeys(jwks.keys) };
  }

  /**
   * Spec section 4.1: the `jwks_uri` is an HTTPS URL on the same domain as the `client_id`. The SDK reads "same
   * domain" strictly, as the same hostname, because the public suffix list is not at hand. The check of the address
   * cannot fail while `#assertAllowed` has accepted that hostname. It stays so the `jwks_uri` rule holds on its own,
   * and does not depend on the check of the agent URL that runs before it.
   */
  #isJwksUriAllowed(jwksUri: unknown, cimdUrl: string): jwksUri is string {
    return (
      isAgentUrl(jwksUri) &&
      sameHostname(jwksUri, cimdUrl) &&
      (this.#allowPrivateAddresses || isPublicHostname(new URL(jwksUri).hostname))
    );
  }

  /** One request, one time limit, and one size limit. The result is the JSON object of the document. */
  async #fetchDocument(url: string, document: DocumentName): Promise<Record<string, unknown>> {
    const signal = AbortSignal.timeout(this.#timeoutMs);
    // A local, so the call below is a plain function call. `this.#fetch(...)` would give the function a receiver, and
    // the global `fetch` of Workers throws "Illegal invocation" with one.
    const plainFetch = this.#fetch;
    try {
      const response = await untilAborted(
        signal,
        () => plainFetch(url, { method: 'GET', redirect: 'manual', headers: { accept: 'application/json' }, signal }),
        cancelBody
      );
      const refusal = refusalOf(response, this.#maxBytes);
      if (refusal !== undefined) {
        cancelBody(response);
        throw new ProblemError(problemFor(refusal, document));
      }
      const parsed = parseJsonObject(await readBody(response, signal, this.#maxBytes, document));
      if (parsed === undefined) {
        throw new ProblemError(problemFor('metadata_not_json', document));
      }
      return parsed;
    } catch (error) {
      if (error instanceof ProblemError) {
        throw error;
      }
      // The fetch failed or was cut off. What it said is not kept: it can hold an address, and it is not for the agent.
      throw new ProblemError(problemFor(signal.aborted ? 'fetch_timeout' : 'fetch_failed', document));
    }
  }
}
