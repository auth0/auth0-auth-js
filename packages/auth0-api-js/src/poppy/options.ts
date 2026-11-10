import { InvalidConfigurationError } from '../errors.js';
import type { ApiClientOptions } from '../types.js';
import {
  DEFAULT_AGENT_METADATA_CACHE_MAX_ENTRIES,
  DEFAULT_AGENT_METADATA_CACHE_TTL_SECONDS,
  DEFAULT_AGENT_METADATA_MAX_BYTES,
  DEFAULT_AGENT_METADATA_TIMEOUT_MS,
  DEFAULT_IAT_WINDOW_SECONDS,
  MAX_AGENT_METADATA_TIMEOUT_MS,
  MAX_URL_LENGTH,
} from './constants.js';
import { isRecord } from './is-record.js';
import type { PoppySessionStore } from './session-store.js';
import { agentUrlProblem, isHttpsOrigin, isPublicHostname, parseUrl, type AgentUrlProblem } from './url-rules.js';

/**
 * The `poppy` option of `ApiClient`, checked, with every default applied. The client builds it once, in its
 * constructor, and never reads the options object it was given again, so changing that object later changes nothing.
 */
export interface ResolvedPoppyOptions {
  /** Whether to verify the `Poppy-Session` header of every request that carries one. */
  verifySession: boolean;
  /** The registered agents: `poppy.agents`, in a copy. `undefined` means there is no list. */
  agents?: ReadonlySet<string>;
  /** The store of known Sessions. Passed through as given: TypeScript is the contract. */
  sessionStore?: PoppySessionStore;
  /** How far the `iat` of a Session JWT may be from the current time, in seconds, in both directions. */
  iatWindowSeconds: number;
  /**
   * The public origin of the API: `poppy.publicOrigin`. It is the `origin` of a URL, so the host is in lower case, a
   * default port is dropped and there is no trailing slash. `undefined` when it is not set.
   */
  publicOrigin?: string;
  /** How to fetch the client metadata and the keys of an agent. */
  agentMetadata: {
    /**
     * A wrapper that calls the `fetch` that was given, or else the global one, as a plain function. Workers can throw
     * "Illegal invocation" when the global `fetch` is called with another receiver, so the wrapper keeps both working,
     * wherever it is called from.
     */
    fetch: typeof fetch;
    /** How long the cache keeps an entry, in milliseconds. */
    ttlMs: number;
    /** How many agents the cache keeps. */
    maxEntries: number;
    /** The time limit for one request, in milliseconds. */
    timeoutMs: number;
    /** The size limit for one response body, in bytes. */
    maxBytes: number;
    /** Whether agent URLs on `localhost` and on private, loopback and link-local addresses are accepted. */
    allowPrivateAddresses: boolean;
  };
}

const MESSAGE_PREFIX = 'Invalid poppy configuration: ';
// The longest value a message repeats.
const MAX_SHOWN_LENGTH = 200;

function invalid(message: string): InvalidConfigurationError {
  return new InvalidConfigurationError(`${MESSAGE_PREFIX}${message}`);
}

// Text that starts with `http://` or `https://` and has no `@` (user info), `?` (query) or `#` (fragment).
const SHOWABLE_URL_PATTERN = /^https?:\/\/[^@?#]*$/i;

/**
 * Whether a configured URL can be repeated in a message. These values are meant to be public URLs, but a mistake can
 * put something else in their place, such as a token, or a connection string with a password. A text such as
 * `admin:secret` even parses as a URL, with `admin` as its scheme. So only a short text that starts with `http://` or
 * `https://`, has no `@`, `?` or `#`, and parses as a URL is repeated.
 */
function canShow(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= MAX_SHOWN_LENGTH &&
    SHOWABLE_URL_PATTERN.test(value) &&
    parseUrl(value) !== undefined
  );
}

/** ` ("value")`, to put after the name of a field, or nothing when the value cannot be repeated. */
function shown(value: unknown): string {
  return canShow(value) ? ` (${JSON.stringify(value)})` : '';
}

function readBoolean(field: string, value: unknown, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'boolean') {
    throw invalid(`"${field}" must be a boolean`);
  }
  return value;
}

/** The rules of `discoveryCache` for its `ttl` and `maxEntries`: a finite number that is not negative. */
function readNonNegative(field: string, value: unknown, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw invalid(`"${field}" must be a number`);
  }
  if (value < 0) {
    throw invalid(`"${field}" must be a non-negative number`);
  }
  return value;
}

/** The message for an entry of `agents` that is not an agent URL. */
function agentUrlError(name: string, entry: unknown, problem: AgentUrlProblem): InvalidConfigurationError {
  switch (problem) {
    case 'not_a_string':
      return invalid(`"${name}" must be a string, the URL of an agent's client metadata`);
    case 'too_long':
      return invalid(`"${name}" is longer than ${MAX_URL_LENGTH} characters`);
    case 'not_a_url':
      return invalid(
        `"${name}" is not a valid URL. Use the https URL of an agent's client metadata, for example "https://agent.example/agent.json".`
      );
    case 'not_https':
      return invalid(`"${name}"${shown(entry)} must be an https URL`);
    case 'has_credentials':
      return invalid(`"${name}" must not contain a username or password`);
    case 'has_fragment':
      return invalid(`"${name}" must not contain a fragment (#)`);
    case 'not_canonical': {
      const canonical = canShow(entry) ? parseUrl(entry)?.href : undefined;
      return invalid(
        canonical === undefined
          ? `"${name}" is not in canonical form: use a lower-case host, a path (at least "/"), no default port, no dot segments and no characters that need escaping. Agent URLs are compared character by character.`
          : `"${name}" (${JSON.stringify(entry)}) is not in canonical form: expected ${JSON.stringify(canonical)}. Agent URLs are compared character by character.`
      );
    }
  }
}

/** Checks the list of agent URLs and returns it as a set. */
function readAgents(value: unknown, allowPrivateAddresses: boolean): ReadonlySet<string> {
  const field = 'agents';
  if (!Array.isArray(value)) {
    throw invalid(`"${field}" must be an array of agent URLs`);
  }
  // A copy, checked and then used, so that changing the caller's array later changes nothing.
  const entries: unknown[] = Array.from(value);
  const urls = new Set<string>();
  for (const [index, entry] of entries.entries()) {
    const name = `${field}[${index}]`;
    const problem = agentUrlProblem(entry);
    if (problem !== undefined) {
      throw agentUrlError(name, entry, problem);
    }
    // Without a problem, the entry is an agent URL, which is a string.
    const url = entry as string;
    if (!allowPrivateAddresses && !isPublicHostname(new URL(url).hostname)) {
      throw invalid(
        `"${name}"${shown(url)} is on localhost, on a private, loopback or link-local address, or on a name with no dot or under .local, .internal, .localdomain or .home.arpa. Section 3 of the Poppy specification forbids connecting to these unless you allow it on purpose. For local development, set "agentMetadata.allowPrivateAddresses" to true.`
      );
    }
    urls.add(url);
  }
  return urls;
}

/** Checks an `https:` origin and returns it in the form of `URL.origin`. */
function readOrigin(field: string, value: unknown): string {
  if (!isHttpsOrigin(value)) {
    throw originError(field, value);
  }
  return new URL(value).origin;
}

function originError(field: string, value: unknown): InvalidConfigurationError {
  const url = canShow(value) ? parseUrl(value) : undefined;
  const suggestion = url?.protocol === 'https:' ? ` Use "${url.origin}".` : '';
  return invalid(
    `"${field}"${shown(value)} must be an https origin: "https://" and a host, with an optional port, an optional trailing slash and nothing else (no username, path, query or fragment).${suggestion}`
  );
}

/**
 * The time limit goes to `AbortSignal.timeout` as it is, and that takes whole milliseconds only: it throws for a
 * fraction, and for a delay over 2^31 - 1 it throws or runs 1 millisecond. So the range is checked here, once, and the
 * fetcher does not change the value.
 */
function readTimeoutMs(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_AGENT_METADATA_TIMEOUT_MS;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_AGENT_METADATA_TIMEOUT_MS) {
    throw invalid(
      `"agentMetadata.timeoutMs" must be a whole number of milliseconds from 1 to ${MAX_AGENT_METADATA_TIMEOUT_MS}`
    );
  }
  return value;
}

function readMaxBytes(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_AGENT_METADATA_MAX_BYTES;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    throw invalid('"agentMetadata.maxBytes" must be a whole number of bytes greater than 0');
  }
  return value;
}

/**
 * The `fetch` for agent metadata: the one of `agentMetadata`, then the `customFetch` of the client, then the global
 * one, which is looked up when it is called. Each is called as a plain function from a wrapper, never as a method of
 * an options object, because Workers can throw "Illegal invocation" when the global `fetch` is called with another
 * receiver.
 */
function readFetch(given: unknown, customFetch: unknown): typeof fetch {
  if (given !== undefined && typeof given !== 'function') {
    throw invalid('"agentMetadata.fetch" must be a function');
  }
  // TypeScript is the contract for the signature of a function.
  const chosen = (given ?? (typeof customFetch === 'function' ? customFetch : undefined)) as typeof fetch | undefined;
  return chosen === undefined ? (input, init) => globalThis.fetch(input, init) : (input, init) => chosen(input, init);
}

function readAgentMetadata(value: unknown, customFetch: unknown): ResolvedPoppyOptions['agentMetadata'] {
  if (value !== undefined && !isRecord(value)) {
    throw invalid('"agentMetadata" must be an object');
  }
  const metadata: Record<string, unknown> = value ?? {};

  const cacheValue = metadata.cache;
  if (cacheValue !== undefined && !isRecord(cacheValue)) {
    throw invalid('"agentMetadata.cache" must be an object');
  }
  const cache: Record<string, unknown> = cacheValue ?? {};

  // The cache values, the time limit and the size limit are read with `??`, as `discoveryCache` reads its values, so a
  // null is the same as a value that is not set. The other options are strict about a null.
  return {
    fetch: readFetch(metadata.fetch, customFetch),
    ttlMs:
      readNonNegative('agentMetadata.cache.ttl', cache.ttl ?? undefined, DEFAULT_AGENT_METADATA_CACHE_TTL_SECONDS) *
      1000,
    maxEntries: readNonNegative(
      'agentMetadata.cache.maxEntries',
      cache.maxEntries ?? undefined,
      DEFAULT_AGENT_METADATA_CACHE_MAX_ENTRIES
    ),
    timeoutMs: readTimeoutMs(metadata.timeoutMs ?? undefined),
    maxBytes: readMaxBytes(metadata.maxBytes ?? undefined),
    allowPrivateAddresses: readBoolean('agentMetadata.allowPrivateAddresses', metadata.allowPrivateAddresses, false),
  };
}

/**
 * Validates the `poppy` option of `ApiClient` and applies the defaults.
 *
 * @param options - The options of the client. Only `poppy` and `customFetch` are read.
 * @returns The resolved options.
 * @throws {InvalidConfigurationError} When an option is invalid. The message starts with
 *   `Invalid poppy configuration: ` and names the field.
 */
export function resolvePoppyOptions(options: ApiClientOptions): ResolvedPoppyOptions {
  const poppy: unknown = options.poppy;
  if (!isRecord(poppy)) {
    throw invalid('"poppy" must be an object');
  }

  const verifySession = readBoolean('verifySession', poppy.verifySession, false);
  const iatWindowSeconds = readNonNegative('iatWindow', poppy.iatWindow, DEFAULT_IAT_WINDOW_SECONDS);
  const agentMetadata = readAgentMetadata(poppy.agentMetadata, options.customFetch);
  const agents =
    poppy.agents === undefined ? undefined : readAgents(poppy.agents, agentMetadata.allowPrivateAddresses);
  const publicOrigin = poppy.publicOrigin === undefined ? undefined : readOrigin('publicOrigin', poppy.publicOrigin);

  return {
    verifySession,
    agents,
    sessionStore: (poppy.sessionStore ?? undefined) as PoppySessionStore | undefined,
    iatWindowSeconds,
    publicOrigin,
    agentMetadata,
  };
}
