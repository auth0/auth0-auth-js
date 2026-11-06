import { InvalidConfigurationError } from '../errors.js';
import type { ApiClientOptions, DomainsResolver } from '../types.js';
import {
  DEFAULT_AGENT_CLIENT_ID_CLAIMS,
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
  /** The registered agents: `poppy.agents`, else `config.agents`, in a copy. `undefined` means there is no list. */
  agents?: ReadonlySet<string>;
  /** The store of known Sessions. Passed through as given: TypeScript is the contract. */
  sessionStore?: PoppySessionStore;
  /** The access token claims that hold the URL of the agent, in the order they are tried. */
  agentClientIdClaims: readonly string[];
  /** How far the `iat` of a Session JWT may be from the current time, in seconds, in both directions. */
  iatWindowSeconds: number;
  /**
   * The public origin of the API: `poppy.baseUrl`, else the `public_origin` of the `config.apis` entry whose
   * `identifier` is the audience. It is the `origin` of a URL, so the host is in lower case, a default port is dropped
   * and there is no trailing slash.
   */
  publicOrigin?: string;
  /**
   * The `issuer` of the config, exactly as written. It is not normalized, because the `aud` of a Session JWT is
   * compared with it character by character. It is checked to be in the canonical form already: the origin of the
   * domain, in lower case, with no default port, and a trailing slash.
   */
  configIssuer?: string;
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

type DomainContext = {
  /** The issuer of `domain`, as `https://host/`, already normalized by `ApiClient`. */
  defaultDomainUrl?: string;
  /** The `domains` option: the normalized issuers of an allowlist, or the resolver function as given. */
  domains?: string[] | DomainsResolver;
};

const MESSAGE_PREFIX = 'Invalid poppy configuration: ';
// The longest value a message repeats, and the most entries of a list it names.
const MAX_SHOWN_LENGTH = 200;
const MAX_LISTED = 5;

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

/** The first values of a list, in quotes, and how many more there are. */
function listed(values: readonly string[]): string {
  const first = values
    .slice(0, MAX_LISTED)
    .map((value) => JSON.stringify(value))
    .join(', ');
  return values.length > MAX_LISTED ? `${first} and ${values.length - MAX_LISTED} more` : first;
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

function readClaims(value: unknown): readonly string[] {
  if (value === undefined) {
    // A copy, so that no client shares the array of the constant.
    return [...DEFAULT_AGENT_CLIENT_ID_CLAIMS];
  }
  // A copy, so that changing the caller's array later changes nothing.
  const claims: unknown[] = Array.isArray(value) ? Array.from(value) : [];
  if (claims.length === 0 || !claims.every((claim): claim is string => typeof claim === 'string' && claim !== '')) {
    throw invalid('"agentClientIdClaims" must be a non-empty array of non-empty strings');
  }
  return claims;
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

/**
 * Checks a list of agent URLs and returns it as a set. `field` is the name of the list in messages, `agents` or
 * `config.agents`.
 */
function readAgents(field: string, value: unknown, allowPrivateAddresses: boolean): ReadonlySet<string> {
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

/**
 * Checks an `https:` origin and returns it in the form of `URL.origin`. `example` turns the origin of the value into
 * the text to suggest when the value has too much after the host.
 */
function readOrigin(field: string, value: unknown, example: (origin: string) => string = (origin) => origin): string {
  if (!isHttpsOrigin(value)) {
    throw originError(field, value, example);
  }
  return new URL(value).origin;
}

function originError(field: string, value: unknown, example: (origin: string) => string): InvalidConfigurationError {
  const url = canShow(value) ? parseUrl(value) : undefined;
  const suggestion = url?.protocol === 'https:' ? ` Use "${example(url.origin)}".` : '';
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

/** The fields of the config that `resolvePoppyOptions` needs, found and not yet checked, except the issuer. */
interface ConfigFields {
  issuer: string;
  /** The name of the `apis` entry for the audience in messages, such as `config.apis[0]`. */
  apiField: string;
  publicOrigin: unknown;
  agents: unknown;
}

function readConfig(value: unknown, audience: string): ConfigFields {
  if (!isRecord(value)) {
    throw invalid('"config" must be an object: the parsed auth0-poppy.json, the config file the Auth0 CLI writes');
  }
  const { issuer, apis, agents } = value;
  if (!isHttpsOrigin(issuer)) {
    throw originError('config.issuer', issuer, (origin) => `${origin}/`);
  }
  // Auth0 writes an issuer as the origin of the domain and a trailing slash, and the `aud` of a Session JWT is compared
  // with the issuer character by character. Any other way of writing it would match no Session, and a `domains`
  // function would never show that, so this is checked whatever the domain options are.
  const canonicalIssuer = `${new URL(issuer).origin}/`;
  if (issuer !== canonicalIssuer) {
    const expected =
      canShow(issuer) && canShow(canonicalIssuer)
        ? ` ${JSON.stringify(canonicalIssuer)}, not ${JSON.stringify(issuer)}`
        : '';
    throw invalid(
      `"config.issuer" must be the canonical issuer${expected}. A canonical issuer has a lower-case host, no default port and a trailing slash, because the "aud" of a Session JWT is compared with it character by character.`
    );
  }
  if (!Array.isArray(apis) || apis.length === 0) {
    throw invalid('"config.apis" must be a non-empty array');
  }

  const entries: unknown[] = Array.from(apis);
  for (const [index, entry] of entries.entries()) {
    if (isRecord(entry) && entry.identifier === audience) {
      return { issuer, apiField: `config.apis[${index}]`, publicOrigin: entry.public_origin, agents };
    }
  }

  const identifiers = entries.flatMap((entry) =>
    isRecord(entry) && typeof entry.identifier === 'string' && entry.identifier.length <= MAX_SHOWN_LENGTH
      ? [entry.identifier]
      : []
  );
  throw invalid(
    `"config.apis" has no entry with the identifier ${JSON.stringify(audience)}, the audience of this client. The identifier must equal the audience exactly.${
      identifiers.length > 0 ? ` The entries have the identifiers ${listed(identifiers)}.` : ''
    }`
  );
}

/**
 * Checks that the issuer of the config, which is already known to be in the canonical form, is the issuer of the domain
 * of the client, or of one of its domains. The `aud` of a Session JWT is compared with the issuer character by
 * character, so another tenant's issuer would refuse every Session.
 */
function checkIssuer(issuer: string, { defaultDomainUrl, domains }: DomainContext): void {
  // With a `domains` function, the allowed issuers are only known for a request, so there is nothing to check.
  if (typeof domains === 'function') {
    return;
  }
  const explanation = 'A Session JWT\'s "aud" is compared with it character by character.';
  if (domains !== undefined) {
    if (!domains.includes(issuer)) {
      throw invalid(
        `"config.issuer" (${JSON.stringify(issuer)}) must be the issuer of one of your "domains" exactly, trailing slash included: expected one of ${listed(domains)}. ${explanation}`
      );
    }
  } else if (defaultDomainUrl !== undefined && issuer !== defaultDomainUrl) {
    throw invalid(
      `"config.issuer" (${JSON.stringify(issuer)}) must be the issuer of your "domain" exactly, trailing slash included: expected ${JSON.stringify(defaultDomainUrl)}. ${explanation}`
    );
  }
}

/**
 * Validates the `poppy` option of `ApiClient` and its config, and applies the defaults.
 *
 * The explicit options win over the config: `agents` over `config.agents`, and `baseUrl` over the `public_origin` of
 * the `config.apis` entry for the audience. A value of the config that an explicit option replaces is not read.
 *
 * @param options - The options of the client. Only `poppy`, `audience` and `customFetch` are read.
 * @param context - The domain options of the client, already normalized: `defaultDomainUrl` is the issuer of `domain`
 *   (`https://host/`), and `domains` is the normalized allowlist or the resolver function as given.
 * @returns The resolved options.
 * @throws {InvalidConfigurationError} When an option or the config is invalid. The message starts with
 *   `Invalid poppy configuration: ` and names the field.
 */
export function resolvePoppyOptions(options: ApiClientOptions, context: DomainContext): ResolvedPoppyOptions {
  const poppy: unknown = options.poppy;
  if (!isRecord(poppy)) {
    throw invalid('"poppy" must be an object');
  }

  const verifySession = readBoolean('verifySession', poppy.verifySession, false);
  const iatWindowSeconds = readNonNegative('iatWindow', poppy.iatWindow, DEFAULT_IAT_WINDOW_SECONDS);
  const agentClientIdClaims = readClaims(poppy.agentClientIdClaims);
  const agentMetadata = readAgentMetadata(poppy.agentMetadata, options.customFetch);
  const config = poppy.config === undefined ? undefined : readConfig(poppy.config, options.audience);

  let agents: ReadonlySet<string> | undefined;
  if (poppy.agents !== undefined) {
    agents = readAgents('agents', poppy.agents, agentMetadata.allowPrivateAddresses);
  } else if (config?.agents !== undefined) {
    agents = readAgents('config.agents', config.agents, agentMetadata.allowPrivateAddresses);
  }

  let publicOrigin: string | undefined;
  if (poppy.baseUrl !== undefined) {
    publicOrigin = readOrigin('baseUrl', poppy.baseUrl);
  } else if (config !== undefined) {
    publicOrigin = readOrigin(`${config.apiField}.public_origin`, config.publicOrigin);
  }

  if (config !== undefined) {
    checkIssuer(config.issuer, context);
  }

  return {
    verifySession,
    agents,
    sessionStore: (poppy.sessionStore ?? undefined) as PoppySessionStore | undefined,
    agentClientIdClaims,
    iatWindowSeconds,
    publicOrigin,
    configIssuer: config?.issuer,
    agentMetadata,
  };
}
