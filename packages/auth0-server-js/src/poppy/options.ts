import { InvalidConfigurationError } from '../errors.js';
import {
  DEFAULT_AGENT_SESSION_MAX_AGE,
  HOST_NAME_PATTERN,
  PROTOCOL_VERSION_PATTERN,
  SCOPE_CHANGES,
  SCOPE_TOKEN_PATTERN,
} from './constants.js';
import type { PoppyConfig, PoppyGuestStore, PoppyOptions, PoppyProtectedResource } from './types.js';

/**
 * @internal
 * The `poppy` option, after the checks.
 */
export interface ResolvedPoppyOptions<TStoreOptions> {
  /**
   * A deep copy, taken at construction. Changing the object that the caller passed, or anything inside it, afterwards
   * does not change this copy.
   */
  config: PoppyConfig;
  guestStore: PoppyGuestStore<TStoreOptions>;
  agentSessionMaxAge: number;
  /**
   * A deep copy, taken at construction. Changing the object that the caller passed, or anything inside it, afterwards
   * does not change this copy.
   */
  protectedResource?: PoppyProtectedResource;
}

// Every message starts the same way and names the field. It never shows the value: the config comes from a file that
// can hold anything, and a value does not belong in a log.
function fail(message: string): never {
  throw new InvalidConfigurationError(`Invalid poppy configuration: ${message}`);
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

const isHttpsUrl = (value: unknown): boolean => {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
};

function checkScopes(scopes: unknown): void {
  if (scopes === undefined) {
    return;
  }

  if (!isObject(scopes)) {
    fail('config.scopes must be an object.');
  }

  for (const [name, scope] of Object.entries(scopes)) {
    if (!SCOPE_TOKEN_PATTERN.test(name)) {
      fail('config.scopes names must be printable ASCII without a space, a double quote or a backslash.');
    }

    if (!isObject(scope) || !isNonEmptyString(scope.description)) {
      fail('config.scopes entries must be objects with a non-empty description.');
    }

    const hints = scope.hints;
    if (
      hints !== undefined &&
      (!isObject(hints) ||
        !(SCOPE_CHANGES as readonly unknown[]).includes(hints.changes) ||
        typeof hints.personal_data !== 'boolean')
    ) {
      fail('config.scopes hints must have changes (none, reversible or irreversible) and a boolean personal_data.');
    }
  }
}

function checkApis(apis: unknown): void {
  if (apis === undefined) {
    return;
  }

  if (!Array.isArray(apis)) {
    fail('config.apis must be an array of objects.');
  }

  for (const api of apis as unknown[]) {
    if (!isObject(api) || !isNonEmptyString(api.type) || !isNonEmptyString(api.description) || !isHttpsUrl(api.url)) {
      fail('config.apis entries must have a non-empty type, a non-empty description and an https url.');
    }
  }
}

// A deep copy of data that the caller passed, so a change by the caller after the construction, to the object or to
// anything inside it, does not reach what is kept. `structuredClone` is in every runtime that this package supports. A
// value that it cannot copy, such as a function or a symbol, ends as the error of this package and not as the
// `DataCloneError` of the runtime. The text is fixed: it holds nothing of the value, the member, or the error that a
// getter raised.
function copyData<T>(value: T, name: string): T {
  try {
    return structuredClone(value);
  } catch {
    fail(`${name} must be plain JSON data.`);
  }
}

// The checks run on the copy, not on the object of the caller: the copy reads each member once, so what is checked is
// what is kept. The members that the SDK does not know are kept as they are: whether the values are right is for the
// config check to say.
function copyProtectedResource(value: unknown): PoppyProtectedResource {
  if (!isObject(value)) {
    fail('protectedResource must be an object.');
  }

  const copy = copyData(value, 'protectedResource');

  if (copy.resource !== undefined && !isNonEmptyString(copy.resource)) {
    fail('protectedResource.resource must be a non-empty string.');
  }

  const servers = copy.authorization_servers;
  if (servers !== undefined) {
    // The clone keeps the holes of a sparse array, and `every` skips holes. `Array.from` turns each hole into
    // `undefined`, which the check below refuses.
    const list = Array.isArray(servers) ? Array.from<unknown>(servers) : undefined;
    if (list === undefined || !list.every(isNonEmptyString)) {
      fail('protectedResource.authorization_servers must be an array of non-empty strings.');
    }

    copy.authorization_servers = list;
  }

  return copy;
}

/**
 * @internal
 * Checks the `poppy` option and returns what the `ServerClient` keeps. Throws `InvalidConfigurationError` for the
 * first rule that fails.
 *
 * @param options The `poppy` option.
 * @param client The `domain` of the `ServerClient` after it is normalized, which is `undefined` for a domain
 * resolver, and its `clientId`.
 */
export function resolvePoppyOptions<TStoreOptions>(
  options: PoppyOptions<TStoreOptions>,
  client: { domain: string | undefined; clientId: string }
): ResolvedPoppyOptions<TStoreOptions> {
  const { domain, clientId } = client;

  if (domain === undefined) {
    fail('domain must be a string. A domain resolver is not supported because Poppy has one issuer.');
  }

  // The config is read from a file, so its shape is checked here and it is read as unknown until then.
  const given: unknown = options.config;

  if (!isObject(given)) {
    fail('config must be an object.');
  }

  // The checks run on a deep copy, as they do for `protectedResource`, and the copy is what is kept. What is checked is
  // then what is used: a change by the caller afterwards cannot change the issuer that a login request is compared with
  // or what `verifyConfig()` reads, and a member that changes between reads cannot get past the checks.
  const config = copyData(given, 'config');

  // Only the shape is checked. This package does not know which versions exist, so it refuses none that it has not
  // seen, and the version is served as it is written. The type is checked first, because `RegExp.test` turns a number,
  // or a list of one string, into text that can match.
  const version = config.protocol_version;

  if (typeof version !== 'string' || !PROTOCOL_VERSION_PATTERN.test(version)) {
    fail("config.protocol_version must be a version such as '0.3'.");
  }

  const organization = config.organization;

  if (!isObject(organization) || !isNonEmptyString(organization.name)) {
    fail('config.organization.name must be a non-empty string.');
  }

  if (typeof organization.domain !== 'string' || !HOST_NAME_PATTERN.test(organization.domain)) {
    fail('config.organization.domain must be a lowercase host name, with no scheme, port, path or trailing dot.');
  }

  // Auth0 puts this exact text in the `iss` claim. A trailing slash is the mistake that people make most.
  if (config.issuer !== `https://${domain}/`) {
    fail("config.issuer must match Auth0's issuer for the ServerClient domain exactly, trailing slash included.");
  }

  const web = config.web;

  if (!isObject(web) || !isHttpsUrl(web.browser_session_endpoint)) {
    fail('config.web.browser_session_endpoint must be an https URL.');
  }

  if (web.client_id !== undefined && web.client_id !== clientId) {
    fail('config.web.client_id must be the clientId of the ServerClient, or left out.');
  }

  if (web.unscoped !== undefined && typeof web.unscoped !== 'boolean') {
    fail('config.web.unscoped must be true or false, or left out.');
  }

  checkScopes(config.scopes);
  checkApis(config.apis);

  const { agentSessionMaxAge, protectedResource } = options;

  if (agentSessionMaxAge !== undefined && !(Number.isSafeInteger(agentSessionMaxAge) && agentSessionMaxAge > 0)) {
    fail('agentSessionMaxAge must be a positive whole number of seconds.');
  }

  return {
    // The checks above ran on this copy, so it has the members of a valid config.
    config: config as unknown as PoppyConfig,
    guestStore: options.guestStore,
    agentSessionMaxAge: agentSessionMaxAge ?? DEFAULT_AGENT_SESSION_MAX_AGE,
    protectedResource: protectedResource === undefined ? undefined : copyProtectedResource(protectedResource),
  };
}
