import { InvalidConfigurationError } from '../errors.js';
import { SESSION_EXPIRY_LEEWAY } from '../state/utils.js';
import { DEFAULT_AGENT_SESSION_MAX_AGE, DOMAIN_PORT_PATTERN, HOST_NAME_PATTERN } from './constants.js';
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

// A guest store is an object with the three methods that the SDK calls. It does not have to extend
// `AbstractPoppyGuestStore`, because the type is an interface.
const isGuestStore = <T>(value: unknown): value is PoppyGuestStore<T> =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as Record<string, unknown>).get === 'function' &&
  typeof (value as Record<string, unknown>).set === 'function' &&
  typeof (value as Record<string, unknown>).delete === 'function';

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
 * Checks `organization.domain` of the config: the host that serves `poppy.json`, which is a lowercase host name,
 * followed by its port when the port is not 443 (Poppy 1.0, section 3.1). `localhost:3000` and `shop.example:8443` are
 * valid, and `shop.example:443` is not, because an agent compares the domain with the host that served the file, and
 * the port 443 is left out of that host.
 *
 * @returns The text that tells how to fix the domain, or `undefined` when the domain is valid. The text never holds
 * the value.
 */
function domainProblem(value: string): string | undefined {
  const [host, port, ...rest] = value.split(':');

  // A scheme or a path puts something in the place of the port that is not digits, so it ends here.
  const portIsNumber = port === undefined || /^\d+$/.test(port);

  if (rest.length > 0 || host === undefined || !HOST_NAME_PATTERN.test(host) || !portIsNumber) {
    return (
      'config.organization.domain must be a lowercase host name, with its port when the port is not 443, ' +
      'and with no scheme, path or trailing dot.'
    );
  }

  if (port === '443') {
    return 'config.organization.domain must not have the port 443. Leave the port out, because 443 is the default.';
  }

  if (port !== undefined && !(DOMAIN_PORT_PATTERN.test(port) && Number(port) <= 65535)) {
    return 'config.organization.domain must have a port from 1 to 65535, written without a leading zero.';
  }

  return undefined;
}

/**
 * @internal
 * Checks the `poppy` option and returns what the `ServerClient` keeps. Throws `InvalidConfigurationError` for the
 * first rule that fails.
 *
 * @param options The `poppy` option.
 * @param client The `domain` of the `ServerClient` after it is normalized, which is `undefined` for a domain
 * resolver.
 */
export function resolvePoppyOptions<TStoreOptions>(
  options: PoppyOptions<TStoreOptions>,
  client: { domain: string | undefined }
): ResolvedPoppyOptions<TStoreOptions> {
  const { domain } = client;

  if (domain === undefined) {
    fail('domain must be a string. A domain resolver is not supported because Poppy has one issuer.');
  }

  // The config is read from a file, so its shape is checked here and it is read as unknown until then.
  const given: unknown = options.config;

  if (!isObject(given)) {
    fail('config must be an object.');
  }

  // The checks run on a deep copy, as they do for `protectedResource`, and the copy is what is kept and served. What is
  // checked is then what is used: a change by the caller afterwards cannot change the issuer that a login request is
  // compared with, or the file that agents read, and a member that changes between reads cannot get past the checks.
  // Only the two rules below are checked. Every other member is the business of the Auth0 CLI that wrote the file.
  const config = copyData(given, 'config');

  const organization = config.organization;
  const organizationDomain = isObject(organization) ? organization.domain : undefined;

  if (typeof organizationDomain !== 'string') {
    fail('config.organization.domain must be a string.');
  }

  const problem = domainProblem(organizationDomain);

  if (problem !== undefined) {
    fail(problem);
  }

  // Auth0 puts this exact text in the `iss` claim. A trailing slash is the mistake that people make most.
  const auth = config.auth;

  // The expected text comes from the `domain` option of the app, never from the file, so it is safe to show. It tells
  // the developer which side to change when the file and the app name different domains.
  if (!isObject(auth) || auth.issuer !== `https://${domain}/`) {
    fail(
      "config.auth.issuer must match Auth0's issuer for the ServerClient domain exactly, trailing slash included. " +
        `Expected: https://${domain}/`
    );
  }

  const { agentSessionMaxAge, protectedResource, guestStore } = options;

  // The guard reads the guest store on every login, a person's included. A missing store would fail on a visitor's
  // login, after the authorization code is spent, so it is refused here.
  if (!isGuestStore(guestStore)) {
    fail('guestStore must be a PoppyGuestStore: an object with the methods get, set and delete.');
  }

  // A session ends `SESSION_EXPIRY_LEEWAY` seconds before its deadline, and a login whose deadline is that near is
  // refused. So a value at or below the leeway would refuse every agent login, and it is refused here instead.
  if (
    agentSessionMaxAge !== undefined &&
    !(Number.isSafeInteger(agentSessionMaxAge) && agentSessionMaxAge > SESSION_EXPIRY_LEEWAY)
  ) {
    fail(
      `agentSessionMaxAge must be a whole number of seconds above ${SESSION_EXPIRY_LEEWAY}, ` +
        `because a session ends ${SESSION_EXPIRY_LEEWAY} seconds before its deadline.`
    );
  }

  return {
    // The checks above ran on this copy, so it has the members that the type names.
    config: config as unknown as PoppyConfig,
    guestStore,
    agentSessionMaxAge: agentSessionMaxAge ?? DEFAULT_AGENT_SESSION_MAX_AGE,
    protectedResource: protectedResource === undefined ? undefined : copyProtectedResource(protectedResource),
  };
}
