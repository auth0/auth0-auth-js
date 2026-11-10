import { BROWSER_SIGN_IN_SCOPE, DISCOVERY_HEADERS, POPPY_JSON_PATH, PROTECTED_RESOURCE_PATH } from './constants.js';
import type { PoppyConfig, PoppyConfigIssue, PoppyDiscoveryDocument, PoppyProtectedResource } from './types.js';

// The two files that a website with Poppy publishes, and the checks of the config that agents make on them.
// Spec: https://personalagentprotocol.org/docs/0.3/spec#discovery
//
// An agent that finds a mismatch between the files and the metadata of Auth0 does not use the files, and it does not
// say so. So the bodies are exact, and the checks are the ones an agent makes.

// The resource of the website: `https://` and the domain, with no path, port or trailing slash. The protected resource
// metadata names it as its `resource`, and the issuer lists it in its `protected_resources`.
// See https://personalagentprotocol.org/docs/0.3/spec#oauth-server
const resourceOf = (config: PoppyConfig): string => `https://${config.organization.domain}`;

// Whether the version of the config is one that has the scope `poppy:browser-sign-in`: Poppy 0.4 and later. The shape of
// the version (`major.minor`) was checked by `resolvePoppyOptions`.
function hasBrowserSignInScope(version: string): boolean {
  const [major = 0, minor = 0] = version.split('.').map(Number);

  return major > 0 || minor >= 4;
}

function toDocument(body: unknown): PoppyDiscoveryDocument {
  return { status: 200, headers: { ...DISCOVERY_HEADERS }, body: JSON.stringify(body) };
}

// The body of poppy.json. Each object is built member by member in the order of the contract, so the config can hold
// more members than the ones that are served (the API SDK reads some of them) and none of them reaches the file.
// `Object.fromEntries` makes a name such as `__proto__` an ordinary member, which an assignment would not.
function poppyJson(config: PoppyConfig): Record<string, unknown> {
  const descriptions = new Map<string, string>();
  const hints = new Map<string, { changes: string; personal_data: boolean }>();

  for (const [name, scope] of Object.entries(config.scopes ?? {})) {
    descriptions.set(name, scope.description);

    if (scope.hints) {
      hints.set(name, { changes: scope.hints.changes, personal_data: scope.hints.personal_data });
    }
  }

  const auth: Record<string, unknown> = { issuer: config.issuer };

  if (descriptions.size > 0) {
    auth.scopes = Object.fromEntries(descriptions);
  }

  if (hints.size > 0) {
    auth.scope_hints = Object.fromEntries(hints);
  }

  const body: Record<string, unknown> = {
    // The version is the one that the config names, as it is. It has the shape that `resolvePoppyOptions` checked.
    protocol_version: config.protocol_version,
    organization: { name: config.organization.name, domain: config.organization.domain },
    auth,
    // `unscoped` is a member of Poppy 0.4. It is served when the config sets it, as a boolean, and left out otherwise.
    web: {
      browser_session_endpoint: config.web.browser_session_endpoint,
      ...(config.web.unscoped !== undefined && { unscoped: config.web.unscoped }),
    },
  };

  if (config.apis && config.apis.length > 0) {
    body.apis = config.apis.map(({ type, url, description }) => ({ type, url, description }));
  }

  return body;
}

// The members of the protected resource metadata that the website serves: `resource` and `authorization_servers` first,
// then the other members of the override in the order the developer wrote them. A member that the override gives is
// served as it is, and a member it leaves out (or sets to `undefined`) is inferred from the config. An empty
// `authorization_servers` is a value that was given. The issuer is copied as the config writes it, never normalized.
// This is the one place that decides what is served, so the check of the override reads the same values.
// See https://personalagentprotocol.org/docs/0.3/spec#oauth-server and https://www.rfc-editor.org/rfc/rfc9728
function protectedResourceOf(config: PoppyConfig, override: PoppyProtectedResource = {}) {
  const { resource, authorization_servers: servers, ...others } = override;

  return {
    resource: resource ?? resourceOf(config),
    authorization_servers: servers ?? [config.issuer],
    ...others,
  };
}

/**
 * @internal
 * Builds the two discovery documents from the config, once. The body of each is text, so a change to the config or to
 * the `protectedResource` object afterwards cannot change it. `poppy.json` does not depend on `protectedResource`.
 *
 * @param config The config, after the checks of `resolvePoppyOptions`.
 * @param protectedResource The `protectedResource` option, after its checks and its copy.
 *
 * @returns The documents by path.
 */
export function buildDiscoveryDocuments(
  config: PoppyConfig,
  protectedResource?: PoppyProtectedResource
): Map<string, PoppyDiscoveryDocument> {
  return new Map([
    [POPPY_JSON_PATH, toDocument(poppyJson(config))],
    [PROTECTED_RESOURCE_PATH, toDocument(protectedResourceOf(config, protectedResource))],
  ]);
}

/**
 * @internal
 * Finds the values of the `protectedResource` option that agents reject. It needs no network. A value that is inferred
 * always passes. A value that does not is still served, because the developer wrote it on purpose. The messages name
 * the member and the resource of the config, and never the value of the override.
 *
 * @param config The config, after the checks of `resolvePoppyOptions`.
 * @param protectedResource The `protectedResource` option, after its checks and its copy.
 *
 * @returns One issue for each member that is wrong, `resource` first.
 */
export function findOverrideIssues(
  config: PoppyConfig,
  protectedResource?: PoppyProtectedResource
): PoppyConfigIssue[] {
  const { resource, authorization_servers: servers } = protectedResourceOf(config, protectedResource);
  const expected = resourceOf(config);
  const issues: PoppyConfigIssue[] = [];

  // The resource must be exactly the https URL of the domain.
  if (resource !== expected) {
    issues.push({
      code: 'protected_resource_override_mismatch',
      message:
        `protectedResource.resource is not exactly ${expected}. ` +
        'Agents do not use the oauth-protected-resource document unless its resource is exactly that.',
    });
  }

  // The issuer must be in the list exactly as the config writes it. A missing trailing slash or another case is another
  // issuer, so there is no normalizing here.
  if (!servers.includes(config.issuer)) {
    issues.push({
      code: 'protected_resource_override_mismatch',
      message:
        'protectedResource.authorization_servers does not list the issuer of the config exactly as written there, ' +
        'trailing slash included. Agents do not use the oauth-protected-resource document without it.',
    });
  }

  return issues;
}

/**
 * @internal
 * Compares the config with the metadata of Auth0 as an agent does. The issuer is not compared: the `ServerClient`
 * requires the `issuer` of the config to match its domain when it is created. The messages are fixed texts. They name
 * the scopes and the resource of the config, and nothing from the metadata.
 * See https://personalagentprotocol.org/docs/0.3/spec#oauth-server
 *
 * @param config The config, after the checks of `resolvePoppyOptions`.
 * @param metadata The metadata of Auth0, as `AuthClient.getServerMetadata()` gives it.
 *
 * @returns The issue about the resource first, then the issue about the scopes. Empty when there is nothing to report.
 */
export function findConfigIssues(config: PoppyConfig, metadata: Record<string, unknown>): PoppyConfigIssue[] {
  const issues: PoppyConfigIssue[] = [];
  const resource = resourceOf(config);
  const listed = metadata.protected_resources;

  // The agent lowercases each entry before it compares, as RFC 3986 allows, so `https://ZEPTO.example` is the resource.
  // The match is exact otherwise: a path, a port or a trailing slash makes another entry. A value that is not a list of
  // strings lists nothing.
  const isListed =
    Array.isArray(listed) &&
    listed.some((entry: unknown) => typeof entry === 'string' && entry.toLowerCase() === resource);

  if (!isListed) {
    issues.push({
      code: 'protected_resource_missing',
      message:
        `Auth0's metadata does not list ${resource} in protected_resources. ` +
        'Agents do not use poppy.json until the issuer lists it there.',
    });
  }

  // A website that offers a browser join has to support `poppy:browser-sign-in` (Poppy 0.4, section 4.7), and every
  // website of this package offers one. It is checked for a config of Poppy 0.4 or later, where the scope exists.
  const expected = Object.keys(config.scopes ?? {});

  if (hasBrowserSignInScope(config.protocol_version) && !expected.includes(BROWSER_SIGN_IN_SCOPE)) {
    expected.push(BROWSER_SIGN_IN_SCOPE);
  }

  // `scopes_supported` must be a list. A string that holds a scope as text is not one.
  const supported = metadata.scopes_supported;
  const missing = expected.filter((scope) => !(Array.isArray(supported) && supported.includes(scope)));

  if (missing.length > 0) {
    issues.push({
      code: 'scopes_not_supported',
      message:
        `Auth0's metadata does not list these scopes in scopes_supported: ${missing.join(', ')}. ` +
        'The issuer should list every scope that an agent can request.',
    });
  }

  return issues;
}

/**
 * @internal
 * The issue for a failure to read the metadata of Auth0. A new object on each call, so a change by the app to an issue
 * it got cannot reach the next one. The cause of the failure is not in the message: it can hold a URL or a response.
 */
export function metadataUnavailableIssue(): PoppyConfigIssue {
  return {
    code: 'metadata_unavailable',
    message:
      "Auth0's metadata could not be read, so the config was not compared with it. " +
      'Check the domain and the network, then run the check again.',
  };
}
