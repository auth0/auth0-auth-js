// Protocol strings, claim names, patterns and defaults for Poppy (Personal Agent Protocol).
// The code was written against Poppy 0.3, which is a draft. It serves the version that the config names.
// Spec: https://personalagentprotocol.org/docs/0.3/spec

/**
 * The shape of `protocol_version` in the config: `major.minor`, such as `0.3`. Only the shape is checked. The package
 * does not know which versions exist, so it serves the version as the config writes it and refuses none that it has
 * not seen. Each number has 1 to 4 digits, and the digits are 0 to 9.
 * See {@link https://personalagentprotocol.org/docs/0.3/spec#fields the specification, section 3.1}.
 */
export const PROTOCOL_VERSION_PATTERN = /^\d{1,4}\.\d{1,4}$/;

/**
 * The scope that lets an agent sign its browser in to the website. Poppy 0.4 defines it. A website that lists a
 * `browser_session_endpoint` and offers sign-in has to support it, so Auth0 should list it in `scopes_supported`.
 * See {@link https://personalagentprotocol.org/docs/0.4/spec#scopes the specification, section 4.7}.
 */
export const BROWSER_SIGN_IN_SCOPE = 'poppy:browser-sign-in';

/** The identifier of the guest store. A cookie-backed guest store uses it as the cookie name. */
export const POPPY_GUEST_IDENTIFIER = '__a0_poppy';

/** The longest an agent's session on the website lasts when `agentSessionMaxAge` is not set: two hours, in seconds. */
export const DEFAULT_AGENT_SESSION_MAX_AGE = 7200;

/**
 * The names of the Poppy members of the `act` claim in the ID token of a browser join.
 *
 * These are Auth0's beta claims. The names may change, and `poppy_session_exp` may go away.
 */
export const ACT_CLAIMS = {
  sessionId: 'poppy_sid',
  userId: 'poppy_user_id',
  agentId: 'poppy_agent_id',
  sessionExp: 'poppy_session_exp',
} as const;

/**
 * A Session id: 1 to 256 characters of the URL-safe base64 alphabet. `@auth0/auth0-api-js` accepts the same ids, so
 * the two SDKs agree on which Sessions exist.
 */
export const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;

/** The profile that marks an anonymous user in the `sub_profile` claim of a token. */
export const ANONYMOUS_USER_PROFILE = 'urn:auth0:anonymous_user';

/**
 * The start of the `sub` of a guest's token. This is temporary: it stands in for `sub_profile` until Auth0 puts that
 * claim on guest tokens.
 */
export const GUEST_SUB_PREFIX = 'anon_poppy@';

/**
 * The bound (exclusive) for a Unix time in seconds. It is the bound that the `session_expiry` check in
 * `state/utils.ts` uses, which does not export it. A number at or above it is almost certainly in milliseconds.
 */
export const MAX_PLAUSIBLE_UNIX_SECONDS = 1e10;

/**
 * A lowercase host name: labels of letters, digits and hyphens, separated by dots. A label has 1 to 63 characters and
 * does not start or end with a hyphen, and the whole name has at most 253. A scheme, a port, a path or a trailing dot
 * does not match.
 */
export const HOST_NAME_PATTERN =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * A scope name: one or more printable ASCII characters, but no space, double quote or backslash.
 * See {@link https://www.rfc-editor.org/rfc/rfc6749#section-3.3 RFC 6749 section 3.3}.
 */
export const SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/**
 * The values of `changes` in a scope hint.
 * See {@link https://personalagentprotocol.org/docs/0.3/spec#scopes the specification, section 4.7}.
 */
export const SCOPE_CHANGES = ['none', 'reversible', 'irreversible'] as const;

/**
 * The path where a Company serves `poppy.json`.
 * See {@link https://personalagentprotocol.org/docs/0.3/spec#discovery the specification, section 3}.
 */
export const POPPY_JSON_PATH = '/.well-known/poppy.json';

/**
 * The path where a Company serves its protected resource metadata.
 * See {@link https://www.rfc-editor.org/rfc/rfc9728#section-3.1 RFC 9728 section 3.1}.
 */
export const PROTECTED_RESOURCE_PATH = '/.well-known/oauth-protected-resource';

/** The headers of both discovery documents. */
export const DISCOVERY_HEADERS = {
  'content-type': 'application/json',
  'cache-control': 'public, max-age=300',
} as const;

/**
 * The query parameters of a request to the login route that name the issuer and the page to land on. Both are optional.
 * See {@link https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin OpenID Connect Core 1.0, section 4}.
 */
export const LOGIN_INITIATION_PARAMS = {
  issuer: 'iss',
  targetLinkUri: 'target_link_uri',
} as const;
