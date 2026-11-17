// Protocol strings, claim names, patterns and defaults for Poppy (Personal Agent Protocol).
// The code follows Poppy 1.0.
// Spec: https://personalagentprotocol.org/docs/1.0/spec

/**
 * The scope that lets an agent sign its browser in to the website. A website that lists a
 * `browser_session_endpoint` and offers sign-in has to support it, so Auth0 should list it in `scopes_supported`.
 * See {@link https://personalagentprotocol.org/docs/1.0/spec#scopes the specification, section 4.7}.
 */
export const BROWSER_SIGN_IN_SCOPE = 'poppy:browser-sign-in';

/** The identifier of the guest store. A cookie-backed guest store uses it as the cookie name. */
export const POPPY_GUEST_IDENTIFIER = '__a0_poppy';

/** The longest an agent's session on the website lasts when `agentSessionMaxAge` is not set: two hours, in seconds. */
export const DEFAULT_AGENT_SESSION_MAX_AGE = 7200;

/**
 * The names of the Poppy members of the `act` claim in the ID token of a browser join.
 *
 * These are Auth0's beta claims. The names may change.
 */
export const ACT_CLAIMS = {
  sessionId: 'poppy_sid',
  userId: 'poppy_user_id',
  agentId: 'poppy_agent_id',
} as const;

/**
 * A Session id: 1 to 256 characters of the URL-safe base64 alphabet. `@auth0/auth0-api-js` accepts the same ids, so
 * the two SDKs agree on which Sessions exist.
 */
export const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;

/** The profile that marks an anonymous user in the `sub_profile` claim of a token. */
export const ANONYMOUS_USER_PROFILE = 'urn:auth0:anonymous_user';

/**
 * The start of the `sub` of a guest's token. Auth0 puts it on the token of a guest next to the `sub_profile`. Either
 * one makes a login a guest candidate, and a guest needs both.
 */
export const GUEST_SUB_PREFIX = 'anon_poppy@';

/**
 * The bound (exclusive) for a Unix time in seconds. It is the bound that the `session_expiry` check in
 * `state/utils.ts` uses, and this is that constant, so the two cannot differ. A number at or above it is almost
 * certainly in milliseconds.
 */
export { MAX_PLAUSIBLE_UNIX_SECONDS } from '../state/utils.js';

/**
 * A lowercase host name: labels of letters, digits and hyphens, separated by dots. A label has 1 to 63 characters and
 * does not start or end with a hyphen, and the whole name has at most 253. A scheme, a port, a path or a trailing dot
 * does not match.
 */
export const HOST_NAME_PATTERN =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * A port after the host name in `organization.domain`: 1 to 5 digits, with no leading zero, so the text is written one
 * way only. The range and the default port are checked apart from this pattern (see `domainProblem` in `options.ts`).
 */
export const DOMAIN_PORT_PATTERN = /^[1-9]\d{0,4}$/;

/**
 * The path where a Company serves `poppy.json`.
 * See {@link https://personalagentprotocol.org/docs/1.0/spec#discovery the specification, section 3}.
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
