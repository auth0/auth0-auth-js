import type { JWTPayload } from 'jose';
import type { PoppySessionStore } from './poppy/session-store.js';

/** @category Configuration */
export type DomainsResolverContext = {
  /**
   * Full request URL, if available.
   * This is populated from `verifyAccessToken({ httpUrl })` when provided.
   */
  url?: string;
  /**
   * HTTP request headers (lowercased keys recommended).
   */
  headers?: Record<string, string | string[] | undefined>;
  /**
   * Unverified issuer extracted from the token.
   */
  unverifiedIss?: string;
};

/**
 * Resolver that returns a list of allowed domains for the current request.
 * @category Configuration
 */
export type DomainsResolver = (context: DomainsResolverContext) => Promise<string[]> | string[];

/**
 * Optional caching configuration for discovery metadata and JWKS fetchers.
 * TTL is expressed in seconds. maxEntries controls the LRU size.
 * @category Configuration
 */
export interface DiscoveryCacheOptions {
  ttl?: number;
  maxEntries?: number;
}

type ApiClientCommonOptions = {
  /**
   * The expected JWT Access Token audience ("aud") value.
   */
  audience: string;
  /**
   * The optional client ID of the application.
   * Required when using the `getAccessTokenForConnection`, `getTokenByExchangeProfile`,
   * or `getTokenOnBehalfOf` methods.
   */
  clientId?: string;
  /**
   * The optional client secret of the application.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using
   * the `getAccessTokenForConnection`, `getTokenByExchangeProfile`, or `getTokenOnBehalfOf` methods.
   */
  clientSecret?: string;
  /**
   * The optional client assertion signing key to use.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using
   * the `getAccessTokenForConnection`, `getTokenByExchangeProfile`, or `getTokenOnBehalfOf` methods.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The optional client assertion signing algorithm to use with the `clientAssertionSigningKey`.
   * If not provided, it will default to `RS256`.
   */
  clientAssertionSigningAlg?: string;
  /**
   * Optional, custom Fetch implementation to use.
   *
   * Unless `poppy.agentMetadata.fetch` is set, it is also the `fetch` that `verifyPoppyRequest` uses to get the client
   * metadata and the keys of agents, so a `customFetch` that adds credentials or rewrites hosts sees the agent URLs as
   * well. Set `poppy.agentMetadata.fetch` to keep it out of those requests.
   */
  customFetch?: typeof fetch;
  /**
   * Optional list of allowed JWT algorithms for access token verification.
   * Defaults to ['RS256'] when not provided. HS* values are rejected.
   */
  algorithms?: string[];
  /**
   * Demonstration of Proof-of-Possession (DPoP) configuration.
   *
   * @defaultValue `{ mode: 'allowed', iatOffset: 300, iatLeeway: 30 }`
   */
  dpop?: DPoPOptions;
  /**
   * Optional discovery cache configuration for OIDC metadata.
   * TTL is in seconds. maxEntries controls the LRU size.
   * Defaults when omitted: ttl = 600 seconds, maxEntries = 100.
   */
  discoveryCache?: DiscoveryCacheOptions;
  /**
   * How a cached On Behalf Of token is matched against a request.
   *
   * @defaultValue `'strict'`
   */
  scopeMatching?: ScopeMatching;
  /**
   * Organization enforcement policy applied during `verifyAccessToken`.
   * - `'allow'` (default): no organization check; behavior identical to prior versions.
   * - `'required'`: the verified access token must carry an `org_id` claim, and when
   *   `organizationId` is set the claim value must be in that allowlist. With no allowlist,
   *   any organization is accepted, so the application must still authorize on `org_id` itself.
   *
   * Any other value throws `InvalidConfigurationError` at construction.
   */
  organizationPolicy?: 'required' | 'allow';
  /**
   * Optional organization allowlist. Valid ONLY when `organizationPolicy` is `'required'`;
   * providing it otherwise throws `InvalidConfigurationError` at construction. A single
   * string is treated as a one-element allowlist. Must be a non-empty string or a non-empty
   * array of non-empty strings.
   *
   * Values are organization IDs (`org_...`, the value of the `org_id` claim), NOT organization
   * names. A name such as `'acme'` never matches and rejects every token.
   *
   * Entries are compared to the claim exactly, so a value carrying surrounding whitespace could
   * never match and is rejected at construction. Trim the values when they come from a delimited
   * source such as `process.env.ORGS.split(',')`.
   *
   * The allowlist is copied at construction, so mutating the array afterwards has no effect.
   */
  organizationId?: string | string[];
  /**
   * Opt-in support for requests from Personal Agents (Poppy 0.3). Without it, and without calls to
   * `verifyPoppyRequest`, the client does exactly what it did before.
   *
   * `verifyPoppyRequest` also works without this option, with every setting at its default. The `Poppy-Session`
   * header is then checked only for a request that sets `requireSession`.
   *
   * @beta
   */
  poppy?: PoppyOptions;
};

/**
 * How a cached On Behalf Of token is matched against a request. Both modes compare the
 * scopes an exchange was **granted**, never the scopes a previous call requested, and
 * both cache a token under the scopes it was granted.
 *
 * - `'strict'`: reuse a cached token only when its granted scopes are exactly the
 *   requested set.
 * - `'non_strict'`: also reuse a cached token whose granted scopes cover the requested
 *   set, preferring the smallest such token. Requires an `IndexedTokenStore`, because
 *   several tokens then coexist per subject and have to be searched rather than looked
 *   up. A request for no scopes never reuses a cached token in this mode.
 *
 * Applies to On Behalf Of tokens only.
 *
 * @category Configuration
 */
export type ScopeMatching = 'strict' | 'non_strict';

/** @category Configuration */
export type ApiClientOptions =
  | (ApiClientCommonOptions & {
      /**
       * The Auth0 domain to use for authentication and non-verification flows.
       * @example 'example.auth0.com'
       */
      domain: string;
      /**
       * Optional domain allowlist or resolver for access token verification.
       * When provided, access token verification uses this instead of `domain`.
       * Provide domains as shown in the Auth0 Dashboard (e.g., "example.auth0.com").
       */
      domains?: string[] | DomainsResolver;
    })
  | (ApiClientCommonOptions & {
      /**
       * Domain allowlist or resolver for access token verification.
       * Provide domains as shown in the Auth0 Dashboard (e.g., "example.auth0.com").
       */
      domains: string[] | DomainsResolver;
      domain?: never;
      clientId?: never;
      clientSecret?: never;
      clientAssertionSigningKey?: never;
      clientAssertionSigningAlg?: never;
    });

/** @category Token Exchange */
export interface AccessTokenForConnectionOptions {
  /**
   * The name of the connection to get the token for.
   */
  connection: string;
  /**
   * The access token used as the subject token to be exchanged.
   */
  accessToken: string;
  /**
   * An optional login hint to pass to the connection.
   */
  loginHint?: string;
}

/** @category Token Exchange */
export interface ConnectionTokenSet {
  /**
   * The access token issued by the connection.
   */
  accessToken: string;
  /**
   * The scope granted by the connection.
   */
  scope: string | undefined;
  /**
   * The access token expiration time, represented in seconds since the Unix epoch.
   */
  expiresAt: number;
  /**
   * The name of the connection the token was requested for.
   */
  connection: string;
  /**
   * An optional login hint that was passed during the exchange.
   */
  loginHint?: string;
}

/**
 * Configuration options for exchanging a token via a Custom Token Exchange Profile (RFC 8693).
 *
 * This interface supports **Custom Token Exchange** for custom token types.
 * Auth0 also supports **Access Token Exchange with Token Vault** for external provider's access tokens.
 *
 * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Custom Token Exchange Documentation}
 * @see {@link https://auth0.com/docs/secure/tokens/token-vault/access-token-exchange-with-token-vault Token Vault Documentation}
 *
 * @example
 * ```typescript
 * const options: ExchangeProfileOptions = {
 *   subjectTokenType: 'urn:example:custom-token',
 *   audience: 'https://api.backend.com',
 *   scope: 'read:data write:data'
 * };
 * ```
 * @category Token Exchange
 */
export interface ExchangeProfileOptions {
  /**
   * URI identifying the type of the subject token being exchanged.
   * Must match a `subject_token_type` configured in a Token Exchange Profile.
   *
   * For custom token types, this must be a URI scoped under your own ownership,
   * such as http://acme.com/legacy-token or urn:acme:legacy-token.
   *
   * Reserved namespaces (cannot be used): http://auth0.com, https://auth0.com,
   * http://okta.com, https://okta.com, urn:ietf, urn:auth0, urn:okta
   *
   * @example "urn:acme:legacy-token"
   * @example "http://acme.com/mcp-token"
   */
  subjectTokenType: string;

  /**
   * The audience (API identifier) for which tokens will be issued.
   * Must match an API identifier configured in your Auth0 tenant.
   *
   * @example "https://api.backend.com"
   */
  audience: string;

  /**
   * Space-separated list of OAuth 2.0 scopes to request for the exchanged token.
   *
   * @example "read:data write:data"
   */
  scope?: string;

  /**
   * Type of token being requested (RFC 8693).
   * Defaults to access_token if not specified.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-2.1 RFC 8693 Section 2.1}
   *
   * @example "urn:ietf:params:oauth:token-type:access_token"
   * @example "urn:ietf:params:oauth:token-type:refresh_token"
   */
  requestedTokenType?: string;

  /**
   * ID or name of the organization to use when authenticating a user.
   * When provided, the user will be authenticated within the organization context,
   * and the organization ID will be present in the access token payload.
   *
   * @see {@link https://auth0.com/docs/manage-users/organizations Auth0 Organizations}
   *
   * @example "org_abc123"
   * @example "my-organization"
   */
  organization?: string;
}

/**
 * Result returned from a token exchange via a Custom Token Exchange Profile (RFC 8693).
 * Contains the exchanged tokens and metadata.
 * @category Token Exchange
 */
export interface TokenExchangeProfileResult {
  /**
   * The access token issued for the target backend API.
   */
  accessToken: string;

  /**
   * The access token expiration time, represented in seconds since the Unix epoch.
   */
  expiresAt: number;

  /**
   * The scope granted by Auth0 for the exchanged token.
   */
  scope?: string;

  /**
   * ID token containing user identity claims (if requested via openid scope).
   */
  idToken?: string;

  /**
   * Refresh token for obtaining new access tokens (if requested via offline_access scope).
   */
  refreshToken?: string;

  /**
   * Token type (typically "Bearer").
   */
  tokenType?: string;

  /**
   * RFC 8693 issued token type indicator (e.g., "urn:ietf:params:oauth:token-type:access_token").
   */
  issuedTokenType?: string;
}

/**
 * Options for exchanging an Auth0 access token for a downstream Auth0 access token
 * on behalf of the same end user.
 * @category Token Exchange
 */
export interface OnBehalfOfTokenOptions {
  /**
   * The audience (API identifier) for which the exchanged access token should be issued.
   *
   * @example "https://api.backend.com"
   */
  audience: string;

  /**
   * Space-separated list of OAuth 2.0 scopes to request for the exchanged token.
   *
   * @example "read:data write:data"
   */
  scope?: string;
}

/**
 * Result returned from an On Behalf Of token exchange.
 * Contains only access-token-oriented fields relevant to OBO.
 * @category Token Exchange
 */
export interface OnBehalfOfTokenResult {
  /**
   * The access token issued for the downstream API.
   */
  accessToken: string;

  /**
   * The access token expiration time, represented in seconds since the Unix epoch.
   */
  expiresAt: number;

  /**
   * The scope string exactly as the authorization server returned it. Absent when the
   * server omitted it, which per RFC 6749 section 5.1 means the scopes were granted as
   * requested.
   *
   * An empty string is meaningful and distinct from the field being absent: it means
   * nothing was granted. A truthiness test such as `if (result.scope)` therefore reads an
   * empty grant the same as an absent one, that is, as a full grant. Test for `undefined`
   * explicitly, or use {@link OnBehalfOfTokenResult.grantedScopes}.
   */
  scope?: string;

  /**
   * The scopes the exchange actually granted: normalized, deduplicated and sorted
   * alphabetically. Always present, on a fresh exchange and on a cache hit alike. When the
   * authorization server omitted `scope` it holds the normalized requested scopes (RFC 6749
   * section 5.1). When the server returned an empty `scope` it is an empty array, because
   * nothing was granted.
   *
   * Use this rather than `scope` to decide whether a result covers what a request needs.
   */
  grantedScopes: string[];

  /**
   * Token type (typically "Bearer").
   */
  tokenType?: string;

  /**
   * RFC 8693 issued token type indicator (typically access token for OBO).
   */
  issuedTokenType?: string;
}

/**
 * Recursive actor claim defined by RFC 8693.
 * The outermost `sub` represents the current actor.
 * Nested `act` values represent prior actors in the delegation chain.
 * @category Utilities
 */
export interface ActClaim {
  /**
   * Subject identifier for the current actor at this level of the chain.
   */
  sub: string;

  /**
   * Optional nested actor representing the prior actor in the chain.
   */
  act?: ActClaim;
}

/**
 * Claims returned from `verifyAccessToken()`.
 * Includes standard JWT claims plus the optional `act` claim used for OBO delegation.
 * @category Token Verification
 */
export type VerifiedAccessTokenClaims = JWTPayload & {
  /**
   * Optional RFC 8693 actor claim.
   */
  act?: ActClaim;
};

/**
 * Options for validating a bearer (non-DPoP) access token.
 * DPoP-related fields must be omitted.
 * @category Token Verification
 */
export type BearerVerifyAccessTokenOptions = {
  /**
   * The access token to verify.
   */
  accessToken: string;
  /**
   * HTTP request headers, used for domain resolution.
   */
  headers?: Record<string, string | string[] | undefined>;
  /**
   * Additional claims that are required to be present in the access token.
   */
  requiredClaims?: string[];
  /**
   * DPoP proof must be omitted for bearer validation.
   */
  dpopProof?: undefined;
  /**
   * HTTP method is not used for bearer validation.
   */
  httpMethod?: undefined;
  /**
   * Full request URL, used for MCD domain resolution when available.
   */
  httpUrl?: string;
  /**
   * Optional scheme (e.g., 'bearer'); DPoP params must be absent.
   */
  scheme?: string;

  /**
   * The allowed asymmetric algorithms to use for verifying the access token's signature.
   *
   * Defaults to ['RS256'] if not provided.
   */
  algorithms?: string[];
};

/**
 * Options for validating a DPoP-bound access token.
 * All DPoP-related fields are required.
 * @category Token Verification
 */
export type DPoPVerifyAccessTokenOptions = {
  /**
   * The access token to verify (must contain cnf.jkt).
   */
  accessToken: string;
  /**
   * HTTP request headers, used for domain resolution.
   */
  headers?: Record<string, string | string[] | undefined>;
  /**
   * Additional claims that are required to be present in the access token.
   */
  requiredClaims?: string[];
  /**
   * The DPoP proof JWT from the `DPoP` header.
   */
  dpopProof: string;
  /**
   * HTTP method of the authorized request (for `htm` validation).
   */
  httpMethod: string;
  /**
   * Full HTTP URL of the authorized request.
   * Used for domain resolution when `domains` is configured and for DPoP `htu` validation.
   */
  httpUrl: string;
  /**
   * Authorization scheme used when presenting the token (e.g., 'dpop').
   */
  scheme: string;

  /**
   * The allowed asymetric algorithms to use for verifying the access token's signature.
   *
   * Defaults to ['RS256'] if not provided.
   */
  algorithms?: string[];
};

/** @category Token Verification */
export type VerifyAccessTokenOptions = BearerVerifyAccessTokenOptions | DPoPVerifyAccessTokenOptions;

/** @category Token Verification */
export interface DPoPOptions {
  /**
   * Controls DPoP behavior.
   * - `allowed` (default): accept Bearer or DPoP; validate proof/binding when DPoP is indicated.
   * - `required`: only DPoP is accepted.
   * - `disabled`: DPoP is ignored; Bearer-only behavior.
   */
  mode?: 'allowed' | 'required' | 'disabled';
  /**
   * Maximum accepted age (in seconds) for a DPoP proof `iat` claim.
   * @default 300
   */
  iatOffset?: number;
  /**
   * Allowed future skew (in seconds) for a DPoP proof `iat` claim.
   * @default 30
   */
  iatLeeway?: number;
}

/**
 * Options for verifying the requests of Personal Agents, as the Poppy (Personal Agent Protocol) 0.3 specification
 * describes. Set them as the `poppy` option of {@link ApiClientOptions}.
 *
 * @see {@link https://personalagentprotocol.org/docs/0.3/spec Poppy 0.3 specification}
 * @beta
 * @category Poppy
 */
export interface PoppyOptions {
  /**
   * Whether to verify the `Poppy-Session` header of every request that carries one. When `false`, the header is
   * ignored unless the request sets `requireSession`.
   *
   * @defaultValue `false`
   */
  verifySession?: boolean;

  /**
   * The registered agents of your Company, each as the URL of its client metadata (its `client_id`). A `Poppy-Session`
   * header from any other agent is refused. While Session checks are on (`verifySession`, or `requireSession` on the
   * request), the access token of a listed agent is refused with `missing_session` when it arrives without that
   * header, whatever the `act` claim of the token holds. The agent of a token is its `client_id` claim, else its `azp`
   * claim.
   *
   * The list does not filter a Session that is read from the `act` claim of a web app's access token (`source:
   * 'token'`). If you need that, check `poppy.agent.cimdUrl` yourself.
   *
   * @defaultValue none. Any agent is accepted, and no access token needs the header.
   */
  agents?: string[];

  /**
   * An opt-in store of known Sessions. When set, the SDK checks known Sessions and saves new ones. Without it, the
   * SDK only returns the verified Session, and your code runs those checks.
   */
  sessionStore?: PoppySessionStore;

  /**
   * How far the `iat` of a Session JWT may be from the current time, in seconds, in both directions. The edges are
   * accepted.
   *
   * @defaultValue `60`
   */
  iatWindow?: number;

  /**
   * The public origin of your API: an `https` origin with no path, for example `https://api.example.com`. The `htu` of
   * a Session JWT, and of the DPoP proof of an access token that `verifyPoppyRequest` verifies, is compared with this
   * origin and the path of the request URL, not with the host the server sees. That keeps verification working behind
   * a proxy or a load balancer. When it is set, it replaces the origin of any absolute `url` you pass.
   *
   * Set it when you pass only a path as `url`, as the Express adapter does. Without it, `url` must be the absolute URL
   * exactly as the agent called it.
   *
   * @defaultValue none
   */
  publicOrigin?: string;

  /**
   * How the SDK fetches the client metadata and the keys of an agent.
   */
  agentMetadata?: PoppyAgentMetadataOptions;
}

/**
 * How the SDK fetches the client metadata document and the key set of an agent. The agent chooses these URLs, so
 * the SDK fetches them with care: HTTPS only, no redirects, no cookies or credentials, and a limit on time and size.
 * It also accepts only a key set that is plain: 1 to 100 public keys, whose members are strings, booleans, numbers or
 * arrays of strings. Any other key set is refused whole.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyAgentMetadataOptions {
  /**
   * The `fetch` to use. Defaults to the `customFetch` of the client, then to the global `fetch`.
   *
   * A plain `fetch` cannot see where a host name resolves, so the built-in address check covers the text of the host:
   * `localhost`, IP literals, names with no dot and names under `.local`, `.internal`, `.localdomain` and
   * `.home.arpa`. To guard against any other host name that resolves to an internal address, pass a hardened `fetch`
   * or send these requests through an egress proxy.
   */
  fetch?: typeof fetch;

  /**
   * The cache for the keys of the agents. TTL is in seconds.
   *
   * This sets how long, and for how many agents, good client metadata and keys are kept. A `ttl` or a `maxEntries` of
   * `0` turns that off, and every request for keys then fetches them again. It does not turn off two protections that
   * the SDK always has, whatever you set here: a fetch that failed is remembered for 30 seconds, so an agent whose host
   * is down is not asked again at once, and the keys of an agent are refetched for an unknown key ID at most once every
   * 30 seconds. Each of the two remembers up to the larger of `maxEntries` and `100` agents.
   *
   * @defaultValue `{ ttl: 600, maxEntries: 100 }`
   */
  cache?: DiscoveryCacheOptions;

  /**
   * The time limit for each request, in milliseconds: a whole number from `1` to `2147483647`. The client metadata and
   * the key set each get this much time, for the request and the whole of the response body. Any other value throws
   * an `InvalidConfigurationError`.
   *
   * @defaultValue `5000`
   */
  timeoutMs?: number;

  /**
   * The size limit for each response body, in bytes.
   *
   * @defaultValue `65536`
   */
  maxBytes?: number;

  /**
   * Whether to accept agent URLs on `localhost`, on private, loopback and link-local IP addresses, and on names that
   * only a local network can resolve: a name with no dot, and names under `.local`, `.internal`, `.localdomain` and
   * `.home.arpa`. The specification forbids connecting to such addresses unless you configured it on purpose
   * (section 3). Turn this on for local development only.
   *
   * @defaultValue `false`
   */
  allowPrivateAddresses?: boolean;
}

/**
 * What a {@link PoppySessionStore} keeps for a Session.
 *
 * @beta
 * @category Poppy
 */
export interface PoppySessionRecord {
  /**
   * The pairwise User ID of the Session. A known Session keeps it.
   *
   * In a Session from the `Poppy-Session` header the agent chooses it, and the specification sets no format for it
   * (section 5.1). The SDK enforces no short limit: only the 16,384 characters of the whole Session JWT bound it, so it
   * can be several KB. Size the column of your database for that.
   */
  userId: string;

  /**
   * The Agent ID of the Session, when the agent sent one. A known Session keeps it. The agent chooses it as well, with
   * the same bound as `userId`: size the column for it.
   */
  poppyAgentId?: string;

  /**
   * Set to `true` to end the Session. Requests for an ended Session are refused with `session_ended`, and the agent
   * then starts a new Session. Any truthy value ends it, such as the `1` of a raw SQL row.
   */
  ended?: boolean;
}

/**
 * A request to verify with `verifyPoppyRequest`.
 *
 * @beta
 * @category Poppy
 */
export interface VerifyPoppyRequestOptions {
  /**
   * The HTTP method of the request.
   */
  method: string;

  /**
   * The full URL as the agent called it, or only its path when `publicOrigin` is set. With `publicOrigin`, only the
   * path of `url` is used. The query and the fragment are ignored.
   *
   * It is used to check a `Poppy-Session` header, a DPoP proof and a `domains` function, which receives it. A request
   * with only a Bearer access token, and no `domains` function, does not use it.
   */
  url: string;

  /**
   * The request headers, as a plain object. Names may be in any case. This is the same type as the `headers` of
   * `verifyAccessToken`. For a Fetch API `Request`, pass `Object.fromEntries(request.headers)`. A `Headers`, a `Map`,
   * an array or any other iterable, and an object with a `get` method, would read as a request with no headers, so they
   * are refused with an `InvalidConfigurationError`.
   */
  headers: Record<string, string | string[] | undefined>;

  /**
   * Whether the route needs a Session. When `true`, the `Poppy-Session` header is checked even if `verifySession` is
   * off, and a request that ends with no verified Session is refused with an `InvalidSessionError` (`code`
   * `invalid_session`, `reason` `missing_session`).
   *
   * @defaultValue `false`
   */
  requireSession?: boolean;
}

/**
 * The result of `verifyPoppyRequest`.
 *
 * @beta
 * @category Poppy
 */
export interface VerifiedPoppyRequest {
  /**
   * The verified Session, from the `Poppy-Session` header or from the `act` claim of a web app's access token.
   * Absent when the request carries no Session.
   */
  poppy?: PoppySession;

  /**
   * The claims of the access token. They are set whenever the request carried an access token, and only after it was
   * verified, whether the request also has a Session or not. Absent when the request carried no access token.
   */
  claims?: VerifiedAccessTokenClaims;
}

/**
 * A verified Poppy Session.
 *
 * @beta
 * @category Poppy
 */
export interface PoppySession {
  /**
   * The Session ID: `sid` of the Session JWT, or `act.poppy_sid` of the access token.
   */
  sessionId: string;

  /**
   * An opaque key, unique for each agent and Session ID. Key your carts, orders and other Session state by it, never
   * by `sessionId` alone, because two agents can pick the same `sid`.
   */
  key: string;

  /**
   * The pairwise User ID for your Company: `sub` of the Session JWT, or `act.poppy_user_id` of the access token.
   */
  userId: string;

  /**
   * The agent that sent the request.
   */
  agent: PoppyAgent;

  /**
   * Whether an access token was verified with the Session.
   */
  state: PoppySessionState;

  /**
   * Where the Session came from.
   */
  source: PoppySessionSource;
}

/**
 * The agent behind a verified Poppy Session.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyAgent {
  /**
   * The URL of the client metadata document of the agent, which is its `client_id`: `iss` of the Session JWT, or
   * `act.sub` of the access token.
   */
  cimdUrl: string;

  /**
   * The Agent ID, when the agent sent one: `agent_id` of the Session JWT, or `act.poppy_agent_id` of the access token.
   */
  poppyAgentId?: string;
}

/**
 * Whether the Session has an account behind it. `'signed_in'` means that an access token for the User's account was
 * verified with the Session. `'signed_out'` means that none was: the request had only the `Poppy-Session` header, or
 * the Session comes from the access token of a guest, an anonymous user whom the agent joined to your web app in the
 * browser. Auth0 marks that token with `sub_profile` (`urn:auth0:anonymous_user`) and a `sub` that starts with
 * `anon_poppy@`, and either one is enough. A guest has no account, so `claims.sub` is not one.
 *
 * @beta
 * @category Poppy
 */
export type PoppySessionState = 'signed_out' | 'signed_in';

/**
 * Where a verified Session came from: `'header'` for the `Poppy-Session` header, and `'token'` for the `act` claim of
 * a web app's access token.
 *
 * @beta
 * @category Poppy
 */
export type PoppySessionSource = 'header' | 'token';

/**
 * Why a Session check failed. It is the `reason` of an {@link InvalidSessionError}, and a stable value for logs and
 * tests.
 *
 * - `missing_session`: the request needs a verified Session and has no `Poppy-Session` header, or it carries the access
 *   token of a registered agent and no header.
 * - `malformed_session`: the header is not a well-formed Session JWT, or the `act` claim of the access token does not
 *   hold a well-formed Session.
 * - `agent_not_allowed`: the agent named in the Session JWT is not allowed.
 * - `agent_metadata_invalid`: the client metadata or the keys of the agent can't be used.
 * - `delegation_invalid`: the delegation of the Session JWT failed verification.
 * - `signature_invalid`: the signature of the Session JWT failed verification.
 * - `claim_mismatch`: `aud`, `htm` or `htu` doesn't match the request.
 * - `iat_out_of_window`: `iat` is outside the accepted window.
 * - `ath_mismatch`: `ath` doesn't match the access token.
 * - `token_client_mismatch`: the access token was not issued to the agent named in the Session JWT.
 * - `session_mismatch`: the User ID or Agent ID doesn't match the known Session.
 *
 * @beta
 * @category Poppy
 */
export type InvalidSessionReason =
  | 'missing_session'
  | 'malformed_session'
  | 'agent_not_allowed'
  | 'agent_metadata_invalid'
  | 'delegation_invalid'
  | 'signature_invalid'
  | 'claim_mismatch'
  | 'iat_out_of_window'
  | 'ath_mismatch'
  | 'token_client_mismatch'
  | 'session_mismatch';
