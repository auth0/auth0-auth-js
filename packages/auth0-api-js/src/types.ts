import type { JWTPayload } from 'jose';

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
