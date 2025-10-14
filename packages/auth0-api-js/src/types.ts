export interface ApiClientOptions {
  /**
   * The Auth0 domain to use for authentication.
   * @example 'example.auth0.com' (without https://)
   */
  domain: string;
  /**
   * The expected JWT Access Token audience ("aud") value.
   */
  audience: string;
  /**
   * The optional client ID of the application.
   * Required when using the `getAccessTokenForConnection` or `getTokenByExchangeProfile` methods.
   */
  clientId?: string;
  /**
   * The optional client secret of the application.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the `getAccessTokenForConnection` or `getTokenByExchangeProfile` methods.
   */
  clientSecret?: string;
  /**
   * The optional client assertion signing key to use.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the `getAccessTokenForConnection` or `getTokenByExchangeProfile` methods.
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
}

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
}

/**
 * Result returned from a token exchange via a Custom Token Exchange Profile (RFC 8693).
 * Contains the exchanged tokens and metadata.
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

export interface VerifyAccessTokenOptions {
  /**
   * The access token to verify.
   */
  accessToken: string;

  /**
   * Additional claims that are required to be present in the access token.
   * If the access token does not contain these claims, the verification will fail.
   * Apart from the claims defined in this array, the SDK will also enforce: `iss`, `aud`, `exp` and `iat`.
   */
  requiredClaims?: string[];
}
