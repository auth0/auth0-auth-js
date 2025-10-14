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
   * Required when using the `getAccessTokenForConnection` method.
   */
  clientId?: string;
  /**
   * The optional client secret of the application.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the `getAccessTokenForConnection` method.
   */
  clientSecret?: string;
  /**
   * The optional client assertion signing key to use.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the `getAccessTokenForConnection` method.
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

/**
 * Options for retrieving a federated provider access token from Token Vault for a connection.
 *
 * Routing and subject token type:
 * - Provide exactly one of `accessToken` or `refreshToken` (mutually exclusive).
 * - The SDK automatically sets the appropriate `subject_token_type` based on which token is present.
 * - Runtime validation will throw an error if both or neither are provided.
 *
 * Access token:
 * - Use for public clients (SPA, mobile, native) where your backend receives an Auth0 access token
 * - Use for confidential clients when handling requests that only carry an access token
 * - Lower risk profile than sending a refresh token to your API
 *
 * Refresh token:
 * - Use only in confidential backends that securely store an Auth0 refresh token
 * - Not applicable to public clients (SPA, mobile, native)
 * - Use when your backend needs a provider token independently of an incoming request
 *
 * Required identity context:
 * - The user must have previously authenticated the given `connection` and consented to any requested scopes.
 * - If the user has multiple identities for the same connection, supply `loginHint` to disambiguate.
 *
 * Security notes:
 * - Do not pass tokens with a "Bearer " prefix or with leading or trailing whitespace.
 */
export interface AccessTokenForConnectionOptions {
  /**
   * Auth0 access token to use as the subject token.
   * Use for public clients (SPA, mobile, native) or when your backend only has an access token.
   * Must be a raw token string with no "Bearer " prefix and no surrounding whitespace.
   * Mutually exclusive with `refreshToken` - provide exactly one.
   */
  accessToken?: string;

  /**
   * Auth0 refresh token to use as the subject token.
   * Use only in confidential backends that securely store refresh tokens.
   * Not applicable to public clients.
   * Mutually exclusive with `accessToken` - provide exactly one.
   */
  refreshToken?: string;

  /**
   * Name of the Token Vault enabled connection, for example "google-oauth2" or "salesforce".
   */
  connection: string;

  /**
   * Optional hint to select a specific linked identity for the connection when the user has more than one.
   * For example an email for Google. If omitted and multiple identities exist, the server may return an error.
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