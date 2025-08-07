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
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  /**
   * The client ID of the application. Required for advanced client operations.
   */
  clientId?: string;
  /**
   * The client secret of the application.
   */
  clientSecret?: string;
  /**
   * The client assertion signing key to use.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The client assertion signing algorithm to use.
   */
  clientAssertionSigningAlg?: string;
  /**
   * Additional parameters to be sent with token endpoint requests.
   */
  tokenEndpointParams?: TokenEndpointParameters;
}

export interface TokenEndpointParameters {
  /**
   * The scope to use for token requests.
   */
  scope?: string;
  /**
   * The audience to use for token requests.
   */
  audience?: string;

  [key: string]: unknown;
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

export interface ConnectionTokenOptions {
  /**
   * The connection for which a token should be requested.
   */
  connection: string;
  /**
   * Login hint to inform which connection account to use.
   */
  loginHint?: string;

  /**
   * The access token to use to get an access token for the connection.
   */
  accessToken: string;
}

export interface ConnectionTokenResult {
  /**
   * The access token for the connection.
   */
  accessToken: string;
  /**
   * The scope of the access token.
   */
  scope?: string;
  /**
   * The time at which the access token expires.
   */
  expiresAt: number;
  /**
   * The connection for which the token was retrieved.
   */
  connection: string;
  /**
   * The login hint used for the connection.
   */
  loginHint?: string;
}