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

  /**
   * The algorithms to use for verifying access tokens.
   * If not provided, it will default to `['RS256', 'PS256']`, allowing both RS256 and PS256 algorithms.
   */
  algorithms?: Array<'RS256' | 'PS256'>;
}