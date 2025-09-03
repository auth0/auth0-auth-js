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
   * The Client ID of your Auth0 Application.
   * Required when using the `getAccessTokenForConnection` method.
   */
  clientId?: string;
  /**
   * The Client Secret of your Auth0 Application.
   * Required when using the `getAccessTokenForConnection` method.
   */
  clientSecret?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
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

export interface AccessTokenForConnectionOptions {
  connection: string;
  accessToken: string;
  loginHint?: string;
}

export interface ConnectionTokenSet {
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
  connection: string;
  loginHint?: string;
}
