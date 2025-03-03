import {
  IDToken,
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from 'openid-client';

export interface AuthClientOptions {
  /**
   * The Auth0 domain to use for authentication.
   * @example 'example.auth0.com' (without https://)
   */
  domain: string;
  /**
   * The client ID of the application.
   */
  clientId: string;
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
   * Authorization Parameters to be sent with the authorization request.
   */
  authorizationParams?: AuthorizationParameters;
}

export interface AuthorizationParameters {
  /**
   * The scope to use for the authentication request.
   */
  scope?: string;
  /**
   * The audience to use for the authentication request.
   */
  audience?: string;
  /**
   * The redirect URI to use for the authentication request, to which Auth0 will redirect the browser after the user has authenticated.
   * @example 'https://example.com/callback'
   */
  redirect_uri?: string;

  [key: string]: unknown;
}

export interface BuildAuthorizationUrlOptions {
  /**
   * Indicates whether the authorization request should be done using a Pushed Authorization Request.
   */
  pushedAuthorizationRequests?: boolean;
  /**
   * Authorization Parameters to be sent with the authorization request.
   */
  authorizationParams: AuthorizationParameters;
}

export interface BuildAuthorizationUrlResult {
  /**
   * The URL to use to authenticate the user, including the query parameters.
   * Redirect the user to this URL to authenticate.
   * @example 'https://example.auth0.com/authorize?client_id=...&scope=...'
   */
  authorizationUrl: URL;
  /**
   * The code verifier that is used for the authorization request.
   */
  codeVerifier: string;
}

export interface TokenByRefreshTokenOptions {
  /**
   * The refresh token to use to get a token.
   */
  refreshToken: string;
}

export interface TokenByCodeOptions {
  /**
   * The code verifier that is used for the authorization request.
   */
  codeVerifier: string;
}

export interface TokenForConnectionOptions {
  /**
   * The connection for which a token should be requested.
   */
  connection: string;
  /**
   * Login hint to inform which connection account to use, can be useful when multiple accounts for the connection exist for the same user.
   */
  loginHint?: string;
  /**
   * The refresh token to use to get an access token for the connection.
   */
  refreshToken: string;
}

export interface BuildLogoutUrlOptions {
  /**
   * The URL to which the user should be redirected after the logout.
   * @example 'https://example.com'
   */
  returnTo: string;
}

export interface VerifyLogoutTokenOptions {
  /**
   * The logout token to verify.
   */
  logoutToken: string;
}

export interface VerifyLogoutTokenResult {
  /**
   * The sid claim of the logout token.
   */
  sid: string;
  /**
   * The sub claim of the logout token.
   */
  sub: string;
}

export interface AuthorizationDetails {
  readonly type: string;
  readonly [parameter: string]: unknown;
}

export class TokenResponse {
  /**
   * The access token retrieved from Auth0.
   */
  accessToken: string;
  /**
   * The id token retrieved from Auth0.
   */
  idToken?: string;
  /**
   * The refresh token retrieved from Auth0.
   */
  refreshToken?: string;
  /**
   * The time at which the access token expires.
   */
  expiresAt: number;
  /**
   * The scope of the access token.
   */
  scope?: string;
  /**
   * The claims of the id token.
   */
  claims?: IDToken;
  /**
   * The authorization details of the token response.
   */
  authorizationDetails?: AuthorizationDetails[];

  constructor(
    accessToken: string,
    expiresAt: number,
    idToken?: string,
    refreshToken?: string,
    scope?: string,
    claims?: IDToken,
    authorizationDetails?: AuthorizationDetails[]
  ) {
    this.accessToken = accessToken;
    this.idToken = idToken;
    this.refreshToken = refreshToken;
    this.expiresAt = expiresAt;
    this.scope = scope;
    this.claims = claims;
    this.authorizationDetails = authorizationDetails;
  }

  /**
   * Create a TokenResponse from a TokenEndpointResponse (openid-client).
   * @param response The TokenEndpointResponse from the token endpoint.
   * @returns A TokenResponse instance.
   */
  static fromTokenEndpointResponse(
    response: TokenEndpointResponse & TokenEndpointResponseHelpers
  ): TokenResponse {
    return new TokenResponse(
      response.access_token,
      Math.floor(Date.now() / 1000) + Number(response.expires_in),
      response.id_token,
      response.refresh_token,
      response.scope,
      response.claims(),
      response.authorization_details
    );
  }
}

export interface BackchannelAuthenticationOptions {
  /**
   * Human-readable message to be displayed at the consumption device and authentication device.
   * This allows the user to ensure the transaction initiated by the consumption device is the same that triggers the action on the authentication device.
   */
  bindingMessage?: string;
  /**
   * The login hint to inform which user to use.
   */
  loginHint: {
    /**
     * The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication, and to which a push notification to authorize the login will be sent.
     */
    sub: string;
  };
  /**
   * Authorization Parameters to be sent with the authorization request.
   */
  authorizationParams?: AuthorizationParameters;
}
