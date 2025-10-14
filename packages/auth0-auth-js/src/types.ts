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
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;

  /**
   * Indicates whether the SDK should use the mTLS endpoints if they are available.
   * 
   * When set to `true`, using a `customFetch` is required.
   */
  useMtls?: boolean;
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
  authorizationParams?: AuthorizationParameters;
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

export interface BuildLinkUserUrlOptions {
  /**
   * The connection for the user to link.
   */
  connection: string;
  /**
   * The scope for the connection.
   */
  connectionScope: string;
  /**
   * The id token of the user initiating the link.
   */
  idToken: string;
  /**
   * Additional authorization parameters to be sent with the link user request.
   */
  authorizationParams?: AuthorizationParameters;
}

export interface BuildLinkUserUrlResult {
  /**
   * The URL to use to link the user, including the query parameters.
   * Redirect the user to this URL to link the user.
   * @example 'https://example.auth0.com/authorize?request_uri=urn:ietf:params:oauth:request_uri&client_id=...'
   */
  linkUserUrl: URL;
  /**
   * The code verifier that is used for the link user request.
   */
  codeVerifier: string;
}

export interface BuildUnlinkUserUrlOptions {
  /**
   * The connection for the user to unlink.
   */
  connection: string;
  /**
   * The id token of the user initiating the unlink.
   */
  idToken: string;
  /**
   * Additional authorization parameters to be sent with the unlink user request.
   */
  authorizationParams?: AuthorizationParameters;
}

export interface BuildUnlinkUserUrlResult {
  /**
   * The URL to use to unlink the user, including the query parameters.
   * Redirect the user to this URL to unlink the user.
   * @example 'https://example.auth0.com/authorize?request_uri=urn:ietf:params:oauth:request_uri&client_id=...'
   */
  unlinkUserUrl: URL;
  /**
   * The code verifier that is used for the unlink user request.
   */
  codeVerifier: string;
}

export interface TokenByClientCredentialsOptions {
  /**
   * The audience for which the token should be requested.
   */
  audience: string;
  /**
   * The organization for which the token should be requested.
   */
  organization?: string;
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
export interface TokenForConnectionOptions {
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
  bindingMessage: string;
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
   * Set a custom expiry time for the CIBA flow in seconds. Defaults to 300 seconds (5 minutes) if not set.
   */
  requestedExpiry?: number;
  /**
   * Optional authorization details to use Rich Authorization Requests (RAR).
   * @see https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests
   */
  authorizationDetails?: AuthorizationDetails[];
  /**
   * Authorization Parameters to be sent with the authorization request.
   */
  authorizationParams?: AuthorizationParameters;
}
