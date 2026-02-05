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

  /**
   * Optional audience for multi-resource refresh token support.
   * When specified, requests an access token for this audience.
   * 
   * @example 'https://api.example.com'
   */
  audience?: string;

  /**
   * When specified, requests an access token with these scopes.
   * Space-separated scope string.
   * 
   * @example 'read:data write:data'
   */
  scope?: string;
}

export interface TokenByCodeOptions {
  /**
   * The code verifier that is used for the authorization request.
   */
  codeVerifier: string;
}

/**
 * @deprecated Since v1.2.0. Use {@link TokenVaultExchangeOptions} with {@link AuthClient#exchangeToken}.
 * This interface remains for backward compatibility and is planned for removal in v2.0.
 */
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
  refreshToken?: string;
  /**
   * The access token to use to get an access token for the connection.
   */
  accessToken?: string;
}

/**
 * Configuration options for Token Exchange via Token Exchange Profile (RFC 8693).
 *
 * Token Exchange Profiles enable first-party on-behalf-of flows where you exchange
 * a custom token for Auth0 tokens targeting a different API, while preserving user identity.
 *
 * **Requirements:**
 * - Requires a confidential client (client_secret or client_assertion must be configured)
 * - Requires a Token Exchange Profile to be created in Auth0 via the Management API
 * - The subject_token_type must match a profile configured in your tenant
 * - Reserved namespaces are validated by the Auth0 platform; the SDK does not pre-validate
 * - The organization parameter is not supported during Early Access
 *
 * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Custom Token Exchange Documentation}
 * @see {@link https://auth0.com/docs/api/management/v2/token-exchange-profiles Token Exchange Profiles API}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8693 RFC 8693: OAuth 2.0 Token Exchange}
 *
 * @example Basic usage
 * ```typescript
 * const response = await authClient.exchangeToken({
 *   subjectTokenType: 'urn:acme:custom-token',
 *   subjectToken: userProvidedToken,
 *   audience: 'https://api.example.com',
 *   scope: 'openid profile read:data'
 * });
 * ```
 *
 * @example With custom parameters for Action validation
 * ```typescript
 * const response = await authClient.exchangeToken({
 *   subjectTokenType: 'urn:acme:legacy-token',
 *   subjectToken: legacyToken,
 *   audience: 'https://api.example.com',
 *   scope: 'openid offline_access',
 *   extra: {
 *     device_id: 'device-12345',
 *     session_token: 'sess-abc'
 *   }
 * });
 * ```
 */
export interface ExchangeProfileOptions {
  /**
   * A URI that identifies the type of the subject token being exchanged.
   * Must match a subject_token_type configured in a Token Exchange Profile.
   *
   * For custom token types, this must be a URI scoped under your own ownership.
   *
   * **Reserved namespaces** (validated by Auth0 platform):
   * - http://auth0.com, https://auth0.com
   * - http://okta.com, https://okta.com
   * - urn:ietf, urn:auth0, urn:okta
   *
   * @example "urn:acme:legacy-token"
   * @example "http://acme.com/mcp-token"
   */
  subjectTokenType: string;

  /**
   * The token to be exchanged.
   */
  subjectToken: string;

  /**
   * The unique identifier (audience) of the target API.
   * Must match an API identifier configured in your Auth0 tenant.
   *
   * @example "https://api.example.com"
   */
  audience?: string;

  /**
   * Space-separated list of OAuth 2.0 scopes to request.
   * Scopes must be allowed by the target API and token exchange profile configuration.
   *
   * @example "openid profile email"
   * @example "openid profile read:data write:data"
   */
  scope?: string;

  /**
   * Type of token being requested (RFC 8693).
   * Defaults to access_token if not specified.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-2.1 RFC 8693 Section 2.1}
   * @example "urn:ietf:params:oauth:token-type:access_token"
   * @example "urn:ietf:params:oauth:token-type:refresh_token"
   */
  requestedTokenType?: string;

  /**
   * ID or name of the organization to use when authenticating a user.
   * When provided, the user will be authenticated within the organization context,
   * and the organization ID will be present in the access token payload.
   * 
   * @see https://auth0.com/docs/manage-users/organizations
   */
  organization?: string;

  /**
   * Additional custom parameters accessible in Auth0 Actions via event.request.body.
   *
   * Use for context like device fingerprints, session IDs, or business metadata.
   * Cannot override reserved OAuth parameters.
   *
   * Array values are limited to 20 items per key to prevent DoS attacks.
   *
   * **Security Warning**: Never include PII (Personally Identifiable Information),
   * secrets, passwords, or sensitive data in extra parameters. These values may be
   * logged by Auth0, stored in audit trails, or visible in network traces. Use only
   * for non-sensitive metadata like device IDs, session identifiers, or request context.
   *
   * @example
   * ```typescript
   * {
   *   device_fingerprint: 'a3d8f7b2c1e4...',
   *   session_id: 'sess_abc123',
   *   risk_score: '0.95'
   * }
   * ```
   */
  extra?: Record<string, string | string[]>;
}

/**
 * Configuration options for Access Token Exchange with Token Vault.
 *
 * Access Token Exchange with Token Vault enables secure access to third-party APIs (e.g., Google Calendar, Salesforce)
 * by exchanging an Auth0 token for an external provider's access token without the client handling
 * the external provider's refresh tokens.
 *
 * **Requirements:**
 * - Requires a confidential client (client credentials must be configured)
 * - Token Vault must be enabled for the specified connection
 * - The connection must support the requested token type
 *
 * @see {@link https://auth0.com/docs/secure/tokens/token-vault Token Vault Documentation}
 * @see {@link https://auth0.com/docs/secure/tokens/token-vault/configure-token-vault Configure Token Vault}
 *
 * @example Using an access token
 * ```typescript
 * const response = await authClient.exchangeToken({
 *   connection: 'google-oauth2',
 *   subjectToken: auth0AccessToken,
 *   subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
 *   loginHint: 'user@example.com'
 * });
 * ```
 *
 * @example Using a refresh token
 * ```typescript
 * const response = await authClient.exchangeToken({
 *   connection: 'google-oauth2',
 *   subjectToken: auth0RefreshToken,
 *   subjectTokenType: 'urn:ietf:params:oauth:token-type:refresh_token'
 * });
 * ```
 */
export interface TokenVaultExchangeOptions {
  /**
   * The name of the connection configured in Auth0 with Token Vault enabled.
   *
   * @example "google-oauth2"
   * @example "salesforce"
   */
  connection: string;

  /**
   * The Auth0 token to exchange (access token or refresh token).
   */
  subjectToken: string;

  /**
   * Type of the Auth0 token being exchanged.
   *
   * **Important**: Defaults to `urn:ietf:params:oauth:token-type:access_token` if not specified.
   * If you're passing a refresh token, you MUST explicitly set this to
   * `urn:ietf:params:oauth:token-type:refresh_token` to avoid token type mismatch errors.
   *
   * @default 'urn:ietf:params:oauth:token-type:access_token'
   */
  subjectTokenType?:
    | 'urn:ietf:params:oauth:token-type:access_token'
    | 'urn:ietf:params:oauth:token-type:refresh_token';

  /**
   * Type of token being requested from the external provider.
   * Typically defaults to the external provider's access token type.
   */
  requestedTokenType?: string;

  /**
   * Hint about which external provider account to use.
   * Useful when multiple accounts for the connection exist for the same user.
   *
   * @example "user@example.com"
   * @example "external_user_id_123"
   */
  loginHint?: string;

  /**
   * Space-separated list of scopes to request from the external provider.
   *
   * @example "https://www.googleapis.com/auth/calendar.readonly"
   */
  scope?: string;

  /**
   * Additional custom parameters.
   * Cannot override reserved OAuth parameters.
   *
   * Array values are limited to 20 items per key to prevent DoS attacks.
   */
  extra?: Record<string, string | string[]>;
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

/**
 * Represents a successful token response from Auth0.
 *
 * Contains all tokens and metadata returned from Auth0 token endpoints,
 * including standard OAuth 2.0 tokens and optional OIDC tokens.
 */
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
   * The time at which the access token expires (Unix timestamp in seconds).
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

  /**
   * The type of the token (typically "Bearer").
   */
  tokenType?: string;

  /**
   * A URI that identifies the type of the issued token (RFC 8693).
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-3 RFC 8693 Section 3}
   * @example "urn:ietf:params:oauth:token-type:access_token"
   */
  issuedTokenType?: string;

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
   *
   * Populates all standard OAuth 2.0 token response fields plus RFC 8693 extensions.
   * Safely handles responses that may not include all optional fields (e.g., ID token,
   * refresh token, issued_token_type).
   *
   * @param response The TokenEndpointResponse from the token endpoint.
   * @returns A TokenResponse instance with all available token data.
   */
  static fromTokenEndpointResponse(
    response: TokenEndpointResponse & TokenEndpointResponseHelpers
  ): TokenResponse {
    const claims = response.id_token ? response.claims() : undefined;

    const tokenResponse = new TokenResponse(
      response.access_token,
      Math.floor(Date.now() / 1000) + Number(response.expires_in),
      response.id_token,
      response.refresh_token,
      response.scope,
      claims,
      response.authorization_details
    );

    tokenResponse.tokenType = response.token_type;
    tokenResponse.issuedTokenType = (
      response as typeof response & { issued_token_type?: string }
    ).issued_token_type;

    return tokenResponse;
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
