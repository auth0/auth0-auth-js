export type { AuthorizationDetails } from '@auth0/auth0-auth-js';

export interface BrowserClientOptions {
  domain: string;
  clientId: string;
  authorizationParams?: AuthorizationParameters;
  transactionIdentifier?: string;
  stateIdentifier?: string;
  /**
   * Optional secret for encrypting data in localStorage.
   * Required if stateStore and transactionStore are not provided.
   */
  secret?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  transactionStore?: TransactionStore;
  stateStore?: StateStore;
  /**
   * Storage location for tokens and session data (spa-js compatible)
   * - 'localstorage': Persists across browser sessions (default)
   * - 'sessionstorage': Cleared when tab/browser closes
   * - 'memory': In-memory only (cleared on page reload)
   */
  cacheLocation?: 'localstorage' | 'sessionstorage' | 'memory';
  /**
   * Enable DPoP (Demonstrating Proof-of-Possession)
   */
  useDpop?: boolean;
}

export interface UserClaims {
  sub: string;
  name?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  org_id?: string;

  [key: string]: unknown;
}

export interface AuthorizationParameters {
  scope?: string;
  audience?: string;
  redirect_uri?: string;

  [key: string]: unknown;
}

export interface TokenSet {
  audience: string;
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
}

export interface InternalStateData {
  sid: string;
  createdAt: number;
}

export interface StateData extends SessionData {
  internal: InternalStateData;
}

export interface SessionData {
  user: UserClaims | undefined;
  idToken: string | undefined;
  refreshToken: string | undefined;
  tokenSets: TokenSet[];

  [key: string]: unknown;
}

export interface TransactionData {
  audience?: string;
  codeVerifier: string;
  [key: string]: unknown;
}

export interface AbstractDataStore<TData> {
  set(identifier: string, state: TData, removeIfExists?: boolean): Promise<void>;

  get(identifier: string): Promise<TData | undefined>;

  delete(identifier: string): Promise<void>;
}

export type LogoutTokenClaims = { sub?: string; sid?: string };

export interface StateStore extends AbstractDataStore<StateData> {
  deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface TransactionStore extends AbstractDataStore<TransactionData> {}

export interface StartInteractiveLoginOptions<TAppState = unknown> {
  pushedAuthorizationRequests?: boolean;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

/**
 * Options for retrieving an access token with MRRT support.
 * Allows requesting tokens for specific audiences and scopes at runtime.
 */
export interface GetAccessTokenOptions {
  /**
   * Optional audience for the requested access token.
   * If not provided, falls back to configuration audience or 'default'.
   * @example 'https://api.example.com'
   */
  audience?: string;

  /**
   * Optional scope for the requested access token.
   * If not provided, falls back to configuration scope.
   * Space-separated scope string.
   * @example 'read:data write:data'
   */
  scope?: string;
}

/**
 * Options for logging out a user.
 * Supports both browser-js format (returnTo) and spa-js format (logoutParams).
 */
export interface LogoutOptions {
  /**
   * @deprecated Use logoutParams.returnTo instead for consistency with spa-js
   */
  returnTo?: string;
  clientId?: string | null;
  /**
   * Set to false to prevent automatic redirect, or provide custom redirect function
   */
  openUrl?: false | ((url: string) => Promise<void>);
  /**
   * Logout parameters (spa-js compatible format)
   */
  logoutParams?: {
    federated?: boolean;
    returnTo?: string;
    [key: string]: unknown;
  };
}

export interface StartLinkUserOptions<TAppState = unknown> {
  connection: string;
  connectionScope: string;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

export interface StartUnlinkUserOptions<TAppState = unknown> {
  connection: string;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

// ============================================================================
// spa-js Compatible Types
// ============================================================================

/**
 * Options for loginWithRedirect (spa-js compatible)
 */
export interface RedirectLoginOptions<TAppState = unknown> {
  authorizationParams?: AuthorizationParameters;
  appState?: TAppState;
  fragment?: string;
  /**
   * Custom function to open the authorization URL (e.g., for testing)
   */
  openUrl?: (url: string) => Promise<void>;
  /**
   * Enable Pushed Authorization Requests (PAR)
   */
  pushedAuthorizationRequests?: boolean;
}

/**
 * Result returned from handleRedirectCallback (spa-js compatible)
 */
export interface RedirectLoginResult<TAppState = unknown> {
  appState?: TAppState;
}

/**
 * Options for getTokenSilently (spa-js compatible)
 */
export interface GetTokenSilentlyOptions {
  authorizationParams?: {
    audience?: string;
    scope?: string;
    redirect_uri?: string;
    [key: string]: unknown;
  };
  /**
   * Cache mode: 'on' (default), 'off' (skip cache), 'cache-only' (never fetch new token)
   */
  cacheMode?: 'on' | 'off' | 'cache-only';
  /**
   * Timeout in seconds for silent authentication
   */
  timeoutInSeconds?: number;
  /**
   * Return detailed token response instead of just access token string
   */
  detailedResponse?: boolean;
}

/**
 * Detailed token response from getTokenSilently (spa-js compatible)
 */
export interface GetTokenSilentlyVerboseResponse {
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

/**
 * ID Token claims (spa-js compatible)
 */
export interface IdToken {
  __raw: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: unknown;
  updated_at?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  azp?: string;
  nonce?: string;
  auth_time?: number;
  at_hash?: string;
  c_hash?: string;
  acr?: string;
  amr?: string;
  sub_jwk?: string;
  cnf?: string;
  sid?: string;
  org_id?: string;
  org_name?: string;
  sub?: string;
  [key: string]: unknown;
}

/**
 * Options for loginWithPopup (spa-js compatible)
 */
export interface PopupLoginOptions<TAppState = unknown> {
  authorizationParams?: AuthorizationParameters;
  appState?: TAppState;
}

/**
 * Configuration for popup behavior (spa-js compatible)
 */
export interface PopupConfigOptions {
  /**
   * Existing popup window to use (optional)
   */
  popup?: Window;
  /**
   * Timeout in seconds before popup authentication fails
   */
  timeoutInSeconds?: number;
  /**
   * Whether to close popup after successful authentication
   */
  closePopup?: boolean;
}

/**
 * Options for getTokenWithPopup (spa-js compatible)
 */
export interface GetTokenWithPopupOptions {
  authorizationParams?: AuthorizationParameters;
  cacheMode?: 'on' | 'off';
}

/**
 * Result from popup authentication
 * @internal
 */
export interface PopupAuthResult {
  code: string;
  state: string;
}

/**
 * Options for custom token exchange (RFC 8693)
 */
export interface CustomTokenExchangeOptions {
  /**
   * The type of token being exchanged
   */
  subjectTokenType: string;
  /**
   * The token to exchange
   */
  subjectToken: string;
  /**
   * Optional audience for the new token
   */
  audience?: string;
  /**
   * Optional scope for the new token
   */
  scope?: string;
  /**
   * Additional parameters for the token exchange
   */
  [key: string]: unknown;
}

/**
 * Configuration for authenticated fetcher
 */
export interface FetcherConfig<TOutput = unknown> {
  /**
   * Custom function to get access token (defaults to client.getTokenSilently)
   */
  getAccessToken?: () => Promise<string | GetTokenSilentlyVerboseResponse>;
  /**
   * Base URL to prepend to all requests
   */
  baseUrl?: string;
  /**
   * Custom fetch implementation
   */
  fetch?: (req: Request) => Promise<TOutput>;
  /**
   * DPoP nonce identifier (for DPoP-enabled clients)
   */
  dpopNonceId?: string;
}

/**
 * Parameters for authenticated fetch request
 */
export interface FetchWithAuthParams {
  /**
   * Audience for token acquisition
   */
  audience?: string;
  /**
   * Scope for token acquisition
   */
  scope?: string;
}
