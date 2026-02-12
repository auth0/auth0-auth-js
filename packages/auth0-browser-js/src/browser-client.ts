import {
  GetAccessTokenOptions,
  BrowserClientOptions,
  SessionData,
  StateData,
  StartInteractiveLoginOptions,
  StartLinkUserOptions,
  StartUnlinkUserOptions,
  StateStore,
  TokenSet,
  TransactionData,
  TransactionStore,
  LogoutOptions,
  RedirectLoginOptions,
  RedirectLoginResult,
  GetTokenSilentlyOptions,
  GetTokenSilentlyVerboseResponse,
  IdToken,
  PopupLoginOptions,
  PopupConfigOptions,
  GetTokenWithPopupOptions,
  FetcherConfig,
} from './types.js';
import { MissingRequiredArgumentError, MissingSessionError, MissingTransactionError } from './errors.js';
import { decodeJWT } from './utils/decode-jwt.js';
import { PopupHandler } from './popup.js';
import { Dpop } from './dpop/dpop.js';
import { Fetcher } from './fetcher.js';
import { updateStateData } from './state/utils.js';
import {
  AuthClient,
  AuthorizationDetails,
  TokenByRefreshTokenError,
  TokenByRefreshTokenOptions,
  MfaClient,
  ExchangeProfileOptions,
  TokenResponse,
} from '@auth0/auth0-auth-js';
import { compareScopes } from './utils.js';
import { LocalStorageStateStore } from './store/local-storage-state-store.js';
import { LocalStorageTransactionStore } from './store/local-storage-transaction-store.js';
import { SessionStorageStateStore } from './store/session-storage-state-store.js';
import { SessionStorageTransactionStore } from './store/session-storage-transaction-store.js';
import { MemoryStateStore } from './store/memory-state-store.js';
import { MemoryTransactionStore } from './store/memory-transaction-store.js';

export class BrowserClient {
  readonly #options: BrowserClientOptions;
  readonly #transactionStore: TransactionStore;
  readonly #transactionStoreIdentifier: string;
  readonly #stateStore: StateStore;
  readonly #stateStoreIdentifier: string;
  #dpop?: Dpop;

  /**
   * The underlying `authClient` instance that can be used to interact with the Auth0 Authentication API.
   * Generally, you should prefer to use the higher-level methods exposed on the `BrowserClient` instance.
   *
   * Important: the methods exposed on the `authClient` instance do not handle any session or state management.
   */
  readonly authClient: AuthClient;

  /**
   * The MFA client for managing multi-factor authentication.
   * Provides methods for listing, enrolling, deleting, and challenging MFA authenticators.
   */
  readonly mfa: MfaClient;

  constructor(options: BrowserClientOptions) {
    this.#options = options;
    this.#stateStoreIdentifier = this.#options.stateIdentifier || '__a0_session';
    this.#transactionStoreIdentifier = this.#options.transactionIdentifier || '__a0_tx';

    // Provide default stores based on cacheLocation if not provided
    if (options.stateStore && options.transactionStore) {
      // Use custom stores
      this.#transactionStore = options.transactionStore;
      this.#stateStore = options.stateStore;
    } else {
      const cacheLocation = options.cacheLocation ?? 'localstorage';

      if (cacheLocation === 'memory') {
        // Memory storage doesn't require secret
        this.#transactionStore = new MemoryTransactionStore();
        this.#stateStore = new MemoryStateStore();
      } else {
        // localStorage and sessionStorage require secret for encryption
        if (!options.secret) {
          throw new MissingRequiredArgumentError('Either provide a "secret" or set cacheLocation to "memory"');
        }

        if (cacheLocation === 'sessionstorage') {
          this.#transactionStore = new SessionStorageTransactionStore({ secret: options.secret });
          this.#stateStore = new SessionStorageStateStore({ secret: options.secret });
        } else {
          // Default to localstorage
          this.#transactionStore = new LocalStorageTransactionStore({ secret: options.secret });
          this.#stateStore = new LocalStorageStateStore({ secret: options.secret });
        }
      }
    }

    this.authClient = new AuthClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      authorizationParams: this.#options.authorizationParams,
      customFetch: this.#options.customFetch,
    });

    this.mfa = new MfaClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      customFetch: this.#options.customFetch,
    });

    // Initialize DPoP if enabled
    if (this.#options.useDpop) {
      this.#dpop = new Dpop({ domain: this.#options.domain });
    }
  }

  /**
   * Starts the interactive login process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Optional options used to configure the interactive login process.
   *
   * @throws {BuildAuthorizationUrlError} If there was an issue when building the Authorization URL.
   *
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startInteractiveLogin(options?: StartInteractiveLoginOptions) {
    const redirectUri = options?.authorizationParams?.redirect_uri ?? this.#options.authorizationParams?.redirect_uri;
    if (!redirectUri) {
      throw new MissingRequiredArgumentError('authorizationParams.redirect_uri');
    }

    const { codeVerifier, authorizationUrl } = await this.authClient.buildAuthorizationUrl({
      pushedAuthorizationRequests: options?.pushedAuthorizationRequests,
      authorizationParams: {
        ...options?.authorizationParams,
        redirect_uri: redirectUri,
      },
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
    };

    if (options?.appState) {
      transactionState.appState = options.appState;
    }

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false);

    window.location.href = authorizationUrl.toString();

    return authorizationUrl;
  }

  /**
   * Completes the interactive login process.
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   *
   * @throws {MissingTransactionError} When no transaction was found.
   * @throws {TokenByCodeError} If there was an issue requesting the access token.
   *
   * @returns A promise resolving to an object, containing the original appState (if present) and the authorizationDetails (when RAR was used).
   */
  public async completeInteractiveLogin<TAppState = unknown>(url?: URL) {
    if (!url) {
      url = new URL(window.location.href);
    }
    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier);

    if (!transactionData) {
      throw new MissingTransactionError();
    }

    const tokenEndpointResponse = await this.authClient.getTokenByCode(url, {
      codeVerifier: transactionData.codeVerifier,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier);

    const stateData = updateStateData(transactionData.audience ?? 'default', existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true);
    await this.#transactionStore.delete(this.#transactionStoreIdentifier);

    return { appState: transactionData.appState, authorizationDetails: tokenEndpointResponse.authorizationDetails } as {
      appState?: TAppState;
      authorizationDetails?: AuthorizationDetails[];
    };
  }

  /**
   * Retrieves the user from the store, or undefined if no user found.
   * @returns The user, or undefined if no user found in the store.
   */
  public async getUser() {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier);

    return stateData?.user;
  }

  /**
   * Retrieve the user session from the store, or undefined if no session found.
   * @returns The session, or undefined if no session found in the store.
   */
  public async getSession(): Promise<SessionData | undefined> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier);

    if (stateData) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { internal, ...sessionData } = stateData;
      return sessionData;
    }
  }

  /**
   * Retrieves the access token from the store, or calls Auth0 when the access token is expired and a refresh token is available in the store.
   * Also updates the store when a new token was retrieved from Auth0.
   *
   * @param options Optional options for requesting specific audience/scope.
   *
   * @throws {TokenByRefreshTokenError} If the refresh token was not found or there was an issue requesting the access token.
   *
   * @returns The Token Set, containing the access token, as well as additional information.
   */
  public async getAccessToken(options?: GetAccessTokenOptions): Promise<TokenSet> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier);
    const audience = options?.audience ?? this.#options.authorizationParams?.audience ?? 'default';
    const scope = options?.scope ?? this.#options.authorizationParams?.scope;

    const tokenSet = stateData?.tokenSets.find(
      (tokenSet) => tokenSet.audience === audience && (!scope || compareScopes(tokenSet.scope, scope)),
    );

    if (tokenSet && tokenSet.expiresAt > Date.now() / 1000) {
      return tokenSet;
    }

    if (!stateData?.refreshToken) {
      throw new TokenByRefreshTokenError(
        'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.',
      );
    }

    const tokenByRefreshTokenOptions: TokenByRefreshTokenOptions = {
      refreshToken: stateData.refreshToken,
      ...(options && { audience, scope }),
    };

    const tokenEndpointResponse = await this.authClient.getTokenByRefreshToken(tokenByRefreshTokenOptions);
    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier);
    const updatedStateData = updateStateData(audience, existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false);

    return {
      accessToken: tokenEndpointResponse.accessToken,
      scope: tokenEndpointResponse.scope,
      expiresAt: tokenEndpointResponse.expiresAt,
      audience: audience,
    };
  }

  /**
   * Logs the user out and returns a URL to redirect the user-agent to after they log out.
   * @param options Options used to configure the logout process (optional for spa-js compatibility).
   * @returns {URL}
   */
  public async logout(options?: LogoutOptions): Promise<URL> {
    await this.#stateStore.delete(this.#stateStoreIdentifier);

    // Support both old format (options.returnTo) and new format (options.logoutParams.returnTo)
    const returnTo = options?.logoutParams?.returnTo || options?.returnTo;

    // Build logout URL
    let logoutUrl: URL;
    if (returnTo) {
      logoutUrl = await this.authClient.buildLogoutUrl({ returnTo });
    } else {
      // Build basic logout URL without returnTo
      logoutUrl = new URL(`https://${this.#options.domain}/v2/logout`);
      logoutUrl.searchParams.set('client_id', this.#options.clientId);
    }

    // Add federated parameter if specified (v2 logout endpoint)
    if (options?.logoutParams?.federated) {
      logoutUrl.searchParams.set('federated', '');
    }

    // Support openUrl option (spa-js compatible)
    if (options?.openUrl === false) {
      // Don't redirect, just clear session
      return logoutUrl;
    }

    if (options?.openUrl) {
      await options.openUrl(logoutUrl.toString());
      return logoutUrl;
    }

    // Default: redirect to logout URL
    window.location.href = logoutUrl.toString();
    return logoutUrl;
  }

  // ============================================================================
  // spa-js Compatible Methods
  // ============================================================================

  /**
   * Starts the login flow by redirecting to Auth0 (spa-js compatible).
   * This is an alias for startInteractiveLogin() that automatically redirects.
   *
   * @deprecated Use startInteractiveLogin() for better control over the redirect.
   *
   * @param options Optional options for the login flow.
   */
  public async loginWithRedirect<TAppState = unknown>(
    options: RedirectLoginOptions<TAppState> = {},
  ): Promise<void> {
    const authUrl = await this.startInteractiveLogin({
      appState: options.appState,
      authorizationParams: options.authorizationParams,
      pushedAuthorizationRequests: options.pushedAuthorizationRequests,
    });

    if (options.openUrl) {
      await options.openUrl(authUrl.toString());
    } else {
      window.location.assign(authUrl.toString());
    }
  }

  /**
   * Handles the redirect callback from Auth0 (spa-js compatible).
   * This is an alias for completeInteractiveLogin().
   *
   * @deprecated Use completeInteractiveLogin() instead.
   *
   * @param url Optional URL to process (defaults to window.location.href).
   * @returns A promise resolving to the result containing appState.
   */
  public async handleRedirectCallback<TAppState = unknown>(
    url?: string,
  ): Promise<RedirectLoginResult<TAppState>> {
    const urlObj = url ? new URL(url) : new URL(window.location.href);
    const result = await this.completeInteractiveLogin<TAppState>(urlObj);

    return {
      appState: result.appState,
    };
  }

  /**
   * Gets an access token silently (spa-js compatible).
   * Can return either a string (access token) or detailed response.
   *
   * @param options Optional options for token acquisition.
   * @returns Access token string or detailed response based on detailedResponse option.
   */
  public async getTokenSilently(
    options: GetTokenSilentlyOptions & { detailedResponse: true },
  ): Promise<GetTokenSilentlyVerboseResponse>;
  public async getTokenSilently(options?: GetTokenSilentlyOptions): Promise<string>;
  public async getTokenSilently(
    options: GetTokenSilentlyOptions = {},
  ): Promise<string | GetTokenSilentlyVerboseResponse> {
    const tokenSet = await this.getAccessToken({
      audience: options.authorizationParams?.audience,
      scope: options.authorizationParams?.scope,
    });

    if (options.detailedResponse) {
      const stateData = await this.#stateStore.get(this.#stateStoreIdentifier);
      return {
        access_token: tokenSet.accessToken,
        id_token: stateData?.idToken,
        token_type: 'Bearer',
        expires_in: Math.floor(tokenSet.expiresAt - Date.now() / 1000),
        scope: tokenSet.scope,
      };
    }

    return tokenSet.accessToken;
  }

  /**
   * Returns ID token claims if available (spa-js compatible).
   *
   * @returns The decoded ID token claims or undefined if not available.
   */
  public async getIdTokenClaims(): Promise<IdToken | undefined> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier);
    if (!stateData?.idToken) {
      return undefined;
    }

    return decodeJWT(stateData.idToken);
  }

  /**
   * Check if user is authenticated (spa-js compatible).
   *
   * @returns True if user has a valid session, false otherwise.
   */
  public async isAuthenticated(): Promise<boolean> {
    const user = await this.getUser();
    return !!user;
  }

  /**
   * Check if user session is still valid (spa-js compatible).
   * Silently attempts to get a token to validate the session.
   *
   * @param options Optional options for token acquisition.
   */
  public async checkSession(options?: GetTokenSilentlyOptions): Promise<void> {
    try {
      await this.getTokenSilently(options);
    } catch {
      // Silently fail - user not authenticated
    }
  }

  /**
   * Opens a popup window for authentication (spa-js compatible).
   *
   * @param options Optional options for the login flow.
   * @param config Optional configuration for popup behavior.
   */
  public async loginWithPopup<TAppState = unknown>(
    options?: PopupLoginOptions<TAppState>,
    config?: PopupConfigOptions,
  ): Promise<void> {
    const redirectUri = options?.authorizationParams?.redirect_uri ?? this.#options.authorizationParams?.redirect_uri;
    if (!redirectUri) {
      throw new MissingRequiredArgumentError('authorizationParams.redirect_uri');
    }

    // Build authorization URL with web_message response mode for popup
    const { codeVerifier, authorizationUrl } = await this.authClient.buildAuthorizationUrl({
      authorizationParams: {
        ...options?.authorizationParams,
        redirect_uri: redirectUri,
        response_mode: 'web_message',
      },
    });

    // Store transaction data
    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
    };

    if (options?.appState) {
      transactionState.appState = options.appState;
    }

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false);

    // Open popup and wait for result
    const { code, state } = await PopupHandler.openPopup(authorizationUrl.toString(), config);

    // Build callback URL with code and state
    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set('code', code);
    callbackUrl.searchParams.set('state', state);

    // Complete the login flow
    await this.completeInteractiveLogin(callbackUrl);
  }

  /**
   * Opens a popup window to acquire additional scopes (spa-js compatible).
   *
   * @param options Optional options for token acquisition.
   * @param config Optional configuration for popup behavior.
   * @returns The access token string.
   */
  public async getTokenWithPopup(
    options?: GetTokenWithPopupOptions,
    config?: PopupConfigOptions,
  ): Promise<string> {
    // Use loginWithPopup to acquire new token with different scopes
    await this.loginWithPopup(
      {
        authorizationParams: options?.authorizationParams,
      },
      config,
    );

    // Return the newly acquired access token
    return this.getTokenSilently({
      authorizationParams: {
        audience: options?.authorizationParams?.audience,
        scope: options?.authorizationParams?.scope,
      },
    });
  }

  // ============================================================================
  // DPoP (Demonstrating Proof-of-Possession) Methods
  // ============================================================================

  /**
   * Get a DPoP nonce for a specific identifier.
   *
   * @param id Optional identifier for the nonce (defaults to 'default').
   * @returns The nonce string or undefined if not found.
   * @throws {Error} If DPoP is not enabled.
   */
  public getDpopNonce(id?: string): string | undefined {
    if (!this.#dpop) {
      throw new Error('DPoP not enabled. Set useDpop: true in BrowserClientOptions.');
    }
    return this.#dpop.getNonce(id);
  }

  /**
   * Store a DPoP nonce for a specific identifier.
   *
   * @param nonce The nonce string to store.
   * @param id Optional identifier for the nonce (defaults to 'default').
   * @throws {Error} If DPoP is not enabled.
   */
  public setDpopNonce(nonce: string, id?: string): void {
    if (!this.#dpop) {
      throw new Error('DPoP not enabled. Set useDpop: true in BrowserClientOptions.');
    }
    this.#dpop.setNonce(nonce, id);
  }

  /**
   * Generate a DPoP proof JWT for demonstrating proof-of-possession.
   *
   * @param params Parameters for generating the proof.
   * @returns The DPoP proof JWT.
   * @throws {Error} If DPoP is not enabled.
   */
  public async generateDpopProof(params: {
    url: string;
    method: string;
    nonce?: string;
    accessToken?: string;
  }): Promise<string> {
    if (!this.#dpop) {
      throw new Error('DPoP not enabled. Set useDpop: true in BrowserClientOptions.');
    }
    return this.#dpop.generateProof(params);
  }

  // ============================================================================
  // Custom Token Exchange (RFC 8693)
  // ============================================================================

  /**
   * Exchanges an external token for Auth0 tokens using RFC 8693 Token Exchange.
   * Stores the resulting tokens in the session.
   *
   * @param options Options for the token exchange.
   * @returns Promise resolving to the token response.
   */
  public async loginWithCustomTokenExchange(options: ExchangeProfileOptions): Promise<TokenResponse> {
    // Exchange the external token for Auth0 tokens
    const tokenResponse = await this.authClient.exchangeToken(options);

    // Determine audience for storage
    const audience = options.audience ?? this.#options.authorizationParams?.audience ?? 'default';

    // Store tokens in state
    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier);
    const stateData = updateStateData(audience, existingStateData, tokenResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, false);

    return tokenResponse;
  }

  // ============================================================================
  // Authenticated Fetcher
  // ============================================================================

  /**
   * Creates an authenticated HTTP client (Fetcher) that automatically injects
   * access tokens into requests.
   *
   * @param config Optional configuration for the fetcher.
   * @returns A new Fetcher instance.
   *
   * @example
   * ```typescript
   * const fetcher = client.createFetcher({
   *   baseUrl: 'https://api.example.com',
   * });
   *
   * const response = await fetcher.fetchWithAuth('/users', {
   *   method: 'GET',
   * });
   * ```
   */
  public createFetcher<TOutput = unknown>(config?: FetcherConfig<TOutput>): Fetcher<TOutput> {
    return new Fetcher<TOutput>(this, config);
  }

  // ============================================================================
  // Cache Management
  // ============================================================================

  /**
   * Get all cache keys for the current client.
   * Returns the state and transaction identifiers.
   *
   * @returns Array of cache keys.
   */
  public getCacheKeys(): string[] {
    return [this.#stateStoreIdentifier, this.#transactionStoreIdentifier];
  }

  /**
   * Clear all cached data.
   *
   * @param options Optional options for clearing cache.
   * @param options.keepRefreshToken If true, preserves the refresh token in the cache.
   */
  public async clearCache(options?: { keepRefreshToken?: boolean }): Promise<void> {
    if (options?.keepRefreshToken) {
      // Get current state to preserve refresh token
      const currentState = await this.#stateStore.get(this.#stateStoreIdentifier);

      if (currentState?.refreshToken) {
        // Clear all token sets but keep refresh token
        const clearedState: StateData = {
          ...currentState,
          tokenSets: [],
          user: undefined,
          idToken: undefined,
        };

        await this.#stateStore.set(this.#stateStoreIdentifier, clearedState, false);
      } else {
        await this.#stateStore.delete(this.#stateStoreIdentifier);
      }
    } else {
      await this.#stateStore.delete(this.#stateStoreIdentifier);
    }

    await this.#transactionStore.delete(this.#transactionStoreIdentifier);
  }
}
