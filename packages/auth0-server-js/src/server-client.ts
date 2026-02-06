import {
  AccessTokenForConnectionOptions,
  ConnectionTokenSet,
  LoginBackchannelOptions,
  LoginBackchannelResult,
  LogoutOptions,
  ServerClientOptions,
  SessionData,
  StartInteractiveLoginOptions,
  StartLinkUserOptions,
  StartUnlinkUserOptions,
  StateStore,
  TokenSet,
  TransactionData,
  TransactionStore,
} from './types.js';
import {
  BackchannelLogoutError,
  MissingRequiredArgumentError,
  MissingSessionError,
  MissingTransactionError,
} from './errors.js';
import { updateStateData, updateStateDataForConnectionTokenSet } from './state/utils.js';
import {
  TokenForConnectionError,
  AuthClient,
  AuthorizationDetails,
  TokenByRefreshTokenError,
} from '@auth0/auth0-auth-js';
import { compareScopes } from './utils.js';
import { DEFAULT_AUDIENCE } from './constants.js';

export class ServerClient<TStoreOptions = unknown> {
  readonly #options: ServerClientOptions<TStoreOptions>;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier: string;
  readonly #stateStore: StateStore<TStoreOptions>;
  readonly #stateStoreIdentifier: string;

  /**
   * The underlying `authClient` instance that can be used to interact with the Auth0 Authentication API.
   * Generally, you should prefer to use the higher-level methods exposed on the `ServerClient` instance.
   * 
   * Important: the methods exposed on the `authClient` instance do not handle any session or state management.
   */
  readonly authClient: AuthClient;

  constructor(options: ServerClientOptions<TStoreOptions>) {
    this.#options = options;
    this.#stateStoreIdentifier = this.#options.stateIdentifier || '__a0_session';
    this.#transactionStoreIdentifier = this.#options.transactionIdentifier || '__a0_tx';
    this.#transactionStore = options.transactionStore;
    this.#stateStore = options.stateStore;

    if (!this.#options.stateStore) {
      throw new MissingRequiredArgumentError('stateStore');
    }

    if (!this.#options.transactionStore) {
      throw new MissingRequiredArgumentError('transactionStore');
    }

    this.authClient = new AuthClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      clientSecret: this.#options.clientSecret,
      clientAssertionSigningKey: this.#options.clientAssertionSigningKey,
      clientAssertionSigningAlg: this.#options.clientAssertionSigningAlg,
      authorizationParams: this.#options.authorizationParams,
      customFetch: this.#options.customFetch,
      useMtls: this.#options.useMtls,
    });
  }

  /**
   * Starts the interactive login process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Optional options used to configure the interactive login process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {BuildAuthorizationUrlError} If there was an issue when building the Authorization URL.
   *
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startInteractiveLogin(options?: StartInteractiveLoginOptions, storeOptions?: TStoreOptions) {
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

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false, storeOptions);

    return authorizationUrl;
  }

  /**
   * Completes the interactive login process.
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {MissingTransactionError} When no transaction was found.
   * @throws {TokenByCodeError} If there was an issue requesting the access token.
   *
   * @returns A promise resolving to an object, containing the original appState (if present) and the authorizationDetails (when RAR was used).
   */
  public async completeInteractiveLogin<TAppState = unknown>(url: URL, storeOptions?: TStoreOptions) {
    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier, storeOptions);

    if (!transactionData) {
      throw new MissingTransactionError();
    }

    const tokenEndpointResponse = await this.authClient.getTokenByCode(url, {
      codeVerifier: transactionData.codeVerifier,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(transactionData.audience ?? DEFAULT_AUDIENCE, existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);
    await this.#transactionStore.delete(this.#transactionStoreIdentifier, storeOptions);

    return { appState: transactionData.appState, authorizationDetails: tokenEndpointResponse.authorizationDetails } as {
      appState?: TAppState;
      authorizationDetails?: AuthorizationDetails[];
    };
  }

  /**
   * Starts the user linking process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Options used to configure the user linking process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {MissingSessionError} If there is no active session.
   * @throws {BuildLinkUserUrlError} If there was an issue when building the Authorization URL.
   *
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startLinkUser(options: StartLinkUserOptions, storeOptions?: TStoreOptions) {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    if (!stateData || !stateData.idToken) {
      throw new MissingSessionError(
        'Unable to start the user linking process without a logged in user. Ensure to login using the SDK before starting the user linking process.'
      );
    }

    const { linkUserUrl, codeVerifier } = await this.authClient.buildLinkUserUrl({
      connection: options.connection,
      connectionScope: options.connectionScope,
      idToken: stateData.idToken,
      authorizationParams: options.authorizationParams,
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
    };

    if (options?.appState) {
      transactionState.appState = options.appState;
    }

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false, storeOptions);

    return linkUserUrl;
  }

  /**
   * Completes the user linking process.
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {MissingTransactionError} When no transaction was found.
   * @throws {TokenByCodeError} If there was an issue requesting the access token.
   *
   * @returns A promise resolving to an object, containing the original appState (if present).
   */
  public async completeLinkUser<TAppState = unknown>(url: URL, storeOptions?: TStoreOptions) {
    // In order to complete the link user flow, we need to exchange the code for a token in the same
    // way as we do for the interactive login flow.
    const result = await this.completeInteractiveLogin<TAppState>(url, storeOptions);

    // As we currently do not support RAR when starting the user linking flow, we will ommit it from being returned as optional altogether.
    return {
      appState: result.appState,
    };
  }

  /**
   * Starts the user unlinking process, and returns a URL to redirect the user-agent to to initialize user unlinking at Auth0.
   * @param options Options used to configure the user unlinking process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {MissingSessionError} If there is no active session.
   * @throws {BuildUnlinkUserUrlError} If there was an issue when building the User Unlinking URL.
   *
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startUnlinkUser(options: StartUnlinkUserOptions, storeOptions?: TStoreOptions) {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    if (!stateData || !stateData.idToken) {
      throw new MissingSessionError(
        'Unable to start the user unlinking process without a logged in user. Ensure to login using the SDK before starting the user unlinking process.'
      );
    }

    const { unlinkUserUrl, codeVerifier } = await this.authClient.buildUnlinkUserUrl({
      connection: options.connection,
      idToken: stateData.idToken,
      authorizationParams: options.authorizationParams,
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
    };

    if (options?.appState) {
      transactionState.appState = options.appState;
    }

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false, storeOptions);

    return unlinkUserUrl;
  }

  /**
   * Completes the user unlinking process.
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {MissingTransactionError} When no transaction was found.
   * @throws {TokenByCodeError} If there was an issue requesting the access token.
   *
   * @returns A promise resolving to an object, containing the original appState (if present).
   */
  public async completeUnlinkUser<TAppState = unknown>(url: URL, storeOptions?: TStoreOptions) {
    // In order to complete the link user flow, we need to exchange the code for a token in the same
    // way as we do for the interactive login flow.
    const result = await this.completeInteractiveLogin<TAppState>(url, storeOptions);

    // As we currently do not support RAR when starting the user unlinking flow, we will ommit it from being returned as optional altogether.
    return {
      appState: result.appState,
    };
  }

  /**
   * Logs in using Client-Initiated Backchannel Authentication.
   *
   * Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
   * @see https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
   * @param options Options used to configure the backchannel login process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {BackchannelAuthenticationError} If there was an issue when doing backchannel authentication.
   *
   * @returns A promise resolving to an object, containing the authorizationDetails (when RAR was used).
   */
  public async loginBackchannel(
    options: LoginBackchannelOptions,
    storeOptions?: TStoreOptions
  ): Promise<LoginBackchannelResult> {
    const tokenEndpointResponse = await this.authClient.backchannelAuthentication({
      bindingMessage: options.bindingMessage,
      loginHint: options.loginHint,
      authorizationParams: options.authorizationParams,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(
      this.#options.authorizationParams?.audience ?? DEFAULT_AUDIENCE,
      existingStateData,
      tokenEndpointResponse
    );

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }

  /**
   * Retrieves the user from the store, or undefined if no user found.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The user, or undefined if no user found in the store.
   */
  public async getUser(storeOptions?: TStoreOptions) {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    return stateData?.user;
  }

  /**
   * Retrieve the user session from the store, or undefined if no session found.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The sessionm or undefined if no session found in the store.
   */
  public async getSession(storeOptions?: TStoreOptions): Promise<SessionData | undefined> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    if (stateData) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { internal, ...sessionData } = stateData;
      return sessionData;
    }
  }

  /**
   * Retrieves the access token from the store, or calls Auth0 when the access token is expired and a refresh token is available in the store.
   * Also updates the store when a new token was retrieved from Auth0.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {TokenByRefreshTokenError} If the refresh token was not found or there was an issue requesting the access token.
   *
   * @returns The Token Set, containing the access token, as well as additional information.
   */
  public async getAccessToken(storeOptions?: TStoreOptions): Promise<TokenSet> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const audience = this.#options.authorizationParams?.audience ?? DEFAULT_AUDIENCE;
    const scope = this.#options.authorizationParams?.scope;

    const tokenSet = stateData?.tokenSets.find(
      (tokenSet) => tokenSet.audience === audience && (!scope || compareScopes(tokenSet.scope, scope))
    );

    if (tokenSet && tokenSet.expiresAt > Date.now() / 1000) {
      return tokenSet;
    }

    if (!stateData?.refreshToken) {
      throw new TokenByRefreshTokenError(
        'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
      );
    }

    const tokenEndpointResponse = await this.authClient.getTokenByRefreshToken({
      refreshToken: stateData.refreshToken,
    });
    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const updatedStateData = updateStateData(audience, existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false, storeOptions);

    return {
      accessToken: tokenEndpointResponse.accessToken,
      scope: tokenEndpointResponse.scope,
      expiresAt: tokenEndpointResponse.expiresAt,
      audience: audience,
    };
  }

  /**
   * Retrieves an access token for a connection.
   *
   * This method attempts to obtain an access token for a specified connection.
   * It first checks if a refresh token exists in the store.
   * If no refresh token is found, it throws an `AccessTokenForConnectionError` indicating
   * that the refresh token was not found.
   *
   * @param options - Options for retrieving an access token for a connection.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {TokenForConnectionError} If the refresh token was not found or there was an issue requesting the access token.
   *
   * @returns The Connection Token Set, containing the access token for the connection, as well as additional information.
   */
  public async getAccessTokenForConnection(options: AccessTokenForConnectionOptions, storeOptions?: TStoreOptions): Promise<ConnectionTokenSet> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const connectionTokenSet = stateData?.connectionTokenSets?.find(
      (tokenSet) => tokenSet.connection === options.connection
    );

    if (connectionTokenSet && connectionTokenSet.expiresAt > Date.now() / 1000) {
      return connectionTokenSet;
    }

    if (!stateData?.refreshToken) {
      throw new TokenForConnectionError(
        'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
      );
    }

    const tokenEndpointResponse = await this.authClient.getTokenForConnection({
      connection: options.connection,
      loginHint: options.loginHint,
      refreshToken: stateData.refreshToken,
    });

    const updatedStateData = updateStateDataForConnectionTokenSet(options, stateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false, storeOptions);

    return {
      accessToken: tokenEndpointResponse.accessToken,
      scope: tokenEndpointResponse.scope,
      expiresAt: tokenEndpointResponse.expiresAt,
      connection: options.connection,
      loginHint: options.loginHint,
    };
  }

  /**
   * Logs the user out and returns a URL to redirect the user-agent to after they log out.
   * @param options Options used to configure the logout process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns {URL}
   */
  public async logout(options: LogoutOptions, storeOptions?: TStoreOptions) {
    await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);

    return this.authClient.buildLogoutUrl(options);
  }

  /**
   * Handles the backchannel logout process by verifying the logout token and deleting the session from the store if the logout token was considered valid.
   * @param logoutToken The logout token to verify and use to delete the session from the store.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   *
   * @throws {BackchannelLogoutError} If the logout token is missing.
   * @throws {VerifyLogoutTokenError} If the logout token is invalid.
   */
  public async handleBackchannelLogout(logoutToken: string, storeOptions?: TStoreOptions) {
    if (!logoutToken) {
      throw new BackchannelLogoutError('Missing Logout Token');
    }

    const logoutTokenClaims = await this.authClient.verifyLogoutToken({ logoutToken });

    await this.#stateStore.deleteByLogoutToken(logoutTokenClaims, storeOptions);
  }
}
