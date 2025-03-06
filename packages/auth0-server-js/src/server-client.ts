import {
  AccessTokenForConnectionOptions,
  LoginBackchannelOptions,
  LoginBackchannelResult,
  LogoutOptions,
  ServerClientOptions,
  ServerClientOptionsWithSecret,
  ServerClientOptionsWithStore,
  SessionData,
  StartInteractiveLoginOptions,
  StateStore,
  TransactionData,
  TransactionStore,
} from './types.js';
import {
  AccessTokenErrorCode,
  AccessTokenForConnectionErrorCode,
  BackchannelLogoutError,
  MissingRequiredArgumentError,
  MissingTransactionError,
} from './errors/index.js';
import { DefaultTransactionStore } from './store/default-transaction-store.js';
import { DefaultStateStore } from './store/default-state-store.js';
import { updateStateData, updateStateDataForConnectionTokenSet } from './state/utils.js';
import {
  AccessTokenError,
  AccessTokenForConnectionError,
  AuthClient,
  AuthorizationDetails,
} from '@auth0/auth0-auth-js';

export class ServerClient<TStoreOptions = unknown> {
  readonly #options: ServerClientOptions<TStoreOptions>;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier: string;
  readonly #stateStore: StateStore<TStoreOptions>;
  readonly #stateStoreIdentifier: string;

  #authClient: AuthClient;

  constructor(options: ServerClientOptionsWithSecret);
  constructor(options: ServerClientOptionsWithStore<TStoreOptions>);
  constructor(options: ServerClientOptions<TStoreOptions>) {
    this.#options = options;
    this.#stateStoreIdentifier = this.#options.stateIdentifier || '__a0_session';
    this.#transactionStoreIdentifier = this.#options.transactionIdentifier || '__a0_tx';
    this.#transactionStore =
      'secret' in options ? new DefaultTransactionStore({ secret: options.secret }) : options.transactionStore;
    this.#stateStore =
      'secret' in options
        ? new DefaultStateStore({ secret: options.secret, absoluteDuration: options.stateAbsoluteDuration })
        : options.stateStore;

    this.#authClient = new AuthClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      clientSecret: this.#options.clientSecret,
      clientAssertionSigningKey: this.#options.clientAssertionSigningKey,
      clientAssertionSigningAlg: this.#options.clientAssertionSigningAlg,
      authorizationParams: this.#options.authorizationParams,
      customFetch: this.#options.customFetch,
    });
  }

  /**
   * Starts the interactive login process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Optional options used to configure the interactive login process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startInteractiveLogin(options?: StartInteractiveLoginOptions, storeOptions?: TStoreOptions) {
    const redirectUri = options?.authorizationParams?.redirect_uri ?? this.#options.authorizationParams?.redirect_uri;
    if (!redirectUri) {
      throw new MissingRequiredArgumentError('authorizationParams.redirect_uri');
    }

    const { codeVerifier, authorizationUrl } = await this.#authClient.buildAuthorizationUrl({
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
   * @returns A promise resolving to an object, containing the original appState (if present) and the authorizationDetails (when RAR was used).
   */
  public async completeInteractiveLogin<TAppState = unknown>(url: URL, storeOptions?: TStoreOptions) {
    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier, storeOptions);

    if (!transactionData) {
      throw new MissingTransactionError();
    }

    const tokenEndpointResponse = await this.#authClient.getTokenByCode(url, {
      codeVerifier: transactionData.codeVerifier,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(transactionData.audience ?? 'default', existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);
    await this.#transactionStore.delete(this.#transactionStoreIdentifier, storeOptions);

    return { appState: transactionData.appState, authorizationDetails: tokenEndpointResponse.authorizationDetails } as {
      appState?: TAppState;
      authorizationDetails?: AuthorizationDetails[];
    };
  }

  /**
   * Logs in using Client-Initiated Backchannel Authentication.
   *
   * @note Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
   * @see https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
   * @param options Options used to configure the backchannel login process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns A promise resolving to an object, containing the authorizationDetails (when RAR was used).
   */
  public async loginBackchannel(
    options: LoginBackchannelOptions,
    storeOptions?: TStoreOptions
  ): Promise<LoginBackchannelResult> {
    const tokenEndpointResponse = await this.#authClient.backchannelAuthentication({
      bindingMessage: options.bindingMessage,
      loginHint: options.loginHint,
      authorizationParams: options.authorizationParams,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(
      this.#options.authorizationParams?.audience ?? 'default',
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
   * @returns The access token, retrieved from the store or Auth0.
   */
  public async getAccessToken(storeOptions?: TStoreOptions) {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const audience = this.#options.authorizationParams?.audience ?? 'default';
    const scope = this.#options.authorizationParams?.scope;

    const tokenSet = stateData?.tokenSets.find(
      (tokenSet) => tokenSet.audience === audience && (!scope || tokenSet.scope === scope)
    );

    if (tokenSet && tokenSet.expiresAt > Date.now() / 1000) {
      return tokenSet.accessToken;
    }

    if (!stateData?.refreshToken) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
        'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
      );
    }

    const tokenEndpointResponse = await this.#authClient.getTokenByRefreshToken({
      refreshToken: stateData.refreshToken,
    });
    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const updatedStateData = updateStateData(audience, existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false, storeOptions);

    return tokenEndpointResponse.accessToken;
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
   * @throws {AccessTokenForConnectionError} If the access token was not found or there was an issue requesting the access token.
   *
   * @returns The access token for the connection
   */
  public async getAccessTokenForConnection(options: AccessTokenForConnectionOptions, storeOptions?: TStoreOptions) {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const connectionTokenSet = stateData?.connectionTokenSets?.find(
      (tokenSet) => tokenSet.connection === options.connection
    );

    if (connectionTokenSet && connectionTokenSet.expiresAt > Date.now() / 1000) {
      return connectionTokenSet.accessToken;
    }

    if (!stateData?.refreshToken) {
      throw new AccessTokenForConnectionError(
        AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN,
        'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
      );
    }

    const tokenEndpointResponse = await this.#authClient.getTokenForConnection({
      connection: options.connection,
      loginHint: options.loginHint,
      refreshToken: stateData.refreshToken,
    });

    const updatedStateData = updateStateDataForConnectionTokenSet(options, stateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false, storeOptions);

    return tokenEndpointResponse.accessToken;
  }

  /**
   * Logs the user out and returns a URL to redirect the user-agent to after they log out.
   * @param param0
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns {URL}
   */
  public async logout(options: LogoutOptions, storeOptions?: TStoreOptions) {
    await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);

    return this.#authClient.buildLogoutUrl(options);
  }

  public async handleBackchannelLogout(logoutToken: string, storeOptions?: TStoreOptions) {
    if (!logoutToken) {
      throw new BackchannelLogoutError('Missing Logout Token');
    }

    const logoutTokenClaims = await this.#authClient.verifyLogoutToken({ logoutToken });

    await this.#stateStore.deleteByLogoutToken(logoutTokenClaims, storeOptions);
  }
}
