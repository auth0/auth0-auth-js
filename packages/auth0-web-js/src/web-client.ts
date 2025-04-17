import {
  LogoutOptions,
  WebClientOptions,
  StateStore,
  TokenSet,
  TransactionData,
  TransactionStore,
  LoginWithRedirectOptions,
} from './types.js';
import {
  MissingTransactionError,
  MissingRequiredArgumentError,
} from './errors.js';
import {
  AuthClient,
  AuthorizationDetails,
  TokenByRefreshTokenError,
} from '@auth0/auth0-auth-js';
import { updateStateData } from './state/utils.js';

export class WebClient<TStoreOptions = unknown> {
  readonly #options: WebClientOptions<TStoreOptions>;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier: string;
  readonly #stateStore: StateStore<TStoreOptions>;
  readonly #stateStoreIdentifier: string;
  readonly #authClient: AuthClient;

  constructor(options: WebClientOptions<TStoreOptions>) {
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

    this.#authClient = new AuthClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      clientAuth: 'none',
      authorizationParams: this.#options.authorizationParams,
      customFetch: this.#options.customFetch,
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
  public async loginWithRedirect(options?: LoginWithRedirectOptions, storeOptions?: TStoreOptions) {
    const redirectUri = options?.authorizationParams?.redirect_uri ?? this.#options.authorizationParams?.redirect_uri;
    if (!redirectUri) {
      throw new MissingRequiredArgumentError('authorizationParams.redirect_uri');
    }

    const { codeVerifier, authorizationUrl } = await this.#authClient.buildAuthorizationUrl({
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

    window.location.assign(authorizationUrl);
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
  public async handleRedirectCallback<TAppState = unknown>(url: URL, storeOptions?: TStoreOptions) {
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

    return {
      appState: transactionData.appState,
      authorizationDetails: tokenEndpointResponse.authorizationDetails
    } as {
      appState?: TAppState;
      authorizationDetails?: AuthorizationDetails[];
    };
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
    const audience = this.#options.authorizationParams?.audience ?? 'default';
    const scope = this.#options.authorizationParams?.scope;

    const tokenSet = stateData?.tokenSets.find(
      (tokenSet) => tokenSet.audience === audience && (!scope || tokenSet.scope === scope)
    );

    if (tokenSet && tokenSet.expiresAt > Date.now() / 1000) {
      return tokenSet;
    }

    if (!stateData?.refreshToken) {
      throw new TokenByRefreshTokenError(
        'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
      );
    }

    const tokenEndpointResponse = await this.#authClient.getTokenByRefreshToken({
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
   * Logs the user out and returns a URL to redirect the user-agent to after they log out.
   * @param options Options used to configure the logout process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns {URL}
   */
  public async logout(options: LogoutOptions, storeOptions?: TStoreOptions) {
    await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);

    const logoutUrl = await this.#authClient.buildLogoutUrl(options);

    window.location.assign(logoutUrl);
  }
}
