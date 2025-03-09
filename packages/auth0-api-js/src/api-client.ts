import { AuthClient, MissingRequiredArgumentError } from '@auth0/auth0-auth-js';
import type { ApiClientOptions, TransactionData, TransactionStore, StartLinkUserOptions } from './types.js';
import { MissingTransactionError } from './errors.js';

export class ApiClient<TStoreOptions = unknown> {
  readonly #options: ApiClientOptions;
  readonly #transactionStore: TransactionStore;
  readonly #transactionStoreIdentifier: string;

  #authClient: AuthClient;

  constructor(options: ApiClientOptions<TStoreOptions>) {
    this.#options = options;

    this.#transactionStoreIdentifier =
      this.#options.transactionIdentifier || '__a0_api_tx';
    this.#transactionStore = options.transactionStore;

    if (!this.#options.transactionStore) {
      throw new MissingRequiredArgumentError('transactionStore');
    }

    this.#authClient = new AuthClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      clientSecret: this.#options.clientSecret,
      clientAssertionSigningKey: this.#options.clientAssertionSigningKey,
      clientAssertionSigningAlg: this.#options.clientAssertionSigningAlg,
      authorizationParams: {
        audience: this.#options.audience,
        ...this.#options.authorizationParams,
      },
      customFetch: this.#options.customFetch,
    });
  }

  /**
   * Starts the user linking process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Options used to configure the user linking process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startLinkUser(
    options: StartLinkUserOptions,
    storeOptions?: TStoreOptions
  ) {

    const { linkUserUrl, codeVerifier } =
      await this.#authClient.buildLinkUserUrl({
        connection: options.connection,
        connectionScope: options.connectionScope,
        idToken: options.idToken,
        authorizationParams: options.authorizationParams,
      });

    const transactionState: TransactionData = {
      audience:
        options?.authorizationParams?.audience ??
        this.#options.authorizationParams?.audience,
      codeVerifier,
    };

    if (options?.appState) {
      transactionState.appState = options.appState;
    }

    await this.#transactionStore.set(
      this.#transactionStoreIdentifier,
      transactionState,
      false,
      storeOptions
    );

    return linkUserUrl;
  }

  /**
   * Completes the user linking process.
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * A promise resolving to an object, containing the original appState (if present).
   */
  public async completeLinkUser<TAppState = unknown>(
    url: URL,
    storeOptions?: TStoreOptions
  ) {
    const transactionData = await this.#transactionStore.get(
      this.#transactionStoreIdentifier,
      storeOptions
    );

    if (!transactionData) {
      throw new MissingTransactionError();
    }

    const tokenEndpointResponse = await this.#authClient.getTokenByCode(url, {
      codeVerifier: transactionData.codeVerifier,
    });

    if (this.#options.onRefreshTokenReceived && tokenEndpointResponse.claims?.sub && tokenEndpointResponse.refreshToken) {
      await this.#options.onRefreshTokenReceived(
        tokenEndpointResponse.claims.sub,
        tokenEndpointResponse.refreshToken
      );
    }

    await this.#transactionStore.delete(
      this.#transactionStoreIdentifier,
      storeOptions
    );

    return { appState: transactionData.appState } as {
      appState?: TAppState;
    };
  }
}
