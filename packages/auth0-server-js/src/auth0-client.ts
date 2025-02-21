import * as client from 'openid-client';
import * as oauth from "oauth4webapi";

import { Auth0ClientOptions, BuildAuthorizationUrlOptions, TransactionData, TransactionStore } from './types.js';
import { ClientNotInitializedError, InvalidStateError, MissingStateError } from './errors/index.js';
import { DefaultTransactionStore } from './store/default-transaction-store.js';

export class Auth0Client<TStoreOptions = unknown> {
  readonly #options: Auth0ClientOptions;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier = '__a0_tx';

  #configuration: client.Configuration | undefined;
  #serverMetadata: client.ServerMetadata | undefined;

  constructor(options: Auth0ClientOptions) {
    this.#options = options;
    this.#transactionStore = options.transactionStore || new DefaultTransactionStore();
  }

  /**
   * Initialized the SDK by performing Metadata Discovery.
   */
  public async init() {
    this.#configuration = await client.discovery(new URL(`https://${this.#options.domain}`), this.#options.clientId, {
      client_secret: this.#options.clientSecret,
    });

    this.#serverMetadata = this.#configuration.serverMetadata();
  }

  /**
   * Returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param param0
   * @returns {URL}
   */
  public async buildAuthorizationUrl(options: BuildAuthorizationUrlOptions, storeOptions?: TStoreOptions) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    const state = oauth.generateRandomState();

    const params = new URLSearchParams({
      client_id: this.#options.clientId,
      client_secret: this.#options.clientSecret,
      scope: options.authorizationParams.scope ?? 'openid profile email offline_access',
      redirect_uri: options.authorizationParams.redirect_uri,
      state
    });

    if (options.authorizationParams.audience) {
      params.append('audience', options.authorizationParams.audience);
    }

    const transactionState: TransactionData = {
      audience: options.authorizationParams.audience,
      state
    };

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, storeOptions);

    return client.buildAuthorizationUrl(this.#configuration, params);
  }

  /**
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @returns The access token, as returned from Auth0.
   */
  public async handleCallback(url: URL, storeOptions?: TStoreOptions) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    const state = url.searchParams.get("state");

    if (!state) {
      throw new MissingStateError();
    }

    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier, storeOptions);

    if (!transactionData || transactionData.state !== state) {
      throw new InvalidStateError();
    }

    const tokenEndpointResponse = await client.authorizationCodeGrant(this.#configuration, url, {
      expectedState: transactionData.state
    });

    await this.#transactionStore.delete(this.#transactionStoreIdentifier, storeOptions);

    return tokenEndpointResponse.access_token;
  }

  /**
   * Returns a URL to redirect the user-agent to after they log out.
   * @param param0
   * @returns {URL}
   */
  public async buildLogoutUrl({ returnTo }: { returnTo: string }) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    return client.buildEndSessionUrl(this.#configuration, {
      post_logout_redirect_uri: returnTo,
    });
  }
}
