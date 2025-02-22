import * as client from 'openid-client';
import * as oauth from 'oauth4webapi';

import {
  Auth0ClientOptions,
  Auth0ClientOptionsWithSecret,
  Auth0ClientOptionsWithStore,
  BuildAuthorizationUrlOptions,
  StateData,
  StateStore,
  TransactionData,
  TransactionStore,
} from './types.js';
import { ClientNotInitializedError, InvalidStateError, MissingStateError } from './errors/index.js';
import { DefaultTransactionStore } from './store/default-transaction-store.js';
import { DefaultStateStore } from './store/default-state-store.js';

export class Auth0Client<TStoreOptions = unknown> {
  readonly #options: Auth0ClientOptions<TStoreOptions>;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier = '__a0_tx';
  readonly #stateStore: StateStore<TStoreOptions>;
  readonly #stateStoreIdentifier = '__a0_session';

  #configuration: client.Configuration | undefined;
  #serverMetadata: client.ServerMetadata | undefined;

  constructor(options: Auth0ClientOptionsWithSecret);
  constructor(options: Auth0ClientOptionsWithStore<TStoreOptions>);
  constructor(options: Auth0ClientOptions<TStoreOptions>) {
    this.#options = options;
    this.#transactionStore = 'secret' in options ? new DefaultTransactionStore() : options.transactionStore;
    this.#stateStore = 'secret' in options ? new DefaultStateStore({ secret: options.secret }) : options.stateStore;
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
   * @param options Options used to build the authorization URL
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
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
      state,
    });

    if (options.authorizationParams.audience) {
      params.append('audience', options.authorizationParams.audience);
    }

    const transactionState: TransactionData = {
      audience: options.authorizationParams.audience,
      state,
    };

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, storeOptions);

    return client.buildAuthorizationUrl(this.#configuration, params);
  }

  /**
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The access token, as returned from Auth0.
   */
  public async handleCallback(url: URL, storeOptions?: TStoreOptions) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    const state = url.searchParams.get('state');

    if (!state) {
      throw new MissingStateError();
    }

    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier, storeOptions);

    if (!transactionData || transactionData.state !== state) {
      throw new InvalidStateError();
    }

    const tokenEndpointResponse = await client.authorizationCodeGrant(this.#configuration, url, {
      expectedState: transactionData.state,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = this.#updateStateData(transactionData, existingStateData, tokenEndpointResponse);

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, storeOptions);
    await this.#transactionStore.delete(this.#transactionStoreIdentifier, storeOptions);

    return tokenEndpointResponse.access_token;
  }

  public async getUser(storeOptions?: TStoreOptions) {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    return stateData?.user;
  }

  /**
   * Returns a URL to redirect the user-agent to after they log out.
   * @param param0
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns {URL}
   */
  public async buildLogoutUrl({ returnTo }: { returnTo: string }, storeOptions?: TStoreOptions) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);

    return client.buildEndSessionUrl(this.#configuration, {
      post_logout_redirect_uri: returnTo,
    });
  }

  #updateStateData(
    transactionData: TransactionData,
    stateDate: StateData | undefined,
    tokenEndpointResponse: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers
  ): StateData {
    if (stateDate) {
      return {
        ...stateDate,
        tokenSets: stateDate.tokenSets.map((tokenSet) =>
          tokenSet.audience === transactionData.audience && tokenSet.scope === tokenEndpointResponse.scope
            ? {
                audience: transactionData.audience,
                access_token: tokenEndpointResponse.access_token,
                refresh_token: tokenEndpointResponse.refresh_token,
                scope: tokenEndpointResponse.scope,
                expires_at: Math.floor(Date.now() / 1000) + Number(tokenEndpointResponse.expires_in),
              }
            : tokenSet
        ),
      };
    } else {
      const user = tokenEndpointResponse.claims();
      return {
        user,
        id_token: tokenEndpointResponse.id_token,
        tokenSets: [
          {
            audience: transactionData.audience ?? 'default',
            access_token: tokenEndpointResponse.access_token,
            refresh_token: tokenEndpointResponse.refresh_token,
            scope: tokenEndpointResponse.scope,
            expires_at: Math.floor(Date.now() / 1000) + Number(tokenEndpointResponse.expires_in),
          },
        ],
        internal: {
          sid: user?.sid as string,
          createdAt: Math.floor(Date.now() / 1000),
        },
      };
    }
  }
}
