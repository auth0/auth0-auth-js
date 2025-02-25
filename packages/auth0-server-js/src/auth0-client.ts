import * as client from 'openid-client';
import * as oauth from 'oauth4webapi';
import {
  createRemoteJWKSet,
  jwtVerify,
  jwksCache,
  JWKSCacheInput,
} from 'jose';

import {
  AccessTokenForConnectionOptions,
  Auth0ClientOptions,
  Auth0ClientOptionsWithSecret,
  Auth0ClientOptionsWithStore,
  LoginBackchannelOptions,
  StartInteractiveLoginOptions,
  StateStore,
  TransactionData,
  TransactionStore,
} from './types.js';
import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  BackchannelLogoutError,
  InvalidStateError,
  LoginBackchannelError,
  MissingRequiredArgumentError,
  MissingStateError,
  NotSupportedError,
  NotSupportedErrorCode,
  OAuth2Error,
} from './errors/index.js';
import { DefaultTransactionStore } from './store/default-transaction-store.js';
import { DefaultStateStore } from './store/default-state-store.js';
import { updateStateData, updateStateDataForConnectionTokenSet } from './state/utils.js';
import { importPKCS8 } from 'jose';
import { stripUndefinedProperties } from './utils.js';

/**
 * A constant representing the grant type for federated connection access token exchange.
 *
 * This grant type is used in OAuth token exchange scenarios where a federated connection
 * access token is required. It is specific to Auth0's implementation and follows the
 * "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" format.
 */
const GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  'urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token';

/**
 * Constant representing the subject type for a refresh token.
 * This is used in OAuth 2.0 token exchange to specify that the token being exchanged is a refresh token.
 *
 * @see {@link https://tools.ietf.org/html/rfc8693#section-3.1 RFC 8693 Section 3.1}
 */
const SUBJECT_TYPE_REFRESH_TOKEN = 'urn:ietf:params:oauth:token-type:refresh_token';

/**
 * A constant representing the token type for federated connection access tokens.
 * This is used to specify the type of token being requested from Auth0.
 *
 * @constant
 * @type {string}
 */
const REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  'http://auth0.com/oauth/token-type/federated-connection-access-token';

const DEFAULT_SCOPES = 'openid profile email offline_access';

export class Auth0Client<TStoreOptions = unknown> {
  readonly #options: Auth0ClientOptions<TStoreOptions>;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier: string;
  readonly #stateStore: StateStore<TStoreOptions>;
  readonly #stateStoreIdentifier: string;
  readonly #jwksCache: JWKSCacheInput = {};

  #configuration: client.Configuration | undefined;
  #serverMetadata: client.ServerMetadata | undefined;

  constructor(options: Auth0ClientOptionsWithSecret);
  constructor(options: Auth0ClientOptionsWithStore<TStoreOptions>);
  constructor(options: Auth0ClientOptions<TStoreOptions>) {
    this.#options = options;
    this.#stateStoreIdentifier = this.#options.stateIdentifier || '__a0_session';
    this.#transactionStoreIdentifier = this.#options.transactionIdentifier || '__a0_tx';
    this.#transactionStore = 'secret' in options ? new DefaultTransactionStore({ secret: options.secret }) : options.transactionStore;
    this.#stateStore = 'secret' in options ? new DefaultStateStore({ secret: options.secret }) : options.stateStore;
  }

  /**
   * Initialized the SDK by performing Metadata Discovery.
   */
  async #discover() {
    if (this.#configuration && this.#serverMetadata) {
      return {
        configuration: this.#configuration,
        serverMetadata: this.#serverMetadata
      }
    }

    const clientAuth = await this.#getClientAuth();

    this.#configuration = await client.discovery(
      new URL(`https://${this.#options.domain}`),
      this.#options.clientId,
      {},
      clientAuth
    );

    this.#serverMetadata = this.#configuration.serverMetadata();

    return {
      configuration: this.#configuration,
      serverMetadata: this.#serverMetadata
    }
  }

  /**
   * Starts the interactive login process, and returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Optional options used to configure the interactive login process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns A promise resolving to a URL object, representing the URL to redirect the user-agent to to request authorization at Auth0.
   */
  public async startInteractiveLogin(options?: StartInteractiveLoginOptions, storeOptions?: TStoreOptions) {
    const { configuration, serverMetadata } = await this.#discover();

    if (options?.pushedAuthorizationRequests && !serverMetadata.pushed_authorization_request_endpoint) {
      throw new NotSupportedError(
        NotSupportedErrorCode.PAR_NOT_SUPPORTED,
        'The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par'
      );
    }

    const code_challenge_method = 'S256';
    const state = oauth.generateRandomState();
    const code_verifier = client.randomPKCECodeVerifier();
    const code_challenge = await client.calculatePKCECodeChallenge(code_verifier);

    if (!this.#options.authorizationParams?.redirect_uri) {
      throw new MissingRequiredArgumentError('authorizationParams.redirect_uri');
    }

    const additionalParams = stripUndefinedProperties({ ...this.#options.authorizationParams, ...options?.authorizationParams });

    const params = new URLSearchParams({
      ...additionalParams,
      client_id: this.#options.clientId,
      scope: options?.authorizationParams?.scope ?? this.#options.authorizationParams.scope ?? DEFAULT_SCOPES,
      redirect_uri: options?.authorizationParams?.redirect_uri ?? this.#options.authorizationParams.redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams.audience,
      state,
      code_verifier,
    };

    if (options?.appState) {
      transactionState.appState = options.appState;
    }

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false, storeOptions);

    return options?.pushedAuthorizationRequests
      ? client.buildAuthorizationUrlWithPAR(configuration, params)
      : client.buildAuthorizationUrl(configuration, params);
  }

  /**
   * Completes the interactive login process.
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @param url The URl from which the query params should be extracted to exchange for a token.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The access token, as returned from Auth0.
   */
  public async completeInteractiveLogin<TAppState = unknown>(url: URL, storeOptions?: TStoreOptions) {
    const { configuration } = await this.#discover();

    const state = url.searchParams.get('state');

    if (!state) {
      throw new MissingStateError();
    }

    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier, storeOptions);

    if (!transactionData || transactionData.state !== state) {
      throw new InvalidStateError();
    }

    try {
      const tokenEndpointResponse = await client.authorizationCodeGrant(configuration, url, {
        expectedState: transactionData.state,
        pkceCodeVerifier: transactionData.code_verifier,
      });

      const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

      const stateData = updateStateData(
        transactionData.audience ?? 'default',
        existingStateData,
        tokenEndpointResponse
      );

      await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);
      await this.#transactionStore.delete(this.#transactionStoreIdentifier, storeOptions);

      return { appState: transactionData.appState } as { appState: TAppState };
    } catch (e) {
      throw new AccessTokenError(
        AccessTokenErrorCode.FAILED_TO_REQUEST_TOKEN,
        'There was an error while trying to request a token. Check the server logs for more information.',
        e as OAuth2Error
      );
    }
  }

  /**
   * Logs in using Client-Initiated Backchannel Authentication.
   * @param options Options used to configure the login process.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The access token, as returned from Auth0.
   */
  public async loginBackchannel(options: LoginBackchannelOptions, storeOptions?: TStoreOptions): Promise<string> {
    const { configuration, serverMetadata } = await this.#discover();

    const additionalParams = stripUndefinedProperties(this.#options.authorizationParams || {});

    const params = new URLSearchParams({
      ...additionalParams,
      client_id: this.#options.clientId,
      login_hint: JSON.stringify({
        format: 'iss_sub',
        iss: serverMetadata.issuer,
        sub: options.login_hint.sub,
      }),
      scope: this.#options.authorizationParams?.scope ?? DEFAULT_SCOPES,
    });

    if (options.binding_message) {
      params.append('binding_message', options.binding_message);
    }

    if (this.#options.authorizationParams?.audience) {
      params.append('audience', this.#options.authorizationParams.audience);
    }

    try {
      const backchannelAuthenticationResponse = await client.initiateBackchannelAuthentication(
        configuration,
        params
      );

      const tokenEndpointResponse = await client.pollBackchannelAuthenticationGrant(
        configuration,
        backchannelAuthenticationResponse
      );

      const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

      const stateData = updateStateData(
        this.#options.authorizationParams?.audience ?? 'default',
        existingStateData,
        tokenEndpointResponse
      );

      await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);

      return tokenEndpointResponse.access_token;
    } catch (e) {
      throw new LoginBackchannelError(e as OAuth2Error);
    }
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
   * Retrieves the access token from the store, or calls Auth0 when the access token is expired and a refresh token is available in the store.
   * Also updates the store when a new token was retrieved from Auth0.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The access token, retrieved from the store or Auth0.
   */
  public async getAccessToken(storeOptions?: TStoreOptions) {
    const { configuration } = await this.#discover();

    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const audience = this.#options.authorizationParams?.audience ?? 'default';
    const scope = this.#options.authorizationParams?.scope;

    const tokenSet = stateData?.tokenSets.find(
      (tokenSet) => tokenSet.audience === audience && (!scope || tokenSet.scope === scope)
    );

    if (tokenSet && tokenSet.expires_at > Date.now() / 1000) {
      return tokenSet.access_token;
    }

    if (!stateData?.refresh_token) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
        'The access token has expired and a refresh token was not provided. The user needs to re-authenticate.'
      );
    }

    try {
      const tokenEndpointResponse = await client.refreshTokenGrant(configuration, stateData.refresh_token);

      const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
      const updatedStateData = updateStateData(audience, existingStateData, tokenEndpointResponse);

      await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false, storeOptions);

      return tokenEndpointResponse.access_token;
    } catch (e) {
      throw new AccessTokenError(
        AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN,
        'The access token has expired and there was an error while trying to refresh it. Check the server logs for more information.',
        e as OAuth2Error
      );
    }
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
    const { configuration } = await this.#discover();

    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const connectionTokenSet = stateData?.connectionTokenSets?.find(
      (tokenSet) => tokenSet.connection === options.connection
    );

    if (connectionTokenSet && connectionTokenSet.expires_at > Date.now() / 1000) {
      return connectionTokenSet.access_token;
    }

    if (!stateData?.refresh_token) {
      throw new AccessTokenForConnectionError(
        AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN,
        'A refresh token was not found but is required to be able to retrieve an access token for a connection.'
      );
    }

    const params = new URLSearchParams();

    params.append('connection', options.connection);
    params.append('subject_token_type', SUBJECT_TYPE_REFRESH_TOKEN);
    params.append('subject_token', stateData.refresh_token);
    params.append('requested_token_type', REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN);

    if (options.login_hint) {
      params.append('login_hint', options.login_hint);
    }

    try {
      const tokenEndpointResponse = await client.genericGrantRequest(
        configuration,
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
        params
      );

      const updatedStateData = updateStateDataForConnectionTokenSet(options, stateData, tokenEndpointResponse);

      await this.#stateStore.set(this.#stateStoreIdentifier, updatedStateData, false, storeOptions);

      return tokenEndpointResponse.access_token;
    } catch (e) {
      throw new AccessTokenForConnectionError(
        AccessTokenForConnectionErrorCode.FAILED_TO_RETRIEVE,
        'There was an error while trying to retrieve an access token for a connection. Check the server logs for more information.',
        e as OAuth2Error
      );
    }
  }

  /**
   * Returns a URL to redirect the user-agent to after they log out.
   * @param param0
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns {URL}
   */
  public async buildLogoutUrl({ returnTo }: { returnTo: string }, storeOptions?: TStoreOptions) {
    const { configuration } = await this.#discover();

    await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);

    return client.buildEndSessionUrl(configuration, {
      post_logout_redirect_uri: returnTo,
    });
  }


  async #getClientAuth(): Promise<oauth.ClientAuth> {
    if (!this.#options.clientSecret && !this.#options.clientAssertionSigningKey) {
      throw new Error('The client secret or client assertion signing key must be provided.');
    }

    let clientPrivateKey = this.#options.clientAssertionSigningKey as CryptoKey | undefined;

    if (clientPrivateKey && !(clientPrivateKey instanceof CryptoKey)) {
      clientPrivateKey = await importPKCS8<CryptoKey>(
        clientPrivateKey,
        this.#options.clientAssertionSigningAlg || 'RS256'
      );
    }

    return clientPrivateKey
      ? oauth.PrivateKeyJwt(clientPrivateKey)
      : oauth.ClientSecretPost(this.#options.clientSecret!);
  }

  public async handleBackchannelLogout(logoutToken: string, storeOptions?: TStoreOptions) {
    if (!logoutToken) {
      throw new BackchannelLogoutError('Missing Logout Token');
    }

    const logoutTokenClaims = await this.#verifyLogoutToken(logoutToken);

    await this.#stateStore.deleteByLogoutToken(logoutTokenClaims, storeOptions);
  }

  async #verifyLogoutToken(logoutToken: string) {
    const keyInput = createRemoteJWKSet(new URL(this.#serverMetadata!.jwks_uri!), {
      [jwksCache]: this.#jwksCache,
    });

    const { payload } = await jwtVerify(logoutToken, keyInput, {
      issuer: this.#serverMetadata!.issuer,
      audience: this.#options.clientId,
      algorithms: ['RS256'],
      requiredClaims: ['iat'],
    });

    if (!('sid' in payload) && !('sub' in payload)) {
      throw new BackchannelLogoutError('either "sid" or "sub" (or both) claims must be present');
    }

    if ('sid' in payload && typeof payload.sid !== 'string') {
      throw new BackchannelLogoutError('"sid" claim must be a string');
    }

    if ('sub' in payload && typeof payload.sub !== 'string') {
      throw new BackchannelLogoutError('"sub" claim must be a string');
    }

    if ('nonce' in payload) {
      throw new BackchannelLogoutError('"nonce" claim is prohibited');
    }

    if (!('events' in payload)) {
      throw new BackchannelLogoutError('"events" claim is missing');
    }

    if (typeof payload.events !== 'object' || payload.events === null) {
      throw new BackchannelLogoutError('"events" claim must be an object');
    }

    if (!('http://schemas.openid.net/event/backchannel-logout' in payload.events)) {
      throw new BackchannelLogoutError(
        '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim'
      );
    }

    if (typeof payload.events['http://schemas.openid.net/event/backchannel-logout'] !== 'object') {
      throw new BackchannelLogoutError(
        '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object'
      );
    }

    return {
      sid: payload.sid as string,
      sub: payload.sub,
    };
  }
}
