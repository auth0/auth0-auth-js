import * as client from 'openid-client';
import { createRemoteJWKSet, importPKCS8, jwtVerify, customFetch } from 'jose';
import {
  BackchannelAuthenticationError,
  BuildAuthorizationUrlError,
  BuildLinkUserUrlError,
  BuildUnlinkUserUrlError,
  MissingClientAuthError,
  NotSupportedError,
  NotSupportedErrorCode,
  OAuth2Error,
  TokenByCodeError,
  TokenByRefreshTokenError,
  TokenForConnectionError,
  VerifyLogoutTokenError,
} from './errors.js';
import {
  AuthClientOptions,
  BackchannelAuthenticationOptions,
  BuildAuthorizationUrlOptions,
  BuildAuthorizationUrlResult,
  BuildLinkUserUrlOptions,
  BuildLinkUserUrlResult,
  BuildLogoutUrlOptions,
  BuildUnlinkUserUrlOptions,
  BuildUnlinkUserUrlResult,
  TokenByCodeOptions,
  TokenByRefreshTokenOptions,
  TokenForConnectionOptions,
  TokenResponse,
  VerifyLogoutTokenOptions,
  VerifyLogoutTokenResult,
} from './types.js';
import { stripUndefinedProperties } from './utils.js';

const DEFAULT_SCOPES = 'openid profile email offline_access';

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
const SUBJECT_TYPE_REFRESH_TOKEN =
  'urn:ietf:params:oauth:token-type:refresh_token';

/**
 * A constant representing the token type for federated connection access tokens.
 * This is used to specify the type of token being requested from Auth0.
 *
 * @constant
 * @type {string}
 */
const REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  'http://auth0.com/oauth/token-type/federated-connection-access-token';

export class AuthClient {
  #configuration: client.Configuration | undefined;
  #serverMetadata: client.ServerMetadata | undefined;
  readonly #options: AuthClientOptions;
  #jwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(options: AuthClientOptions) {
    this.#options = options;
  }

  /**
   * Initialized the SDK by performing Metadata Discovery.
   */
  async #discover() {
    if (this.#configuration && this.#serverMetadata) {
      return {
        configuration: this.#configuration,
        serverMetadata: this.#serverMetadata,
      };
    }

    const clientAuth = await this.#getClientAuth();

    this.#configuration = await client.discovery(
      new URL(`https://${this.#options.domain}`),
      this.#options.clientId,
      {},
      clientAuth,
      {
        [client.customFetch]: this.#options.customFetch,
      }
    );

    this.#serverMetadata = this.#configuration.serverMetadata();
    this.#configuration[client.customFetch] =
      this.#options.customFetch || fetch;

    return {
      configuration: this.#configuration,
      serverMetadata: this.#serverMetadata,
    };
  }

  /**
   * Builds the URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Options used to configure the authorization URL.
   *
   * @throws {BuildAuthorizationUrlError} If there was an issue when building the Authorization URL.
   *
   * @returns A promise resolving to an object, containing the authorizationUrl and codeVerifier.
   */
  async buildAuthorizationUrl(
    options?: BuildAuthorizationUrlOptions
  ): Promise<BuildAuthorizationUrlResult> {
    const { serverMetadata } = await this.#discover();

    if (
      options?.pushedAuthorizationRequests &&
      !serverMetadata.pushed_authorization_request_endpoint
    ) {
      throw new NotSupportedError(
        NotSupportedErrorCode.PAR_NOT_SUPPORTED,
        'The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par'
      );
    }

    try {
      return await this.#buildAuthorizationUrl(options);
    } catch (e) {
      throw new BuildAuthorizationUrlError(e as OAuth2Error);
    }
  }

  /**
   * Builds the URL to redirect the user-agent to to link a user account at Auth0.
   * @param options Options used to configure the link user URL.
   *
   * @throws {BuildLinkUserUrlError} If there was an issue when building the Link User URL.
   *
   * @returns A promise resolving to an object, containing the linkUserUrl and codeVerifier.
   */
  public async buildLinkUserUrl(
    options: BuildLinkUserUrlOptions
  ): Promise<BuildLinkUserUrlResult> {
    try {
      const result = await this.#buildAuthorizationUrl({
        authorizationParams: {
          ...options.authorizationParams,
          requested_connection: options.connection,
          requested_connection_scope: options.connectionScope,
          scope: 'openid link_account offline_access',
          id_token_hint: options.idToken,
        },
      });

      return {
        linkUserUrl: result.authorizationUrl,
        codeVerifier: result.codeVerifier,
      };
    } catch (e) {
      throw new BuildLinkUserUrlError(e as OAuth2Error);
    }
  }

  /**
   * Builds the URL to redirect the user-agent to to unlink a user account at Auth0.
   * @param options Options used to configure the unlink user URL.
   *
   * @throws {BuildUnlinkUserUrlError} If there was an issue when building the Unlink User URL.
   *
   * @returns A promise resolving to an object, containing the unlinkUserUrl and codeVerifier.
   */
  public async buildUnlinkUserUrl(
    options: BuildUnlinkUserUrlOptions
  ): Promise<BuildUnlinkUserUrlResult> {
    try {
      const result = await this.#buildAuthorizationUrl({
        authorizationParams: {
          ...options.authorizationParams,
          requested_connection: options.connection,
          scope: 'openid unlink_account',
          id_token_hint: options.idToken,
        },
      });

      return {
        unlinkUserUrl: result.authorizationUrl,
        codeVerifier: result.codeVerifier,
      };
    } catch (e) {
      throw new BuildUnlinkUserUrlError(e as OAuth2Error);
    }
  }

  /**
   * Authenticates using Client-Initiated Backchannel Authentication.
   *
   * This method will initialize the backchannel authentication process with Auth0, and poll the token endpoint until the authentication is complete.
   *
   * Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
   * @see https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
   * @param options Options used to configure the backchannel authentication process.
   *
   * @throws {BackchannelAuthenticationError} If there was an issue when doing backchannel authentication.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  async backchannelAuthentication(
    options: BackchannelAuthenticationOptions
  ): Promise<TokenResponse> {
    const { configuration, serverMetadata } = await this.#discover();

    const additionalParams = stripUndefinedProperties({
      ...this.#options.authorizationParams,
      ...options?.authorizationParams,
    });

    const params = new URLSearchParams({
      scope: DEFAULT_SCOPES,
      ...additionalParams,
      client_id: this.#options.clientId,
      login_hint: JSON.stringify({
        format: 'iss_sub',
        iss: serverMetadata.issuer,
        sub: options.loginHint.sub,
      }),
    });

    if (options.bindingMessage) {
      params.append('binding_message', options.bindingMessage);
    }

    try {
      const backchannelAuthenticationResponse =
        await client.initiateBackchannelAuthentication(configuration, params);

      const tokenEndpointResponse =
        await client.pollBackchannelAuthenticationGrant(
          configuration,
          backchannelAuthenticationResponse
        );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new BackchannelAuthenticationError(e as OAuth2Error);
    }
  }

  /**
   * Retrieves a token for a connection.
   * @param options - Options for retrieving an access token for a connection.
   *
   * @throws {TokenForConnectionError} If there was an issue requesting the access token.
   *
   * @returns The access token for the connection
   */
  public async getTokenForConnection(
    options: TokenForConnectionOptions
  ): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    const params = new URLSearchParams();

    params.append('connection', options.connection);
    params.append('subject_token_type', SUBJECT_TYPE_REFRESH_TOKEN);
    params.append('subject_token', options.refreshToken);
    params.append(
      'requested_token_type',
      REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN
    );

    if (options.loginHint) {
      params.append('login_hint', options.loginHint);
    }

    try {
      const tokenEndpointResponse = await client.genericGrantRequest(
        configuration,
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
        params
      );

      return {
        accessToken: tokenEndpointResponse.access_token,
        expiresAt:
          Math.floor(Date.now() / 1000) +
          Number(tokenEndpointResponse.expires_in),
        scope: tokenEndpointResponse.scope,
      };
    } catch (e) {
      throw new TokenForConnectionError(
        'There was an error while trying to retrieve an access token for a connection.',
        e as OAuth2Error
      );
    }
  }

  /**
   * Retrieves a token by exchanging an authorization code.
   * @param url The URL containing the authorization code.
   * @param options Options for exchanging the authorization code, containing the expected code verifier.
   *
   * @throws {TokenByCodeError} If there was an issue requesting the access token.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  public async getTokenByCode(
    url: URL,
    options: TokenByCodeOptions
  ): Promise<TokenResponse> {
    const { configuration } = await this.#discover();
    try {
      const tokenEndpointResponse = await client.authorizationCodeGrant(
        configuration,
        url,
        {
          pkceCodeVerifier: options.codeVerifier,
        }
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenByCodeError(
        'There was an error while trying to request a token.',
        e as OAuth2Error
      );
    }
  }

  /**
   * Retrieves a token by exchanging a refresh token.
   * @param options Options for exchanging the refresh token.
   *
   * @throws {TokenByRefreshTokenError} If there was an issue requesting the access token.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  public async getTokenByRefreshToken(options: TokenByRefreshTokenOptions) {
    const { configuration } = await this.#discover();

    try {
      const tokenEndpointResponse = await client.refreshTokenGrant(
        configuration,
        options.refreshToken
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenByRefreshTokenError(
        'The access token has expired and there was an error while trying to refresh it.',
        e as OAuth2Error
      );
    }
  }

  /**
   * Builds the URL to redirect the user-agent to to request logout at Auth0.
   * @param options Options used to configure the logout URL.
   * @returns A promise resolving to the URL to redirect the user-agent to.
   */
  public async buildLogoutUrl(options: BuildLogoutUrlOptions): Promise<URL> {
    const { configuration } = await this.#discover();

    return client.buildEndSessionUrl(configuration, {
      post_logout_redirect_uri: options.returnTo,
    });
  }

  /**
   * Verifies whether a logout token is valid.
   * @param options Options used to verify the logout token.
   *
   * @throws {VerifyLogoutTokenError} If there was an issue verifying the logout token.
   *
   * @returns An object containing the `sid` and `sub` claims from the logout token.
   */
  async verifyLogoutToken(
    options: VerifyLogoutTokenOptions
  ): Promise<VerifyLogoutTokenResult> {
    const { serverMetadata } = await this.#discover();
    this.#jwks ||= createRemoteJWKSet(new URL(serverMetadata!.jwks_uri!), {
      [customFetch]: this.#options.customFetch,
    });

    const { payload } = await jwtVerify(options.logoutToken, this.#jwks, {
      issuer: serverMetadata!.issuer,
      audience: this.#options.clientId,
      algorithms: ['RS256'],
      requiredClaims: ['iat'],
    });

    if (!('sid' in payload) && !('sub' in payload)) {
      throw new VerifyLogoutTokenError(
        'either "sid" or "sub" (or both) claims must be present'
      );
    }

    if ('sid' in payload && typeof payload.sid !== 'string') {
      throw new VerifyLogoutTokenError('"sid" claim must be a string');
    }

    if ('sub' in payload && typeof payload.sub !== 'string') {
      throw new VerifyLogoutTokenError('"sub" claim must be a string');
    }

    if ('nonce' in payload) {
      throw new VerifyLogoutTokenError('"nonce" claim is prohibited');
    }

    if (!('events' in payload)) {
      throw new VerifyLogoutTokenError('"events" claim is missing');
    }

    if (typeof payload.events !== 'object' || payload.events === null) {
      throw new VerifyLogoutTokenError('"events" claim must be an object');
    }

    if (
      !('http://schemas.openid.net/event/backchannel-logout' in payload.events)
    ) {
      throw new VerifyLogoutTokenError(
        '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim'
      );
    }

    if (
      typeof payload.events[
        'http://schemas.openid.net/event/backchannel-logout'
      ] !== 'object'
    ) {
      throw new VerifyLogoutTokenError(
        '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object'
      );
    }

    return {
      sid: payload.sid as string,
      sub: payload.sub as string,
    };
  }

  /**
   * Gets the client authentication method based on the provided options.
   * @returns The ClientAuth object to use for client authentication.
   */
  async #getClientAuth(): Promise<client.ClientAuth> {
    if (
      !this.#options.clientSecret &&
      !this.#options.clientAssertionSigningKey
    ) {
      throw new MissingClientAuthError();
    }

    let clientPrivateKey = this.#options.clientAssertionSigningKey as
      | CryptoKey
      | undefined;

    if (clientPrivateKey && !(clientPrivateKey instanceof CryptoKey)) {
      clientPrivateKey = await importPKCS8(
        clientPrivateKey,
        this.#options.clientAssertionSigningAlg || 'RS256'
      );
    }

    return clientPrivateKey
      ? client.PrivateKeyJwt(clientPrivateKey)
      : client.ClientSecretPost(this.#options.clientSecret!);
  }

  /**
   * Builds the URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Options used to configure the authorization URL.
   * @returns A promise resolving to an object, containing the authorizationUrl and codeVerifier.
   */
  async #buildAuthorizationUrl(
    options?: BuildAuthorizationUrlOptions
  ): Promise<BuildAuthorizationUrlResult> {
    const { configuration } = await this.#discover();

    const codeChallengeMethod = 'S256';
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

    const additionalParams = stripUndefinedProperties({
      ...this.#options.authorizationParams,
      ...options?.authorizationParams,
    });

    const params = new URLSearchParams({
      scope: DEFAULT_SCOPES,
      ...additionalParams,
      client_id: this.#options.clientId,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    });

    const authorizationUrl = options?.pushedAuthorizationRequests
      ? await client.buildAuthorizationUrlWithPAR(configuration, params)
      : await client.buildAuthorizationUrl(configuration, params);

    return {
      authorizationUrl,
      codeVerifier,
    };
  }
}
