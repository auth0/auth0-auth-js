import * as client from 'openid-client';
import { createRemoteJWKSet, importPKCS8, jwtVerify, customFetch, jwksCache, decodeJwt } from 'jose';
import type { JWKSCacheInput } from 'jose';
import {
  BackchannelAuthenticationError,
  BuildAuthorizationUrlError,
  BuildLinkUserUrlError,
  BuildUnlinkUserUrlError,
  TokenExchangeError,
  MissingClientAuthError,
  NotSupportedError,
  NotSupportedErrorCode,
  OAuth2Error,
  toOAuth2Error,
  TokenByClientCredentialsError,
  TokenByCodeError,
  TokenByPasswordError,
  TokenByRefreshTokenError,
  TokenForConnectionError,
  VerifyLogoutTokenError,
} from './errors.js';
import { stripUndefinedProperties, assertValidOrganization, validateOrganizationClaim } from './utils.js';
import { MfaClient } from './mfa/mfa-client.js';
import { PasskeyClient, PASSKEY_GRANT_TYPE } from './passkey/passkey-client.js';
import { PasswordlessClient } from './passwordless/passwordless-client.js';
import { PasswordlessVerifyError } from './passwordless/errors.js';
import { isE164PhoneNumber } from './passwordless/utils.js';
import { createTelemetryFetch, getTelemetryConfig } from './telemetry.js';
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
  ExchangeProfileOptions,
  TokenVaultExchangeOptions,
  TokenByClientCredentialsOptions,
  TokenByCodeOptions,
  TokenByMagicLinkCodeOptions,
  TokenByPasswordOptions,
  TokenByPasswordlessEmailOptions,
  TokenByPasswordlessSmsOptions,
  TokenByRefreshTokenOptions,
  TokenForConnectionOptions,
  TokenResponse,
  ActClaim,
  VerifyLogoutTokenOptions,
  VerifyLogoutTokenResult,
} from './types.js';
import { resolveCacheConfig, DiscoveryCacheFactory } from './cache-provider.js';
import type { DiscoveryCache } from './cache-provider.js';

const DEFAULT_SCOPES = 'openid profile email offline_access';

type DiscoveryCacheEntry = {
  serverMetadata: client.ServerMetadata;
};

/**
 * Maximum number of values allowed per parameter key in extras.
 *
 * This limit prevents potential DoS attacks from maliciously large arrays and ensures
 * reasonable payload sizes. If you have a legitimate use case requiring more than 20
 * values for a single parameter, consider:
 * - Aggregating the data into a single structured value (e.g., JSON string)
 * - Splitting the request across multiple token exchanges
 * - Using a different parameter design that doesn't require arrays
 *
 * This limit is not currently configurable. If you need a higher limit, please open
 * an issue describing your use case.
 */
const MAX_ARRAY_VALUES_PER_KEY = 20;

/**
 * OAuth parameter denylist - parameters that cannot be overridden via extras.
 *
 * These parameters are denied to prevent security issues and maintain API contract clarity:
 *
 * - grant_type: Core protocol parameter, modifying breaks OAuth flow integrity
 * - client_id, client_secret, client_assertion, client_assertion_type: Client authentication
 *   credentials must be managed through configuration, not request parameters
 * - subject_token, subject_token_type: Core token exchange parameters, overriding creates
 *   ambiguity about which token is being exchanged
 * - actor_token, actor_token_type: Actor token parameters for delegation exchanges, must use
 *   explicit typed parameters to ensure correct delegation semantics
 * - requested_token_type: Determines the type of token returned, must be explicit
 * - audience, aud, resource, resources, resource_indicator: Target API parameters must use
 *   explicit API parameters to prevent confusion about precedence and ensure correct routing
 * - scope: Overriding via extras bypasses the explicit scope parameter and creates ambiguity
 *   about which scope takes precedence, potentially granting unintended permissions
 * - connection: Determines token source for Token Vault, must be explicit
 * - login_hint: Affects user identity resolution, must be explicit
 * - organization: Affects tenant context, must be explicit
 * - assertion: SAML assertion parameter, must be managed separately
 *
 * These restrictions ensure that security-critical and routing parameters are always
 * set through explicit, typed API parameters rather than untyped extras.
 */
const PARAM_DENYLIST = Object.freeze(
  new Set([
    'grant_type',
    'client_id',
    'client_secret',
    'client_assertion',
    'client_assertion_type',
    'subject_token',
    'subject_token_type',
    'requested_token_type',
    'actor_token',
    'actor_token_type',
    'audience',
    'aud',
    'resource',
    'resources',
    'resource_indicator',
    'scope',
    'connection',
    'login_hint',
    'organization',
    'assertion',
  ])
);

/**
 * Validates subject token input to fail fast with clear error messages.
 * Detects common footguns like whitespace, Bearer prefix, and empty values.
 */
function validateSubjectToken(token: string): void {
  if (token == null) {
    throw new TokenExchangeError('subject_token is required');
  }
  if (typeof token !== 'string') {
    throw new TokenExchangeError('subject_token must be a string');
  }
  // Fail fast on blank or whitespace-only
  if (token.trim().length === 0) {
    throw new TokenExchangeError('subject_token cannot be blank or whitespace');
  }
  // Be explicit about surrounding spaces
  if (token !== token.trim()) {
    throw new TokenExchangeError('subject_token must not include leading or trailing whitespace');
  }
  // Very common copy paste mistake (case-insensitive check)
  if (/^bearer\s+/i.test(token)) {
    throw new TokenExchangeError("subject_token must not include the 'Bearer ' prefix");
  }
}

/**
 * Appends extra parameters to URLSearchParams while enforcing security constraints.
 */
function appendExtraParams(params: URLSearchParams, extra?: Record<string, string | string[]>): void {
  if (!extra) return;

  for (const [parameterKey, parameterValue] of Object.entries(extra)) {
    if (PARAM_DENYLIST.has(parameterKey)) continue;

    if (Array.isArray(parameterValue)) {
      if (parameterValue.length > MAX_ARRAY_VALUES_PER_KEY) {
        throw new TokenExchangeError(
          `Parameter '${parameterKey}' exceeds maximum array size of ${MAX_ARRAY_VALUES_PER_KEY}`
        );
      }
      parameterValue.forEach((arrayItem) => {
        params.append(parameterKey, arrayItem);
      });
    } else {
      params.append(parameterKey, parameterValue);
    }
  }
}

/**
 * A constant representing the grant type for federated connection access token exchange.
 *
 * This grant type is used in OAuth token exchange scenarios where a federated connection
 * access token is required. It is specific to Auth0's implementation and follows the
 * "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" format.
 */
const GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  'urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token' as const;

/**
 * RFC 8693 grant type for OAuth 2.0 Token Exchange.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8693 RFC 8693: OAuth 2.0 Token Exchange}
 */
const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange' as const;

/**
 * Constant representing the subject type for a refresh token.
 * This is used in OAuth 2.0 token exchange to specify that the token being exchanged is a refresh token.
 *
 * @see {@link https://tools.ietf.org/html/rfc8693#section-3.1 RFC 8693 Section 3.1}
 */
const SUBJECT_TYPE_REFRESH_TOKEN = 'urn:ietf:params:oauth:token-type:refresh_token';

/**
 * Constant representing the subject type for an access token.
 * This is used in OAuth 2.0 token exchange to specify that the token being exchanged is an access token.
 *
 * @see {@link https://tools.ietf.org/html/rfc8693#section-3.1 RFC 8693 Section 3.1}
 */
const SUBJECT_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * A constant representing the token type for federated connection access tokens.
 * This is used to specify the type of token being requested from Auth0.
 *
 * @constant
 * @type {string}
 */
const REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  'http://auth0.com/oauth/token-type/federated-connection-access-token';

/**
 * Wraps a fetch implementation so that the passkey (WebAuthn) token request is
 * sent as `application/json` with `authn_response` as a nested object.
 *
 * `openid-client`/`oauth4webapi` always serialize token requests as
 * `application/x-www-form-urlencoded`, which would stringify `authn_response`
 * and cause Auth0 to reject it (`"authn_response" must be of type object`).
 * This shim runs after client authentication has been applied to the body, so
 * any injected `client_secret`/`client_assertion` fields are preserved.
 *
 * For any other grant type — or if the body is not the expected
 * `URLSearchParams` — the request is passed through unchanged.
 */
function createPasskeyFetch(customFetch: typeof fetch, grantType: string): typeof fetch {
  return (input, init) => {
    const body = init?.body;

    if (grantType !== PASSKEY_GRANT_TYPE || !(body instanceof URLSearchParams)) {
      return customFetch(input, init);
    }

    const jsonBody: Record<string, unknown> = {};
    for (const [key, value] of body) {
      // `authn_response` is serialized by PasskeyClient (JSON.stringify) to fit
      // through URLSearchParams; restore it to a nested object for the JSON body.
      jsonBody[key] = key === 'authn_response' ? JSON.parse(value) : value;
    }

    const headers = new Headers(init?.headers);
    headers.set('Content-Type', 'application/json');

    return customFetch(input, {
      ...init,
      headers,
      body: JSON.stringify(jsonBody),
    });
  };
}

/**
 * Auth0 authentication client for handling OAuth 2.0 and OIDC flows.
 *
 * Provides methods for authorization, token exchange, token refresh, and verification
 * of tokens issued by Auth0. Supports multiple authentication methods including
 * client_secret_post, private_key_jwt, and mTLS.
 */
export class AuthClient {
  #configuration: client.Configuration | undefined;
  #serverMetadata: client.ServerMetadata | undefined;
  #clientAuthPromise: Promise<client.ClientAuth> | undefined;
  readonly #options: AuthClientOptions;
  readonly #customFetch: typeof fetch;
  #jwks?: ReturnType<typeof createRemoteJWKSet>;
  readonly #discoveryCache: DiscoveryCache<string, DiscoveryCacheEntry>;
  readonly #inFlightDiscovery: Map<string, Promise<DiscoveryCacheEntry>>;
  readonly #jwksCache: JWKSCacheInput;
  public mfa: MfaClient;
  public passkey: PasskeyClient;
  /**
   * Sub-client for the Auth0 Passwordless `/passwordless/start` endpoint
   * (`sendEmail`, `sendSms`). Token exchange for the codes it sends is done via
   * {@link AuthClient#getTokenByPasswordlessEmail} / {@link AuthClient#getTokenByPasswordlessSms}.
   */
  public passwordless: PasswordlessClient;

  constructor(options: AuthClientOptions) {
    this.#options = options;

    // When mTLS is being used, a custom fetch implementation is required.
    if (options.useMtls && !options.customFetch) {
      throw new NotSupportedError(
        NotSupportedErrorCode.MTLS_WITHOUT_CUSTOMFETCH_NOT_SUPPORT,
        'Using mTLS without a custom fetch implementation is not supported'
      );
    }

    this.#customFetch = createTelemetryFetch(
      options.customFetch ?? ((...args) => fetch(...args)),
      getTelemetryConfig(options.telemetry)
    );

    // Use factory to create appropriate cache implementations
    const cacheConfig = resolveCacheConfig(options.discoveryCache);
    this.#discoveryCache = DiscoveryCacheFactory.createDiscoveryCache<string, DiscoveryCacheEntry>(cacheConfig);
    this.#inFlightDiscovery = new Map<string, Promise<DiscoveryCacheEntry>>();
    this.#jwksCache = DiscoveryCacheFactory.createJwksCache();

    this.mfa = new MfaClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      clientSecret: this.#options.clientSecret,
      customFetch: this.#customFetch,
      getConfiguration: async () => (await this.#discover()).configuration,
    });

    this.passkey = new PasskeyClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      customFetch: this.#customFetch,
      grantRequest: async (grantType, params) => {
        // The passkey token exchange authenticates the client like any other
        // grant; `#discover()` throws `MissingClientAuthError` for public
        // clients that have no credentials configured.
        const { serverMetadata } = await this.#discover();

        // Build a dedicated configuration so the passkey JSON fetch shim is not
        // applied to the shared configuration used by other grants. The passkey
        // token endpoint requires a JSON body with `authn_response` as a nested
        // object; the shim rewrites the form-encoded request accordingly.
        const configuration = await this.#createConfiguration(serverMetadata);
        configuration[client.customFetch] = createPasskeyFetch(this.#customFetch, grantType);

        const tokenEndpointResponse = await client.genericGrantRequest(configuration, grantType, params);
        return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
      },
    });

    // `/passwordless/start` requires body-level client authentication, so the
    // sub-client receives the client-auth options in addition to the MFA-style trio.
    this.passwordless = new PasswordlessClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId,
      customFetch: this.#customFetch,
      clientSecret: this.#options.clientSecret,
      clientAssertionSigningKey: this.#options.clientAssertionSigningKey,
      clientAssertionSigningAlg: this.#options.clientAssertionSigningAlg,
      useMtls: this.#options.useMtls,
    });
  }

  #getDiscoveryCacheKey(): string {
    const domain = this.#options.domain.toLowerCase();
    return `${domain}|mtls:${this.#options.useMtls ? '1' : '0'}`;
  }

  async #createConfiguration(serverMetadata: client.ServerMetadata): Promise<client.Configuration> {
    const clientAuth = await this.#getClientAuth();
    const configuration = new client.Configuration(
      serverMetadata,
      this.#options.clientId,
      this.#options.clientSecret,
      clientAuth
    );
    configuration[client.customFetch] = this.#customFetch;
    return configuration;
  }

  /**
   * Initializes the SDK by performing Metadata Discovery.
   *
   * Discovers and caches the OAuth 2.0 Authorization Server metadata from the
   * Auth0 tenant's well-known endpoint. This metadata is required for subsequent
   * operations and is cached for the lifetime of the AuthClient instance.
   *
   * @private
   * @returns Promise resolving to the cached configuration and server metadata
   */
  async #discover() {
    if (this.#configuration && this.#serverMetadata) {
      return {
        configuration: this.#configuration,
        serverMetadata: this.#serverMetadata,
      };
    }

    const cacheKey = this.#getDiscoveryCacheKey();
    const cached = this.#discoveryCache.get(cacheKey);

    if (cached) {
      this.#serverMetadata = cached.serverMetadata;
      this.#configuration = await this.#createConfiguration(cached.serverMetadata);
      return {
        configuration: this.#configuration,
        serverMetadata: this.#serverMetadata,
      };
    }

    const inFlight = this.#inFlightDiscovery.get(cacheKey);
    if (inFlight) {
      const entry = await inFlight;
      this.#serverMetadata = entry.serverMetadata;
      this.#configuration = await this.#createConfiguration(entry.serverMetadata);
      return {
        configuration: this.#configuration,
        serverMetadata: this.#serverMetadata,
      };
    }

    const discoveryPromise = (async () => {
      const clientAuth = await this.#getClientAuth();

      const configuration = await client.discovery(
        new URL(`https://${this.#options.domain}`),
        this.#options.clientId,
        { use_mtls_endpoint_aliases: this.#options.useMtls },
        clientAuth,
        {
          [client.customFetch]: this.#customFetch,
        }
      );

      const serverMetadata = configuration.serverMetadata();
      this.#discoveryCache.set(cacheKey, { serverMetadata });
      return { configuration, serverMetadata };
    })();

    const inFlightEntry = discoveryPromise.then(({ serverMetadata }) => ({
      serverMetadata,
    }));
    // Prevent unhandled rejection warnings when discovery fails.
    void inFlightEntry.catch(() => undefined);
    this.#inFlightDiscovery.set(cacheKey, inFlightEntry);

    try {
      const { configuration, serverMetadata } = await discoveryPromise;
      this.#configuration = configuration;
      this.#serverMetadata = serverMetadata;
      this.#configuration[client.customFetch] = this.#customFetch;
    } finally {
      this.#inFlightDiscovery.delete(cacheKey);
    }

    return {
      configuration: this.#configuration,
      serverMetadata: this.#serverMetadata,
    };
  }

  /**
   * Returns the discovered server metadata for the configured domain.
   */
  public async getServerMetadata(): Promise<client.ServerMetadata> {
    const { serverMetadata } = await this.#discover();
    return serverMetadata;
  }

  /**
   * Builds the URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Options used to configure the authorization URL.
   *
   * @throws {BuildAuthorizationUrlError} If there was an issue when building the Authorization URL.
   *
   * @returns A promise resolving to an object, containing the authorizationUrl and codeVerifier.
   */
  async buildAuthorizationUrl(options?: BuildAuthorizationUrlOptions): Promise<BuildAuthorizationUrlResult> {
    const { serverMetadata } = await this.#discover();

    if (options?.pushedAuthorizationRequests && !serverMetadata.pushed_authorization_request_endpoint) {
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
  public async buildLinkUserUrl(options: BuildLinkUserUrlOptions): Promise<BuildLinkUserUrlResult> {
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
  public async buildUnlinkUserUrl(options: BuildUnlinkUserUrlOptions): Promise<BuildUnlinkUserUrlResult> {
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
  async backchannelAuthentication(options: BackchannelAuthenticationOptions): Promise<TokenResponse> {
    const { configuration, serverMetadata } = await this.#discover();

    const additionalParams = stripUndefinedProperties({
      ...this.#options.authorizationParams,
      ...options?.authorizationParams,
    });

    const params = new URLSearchParams({
      scope: DEFAULT_SCOPES,
      ...additionalParams,
      client_id: this.#options.clientId,
      binding_message: options.bindingMessage,
      login_hint: JSON.stringify({
        format: 'iss_sub',
        iss: serverMetadata.issuer,
        sub: options.loginHint.sub,
      }),
    });

    if (options.requestedExpiry) {
      params.append('requested_expiry', options.requestedExpiry.toString());
    }

    if (options.authorizationDetails) {
      params.append('authorization_details', JSON.stringify(options.authorizationDetails));
    }

    try {
      const backchannelAuthenticationResponse = await client.initiateBackchannelAuthentication(configuration, params);

      const tokenEndpointResponse = await client.pollBackchannelAuthenticationGrant(
        configuration,
        backchannelAuthenticationResponse
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new BackchannelAuthenticationError(e as OAuth2Error);
    }
  }

  /**
   * Initiates Client-Initiated Backchannel Authentication flow by calling the `/bc-authorize` endpoint.
   * This method only initiates the authentication request and returns the `auth_req_id` to be used in subsequent calls to `backchannelAuthenticationGrant`.
   *
   * Typically, you would call this method to start the authentication process, then use the returned `auth_req_id` to poll for the token using `backchannelAuthenticationGrant`.
   *
   * @param options Options used to configure the backchannel authentication initiation.
   *
   * @throws {BackchannelAuthenticationError} If there was an issue when initiating backchannel authentication.
   *
   * @returns An object containing `authReqId`, `expiresIn`, and `interval` for polling.
   */
  async initiateBackchannelAuthentication(options: BackchannelAuthenticationOptions) {
    const { configuration, serverMetadata } = await this.#discover();

    const additionalParams = stripUndefinedProperties({
      ...this.#options.authorizationParams,
      ...options?.authorizationParams,
    });

    const params = new URLSearchParams({
      scope: DEFAULT_SCOPES,
      ...additionalParams,
      client_id: this.#options.clientId,
      binding_message: options.bindingMessage,
      login_hint: JSON.stringify({
        format: 'iss_sub',
        iss: serverMetadata.issuer,
        sub: options.loginHint.sub,
      }),
    });

    if (options.requestedExpiry) {
      params.append('requested_expiry', options.requestedExpiry.toString());
    }

    if (options.authorizationDetails) {
      params.append('authorization_details', JSON.stringify(options.authorizationDetails));
    }

    try {
      const backchannelAuthenticationResponse = await client.initiateBackchannelAuthentication(configuration, params);

      return {
        authReqId: backchannelAuthenticationResponse.auth_req_id,
        expiresIn: backchannelAuthenticationResponse.expires_in,
        interval: backchannelAuthenticationResponse.interval,
      };
    } catch (e) {
      throw new BackchannelAuthenticationError(e as OAuth2Error);
    }
  }

  /**
   * Exchanges the `auth_req_id` obtained from `initiateBackchannelAuthentication` for tokens.
   *
   * @param authReqId The `auth_req_id` obtained from `initiateBackchannelAuthentication`.
   *
   * @throws {BackchannelAuthenticationError} If there was an issue when exchanging the `auth_req_id` for tokens.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  async backchannelAuthenticationGrant({ authReqId }: { authReqId: string }) {
    const { configuration } = await this.#discover();
    const params = new URLSearchParams({
      auth_req_id: authReqId,
    });

    try {
      const tokenEndpointResponse = await client.genericGrantRequest(
        configuration,
        'urn:openid:params:grant-type:ciba',
        params
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new BackchannelAuthenticationError(e as OAuth2Error);
    }
  }

  /**
   * Retrieves a token for a connection using Token Vault.
   *
   * @deprecated Since v1.2.0. Use {@link exchangeToken} with a Token Vault payload:
   *   `exchangeToken({ connection, subjectToken, subjectTokenType, loginHint?, scope?, extra? })`.
   * This method remains for backward compatibility and is planned for removal in v2.0.
   *
   * This is a convenience wrapper around exchangeToken() for Token Vault scenarios,
   * providing a simpler API for the common use case of exchanging Auth0 tokens for
   * federated access tokens.
   *
   * Either a refresh token or access token must be provided, but not both. The method
   * automatically determines the correct subject_token_type based on which token is provided.
   *
   * @param options Options for retrieving an access token for a connection.
   *
   * @throws {TokenForConnectionError} If there was an issue requesting the access token,
   *                                    or if both/neither token types are provided.
   *
   * @returns The access token for the connection
   *
   * @see {@link exchangeToken} for the unified token exchange method with more options
   *
   * @example Using an access token (deprecated, use exchangeToken instead)
   * ```typescript
   * const response = await authClient.getTokenForConnection({
   *   connection: 'google-oauth2',
   *   accessToken: auth0AccessToken,
   *   loginHint: 'user@example.com'
   * });
   * ```
   *
   * @example Using a refresh token (deprecated, use exchangeToken instead)
   * ```typescript
   * const response = await authClient.getTokenForConnection({
   *   connection: 'salesforce',
   *   refreshToken: auth0RefreshToken
   * });
   * ```
   */
  public async getTokenForConnection(options: TokenForConnectionOptions): Promise<TokenResponse> {
    if (options.refreshToken && options.accessToken) {
      throw new TokenForConnectionError('Either a refresh or access token should be specified, but not both.');
    }

    const subjectTokenValue = options.accessToken ?? options.refreshToken;
    if (!subjectTokenValue) {
      throw new TokenForConnectionError('Either a refresh or access token must be specified.');
    }

    try {
      return await this.exchangeToken({
        connection: options.connection,
        subjectToken: subjectTokenValue,
        subjectTokenType: options.accessToken ? SUBJECT_TYPE_ACCESS_TOKEN : SUBJECT_TYPE_REFRESH_TOKEN,
        loginHint: options.loginHint,
      } as TokenVaultExchangeOptions);
    } catch (e) {
      // Wrap TokenExchangeError in TokenForConnectionError for backward compatibility
      if (e instanceof TokenExchangeError) {
        throw new TokenForConnectionError(e.message, e.cause);
      }
      throw e;
    }
  }

  /**
   * Internal implementation for Access Token Exchange with Token Vault.
   *
   * Exchanges an Auth0 token (access token or refresh token) for an external provider's access token
   * from a third-party provider configured in Token Vault. The external provider's refresh token
   * is securely stored in Auth0 and never exposed to the client.
   *
   * This method constructs the appropriate request for Auth0's proprietary Token Vault
   * grant type and handles the exchange with proper validation and error handling.
   *
   * @private
   * @param options Access Token Exchange with Token Vault configuration including connection and optional hints
   * @returns Promise resolving to TokenResponse containing the external provider's access token
   * @throws {TokenExchangeError} When validation fails, audience/resource are provided,
   *                               or the exchange operation fails
   */
  async #exchangeTokenVaultToken(options: TokenVaultExchangeOptions): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    if ('audience' in options || 'resource' in options) {
      throw new TokenExchangeError('audience and resource parameters are not supported for Token Vault exchanges');
    }

    validateSubjectToken(options.subjectToken);

    const tokenRequestParams = new URLSearchParams({
      connection: options.connection,
      subject_token: options.subjectToken,
      subject_token_type: options.subjectTokenType ?? SUBJECT_TYPE_ACCESS_TOKEN,
      requested_token_type: options.requestedTokenType ?? REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
    });

    if (options.loginHint) {
      tokenRequestParams.append('login_hint', options.loginHint);
    }
    if (options.scope) {
      tokenRequestParams.append('scope', options.scope);
    }

    appendExtraParams(tokenRequestParams, options.extra);

    try {
      const tokenEndpointResponse = await client.genericGrantRequest(
        configuration,
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
        tokenRequestParams
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenExchangeError(
        `Failed to exchange token for connection '${options.connection}'.`,
        toOAuth2Error(e)
      );
    }
  }

  /**
   * Internal implementation for Token Exchange via Token Exchange Profile (RFC 8693).
   *
   * Exchanges a custom token for Auth0 tokens targeting a specific API audience,
   * preserving user identity. This enables first-party on-behalf-of flows where
   * a custom token (e.g., from an MCP server, legacy system, or partner service)
   * is exchanged for Auth0 tokens.
   *
   * Requires a Token Exchange Profile configured in Auth0 that defines the
   * subject_token_type, validation logic, and user mapping.
   *
   * @private
   * @param options Token Exchange Profile configuration including token type and target API
   * @returns Promise resolving to TokenResponse containing Auth0 tokens
   * @throws {TokenExchangeError} When validation fails or the exchange operation fails
   */
  async #exchangeProfileToken(options: ExchangeProfileOptions): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    validateSubjectToken(options.subjectToken);

    if (options.organization !== undefined) {
      assertValidOrganization(options.organization);
    }

    if (options.actorToken !== undefined && options.actorTokenType === undefined) {
      throw new TokenExchangeError('actorTokenType is required when actorToken is provided');
    }

    const tokenRequestParams = new URLSearchParams({
      subject_token_type: options.subjectTokenType,
      subject_token: options.subjectToken,
    });

    if (options.audience) {
      tokenRequestParams.append('audience', options.audience);
    }
    if (options.scope) {
      tokenRequestParams.append('scope', options.scope);
    }
    if (options.requestedTokenType) {
      tokenRequestParams.append('requested_token_type', options.requestedTokenType);
    }
    if (options.organization) {
      tokenRequestParams.append('organization', options.organization);
    }
    if (options.actorToken) {
      tokenRequestParams.append('actor_token', options.actorToken);
    }
    if (options.actorTokenType) {
      tokenRequestParams.append('actor_token_type', options.actorTokenType);
    }

    appendExtraParams(tokenRequestParams, options.extra);

    let tokenResponse: TokenResponse;
    let tokenEndpointResponse: Awaited<ReturnType<typeof client.genericGrantRequest>>;
    try {
      tokenEndpointResponse = await client.genericGrantRequest(
        configuration,
        TOKEN_EXCHANGE_GRANT_TYPE,
        tokenRequestParams
      );

      tokenResponse = TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenExchangeError(
        `Failed to exchange token of type '${options.subjectTokenType}'${options.audience ? ` for audience '${options.audience}'` : ''}.`,
        toOAuth2Error(e)
      );
    }

    if (options.organization) {
      validateOrganizationClaim(tokenResponse.claims, options.organization);
    }

    if (options.actorToken) {
      if (tokenResponse.claims?.act) {
        tokenResponse.act = tokenResponse.claims.act as ActClaim;
      } else {
        try {
          tokenResponse.act = decodeJwt(tokenEndpointResponse.access_token).act as ActClaim | undefined;
        } catch {
          // opaque access token — act claim not available
        }
      }
    }

    return tokenResponse;
  }

  /**
   * @overload
   * Exchanges a custom token for Auth0 tokens using RFC 8693 Token Exchange via Token Exchange Profile.
   *
   * This overload is used when you DON'T provide a `connection` parameter.
   * It enables exchanging custom tokens (from MCP servers, legacy systems, or partner
   * services) for Auth0 tokens targeting a specific API audience. Requires a Token
   * Exchange Profile configured in Auth0.
   *
   * When `organization` is provided, the returned ID token's organization claim is
   * validated against it (an `org_` prefix is matched exactly against `org_id`,
   * otherwise the value is matched case-insensitively against `org_name`).
   *
   * @param options Token Exchange Profile configuration (without `connection` parameter)
   * @returns Promise resolving to TokenResponse with Auth0 tokens
   * @throws {TokenExchangeError} When the token exchange or non-organization option validation fails
   * @throws {MissingClientAuthError} When client authentication is not configured
   * @throws {OrganizationValidationError} When `organization` is blank, or when an ID token is returned whose organization claim is missing or does not match
   *
   * @example
   * ```typescript
   * // Exchange custom token (organization is optional)
   * const response = await authClient.exchangeToken({
   *   subjectTokenType: 'urn:acme:mcp-token',
   *   subjectToken: mcpServerToken,
   *   audience: 'https://api.example.com',
   *   organization: 'org_abc123', // Optional - Organization ID or name
   *   scope: 'openid profile read:data'
   * });
   * // The resulting access token will include the organization ID in its payload
   * ```
   */
  public exchangeToken(options: ExchangeProfileOptions): Promise<TokenResponse>;

  /**
   * @overload
   * Exchanges an Auth0 token for an external provider's access token using Token Vault.
   *
   * This overload is used when you DO provide a `connection` parameter.
   * It exchanges Auth0 tokens (access or refresh) for external provider's access tokens
   * (Google, Facebook, etc.). The external provider's refresh token is securely stored in
   * Auth0's Token Vault.
   *
   * @param options Token Vault exchange configuration (with `connection` parameter)
   * @returns Promise resolving to TokenResponse with external provider's access token
   * @throws {TokenExchangeError} When exchange fails or validation errors occur
   * @throws {MissingClientAuthError} When client authentication is not configured
   *
   * @example
   * ```typescript
   * const response = await authClient.exchangeToken({
   *   connection: 'google-oauth2',
   *   subjectToken: auth0AccessToken,
   *   loginHint: 'user@example.com'
   * });
   * ```
   */
  public exchangeToken(options: TokenVaultExchangeOptions): Promise<TokenResponse>;

  /**
   * Exchanges a token using either Token Exchange via Token Exchange Profile (RFC 8693) or Access Token Exchange with Token Vault.
   *
   * **Method routing is determined by the presence of the `connection` parameter:**
   * - **Without `connection`**: Token Exchange via Token Exchange Profile (RFC 8693)
   * - **With `connection`**: Access Token Exchange with Token Vault
   *
   * Both flows require a confidential client (client credentials must be configured).
   *
   * @see {@link ExchangeProfileOptions} for Token Exchange Profile parameters
   * @see {@link TokenVaultExchangeOptions} for Token Vault parameters
   * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Custom Token Exchange Docs}
   * @see {@link https://auth0.com/docs/secure/tokens/token-vault Token Vault Docs}
   *
   * @example Token Exchange with validation context
   * ```typescript
   * const response = await authClient.exchangeToken({
   *   subjectTokenType: 'urn:acme:legacy-token',
   *   subjectToken: legacySystemToken,
   *   audience: 'https://api.acme.com',
   *   scope: 'openid offline_access',
   *   extra: {
   *     device_id: 'device-12345',
   *     session_id: 'sess-abc',
   *     migration_context: 'legacy-system-v1'
   *   }
   * });
   * ```
   */
  public async exchangeToken(options: ExchangeProfileOptions | TokenVaultExchangeOptions): Promise<TokenResponse> {
    return 'connection' in options ? this.#exchangeTokenVaultToken(options) : this.#exchangeProfileToken(options);
  }

  /**
   * Retrieves a token by exchanging an authorization code.
   * @param url The URL containing the authorization code.
   * @param options Options for exchanging the authorization code, containing the expected code verifier.
   *
   * @throws {TokenByCodeError} If there was an issue requesting the access token.
   * @throws {OrganizationValidationError} If `organization` is blank, or if an ID token is returned whose organization claim is missing or does not match.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  public async getTokenByCode(url: URL, options: TokenByCodeOptions): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    if (options.organization !== undefined) {
      assertValidOrganization(options.organization);
    }

    let tokenResponse: TokenResponse;
    try {
      const tokenEndpointResponse = await client.authorizationCodeGrant(configuration, url, {
        pkceCodeVerifier: options.codeVerifier,
      });

      tokenResponse = TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenByCodeError('There was an error while trying to request a token.', toOAuth2Error(e));
    }

    if (options.organization) {
      validateOrganizationClaim(tokenResponse.claims, options.organization);
    }

    return tokenResponse;
  }

  /**
   * Completes a magic-link sign-in by exchanging the authorization code on the callback URL
   * for tokens, WITHOUT PKCE.
   *
   * Unlike {@link AuthClient#getTokenByCode}, this method does not present a `code_verifier`:
   * `/passwordless/start` delivers the link but never registers a `code_challenge`, so presenting
   * a verifier at the exchange would be rejected with `invalid_grant`. The `pkceCodeVerifier` option
   * is intentionally omitted, which makes the underlying `openid-client` use its no-PKCE sentinel.
   * The returned `state` is validated against `options.expectedState` (anti-forgery binding).
   *
   * This is the token-layer primitive used by the session layer's `completePasswordlessMagicLink`.
   * The PKCE-bound {@link AuthClient#getTokenByCode} remains the path for interactive logins.
   *
   * @param url The callback URL containing the authorization `code` and `state`.
   * @param options Options for the exchange, including the expected `state`.
   *
   * @throws {TokenByCodeError} If state validation fails or the token exchange fails.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   *
   * @example
   * const tokenResponse = await authClient.getTokenByMagicLinkCode(callbackUrl, {
   *   expectedState: persistedState,
   * });
   */
  public async getTokenByMagicLinkCode(
    url: URL,
    options?: TokenByMagicLinkCodeOptions
  ): Promise<TokenResponse> {
    const { configuration } = await this.#discover();
    try {
      const tokenEndpointResponse = await client.authorizationCodeGrant(configuration, url, {
        // `pkceCodeVerifier` intentionally omitted: openid-client substitutes its no-PKCE sentinel
        // (oauth.nopkce). `expectedState` drives oauth.validateAuthResponse for anti-forgery binding.
        expectedState: options?.expectedState,
      });

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      // Surface the underlying message (e.g. openid-client state-mismatch) instead of a
      // generic string, so a non-token-endpoint failure is not mislabeled as one.
      const message = e instanceof Error && e.message ? e.message : 'There was an error while trying to request a token.';
      throw new TokenByCodeError(message, e as OAuth2Error);
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

    const additionalParameters = new URLSearchParams();

    if (options.audience) {
      additionalParameters.append('audience', options.audience);
    }

    if (options.scope) {
      additionalParameters.append('scope', options.scope);
    }

    try {
      const tokenEndpointResponse = await client.refreshTokenGrant(
        configuration,
        options.refreshToken,
        additionalParameters
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenByRefreshTokenError(
        'The access token has expired and there was an error while trying to refresh it.',
        toOAuth2Error(e)
      );
    }
  }

  /**
   * Retrieves a token using Resource Owner Password Grant.
   * @param options Options for authenticating with username and password.
   *
   * @throws {TokenByPasswordError} If there was an issue requesting the access token.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  public async getTokenByPassword(
    options: TokenByPasswordOptions
  ): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    const params = new URLSearchParams({
      username: options.username,
      password: options.password,
    });

    if (options.audience) {
      params.append('audience', options.audience);
    }

    if (options.scope) {
      params.append('scope', options.scope);
    }

    if (options.realm) {
      params.append('realm', options.realm);
    }

    // When auth0ForwardedFor is needed, create a separate configuration with a
    // wrapped fetch so we never mutate the shared cached configuration.
    let requestConfig = configuration;

    if (options.auth0ForwardedFor) {
      const clientAuth = await this.#getClientAuth();
      requestConfig = new client.Configuration(
        configuration.serverMetadata(),
        this.#options.clientId,
        this.#options.clientSecret,
        clientAuth,
      );

      requestConfig[client.customFetch] = ((url: string, init: client.CustomFetchOptions) => {
        return (this.#customFetch as client.CustomFetch)(url, {
          ...init,
          headers: {
            ...init.headers,
            'auth0-forwarded-for': options.auth0ForwardedFor!,
          },
        } as client.CustomFetchOptions);
      }) as client.CustomFetch;
    }

    try {
      const tokenEndpointResponse = await client.genericGrantRequest(
        requestConfig,
        'password',
        params
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenByPasswordError(
        'There was an error while trying to request a token.',
        toOAuth2Error(e)
      );
    }
  }

  /**
   * Exchanges a passwordless email one-time code for a token (OTP grant).
   *
   * For the `send: 'code'` flow only. Magic links are completed through the standard
   * authorization-code exchange ({@link AuthClient#getTokenByCode}) plus the redirect
   * callback, not through this method.
   *
   * Tenant prerequisites: a confidential application with the Passwordless OTP grant
   * enabled and an Identifier-First authentication profile.
   *
   * @param options Options containing the email, code, and optional audience/scope.
   *
   * @throws {PasswordlessVerifyError} If the code is invalid, expired, or rate-limited.
   * @throws {PasswordlessVerifyError} On a failed exchange. When the connection requires MFA the
   *   server responds with `403 mfa_required`; narrow the error with `isMfaRequiredError` and
   *   complete the challenge via `authClient.mfa`.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   *
   * @example
   * ```typescript
   * const tokens = await authClient.getTokenByPasswordlessEmail({
   *   email: 'user@example.com',
   *   code: '123456',
   *   scope: 'openid profile', // include 'openid' for an id_token; SDK does not inject it
   * });
   * ```
   */
  public async getTokenByPasswordlessEmail(options: TokenByPasswordlessEmailOptions): Promise<TokenResponse> {
    const params = new URLSearchParams({
      username: options.email,
      otp: options.code,
      realm: 'email',
    });

    if (options.audience) {
      params.append('audience', options.audience);
    }

    if (options.scope) {
      params.append('scope', options.scope);
    }

    return this.#getTokenByPasswordlessOtp(params);
  }

  /**
   * Exchanges a passwordless SMS one-time code for a token (OTP grant).
   *
   * @param options Options containing the phone number (E.164), code, and optional audience/scope.
   *
   * @throws {PasswordlessVerifyError} If the phone number is invalid, or the code is invalid,
   *   expired, or rate-limited.
   * @throws {PasswordlessVerifyError} On a failed exchange. When the connection requires MFA the
   *   server responds with `403 mfa_required`; narrow the error with `isMfaRequiredError` and
   *   complete the challenge via `authClient.mfa`.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   *
   * @example
   * ```typescript
   * const tokens = await authClient.getTokenByPasswordlessSms({
   *   phoneNumber: '+14155550100',
   *   code: '123456',
   * });
   * ```
   */
  public async getTokenByPasswordlessSms(options: TokenByPasswordlessSmsOptions): Promise<TokenResponse> {
    if (!isE164PhoneNumber(options.phoneNumber)) {
      throw new PasswordlessVerifyError('Phone number must be in E.164 format (e.g. +14155550100).');
    }

    const params = new URLSearchParams({
      username: options.phoneNumber,
      otp: options.code,
      realm: 'sms',
    });

    if (options.audience) {
      params.append('audience', options.audience);
    }

    if (options.scope) {
      params.append('scope', options.scope);
    }

    return this.#getTokenByPasswordlessOtp(params);
  }

  /**
   * Executes the passwordless OTP grant and maps errors to {@link PasswordlessVerifyError}.
   *
   * A `403 mfa_required` response is not a distinct error type: like the other token
   * methods (`getTokenByPassword`, `passkey.getTokenByPasskey`), the thrown
   * `PasswordlessVerifyError` carries `cause.error === 'mfa_required'` with the
   * server's `mfa_token` lifted onto `cause`. Callers narrow with {@link isMfaRequiredError}
   * and drive the challenge via `authClient.mfa`.
   */
  async #getTokenByPasswordlessOtp(params: URLSearchParams): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    try {
      const tokenEndpointResponse = await client.genericGrantRequest(
        configuration,
        'http://auth0.com/oauth/grant-type/passwordless/otp',
        params
      );

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      // `toOAuth2Error` lifts `mfa_token` / `mfa_requirements` from the nested
      // openid-client `cause` so `isMfaRequiredError` can detect an MFA requirement.
      throw new PasswordlessVerifyError('There was an error while trying to request a token.', toOAuth2Error(e));
    }
  }

  /**
   * Retrieves a token by exchanging client credentials.
   * @param options Options for retrieving the token.
   *
   * @throws {TokenByClientCredentialsError} If there was an issue requesting the access token.
   *
   * @returns A Promise, resolving to the TokenResponse as returned from Auth0.
   */
  public async getTokenByClientCredentials(options: TokenByClientCredentialsOptions): Promise<TokenResponse> {
    const { configuration } = await this.#discover();

    try {
      const params = new URLSearchParams({
        audience: options.audience,
      });

      if (options.organization) {
        params.append('organization', options.organization);
      }

      const tokenEndpointResponse = await client.clientCredentialsGrant(configuration, params);

      return TokenResponse.fromTokenEndpointResponse(tokenEndpointResponse);
    } catch (e) {
      throw new TokenByClientCredentialsError('There was an error while trying to request a token.', toOAuth2Error(e));
    }
  }

  /**
   * Builds the URL to redirect the user-agent to to request logout at Auth0.
   * @param options Options used to configure the logout URL.
   * @returns A promise resolving to the URL to redirect the user-agent to.
   */
  public async buildLogoutUrl(options: BuildLogoutUrlOptions): Promise<URL> {
    const { configuration, serverMetadata } = await this.#discover();

    // We should not call `client.buildEndSessionUrl` when we do not have an `end_session_endpoint`
    // In that case, we rely on the v2 logout endpoint.
    // This can happen for tenants that do not have RP-Initiated Logout enabled.
    if (!serverMetadata.end_session_endpoint) {
      const url = new URL(`https://${this.#options.domain}/v2/logout`);
      url.searchParams.set('returnTo', options.returnTo);
      url.searchParams.set('client_id', this.#options.clientId);
      return url;
    }

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
  async verifyLogoutToken(options: VerifyLogoutTokenOptions): Promise<VerifyLogoutTokenResult> {
    const { serverMetadata } = await this.#discover();
    const cacheConfig = resolveCacheConfig(this.#options.discoveryCache);
    const jwksUri = serverMetadata!.jwks_uri!;

    this.#jwks ||= createRemoteJWKSet(new URL(jwksUri), {
      cacheMaxAge: cacheConfig.ttlMs,
      [customFetch]: this.#customFetch,
      [jwksCache]: this.#jwksCache,
    });

    const { payload } = await jwtVerify(options.logoutToken, this.#jwks, {
      issuer: serverMetadata!.issuer,
      audience: this.#options.clientId,
      algorithms: ['RS256'],
      requiredClaims: ['iat'],
    });

    if (!('sid' in payload) && !('sub' in payload)) {
      throw new VerifyLogoutTokenError('either "sid" or "sub" (or both) claims must be present');
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

    if (!('http://schemas.openid.net/event/backchannel-logout' in payload.events)) {
      throw new VerifyLogoutTokenError(
        '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim'
      );
    }

    if (typeof payload.events['http://schemas.openid.net/event/backchannel-logout'] !== 'object') {
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
   *
   * Supports three authentication methods in order of preference:
   * 1. mTLS (mutual TLS) - requires customFetch with client certificate
   * 2. private_key_jwt - requires clientAssertionSigningKey
   * 3. client_secret_post - requires clientSecret
   *
   * @private
   * @returns The ClientAuth object to use for client authentication.
   * @throws {MissingClientAuthError} When no valid authentication method is configured
   */
  async #getClientAuth(): Promise<client.ClientAuth> {
    if (!this.#clientAuthPromise) {
      this.#clientAuthPromise = (async () => {
        if (!this.#options.clientSecret && !this.#options.clientAssertionSigningKey && !this.#options.useMtls) {
          throw new MissingClientAuthError();
        }

        if (this.#options.useMtls) {
          return client.TlsClientAuth();
        }

        let clientPrivateKey = this.#options.clientAssertionSigningKey as CryptoKey | undefined;

        if (clientPrivateKey && !(clientPrivateKey instanceof CryptoKey)) {
          clientPrivateKey = await importPKCS8(
            clientPrivateKey,
            this.#options.clientAssertionSigningAlg || 'RS256'
          );
        }

        return clientPrivateKey
          ? client.PrivateKeyJwt(clientPrivateKey)
          : client.ClientSecretPost(this.#options.clientSecret!);
      })().catch((error) => {
        this.#clientAuthPromise = undefined;
        throw error;
      });
    }

    return this.#clientAuthPromise;
  }

  /**
   * Builds the URL to redirect the user-agent to to request authorization at Auth0.
   * @param options Options used to configure the authorization URL.
   * @returns A promise resolving to an object, containing the authorizationUrl and codeVerifier.
   */
  async #buildAuthorizationUrl(options?: BuildAuthorizationUrlOptions): Promise<BuildAuthorizationUrlResult> {
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
