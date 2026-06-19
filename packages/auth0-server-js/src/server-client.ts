import {
  AccessTokenForConnectionOptions,
  ConnectionTokenSet,
  CustomTokenExchangeOptions,
  DomainResolver,
  LoginBackchannelOptions,
  LoginBackchannelResult,
  LoginWithCustomTokenExchangeOptions,
  LoginWithCustomTokenExchangeResult,
  CompletePasswordlessOptions,
  CompletePasswordlessResult,
  LogoutOptions,
  PasskeyRegisterResponse,
  PasskeyRegisterOptions,
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyGetTokenOptions,
  PasskeyGetTokenResult,
  ServerClientOptions,
  SessionData,
  StartInteractiveLoginOptions,
  StartLinkUserOptions,
  StartPasswordlessOptions,
  StartUnlinkUserOptions,
  StateData,
  StateStore,
  TokenSet,
  TransactionData,
  TransactionStore,
} from './types.js';
import {
  BackchannelLogoutError,
  InvalidConfigurationError,
  MissingRequiredArgumentError,
  MissingSessionError,
  MissingTransactionError,
} from './errors.js';
import { updateStateData, updateStateDataForConnectionTokenSet } from './state/utils.js';
import {
  TokenForConnectionError,
  AuthClient,
  AuthorizationDetails,
  PasswordlessStartError,
  PasswordlessVerifyError,
  TokenByRefreshTokenError,
  TokenResponse,
} from '@auth0/auth0-auth-js';
import { compareScopes } from './utils.js';
import { decodeJwt } from 'jose';
import type { AuthClientOptions } from '@auth0/auth0-auth-js';
import { getTelemetryConfig } from './telemetry.js';
import { ServerMfaClient } from './mfa/server-mfa-client.js';

const DEFAULT_SCOPES = 'openid profile email offline_access';

const normalizeDomain = (value: string) => {
  const trimmed = value.trim();
  const parsed = trimmed.startsWith('http') ? new URL(trimmed) : new URL(`https://${trimmed}`);
  return parsed.host.toLowerCase();
};

const decodeIssuer = (token: string) => {
  try {
    const { iss } = decodeJwt(token);
    return typeof iss === 'string' ? iss : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Ensures that the "openid" scope is always included in the scope string.
 *
 * @param scope - The scope provided by the user (optional)
 * @returns A scope string that includes "openid" if it was not already present.
 */
const ensureOpenIdScope = (scope?: string) => {
  if (!scope) {
    return DEFAULT_SCOPES;
  }

  const scopes = scope.split(' ');
  if (!scopes.includes('openid')) {
    scopes.unshift('openid');
  }

  return scopes.join(' ');
};

export class ServerClient<TStoreOptions = unknown> {
  readonly #options: ServerClientOptions<TStoreOptions>;
  readonly #transactionStore: TransactionStore<TStoreOptions>;
  readonly #transactionStoreIdentifier: string;
  readonly #stateStore: StateStore<TStoreOptions>;
  readonly #stateStoreIdentifier: string;
  readonly #authClientOptions: Omit<AuthClientOptions, 'domain'>;
  readonly #staticDomain?: string;
  readonly #authClient?: AuthClient;
  readonly #mfaClient?: ServerMfaClient<TStoreOptions>;

  /**
   * The underlying `authClient` instance that can be used to interact with the Auth0 Authentication API.
   * Generally, you should prefer to use the higher-level methods exposed on the `ServerClient` instance.
   *
   * This property can only be used when `domain` is configured as a static string.
   * In resolver mode (`domain` as a function), the SDK resolves the domain per request,
   * so use `ServerClient` methods instead.
   *
   * Important: the methods exposed on the `authClient` instance do not handle any session or state management.
   */
  public get authClient(): AuthClient {
    if (!this.#authClient) {
      throw new InvalidConfigurationError('authClient is only available when using a static domain configuration.');
    }
    return this.#authClient;
  }

  /**
   * The MFA client for managing multi-factor authentication operations.
   *
   * Provides methods to list, enroll, and challenge MFA authenticators,
   * as well as verify MFA challenges to complete authentication.
   *
   * The `verify` method integrates with the session state store, persisting tokens
   * and user data after successful MFA verification.
   *
   * This property can only be used when `domain` is configured as a static string.
   * In resolver mode (`domain` as a function), MFA is not supported.
   */
  public get mfa(): ServerMfaClient<TStoreOptions> {
    if (!this.#mfaClient) {
      throw new InvalidConfigurationError('mfa is only available when using a static domain configuration.');
    }
    return this.#mfaClient;
  }

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

    if (typeof this.#options.domain !== 'string' && typeof this.#options.domain !== 'function') {
      throw new InvalidConfigurationError('domain must be a string or resolver function');
    }

    this.#authClientOptions = {
      clientId: this.#options.clientId,
      clientSecret: this.#options.clientSecret,
      clientAssertionSigningKey: this.#options.clientAssertionSigningKey,
      clientAssertionSigningAlg: this.#options.clientAssertionSigningAlg,
      authorizationParams: this.#options.authorizationParams,
      discoveryCache: this.#options.discoveryCache,
      customFetch: this.#options.customFetch,
      useMtls: this.#options.useMtls,
    };

    if (typeof this.#options.domain === 'string') {
      const domain = normalizeDomain(this.#options.domain);
      this.#staticDomain = domain;
      this.#authClient = new AuthClient({
        domain,
        ...this.#authClientOptions,
        telemetry: getTelemetryConfig(this.#options.telemetry),
      });

      this.#mfaClient = new ServerMfaClient({
        authClient: this.#authClient,
        domain,
        stateStore: this.#stateStore,
        stateStoreIdentifier: this.#stateStoreIdentifier,
        defaultAudience: this.#options.authorizationParams?.audience ?? 'default',
      });
    }
  }

  async #resolveDomain(storeOptions?: TStoreOptions): Promise<string> {
    if (typeof this.#options.domain === 'function') {
      const resolved = await (this.#options.domain as DomainResolver<TStoreOptions>)(storeOptions);
      if (typeof resolved !== 'string' || resolved.trim().length === 0) {
        throw new InvalidConfigurationError('domainResolver returned no domain');
      }
      return normalizeDomain(resolved);
    }

    return normalizeDomain(this.#options.domain);
  }

  #createAuthClient(domain: string): AuthClient {
    return new AuthClient({
      domain,
      ...this.#authClientOptions,
      telemetry: getTelemetryConfig(this.#options.telemetry),
    });
  }

  #getAuthClient(domain: string): AuthClient {
    const normalizedDomain = normalizeDomain(domain);
    if (this.#authClient && this.#staticDomain === normalizedDomain) {
      return this.#authClient;
    }
    return this.#createAuthClient(normalizedDomain);
  }

  #getSessionDomain(stateData: StateData): string | undefined {
    if (stateData.domain) {
      return normalizeDomain(stateData.domain);
    }

    if (this.#staticDomain) {
      return this.#staticDomain;
    }

    // Legacy sessions may not have `domain` persisted yet; infer it from ID token claims.
    const issuerFromClaims = stateData.user?.iss;
    if (typeof issuerFromClaims === 'string' && issuerFromClaims.trim().length > 0) {
      return normalizeDomain(issuerFromClaims);
    }

    return;
  }

  #isResolverMode(): boolean {
    return typeof this.#options.domain === 'function';
  }

  async #isSessionForCurrentDomain(stateData: StateData, storeOptions?: TStoreOptions): Promise<boolean> {
    const sessionDomain = this.#getSessionDomain(stateData);
    if (!sessionDomain) {
      return false;
    }
    const resolvedDomain = await this.#resolveDomain(storeOptions);
    return sessionDomain === resolvedDomain;
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

    const scope = ensureOpenIdScope(options?.authorizationParams?.scope ?? this.#options.authorizationParams?.scope);

    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);
    const { codeVerifier, authorizationUrl } = await authClient.buildAuthorizationUrl({
      pushedAuthorizationRequests: options?.pushedAuthorizationRequests,
      authorizationParams: {
        ...options?.authorizationParams,
        redirect_uri: redirectUri,
        scope,
      },
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
      domain,
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

    const domain = transactionData.domain ?? (await this.#resolveDomain(storeOptions));
    const authClient = this.#getAuthClient(domain);
    const tokenEndpointResponse = await authClient.getTokenByCode(url, {
      // TransactionData.codeVerifier is optional only to accommodate magic-link transactions.
      codeVerifier: transactionData.codeVerifier!,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const stateData = updateStateData(transactionData.audience ?? 'default', existingStateData, tokenEndpointResponse, {
      domain,
    });

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

    if (this.#isResolverMode()) {
      const isCurrentDomain = await this.#isSessionForCurrentDomain(stateData, storeOptions);
      if (!isCurrentDomain) {
        throw new MissingSessionError('Session domain does not match the current domain.');
      }
    }

    const domain = this.#getSessionDomain(stateData)!;
    const authClient = this.#getAuthClient(domain);
    const { linkUserUrl, codeVerifier } = await authClient.buildLinkUserUrl({
      connection: options.connection,
      connectionScope: options.connectionScope,
      idToken: stateData.idToken,
      authorizationParams: options.authorizationParams,
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
      domain,
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

    if (this.#isResolverMode()) {
      const isCurrentDomain = await this.#isSessionForCurrentDomain(stateData, storeOptions);
      if (!isCurrentDomain) {
        throw new MissingSessionError('Session domain does not match the current domain.');
      }
    }

    const domain = this.#getSessionDomain(stateData)!;
    const authClient = this.#getAuthClient(domain);
    const { unlinkUserUrl, codeVerifier } = await authClient.buildUnlinkUserUrl({
      connection: options.connection,
      idToken: stateData.idToken,
      authorizationParams: options.authorizationParams,
    });

    const transactionState: TransactionData = {
      audience: options?.authorizationParams?.audience ?? this.#options.authorizationParams?.audience,
      codeVerifier,
      domain,
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
    const scope = ensureOpenIdScope(options.authorizationParams?.scope ?? this.#options.authorizationParams?.scope);
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);
    const tokenEndpointResponse = await authClient.backchannelAuthentication({
      bindingMessage: options.bindingMessage,
      loginHint: options.loginHint,
      authorizationParams: {
        ...options.authorizationParams,
        scope,
      },
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(
      this.#options.authorizationParams?.audience ?? 'default',
      existingStateData,
      tokenEndpointResponse,
      { domain }
    );

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }

  /**
   * Requests a passkey signup challenge for a new user.
   *
   * Returns the `authSession` and the WebAuthn credential creation options
   * (`authnParamsPublicKey`). The application must return these to the browser,
   * pass `authnParamsPublicKey` to `navigator.credentials.create()`, and then
   * call `passkeyGetToken()` with the resulting credential to complete signup.
   *
   * This method does not create a session; no state is persisted.
   *
   * @param options User profile data and optional realm/organization.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge.
   *
   * @returns A promise resolving to the signup challenge.
   */
  public async passkeyRegister(
    options: PasskeyRegisterOptions,
    storeOptions?: TStoreOptions
  ): Promise<PasskeyRegisterResponse> {
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);

    return authClient.passkey.register(options);
  }

  /**
   * Requests a passkey login challenge for an existing user.
   *
   * Returns the `authSession` and the WebAuthn credential request options
   * (`authnParamsPublicKey`). The application must return these to the browser,
   * pass `authnParamsPublicKey` to `navigator.credentials.get()`, and then
   * call `passkeyGetToken()` with the resulting credential to complete login.
   *
   * This method does not create a session; no state is persisted.
   *
   * @param options Optional realm/organization configuration.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {PasskeyChallengeError} If there was an issue requesting the login challenge.
   *
   * @returns A promise resolving to the login challenge.
   */
  public async passkeyChallenge(
    options?: PasskeyChallengeOptions,
    storeOptions?: TStoreOptions
  ): Promise<PasskeyChallengeResponse> {
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);

    return authClient.passkey.challenge(options);
  }

  /**
   * Completes a passkey authentication flow (signup or login) by exchanging the
   * WebAuthn credential for tokens, and persists the resulting session.
   *
   * Call this after obtaining a credential from `navigator.credentials.create()`
   * (signup) or `navigator.credentials.get()` (login), passing the `authSession`
   * returned by `passkeyRegister()` / `passkeyChallenge()` together with the
   * serialized credential.
   *
   * @param options The auth session, serialized credential, and optional realm/scope/audience/organization.
   * @param storeOptions Optional options used to pass to the State Store (and to resolve the domain in resolver mode).
   *
   * @throws {PasskeyGetTokenError} If there was an issue exchanging the credential for tokens. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`. No session is persisted in this case.
   *
   * @returns A promise resolving to an object containing the authorizationDetails (when RAR was used).
   */
  public async passkeyGetToken(
    options: PasskeyGetTokenOptions,
    storeOptions?: TStoreOptions
  ): Promise<PasskeyGetTokenResult> {
    const scope = ensureOpenIdScope(options.scope ?? this.#options.authorizationParams?.scope);
    const audience = options.audience ?? this.#options.authorizationParams?.audience;

    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);

    const tokenEndpointResponse = await authClient.passkey.getTokenByPasskey({
      ...options,
      scope,
      audience,
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(audience ?? 'default', existingStateData, tokenEndpointResponse, { domain });

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }

  /**
   * Starts a passwordless flow by sending a one-time code (OTP) or a magic link.
   *
   * Discriminated on `connection` (and, for email, `send`) to mirror the
   * `@auth0/nextjs-auth0` `passwordless.start()` surface:
   * - `{ connection: 'email' }` / `{ connection: 'email', send: 'code' }` — email OTP
   * - `{ connection: 'email', send: 'link', redirectUri }` — email magic link
   * - `{ connection: 'sms' }` — SMS OTP
   *
   * OTP modes are a stateless passthrough to the Authentication API (no session, no transaction);
   * complete them with {@link ServerClient#completePasswordless}.
   *
   * Magic-link mode is stateful: the SDK generates an opaque anti-forgery `state`, sends the link
   * with the OAuth parameters embedded (`redirect_uri`, `response_type=code`, `scope`, `state`),
   * and persists a transaction carrying that `state`. NO PKCE challenge is registered, so the
   * transaction holds no `codeVerifier`. Complete it with
   * {@link ServerClient#completePasswordlessMagicLink}. Requires the tenant setting
   * `allow_magiclink_verify_without_session: true` for server-side completion.
   *
   * @param options Discriminated start options.
   * @param storeOptions Optional options passed to the resolver / stores.
   *
   * @throws {PasswordlessStartError} If the request fails, or if a magic link is requested without a `redirectUri`.
   *
   * @example
   * // Email OTP
   * await serverClient.startPasswordless({ connection: 'email', email: 'user@example.com' });
   * // SMS OTP
   * await serverClient.startPasswordless({ connection: 'sms', phoneNumber: '+14155550100' });
   * // Email magic link
   * await serverClient.startPasswordless({
   *   connection: 'email',
   *   email: 'user@example.com',
   *   send: 'link',
   *   redirectUri: 'https://app.example.com/auth/callback',
   * });
   */
  public async startPasswordless(
    options: StartPasswordlessOptions,
    storeOptions?: TStoreOptions
  ): Promise<void> {
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);

    if (options.connection === 'sms') {
      await authClient.passwordless.sendSms({
        phoneNumber: options.phoneNumber,
        language: options.language,
      });
      return;
    }

    // Email OTP
    if (options.send !== 'link') {
      await authClient.passwordless.sendEmail({
        email: options.email,
        send: 'code',
        language: options.language,
      });
      return;
    }

    // Email magic link (stateful)
    if (!options.redirectUri || typeof options.redirectUri !== 'string') {
      throw new PasswordlessStartError('redirectUri is required to start a passwordless magic-link login.');
    }

    const state = crypto.randomUUID();
    const scope = ensureOpenIdScope(options.scope ?? this.#options.authorizationParams?.scope);
    const audience = options.audience ?? this.#options.authorizationParams?.audience;

    await authClient.passwordless.sendEmail({
      email: options.email,
      send: 'link',
      language: options.language,
      authParams: {
        ...options.authParams,
        redirect_uri: options.redirectUri,
        response_type: 'code',
        scope,
        ...(audience ? { audience } : {}),
        state,
      },
    });

    const transactionState: TransactionData = {
      audience,
      domain,
      state,
    };

    await this.#transactionStore.set(this.#transactionStoreIdentifier, transactionState, false, storeOptions);
  }

  /**
   * Completes a passwordless OTP login and persists the resulting session.
   *
   * Discriminated on `connection` to mirror the `@auth0/nextjs-auth0` `passwordless.verify()`
   * surface. Non-redirect flow: no PKCE and no transaction store (mirrors
   * {@link ServerClient#loginBackchannel}). The `openid` scope is always ensured by this layer.
   *
   * Note: the state store is read-then-written; if your deployment performs concurrent
   * logins for the same session identifier, use a state store with atomic/serializable
   * writes to avoid last-write-wins races.
   *
   * @param options Discriminated completion options (`connection`, identifier, `verificationCode`).
   * @param storeOptions Optional options passed to the resolver / stores.
   *
   * @throws {PasswordlessVerifyError} If the code is invalid, expired, or rate-limited. When the
   *   connection requires MFA, the server responds with `mfa_required`; narrow the thrown error
   *   with `isMfaRequiredError(error)` to read `cause.mfa_token`.
   *
   * @returns A promise resolving to the authorizationDetails (when RAR was used).
   */
  public async completePasswordless(
    options: CompletePasswordlessOptions,
    storeOptions?: TStoreOptions
  ): Promise<CompletePasswordlessResult> {
    const scope = ensureOpenIdScope(options.authorizationParams?.scope ?? this.#options.authorizationParams?.scope);
    const audience = options.authorizationParams?.audience ?? this.#options.authorizationParams?.audience;
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);

    const tokenEndpointResponse =
      options.connection === 'sms'
        ? await authClient.getTokenByPasswordlessSms({
            phoneNumber: options.phoneNumber,
            code: options.verificationCode,
            audience,
            scope,
          })
        : await authClient.getTokenByPasswordlessEmail({
            email: options.email,
            code: options.verificationCode,
            audience,
            scope,
          });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(
      this.#options.authorizationParams?.audience ?? 'default',
      existingStateData,
      tokenEndpointResponse,
      { domain }
    );

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }

  /**
   * Completes a passwordless magic-link login and persists the resulting session.
   *
   * Loads the transaction persisted by {@link ServerClient#startPasswordless} (magic-link mode), validates the
   * `state` returned on the callback URL against the stored `state` (anti-forgery binding), exchanges
   * the authorization code WITHOUT PKCE, writes the session, and deletes the transaction. The existing
   * interactive login path ({@link ServerClient#completeInteractiveLogin}) is not used.
   *
   * @param url The callback URL containing the authorization `code` and `state`.
   * @param storeOptions Optional options passed to the resolver / stores.
   *
   * @throws {MissingTransactionError} If no magic-link transaction was found.
   * @throws {PasswordlessVerifyError} If the returned `state` is missing or does not match.
   * @throws {TokenByCodeError} If the token exchange fails.
   *
   * @returns A promise resolving to the authorizationDetails (when RAR was used).
   *
   * @example
   * const result = await serverClient.completePasswordlessMagicLink(callbackUrl, storeOptions);
   */
  public async completePasswordlessMagicLink(
    url: URL,
    storeOptions?: TStoreOptions
  ): Promise<CompletePasswordlessResult> {
    const transactionData = await this.#transactionStore.get(this.#transactionStoreIdentifier, storeOptions);

    if (!transactionData) {
      throw new MissingTransactionError();
    }

    // TransactionData.state is `unknown` ([key: string]: unknown); validate the type
    // rather than assert it, so a non-string state (e.g. number from a custom store)
    // falls through to the mismatch branch instead of comparing wrongly.
    const expectedState = typeof transactionData.state === 'string' ? transactionData.state : undefined;
    const returnedState = url.searchParams.get('state');
    if (!returnedState || !expectedState || returnedState !== expectedState) {
      throw new PasswordlessVerifyError('State mismatch on magic-link callback');
    }

    const domain = transactionData.domain ?? (await this.#resolveDomain(storeOptions));
    const authClient = this.#getAuthClient(domain);

    // Belt-and-suspenders: `expectedState` is re-validated inside getTokenByMagicLinkCode
    // (openid-client's anti-forgery binding). This is intentionally redundant with the
    // manual check above — do not remove one without auditing the other.
    const tokenEndpointResponse = await authClient.getTokenByMagicLinkCode(url, { expectedState });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(transactionData.audience ?? 'default', existingStateData, tokenEndpointResponse, {
      domain,
    });

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);
    await this.#transactionStore.delete(this.#transactionStoreIdentifier, storeOptions);

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

    if (!stateData) {
      return;
    }

    if (this.#isResolverMode()) {
      const isCurrentDomain = await this.#isSessionForCurrentDomain(stateData, storeOptions);
      if (!isCurrentDomain) {
        return;
      }
    }

    return stateData.user;
  }

  /**
   * Retrieve the user session from the store, or undefined if no session found.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @returns The session or undefined if no session found in the store.
   */
  public async getSession(storeOptions?: TStoreOptions): Promise<SessionData | undefined> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    if (stateData) {
      if (this.#isResolverMode()) {
        const isCurrentDomain = await this.#isSessionForCurrentDomain(stateData, storeOptions);
        if (!isCurrentDomain) {
          return;
        }
      }

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
   * @throws {TokenByRefreshTokenError} If the refresh token was not found or there was an issue requesting the access token. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`.
   *
   * @returns The Token Set, containing the access token, as well as additional information.
   */
  public async getAccessToken(storeOptions?: TStoreOptions): Promise<TokenSet> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const audience = this.#options.authorizationParams?.audience ?? 'default';
    const scope = this.#options.authorizationParams?.scope;

    const sessionDomain = stateData ? this.#getSessionDomain(stateData) : this.#staticDomain;
    if (this.#isResolverMode()) {
      if (!stateData) {
        throw new MissingSessionError('Unable to retrieve access token without a logged in user.');
      }
      if (!sessionDomain) {
        throw new MissingSessionError('Session domain does not match the current domain.');
      }
      const resolvedDomain = await this.#resolveDomain(storeOptions);
      if (sessionDomain !== resolvedDomain) {
        throw new MissingSessionError('Session domain does not match the current domain.');
      }
    }

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

    const domainForSession = sessionDomain!;
    const tokenEndpointResponse = await this.#getAuthClient(domainForSession).getTokenByRefreshToken({
      refreshToken: stateData.refreshToken,
    });
    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const updatedStateData = updateStateData(audience, existingStateData, tokenEndpointResponse, {
      domain: domainForSession,
    });

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
  public async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions,
    storeOptions?: TStoreOptions
  ): Promise<ConnectionTokenSet> {
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);

    const sessionDomain = stateData ? this.#getSessionDomain(stateData) : this.#staticDomain;
    if (this.#isResolverMode()) {
      if (!stateData) {
        throw new MissingSessionError('Unable to retrieve an access token for a connection without a logged in user.');
      }
      if (!sessionDomain) {
        throw new MissingSessionError('Session domain does not match the current domain.');
      }
      const resolvedDomain = await this.#resolveDomain(storeOptions);
      if (sessionDomain !== resolvedDomain) {
        throw new MissingSessionError('Session domain does not match the current domain.');
      }
    }

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

    const domainForSession = sessionDomain!;
    const tokenEndpointResponse = await this.#getAuthClient(domainForSession).getTokenForConnection({
      connection: options.connection,
      loginHint: options.loginHint,
      refreshToken: stateData.refreshToken,
    });

    const updatedStateData = updateStateDataForConnectionTokenSet(
      options,
      {
        ...stateData,
        domain: stateData.domain ?? domainForSession,
      },
      tokenEndpointResponse
    );

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
    if (!this.#isResolverMode()) {
      await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);
      return this.authClient.buildLogoutUrl(options);
    }

    const resolvedDomain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(resolvedDomain);
    const stateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const sessionDomain = stateData ? this.#getSessionDomain(stateData) : undefined;

    if (!stateData) {
      // No local session, still return a logout URL for the current domain.
      return authClient.buildLogoutUrl(options);
    }

    if (sessionDomain && sessionDomain === resolvedDomain) {
      await this.#stateStore.delete(this.#stateStoreIdentifier, storeOptions);
    }

    return authClient.buildLogoutUrl(options);
  }

  /**
   * Exchanges a custom token for Auth0 tokens and persists the resulting session (RFC 8693).
   *
   * Calls the token endpoint using the RFC 8693 Token Exchange grant, then stores the
   * resulting tokens in the StateStore — effectively logging the user in without an
   * interactive browser flow. Use this when the caller already holds a trusted external
   * token (e.g. a Google ID token, a legacy system token) and wants to establish an
   * Auth0 session from it.
   *
   * Requires a Token Exchange Profile configured in your Auth0 tenant.
   *
   * @param options Options for the custom token exchange, including the subject token and its type.
   * @param storeOptions Optional options passed to the StateStore.
   *
   * @throws {TokenExchangeError} If the exchange fails or the subject token is invalid.
   * @throws {MissingClientAuthError} If client credentials are not configured.
   *
   * @returns A promise resolving to an object containing `authorizationDetails` when RAR was used.
   */
  public async loginWithCustomTokenExchange(
    options: LoginWithCustomTokenExchangeOptions,
    storeOptions?: TStoreOptions
  ): Promise<LoginWithCustomTokenExchangeResult> {
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);
    const tokenEndpointResponse = await authClient.exchangeToken({
      ...options,
      scope: ensureOpenIdScope(options.scope),
    });

    const existingStateData = await this.#stateStore.get(this.#stateStoreIdentifier, storeOptions);
    const stateData = updateStateData(
      this.#options.authorizationParams?.audience ?? 'default',
      existingStateData,
      tokenEndpointResponse,
      { domain }
    );

    await this.#stateStore.set(this.#stateStoreIdentifier, stateData, true, storeOptions);

    return { authorizationDetails: tokenEndpointResponse.authorizationDetails };
  }

  /**
   * Exchanges a custom token for Auth0 tokens without establishing a session (RFC 8693).
   *
   * Performs the same RFC 8693 Token Exchange as `loginWithCustomTokenExchange` but
   * returns the raw token response without writing anything to the StateStore. Use this
   * for delegation or impersonation flows where you need downstream tokens but do not
   * want to create or modify the current user session.
   *
   * Requires a Token Exchange Profile configured in your Auth0 tenant.
   *
   * @param options Options for the custom token exchange, including the subject token and its type.
   * @param storeOptions Optional options passed to the StateStore (used only for domain resolution in resolver mode).
   *
   * @throws {TokenExchangeError} If the exchange fails or the subject token is invalid.
   * @throws {MissingClientAuthError} If client credentials are not configured.
   *
   * @returns A promise resolving to the token response from Auth0.
   */
  public async customTokenExchange(
    options: CustomTokenExchangeOptions,
    storeOptions?: TStoreOptions
  ): Promise<TokenResponse> {
    const domain = await this.#resolveDomain(storeOptions);
    const authClient = this.#getAuthClient(domain);
    return authClient.exchangeToken(options);
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

    if (!this.#isResolverMode()) {
      const logoutTokenClaims = await this.authClient.verifyLogoutToken({ logoutToken });
      await this.#stateStore.deleteByLogoutToken(logoutTokenClaims, storeOptions);
      return;
    }

    const issuer = decodeIssuer(logoutToken);
    if (!issuer) {
      throw new BackchannelLogoutError('Logout token is missing an issuer');
    }

    const resolvedDomain = await this.#resolveDomain(storeOptions);
    const domain = normalizeDomain(issuer);
    if (domain !== resolvedDomain) {
      throw new BackchannelLogoutError('Logout token issuer does not match the resolved domain');
    }

    const authClient = this.#getAuthClient(domain);
    const logoutTokenClaims = await authClient.verifyLogoutToken({ logoutToken });

    await this.#stateStore.deleteByLogoutToken({ ...logoutTokenClaims, iss: issuer }, storeOptions);
  }
}
