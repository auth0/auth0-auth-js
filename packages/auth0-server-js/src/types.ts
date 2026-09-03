import type { ActClaim, AuthorizationDetails, DiscoveryCacheOptions, ExchangeProfileOptions, TelemetryConfig } from '@auth0/auth0-auth-js';
export type { ApiResponse, FullResponseOption } from '@auth0/auth0-auth-js';

export type {
  DiscoveryCacheOptions,
  PasskeySignupChallengeOptions as PasskeyRegisterOptions,
  PasskeySignupChallengeResponse as PasskeyRegisterResponse,
  PasskeyLoginChallengeOptions as PasskeyChallengeOptions,
  PasskeyLoginChallengeResponse as PasskeyChallengeResponse,
  PasskeyCredentialResponse,
  GetTokenByPasskeyOptions as PasskeyGetTokenOptions,
  PasskeyCreationOptions,
  PasskeyRequestOptions,
  SignUpOptions,
  ChangePasswordOptions,
  SignUpResult,
} from '@auth0/auth0-auth-js';

/**
 * Resolves the Auth0 custom domain at runtime using request-specific context.
 *
 * Should return a custom domain hostname (for example,
 * `brand-1.custom-domain.com`) without protocol.
 *
 * The resolver receives a context object from SDK method calls (typically
 * the same `storeOptions` object passed by the application).
 * Resolved custom domains must be trusted and must belong to the same Auth0 tenant.
 * Do not derive the returned domain directly from untrusted request input.
 *
 * The resolver must return a non-empty domain string. If it returns `null`,
 * `undefined`, or an empty string at runtime, the SDK throws
 * `InvalidConfigurationError`.
 */
export type DomainResolver<TStoreOptions> = (context?: TStoreOptions) => Promise<string> | string;

export type { TelemetryConfig } from '@auth0/auth0-auth-js';

export interface ServerClientOptions<TStoreOptions = unknown> {
  domain: string | DomainResolver<TStoreOptions>;
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  authorizationParams?: AuthorizationParameters;
  /**
   * Default organization for all interactive login flows from this client.
   * Can be an organization ID (e.g. `org_abc123`) or an organization name (e.g. `acme-corp`).
   * A per-login value in {@link StartInteractiveLoginOptions} overrides this.
   */
  organization?: string;
  discoveryCache?: DiscoveryCacheOptions;
  transactionIdentifier?: string;
  stateIdentifier?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  transactionStore: TransactionStore<TStoreOptions>;
  stateStore: StateStore<TStoreOptions>;

  /**
   * Indicates whether the SDK should use the mTLS endpoints if they are available.
   *
   * When set to `true`, using a `customFetch` is required.
   */
  useMtls?: boolean;

  /**
   * Optional telemetry configuration.
   * Telemetry is enabled by default and sends the Auth0-Client header with package name and version.
   */
  telemetry?: TelemetryConfig;
}

export interface UserClaims {
  sub: string;
  name?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  org_id?: string;
  org_name?: string;

  /**
   * The actor (`act`) claim, present when the session was established via impersonation
   * (e.g. Custom Token Exchange Session Transfer). Identifies the acting party — read it
   * to drive UI such as an impersonation banner.
   */
  act?: ActClaim;

  [key: string]: unknown;
}

export interface AuthorizationParameters {
  scope?: string;
  audience?: string;
  redirect_uri?: string;
  /**
   * The organization to log the user into. Prefer the first-class `organization`
   * option on {@link StartInteractiveLoginOptions} / {@link ServerClientOptions};
   * this is supported for backwards compatibility.
   */
  organization?: string;
  /**
   * Forces the user into a specific Experiment Center experiment variation for this
   * authorization request, bypassing the server-side deterministic assignment.
   * Requires `variation_id`.
   */
  experiment_id?: string;
  /**
   * The variation (arm) to assign the user to within the experiment for this
   * authorization request. Required when `experiment_id` is set.
   */
  variation_id?: string;
  /**
   * Scopes the experiment override to a specific segment for this authorization
   * request. Optional — only needed when the experiment uses segment targeting.
   */
  segment_id?: string;

  [key: string]: unknown;
}

export interface TokenSet {
  audience: string;
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
}

export interface ConnectionTokenSet {
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
  connection: string;
  loginHint?: string;
}

export interface InternalStateData {
  sid: string;
  createdAt: number;
}

export interface StateData extends SessionData {
  internal: InternalStateData;
}

export interface SessionData {
  user: UserClaims | undefined;
  idToken: string | undefined;
  refreshToken: string | undefined;
  tokenSets: TokenSet[];
  connectionTokenSets?: ConnectionTokenSet[];
  domain?: string;
  /**
   * IPSIE SL1 `session_expiry` ceiling for this session, as an absolute Unix timestamp in
   * seconds. Present only when the user logged in through an enterprise connection configured
   * with `id_token_session_expiry_supported: true`. When set, the SDK treats the session as
   * expired once this time is reached (minus a small leeway) and forces re-authentication.
   * Absent for database/social logins, connections without the option, and sessions created
   * before this feature — those behave unchanged.
   */
  sessionExpiresAt?: number;
  [key: string]: unknown;
}

export interface TransactionData {
  audience?: string;
  /**
   * PKCE code verifier for interactive (authorization-code) logins. Optional because
   * magic-link transactions are bound by anti-forgery `state` only and register no PKCE
   * challenge, so they persist no verifier.
   */
  codeVerifier?: string;
  domain?: string;
  /**
   * The organization requested at login, carried across the redirect so the
   * returned ID token's organization claim can be validated at callback.
   */
  organization?: string;
  [key: string]: unknown;
}

export interface AbstractDataStore<TData, TStoreOptions = unknown> {
  set(identifier: string, state: TData, removeIfExists?: boolean, options?: TStoreOptions): Promise<void>;

  get(identifier: string, options?: TStoreOptions): Promise<TData | undefined>;

  delete(identifier: string, options?: TStoreOptions): Promise<void>;
}

/**
 * Claims used to identify sessions for Backchannel Logout.
 *
 * `iss` is optional for backward compatibility, but is included by resolver-mode
 * implementations to disambiguate sessions across multiple issuers/domains.
 */
export type LogoutTokenClaims = { sub?: string; sid?: string; iss?: string };

export interface StateStore<TStoreOptions = unknown> extends AbstractDataStore<StateData, TStoreOptions> {
  deleteByLogoutToken(claims: LogoutTokenClaims, options?: TStoreOptions): Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface TransactionStore<TStoreOptions = unknown> extends AbstractDataStore<TransactionData, TStoreOptions> {}

export interface EncryptedStoreOptions {
  /**
   * The secret(s) to use for encryption and decryption. Can be a single string or an array of strings for secret rotation support.
   * When using an array of secrets, the first one is used for encryption, while all secrets are tried, in-order, for decryption.
   */
  secret: string | string[];
}

export interface StartInteractiveLoginOptions<TAppState = unknown> {
  pushedAuthorizationRequests?: boolean;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
  /**
   * The organization to log the user into. Overrides the client-level
   * `organization` default. Can be an organization ID (`org_abc123`) or name
   * (`acme-corp`). Also passable via `authorizationParams.organization`.
   */
  organization?: string;
  /**
   * The organization invitation ticket, when handling an invitation-acceptance flow.
   * Requires `organization` to be set (per-login, client-level default, or via
   * `authorizationParams`); providing `invitation` without an organization throws.
   */
  invitation?: string;
}

export interface LoginBackchannelOptions {
  bindingMessage: string;
  loginHint: {
    sub: string;
  };
  authorizationParams?: AuthorizationParameters;
}

export interface LoginBackchannelResult {
  authorizationDetails?: AuthorizationDetails[];
}

/**
 *  Result of completing a passkey authentication flow (signup or login).
 */
export interface PasskeyGetTokenResult {
  authorizationDetails?: AuthorizationDetails[];
}

/**
 * Options for starting an email passwordless flow by sending a one-time code (OTP).
 *
 * Complete it with {@link ServerClient#loginWithPasswordless}.
 */
export interface StartPasswordlessEmailCodeOptions {
  /** Discriminator: email connection. */
  connection: 'email';
  /** The destination email address. */
  email: string;
  /** Send a one-time code. Optional; this is the default for the email connection. */
  send?: 'code';
  /**
   * BCP-47 language tag forwarded as `x-request-language` to localize the email template.
   */
  language?: string;
}

/**
 * Options for starting an email passwordless magic-link flow.
 *
 * The SDK generates and persists an anti-forgery `state`, sends the link, and validates
 * `state` on the callback. No PKCE is used. Complete it with
 * {@link ServerClient#completePasswordlessMagicLink}.
 */
export interface StartPasswordlessEmailLinkOptions {
  /** Discriminator: email connection. */
  connection: 'email';
  /** The destination email address. */
  email: string;
  /** Send a magic link. Required literal to select link mode. */
  send: 'link';
  /**
   * The callback URL Auth0 redirects to after the magic link is clicked. Embedded in the link
   * as `redirect_uri`; must be registered on the application.
   */
  redirectUri: string;
  /**
   * Additional OAuth authorization parameters merged into the link. `client_id`, `response_type`,
   * and `state` are set by the SDK and cannot be overridden.
   */
  authParams?: Record<string, unknown>;
  /**
   * Scope for the resulting tokens. `openid` is ensured. Include `offline_access` for a refresh token.
   */
  scope?: string;
  /**
   * Audience for the resulting access token.
   */
  audience?: string;
  /**
   * BCP-47 language tag forwarded as `x-request-language` to localize the email template.
   */
  language?: string;
}

/**
 * Options for starting an SMS passwordless flow (one-time code only; SMS has no magic link).
 *
 * Complete it with {@link ServerClient#loginWithPasswordless}.
 */
export interface StartPasswordlessSmsOptions {
  /** Discriminator: sms connection. */
  connection: 'sms';
  /** Phone number in E.164 format, e.g. `+14155550100`. */
  phoneNumber: string;
  /**
   * BCP-47 language tag forwarded as `x-request-language` to localize the SMS template.
   */
  language?: string;
}

/**
 * Options for starting a passwordless flow. Discriminated on `connection` (and, for email,
 * on `send`) to mirror the `@auth0/nextjs-auth0` `passwordless.start()` surface.
 *
 * - `{ connection: 'email', send?: 'code' }` — email OTP (default)
 * - `{ connection: 'email', send: 'link', redirectUri }` — email magic link
 * - `{ connection: 'sms' }` — SMS OTP
 */
export type StartPasswordlessOptions =
  | StartPasswordlessEmailCodeOptions
  | StartPasswordlessEmailLinkOptions
  | StartPasswordlessSmsOptions;

/**
 * Options for completing an email passwordless OTP login and establishing a session.
 */
export interface CompletePasswordlessEmailOptions {
  /** Discriminator: email connection. */
  connection: 'email';
  /** The email address the code was sent to. */
  email: string;
  /** The one-time code entered by the user. */
  verificationCode: string;
  authorizationParams?: AuthorizationParameters;
}

/**
 * Options for completing an SMS passwordless OTP login and establishing a session.
 */
export interface CompletePasswordlessSmsOptions {
  /** Discriminator: sms connection. */
  connection: 'sms';
  /** The phone number the code was sent to, in E.164 format. */
  phoneNumber: string;
  /** The one-time code entered by the user. */
  verificationCode: string;
  authorizationParams?: AuthorizationParameters;
}

/**
 * Options for completing a passwordless OTP login. Discriminated on `connection` to mirror the
 * `@auth0/nextjs-auth0` `passwordless.verify()` surface.
 */
export type CompletePasswordlessOptions =
  | CompletePasswordlessEmailOptions
  | CompletePasswordlessSmsOptions;

/**
 * Result of a passwordless login (OTP or magic link). The session is persisted to the state
 * store; `authorizationDetails` is included when Rich Authorization Requests (RAR) were used.
 */
export interface CompletePasswordlessResult {
  authorizationDetails?: AuthorizationDetails[];
}

export interface AccessTokenForConnectionOptions {
  connection: string;
  loginHint?: string;
}

/**
 * Options for retrieving an access token with MRRT support.
 * Allows requesting tokens for specific audiences and scopes at runtime.
 */
export interface GetAccessTokenOptions {
  /**
   * Optional audience for the requested access token.
   * If not provided, falls back to configuration audience or 'default'.
   * @example 'https://api.example.com'
   */
  audience?: string;

  /**
   * Optional scope for the requested access token.
   * If not provided, falls back to configuration scope.
   * Space-separated scope string.
   * @example 'read:data write:data'
   */
  scope?: string;
}

export interface RevokeRefreshTokenOptions {
  /**
   * Explicitly provide a refresh token to revoke.
   * If omitted, the token stored in the current session is used.
   */
  token?: string;
}

export interface LogoutOptions {
  returnTo: string;
}

export interface StartLinkUserOptions<TAppState = unknown> {
  connection: string;
  connectionScope: string;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

export interface StartUnlinkUserOptions<TAppState = unknown> {
  connection: string;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

export interface SessionConfiguration {
  /**
   * A boolean indicating whether rolling sessions should be used or not.
   *
   * When enabled, the session will continue to be extended as long as it is used within the inactivity duration.
   * Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended.
   *
   * Default: `true`.
   */
  rolling?: boolean;
  /**
   * The absolute duration after which the session will expire. The value must be specified in seconds..
   *
   * Once the absolute duration has been reached, the session will no longer be extended.
   *
   * Default: 3 days.
   */
  absoluteDuration?: number;
  /**
   * The duration of inactivity after which the session will expire. The value must be specified in seconds.
   *
   * The session will be extended as long as it was active before the inactivity duration has been reached.
   *
   * Default: 1 day.
   */
  inactivityDuration?: number;

  /**
   * The options for the session cookie.
   */
  cookie?: SessionCookieOptions;
}

export interface SessionStore<TStoreOptions> {
  delete(identifier: string): Promise<void>;
  set(identifier: string, stateData: StateData): Promise<void>;
  get(identifier: string): Promise<StateData | undefined>;
  deleteByLogoutToken(claims: LogoutTokenClaims, options?: TStoreOptions | undefined): Promise<void>;
}

/**
 * Options for exchanging a custom token and persisting the resulting session (RFC 8693).
 *
 * Mirrors `ExchangeProfileOptions` from `auth0-auth-js`. The `audience` field is
 * also used to key the token set stored in the session.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8693 RFC 8693: OAuth 2.0 Token Exchange}
 */
export type LoginWithCustomTokenExchangeOptions = ExchangeProfileOptions;

/**
 * Options for performing a custom token exchange without any session side effects (RFC 8693).
 *
 * Use this when you need delegated tokens for downstream service calls but do not want
 * to establish a user session (e.g. impersonation, service-to-service delegation).
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8693 RFC 8693: OAuth 2.0 Token Exchange}
 */
export type CustomTokenExchangeOptions = ExchangeProfileOptions;

/**
 * Result of a successful custom token exchange with session persistence.
 */
export interface LoginWithCustomTokenExchangeResult {
  /**
   * Authorization details returned by the token endpoint when RAR was used.
   */
  authorizationDetails?: AuthorizationDetails[];
}

/**
 * An explicit actor (the acting party) for a Session Transfer Token request.
 *
 * Supplying this overrides the default behaviour of sourcing the actor from the
 * current agent session's ID token. The session is not read at all when this is
 * given, so it also works where there is no logged-in agent.
 */
export interface SessionTransferActor {
  /**
   * The actor token — for the default flow this is the agent's ID token.
   *
   * When {@link SessionTransferActor.type} is the ID token URN (the default), Auth0
   * validates this token and requires an unexpired, asymmetrically-signed Auth0 ID
   * token: signed with `RS256` or `PS256` (`HS256` is rejected, as it uses a shared
   * secret), carrying `sub`, `iss`, `exp` and `iat`, issued to the same client making
   * the exchange, and belonging to a user who still exists and is not blocked. A token
   * failing any of these fails the exchange with a `TokenExchangeError`.
   */
  token: string;
  /**
   * The actor token type URI. Defaults to the ID token URN when omitted
   * (`urn:ietf:params:oauth:token-type:id_token`).
   */
  type?: string;
}

/**
 * Options for requesting a Session Transfer Token (STT) for impersonation via
 * session transfer (Custom Token Exchange Release 2).
 *
 * The SDK fills in the protocol plumbing (audience, grant type, and the actor token
 * pair). The `subjectToken` is always developer-supplied — it is your own proof of
 * which customer to impersonate, validated only by your Action.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8693 RFC 8693: OAuth 2.0 Token Exchange}
 */
export interface RequestSessionTransferTokenOptions {
  /**
   * Your proof of which customer to impersonate — opaque to Auth0 and validated by
   * your Action (which then calls `setUserById`). The SDK never produces it.
   */
  subjectToken: string;
  /**
   * A URI identifying the type of the subject token, routing the request to your
   * Token Exchange Profile / Action.
   */
  subjectTokenType: string;
  /**
   * An explicit actor to override the default (the agent session's ID token).
   *
   * Resolution order: this explicit `actor` wins, and the session is not read at all;
   * otherwise the agent session's ID token is used (refreshed when expired); if neither
   * is available the request fails client-side with a `TokenExchangeError` whose code is
   * `actor_unavailable`, before any network call.
   */
  actor?: SessionTransferActor;
  /**
   * Space-separated list of OAuth 2.0 scopes to request for the session's tokens.
   */
  scope?: string;
  /**
   * The organization (ID or name) to mint the STT in the context of.
   *
   * Sending it here has the tenant validate the organization against the client's
   * organization settings while minting, so an organization the client is not allowed
   * to use fails at this call instead of the STT being issued without it.
   *
   * This is a separate parameter from {@link BuildSessionTransferRedirectOptions.organization},
   * which is forwarded to the target's `/authorize` on the redirect. They are sent on
   * different requests and neither implies the other. The one on the redirect is what
   * org-scopes the session the target establishes, so setting only this one validates the
   * organization without scoping that session.
   */
  organization?: string;
  /**
   * Additional custom parameters forwarded to the token endpoint (and thus to your
   * Action via `event.request.body`). Cannot override reserved OAuth parameters.
   */
  extra?: Record<string, string | string[]>;
}

/**
 * Options for {@link ServerClient.buildSessionTransferRedirect}.
 */
export interface BuildSessionTransferRedirectOptions {
  /**
   * The organization identifier to forward to the target's `/authorize` (as the
   * `organization` query parameter). Required only when the STT was issued in an
   * organization context.
   */
  organization?: string;
}

/**
 * The result of requesting a Session Transfer Token (STT) for impersonation via
 * session transfer (Custom Token Exchange).
 *
 * The STT is opaque, single-use, and short-lived (~60s). Hand it to
 * {@link ServerClient.buildSessionTransferRedirect} and do not decode, cache, or persist
 * it. The `act` claim is deliberately not on this result — it only appears on the tokens
 * of the session established after the STT is redeemed at `/authorize`.
 */
export interface SessionTransferTokenResult {
  /**
   * The opaque, single-use Session Transfer Token. Never decode, cache, or persist it.
   */
  sessionTransferToken: string;
  /**
   * The issued token type URI — the session-transfer URN
   * (`urn:auth0:params:oauth:token-type:session_transfer_token`). Branch on this,
   * never on {@link SessionTransferTokenResult.tokenType}.
   */
  issuedTokenType: string;
  /**
   * The token lifetime in seconds (typically ~60).
   */
  expiresIn: number;
  /**
   * The token type as returned by the server (typically `"N_A"`). Informational only —
   * never branch on it.
   */
  tokenType?: string;
  /**
   * The granted scopes, when returned by the server.
   */
  scope?: string;
}

export interface SessionCookieOptions {
  /**
   * The name of the session cookie.
   *
   * Default: `__a0_session`.
   */
  name?: string;
  /**
   * The sameSite attribute of the session cookie.
   *
   * Default: `lax`.
   */
  sameSite?: 'strict' | 'lax' | 'none';
  /**
   * The secure attribute of the session cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;

  /**
   * The path attribute of the session cookie.
   *
   * Default: `/`.
   *
   * @remarks
   * Changing the cookie path will cause existing cookies to behave differently:
   *
   * - If the cookie path is currently "/" (which is the default) and you change it to "/something", existing cookies (using "/" as the path) will be picked up when using "/something", but also for anything outside of "/something", additionally logout will not correctly delete the cookie.
   * - If the cookiepath is "/something" and you change it to "/", the existing cookie will not be picked up by anything other than "/something".
   *
   *  In general, changing the cookie path affects existing cookies and needs to be done with extra care around existing cookie implications.
   */
  path?: string;
}

// ApiResponse<T> and FullResponseOption are re-exported from @auth0/auth0-auth-js (see top of file).
// server-js uses the canonical definitions from auth-js rather than maintaining duplicates.
