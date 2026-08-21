import type { ActClaim, AuthorizationDetails, DiscoveryCacheOptions, ExchangeProfileOptions, TelemetryConfig } from '@auth0/auth0-auth-js';

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
   * Identifier (and cookie name, for cookie-backed stores) used for the anonymous session.
   *
   * Default: `__a0_anon`. This is the SDK's own store on your application's domain. It is
   * unrelated to the `auth0_anon` cookie Auth0 sets on the Auth0 domain.
   */
  anonymousSessionIdentifier?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  transactionStore: TransactionStore<TStoreOptions>;
  stateStore: StateStore<TStoreOptions>;
  /**
   * Store for anonymous sessions. Required to use the `anonymous` sub-client; accessing
   * `serverClient.anonymous` without it throws `InvalidConfigurationError`.
   *
   * Pass a {@link StatelessAnonymousStore} for the cookie-backed default.
   */
  anonymousStore?: AnonymousStore<TStoreOptions>;

  /**
   * Whether the anonymous session is discarded once the visitor logs in. Default: `true`.
   *
   * An anonymous session holds a bearer credential for the anonymous identity that stays
   * valid for 30 days by default. Once the visitor has authenticated, that credential has
   * no purpose: leaving it behind keeps a cookie on every request and lets
   * `anonymous.getAccessToken()` keep minting anonymous tokens for someone who is logged
   * in. So every method that establishes a user session drops the anonymous session
   * afterwards.
   *
   * The drop is best-effort and happens after the user session is written, so it can never
   * fail a login.
   *
   * Set this to `false` when you need the anonymous identity on a later request — for
   * example to merge a guest cart in a background job — and call
   * `serverClient.anonymous.logout()` yourself once you are done with it. With the default
   * `true`, read `serverClient.anonymous.getSession()` **before** completing the login:
   *
   * ```typescript
   * const anonymousSession = await serverClient.anonymous.getSession(storeOptions);
   * await serverClient.completeInteractiveLogin(url, storeOptions);
   * if (anonymousSession?.sub) {
   *   await mergeGuestCart(anonymousSession.sub);
   * }
   * ```
   *
   * Has no effect when no `anonymousStore` is configured. `serverClient.logout()` clears the
   * anonymous session regardless of this setting; see {@link ServerClient.logout} for the one
   * resolver-mode exception.
   */
  clearAnonymousSessionOnLogin?: boolean;

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

/**
 * An anonymous access token as held in the anonymous store.
 *
 * `scope` is what Auth0 granted, exactly as for a user session. Auth0 is free to grant less
 * than was asked for: a scope an anonymous caller is not entitled to is dropped and the
 * response still comes back successfully, with a narrower `scope`. That is why the scope
 * asked for is recorded alongside it — a cache keyed only on the granted scope would never
 * match the request that produced it, so every call would mint a new token instead of
 * reusing the cached one.
 */
export interface AnonymousTokenSet extends TokenSet {
  /**
   * The scope that was requested when this token was minted, recorded only when Auth0
   * granted something else. Used to look the token up again; `scope` stays authoritative
   * for what the token actually carries.
   */
  requestedScope?: string;
}

/**
 * An anonymous session, as exposed to the application by
 * {@link ServerAnonymousClient.getSession}.
 *
 * Deliberately does NOT carry the anonymous session token. That token is a long-lived
 * bearer credential for the anonymous identity and is kept inside the SDK's anonymous
 * store, in the same way the refresh token of a user session is never handed to
 * application code by `getAccessToken()`.
 */
export interface AnonymousSessionData {
  /**
   * The anonymous identity, in the form `anon@<uuid>`. This is the `sub` claim of every
   * anonymous access token minted for this session, so it is the key to use for anything
   * you store for the visitor before they log in (a guest cart, for instance).
   *
   * Captured from the first anonymous access token at creation. `undefined` when that token
   * could not be read, which happens when the resource server has token encryption
   * (`token_encryption`) enabled: the access token is then an encrypted JWE and nothing
   * outside the API can read its claims. For such an audience the anonymous `sub` is not
   * obtainable through this SDK, so treat it as optional in any merge path.
   */
  sub?: string;
  /**
   * The metadata attached to the anonymous identity at creation, as it was sent to Auth0.
   *
   * Kept here so the application does not have to shadow what it just supplied. Metadata is
   * write-once, so this value cannot go stale.
   */
  metadata?: Record<string, string>;
  /**
   * Unix timestamp (seconds) at which this anonymous session was created by the SDK.
   *
   * The cookie lifetime is anchored to this value, so renewing an access token never
   * extends the anonymous session.
   */
  createdAt: number;
  /**
   * Unix timestamp (seconds) at which the anonymous session itself expires (30 days by
   * default, tenant-configurable).
   *
   * Currently always `undefined`: Auth0 returns the remaining session lifetime as
   * `session_expires_in` on every anonymous token response, but `@auth0/auth0-auth-js`
   * does not surface it yet. Until it does, the store falls back to a configured
   * lifetime measured from {@link AnonymousSessionData.createdAt}.
   */
  sessionTokenExpiresAt?: number;
  /**
   * Anonymous access tokens held for this session, cached per audience and requested scope.
   */
  tokenSets: AnonymousTokenSet[];
  /**
   * The Auth0 domain the anonymous session was created against. Used in resolver
   * (multi-tenant) mode to make sure a session is never reused across tenants.
   */
  domain?: string;
  [key: string]: unknown;
}

/**
 * The anonymous session as persisted by an {@link AnonymousStore}. Adds the session
 * token, which never leaves the SDK.
 */
export interface AnonymousStateData extends AnonymousSessionData {
  /**
   * The opaque handle for the anonymous identity, returned once by Auth0 at creation
   * and never reissued. Used to re-mint anonymous access tokens.
   */
  sessionToken: string;
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

/**
 * Store for anonymous sessions.
 *
 * Separate from the state store on purpose: an anonymous session is not a user session.
 * Writing one into the state store would make `getSession()` and `getUser()` return
 * something for a visitor who has not logged in, which every framework integration reads
 * as "authenticated".
 *
 * Use {@link StatelessAnonymousStore} for the cookie-backed default, or implement this
 * interface to keep anonymous sessions in your own backend.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface AnonymousStore<TStoreOptions = unknown>
  extends AbstractDataStore<AnonymousStateData, TStoreOptions> {}

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
