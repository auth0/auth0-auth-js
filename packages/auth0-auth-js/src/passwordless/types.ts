import type { TokenResponse } from '../types.js';

/**
 * Function signature for performing an OAuth grant request and returning a typed TokenResponse.
 * Injected by AuthClient to allow PasswordlessClient to exchange an OTP for tokens via the
 * token endpoint with proper client authentication and DPoP support (handled at the
 * `openid-client` configuration layer).
 * @internal
 */
export type GrantRequestFn = (grantType: string, params: URLSearchParams) => Promise<TokenResponse>;

/**
 * Constructor options for the {@link PasswordlessClient} sub-client.
 *
 * Superset of the MFA sub-client options: `/passwordless/start` requires client
 * authentication on the request body (FR-1c), so the client-auth fields are
 * bundled here. Mirrors the auth method resolution used by `AuthClient`.
 */
export interface PasswordlessClientOptions {
  /**
   * The Auth0 domain, e.g. `tenant.auth0.com`.
   */
  domain: string;
  /**
   * The Auth0 client ID.
   */
  clientId: string;
  /**
   * Optional custom fetch implementation (typically telemetry-wrapped by AuthClient).
   */
  customFetch?: typeof fetch;
  /**
   * Client secret, for `client_secret_post` body authentication.
   */
  clientSecret?: string;
  /**
   * Private key (PEM string or `CryptoKey`) for `private_key_jwt` (`client_assertion`).
   */
  clientAssertionSigningKey?: CryptoKey | string;
  /**
   * JWT signing algorithm for `client_assertion`. Defaults to `RS256`.
   */
  clientAssertionSigningAlg?: string;
  /**
   * When using mTLS, no body-level client authentication is added (the certificate
   * is supplied by the custom fetch implementation).
   */
  useMtls?: boolean;
  /**
   * Delegate function for performing the OTP token exchange via the token endpoint.
   * Provided by AuthClient so the exchange runs through `openid-client`'s discovered
   * configuration (centralized client authentication and DPoP support).
   * @internal
   */
  grantRequest: GrantRequestFn;
}

/**
 * Options for sending a passwordless email.
 *
 * Discriminated union on `send`:
 * - omit `send` (or pass `send: 'code'`) to send a one-time code (OTP) — the default.
 * - pass `send: 'link'` to send a magic link; `authParams` carries the OAuth params
 *   (`redirect_uri`, `response_type`, `scope`, `state`) used when the link is followed.
 */
export type SendEmailOptions = SendEmailCodeOptions | SendEmailLinkOptions;

/**
 * Options for sending a one-time code (OTP) by email. This is the default `send` mode.
 */
export interface SendEmailCodeOptions {
  /**
   * The destination email address.
   */
  email: string;
  /**
   * Send a one-time code. Optional; this is the default when `send` is omitted.
   * To send a magic link instead, use {@link SendEmailLinkOptions} (`send: 'link'`).
   */
  send?: 'code';
  /**
   * Not applicable in code mode. `authParams` is only honored for magic links
   * ({@link SendEmailLinkOptions}); declared here as `never` so passing it with a
   * code is a compile-time error rather than a silently-ignored field.
   */
  authParams?: never;
  /**
   * Optional BCP-47 language tag (e.g. `fr-CA`) sent as the `x-request-language`
   * HTTP header to localize the email template. Not part of the request body.
   */
  language?: string;
}

/**
 * Options for sending a magic link by email.
 */
export interface SendEmailLinkOptions {
  /**
   * The destination email address.
   */
  email: string;
  /**
   * Send a magic link. Required literal to select link mode.
   */
  send: 'link';
  /**
   * OAuth authorization parameters forwarded verbatim to the authorize step that
   * the magic link triggers, e.g. `{ redirect_uri, response_type, scope, state }`.
   *
   * The caller owns `state` (per OQ-7). These are sent under the `authParams` key
   * in camelCase on the wire (the sole field that bypasses snake_case) to match
   * node-auth0 and the shipped nextjs-auth0 behavior.
   */
  authParams?: Record<string, unknown>;
  /**
   * Optional BCP-47 language tag (e.g. `fr-CA`) sent as the `x-request-language`
   * HTTP header to localize the email template. Not part of the request body.
   */
  language?: string;
}

/**
 * Options for sending a passwordless SMS (one-time code only; no magic link for SMS).
 */
export interface SendSmsOptions {
  /**
   * The destination phone number in E.164 format, e.g. `+14155550100`.
   */
  phoneNumber: string;
  /**
   * Optional BCP-47 language tag (e.g. `fr-CA`) sent as the `x-request-language`
   * HTTP header to localize the SMS template. Not part of the request body.
   */
  language?: string;
  // NOTE: no `deliveryMethod` — that belongs to the `/otp/challenge` DB-connection
  // endpoint (SDKREQ-315), not classic `/passwordless/start`. node-auth0 sends
  // `phone_number` + `connection` only.
}

/**
 * Options for email OTP challenge against a database connection.
 *
 * Initiates a challenge for a database connection configured with `email_otp`.
 * The challenge returns an opaque `auth_session` token for subsequent OTP verification.
 */
export interface ChallengeWithEmailOptions {
  /**
   * The destination email address. Required.
   */
  email: string;

  /**
   * Auth0 database connection name. Required.
   */
  connection: string;

  /**
   * Allow automatic user signup if the email does not exist.
   * Defaults to false. Maps to wire `allow_signup`.
   */
  allowSignup?: boolean;
}

/**
 * Options for phone OTP challenge against a database connection.
 *
 * Initiates a challenge for a database connection configured with `phone_otp`.
 * The challenge returns an opaque `auth_session` token for subsequent OTP verification.
 */
export interface ChallengeWithPhoneNumberOptions {
  /**
   * The destination phone number in E.164 format (e.g. `+14155550100`). Required.
   * Validation occurs before any network call. Invalid format throws synchronously.
   */
  phoneNumber: string;

  /**
   * Auth0 database connection name. Required.
   */
  connection: string;

  /**
   * Delivery channel for the OTP. Either 'text' (SMS) or 'voice' (call).
   * Defaults to 'text'. Only applicable when the connection supports multiple media.
   * Maps to wire `delivery_method`.
   */
  deliveryMethod?: 'text' | 'voice';

  /**
   * Allow automatic user signup if the phone number does not exist.
   * Defaults to false. Maps to wire `allow_signup`.
   */
  allowSignup?: boolean;
}

/**
 * Represents a successful OTP challenge response.
 *
 * The `authSession` is an opaque token that must be passed to the subsequent
 * token exchange ({@link TokenByPasswordlessDbConnectionOptions}). Never parse,
 * decode, log, or inspect it.
 */
export interface PasswordlessChallenge {
  /**
   * Opaque Auth0 server-issued session token bound to the challenge intent
   * (login or signup). Must be passed to the subsequent token-exchange call.
   *
   * This token is completely opaque: never parse, decode, log, or inspect it.
   * Its format and internal structure are subject to change without notice.
   */
  authSession: string;
}

/**
 * Options for exchanging a passwordless OTP (against a database connection) for tokens.
 *
 * Completes the embedded DB-connection flow: pass the opaque `authSession` from
 * {@link ChallengeWithEmailOptions}/{@link ChallengeWithPhoneNumberOptions} together
 * with the user-entered `otp`. Sent to `/oauth/token` with grant type
 * `http://auth0.com/oauth/grant-type/passwordless/otp`.
 */
export interface TokenByPasswordlessDbConnectionOptions {
  /**
   * The opaque `authSession` returned by a prior challenge call. Never parsed or logged.
   */
  authSession: string;
  /**
   * The one-time code entered by the user.
   */
  otp: string;
  /**
   * The scope for which the token should be requested.
   *
   * Optional and never injected at this layer: include `openid` to receive an id_token,
   * and `offline_access` to receive a refresh_token.
   */
  scope?: string;
  /**
   * The audience for which the token should be requested.
   */
  audience?: string;
}
