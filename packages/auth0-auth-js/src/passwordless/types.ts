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
}

/**
 * Options for sending a passwordless SMS (one-time code only; no magic link for SMS).
 */
export interface SendSmsOptions {
  /**
   * The destination phone number in E.164 format, e.g. `+14155550100`.
   */
  phoneNumber: string;
  // NOTE: no `deliveryMethod` — that belongs to the `/otp/challenge` DB-connection
  // endpoint (SDKREQ-315), not classic `/passwordless/start`. node-auth0 sends
  // `phone_number` + `connection` only.
}
