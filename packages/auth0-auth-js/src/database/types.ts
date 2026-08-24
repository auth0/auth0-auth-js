import type { TelemetryConfig } from '../telemetry.js';

export interface DatabaseClientOptions {
  domain: string;
  clientId: string;
  customFetch?: typeof fetch;
  /**
   * @internal
   * Telemetry config used to re-wrap a per-request `customFetch` so the
   * `Auth0-Client` header is preserved. Provided by `AuthClient`.
   */
  telemetryConfig?: TelemetryConfig;
}

export interface SignUpOptions {
  email: string;
  password: string;
  connection: string;
  clientId?: string;
  username?: string;
  givenName?: string;
  familyName?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  // TODO(DEFER): phone_number — gated on `fuji_connection_attribute_configuration`
  // feature flag + connection attribute config (Flexible Identifiers). Not part of
  // the classic /dbconnections/signup contract; add when the gated path is GA.
  /**
   * Additional user metadata. Server constraints: values must be strings,
   * max 10 fields, field names ≤ 100 chars, values ≤ 500 chars, no dotted keys.
   */
  userMetadata?: Record<string, string>;
}

export interface ChangePasswordOptions {
  /** User's email. Provide `email` or `username`; at least one is required. Ignored server-side when both are sent. */
  email?: string;
  /** User's username, for username-only database connections. Provide `email` or `username`; at least one is required. */
  username?: string;
  connection: string;
  clientId?: string;
  organization?: string;
}

export interface SignUpResult {
  /** Normalized user identifier (from `id`, `_id`, or `user_id`). May be undefined when the server response omits an identifier. */
  id?: string;
  email: string;
  emailVerified: boolean;
  username?: string;
  givenName?: string;
  familyName?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  userMetadata?: Record<string, unknown>;
  /** Optional HTTP response metadata (status, headers). Present when available. */
  httpResponse?: import('../types.js').HttpResponseMetadata;
}
