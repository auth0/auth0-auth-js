/**
 * Configuration options for the AnonymousSessionClient.
 */
export interface AnonymousSessionClientOptions {
  /**
   * The Auth0 domain (without https://).
   * @example 'example.auth0.com'
   */
  domain: string;
  /**
   * The client ID of the application.
   */
  clientId: string;
  /**
   * The client secret. Used for `client_secret_post` authentication.
   */
  clientSecret?: string;
  /**
   * A private key (PEM string or `CryptoKey`) used to sign a client assertion
   * JWT for `private_key_jwt` authentication.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The algorithm used to sign the client assertion JWT.
   * Defaults to `'RS256'` when `clientAssertionSigningKey` is provided.
   */
  clientAssertionSigningAlg?: string;
  /**
   * Set to `true` when the client authenticates with a mutual TLS certificate.
   * No body-level credential is sent — the certificate handles authentication.
   */
  useMtls?: boolean;
  /**
   * Optional custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
}

/**
 * Represents an active anonymous session.
 *
 * Stores both the long-lived session token (used to re-mint access tokens)
 * and the current short-lived access token (used to call APIs).
 */
export interface AnonymousSession {
  /**
   * Long-lived handle for the anonymous identity.
   * Never sent to APIs directly. Used by the SDK to re-mint access tokens.
   */
  sessionToken: string;
  /**
   * Short-lived Bearer token for calling APIs.
   */
  accessToken: string;
  /**
   * Unix timestamp (seconds) at which the access token expires.
   */
  expiresAt: number;
  /**
   * Scopes granted to this anonymous session.
   */
  scope?: string;
}

/**
 * Tokens returned from the anonymous token endpoint.
 *
 * On session creation both `accessToken` and `sessionToken` are present.
 * On token renewal (re-mint) only `accessToken` is returned; the `sessionToken`
 * remains unchanged.
 */
export interface AnonymousTokens {
  /**
   * Short-lived Bearer token for calling APIs.
   */
  accessToken: string;
  /**
   * Number of seconds until the access token expires.
   */
  expiresIn: number;
  /**
   * Unix timestamp (seconds) at which the access token expires.
   */
  expiresAt: number;
  /**
   * Scopes granted to this token.
   */
  scope?: string;
  /**
   * Long-lived handle for the anonymous identity.
   * Only present when a new session is created (not on re-mint).
   */
  sessionToken?: string;
}

/**
 * Decoded claims from an anonymous session token (JWT).
 *
 * **Not returned by any method in EA.** In EA, session tokens are issued as
 * opaque JWEs — they cannot be decoded client-side and no SDK method currently
 * returns this type. It is exported for forward compatibility: if session tokens
 * move to a readable JWT format in a future release, this interface will describe
 * the claims shape without a breaking change.
 */
export interface AnonymousSessionClaims {
  /** Issuer of the token. */
  iss: string;
  /** Subject — the anonymous identity, e.g. `anon@abc123`. */
  sub: string;
  /** Unique identifier for the anonymous session. */
  session_id: string;
  /** Unix timestamp when the anonymous session was created. */
  created_at: number;
  /** Up to 1KB of key-value metadata set at session creation time. */
  metadata?: Record<string, unknown>;
}

/**
 * Options for creating a new anonymous session.
 *
 * Metadata is set once at creation time and cannot be changed afterwards.
 */
export interface CreateAnonymousSessionOptions {
  /**
   * The API audience the access token should be scoped to.
   * Must be a resource server that has `allow_anonymous_access` enabled.
   */
  audience?: string;
  /**
   * Space-separated list of scopes to request.
   */
  scope?: string;
  /**
   * Up to 1KB of arbitrary key-value metadata to attach to the anonymous session.
   * Set once at creation time — cannot be changed after the session is created.
   */
  metadata?: Record<string, unknown>;
}

/**
 * Options for silently obtaining a valid anonymous access token.
 */
export interface GetAnonymousTokenSilentlyOptions {
  /**
   * The session token from an existing anonymous session.
   * When provided, the SDK will re-mint the access token using the session token.
   * When omitted, a fresh anonymous session is created.
   */
  sessionToken?: string;
  /**
   * The API audience the access token should be scoped to.
   */
  audience?: string;
  /**
   * Space-separated list of scopes to request.
   */
  scope?: string;
}

// ─── Internal wire types (snake_case matching Auth0 API) ─────────────────────

/**
 * @internal
 * Raw response body from `POST /anonymous/token`.
 */
export interface AnonymousTokenApiResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  /** Only present on session creation, not on re-mint. */
  session_token?: string;
}

