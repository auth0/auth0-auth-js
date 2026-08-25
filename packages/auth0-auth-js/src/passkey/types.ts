import type { TokenResponse, RequestOptions, ApiResponse } from '../types.js';
import type { TelemetryConfig } from '../telemetry.js';

/**
 * Function signature for performing an OAuth grant request and returning a typed TokenResponse.
 * Injected by AuthClient to allow PasskeyClient to exchange credentials for tokens
 * via the token endpoint with proper client authentication and DPoP support.
 * Accepts per-request options so the token exchange can use a request-scoped fetch.
 * @internal
 */
export type GrantRequestFn = (
  grantType: string,
  params: URLSearchParams,
  requestOptions?: RequestOptions,
  capture?: boolean
) => Promise<TokenResponse | ApiResponse<TokenResponse>>;

/**
 * Configuration options for the Passkey client.
 */
export interface PasskeyClientOptions {
  /**
   * The Auth0 domain to use for passkey operations.
   * @example 'example.auth0.com' (without https://)
   */
  domain: string;
  /**
   * The client ID of the application.
   */
  clientId: string;
  /**
   * Client secret, used to authenticate confidential clients on `/passkey/register`
   * and `/passkey/challenge` via `client_secret_post`.
   *
   * Omitted for public clients (e.g. SPAs / native apps), which authenticate with
   * `client_id` alone. Ignored when {@link PasskeyClientOptions.useMtls} is set.
   */
  clientSecret?: string;
  /**
   * Whether the client authenticates with mTLS. When set, no body-level client
   * credential is sent, because Auth0 rejects a request that carries both a
   * certificate and a body credential. This takes precedence over
   * {@link PasskeyClientOptions.clientSecret}, which is not used when both are set.
   *
   * `/passkey/register` and `/passkey/challenge` are not served on the mTLS
   * endpoint aliases, so a client relying on mTLS has no credential for them and
   * is rejected once the certificate headers turn out to be absent. Only a
   * `clientSecret` authenticates a confidential client here.
   */
  useMtls?: boolean;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  /**
   * @internal
   * Telemetry config used to re-wrap a per-request `customFetch` so the
   * `Auth0-Client` header is preserved. Provided by `AuthClient`.
   */
  telemetryConfig?: TelemetryConfig;
  /**
   * Delegate function for performing OAuth grant requests via the token endpoint.
   * Provided by AuthClient to enable proper client authentication and DPoP support.
   * @internal
   */
  grantRequest: GrantRequestFn;
}

// ---------------------------------------------------------------------------
// Shared WebAuthn types
// ---------------------------------------------------------------------------

/**
 * Public key credential creation options returned by signup challenges.
 */
export interface PasskeyCreationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  authenticatorSelection?: {
    residentKey?: string;
    userVerification?: string;
  };
  timeout?: number;
}

/**
 * Public key credential request options returned by login challenges.
 */
export interface PasskeyRequestOptions {
  challenge: string;
  rpId: string;
  timeout?: number;
  userVerification?: string;
}

/**
 * Serialized credential response from the platform WebAuthn API.
 * All binary fields (rawId, clientDataJSON, etc.) must be base64url-encoded strings.
 */
export interface PasskeyCredentialResponse {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    signature?: string;
    userHandle?: string;
  };
  clientExtensionResults?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Authentication (Login & Signup) types
// ---------------------------------------------------------------------------

/**
 * Base fields shared by all signup challenge option variants.
 */
interface PasskeySignupChallengeBaseOptions {
  /** Display name for the user (optional) */
  name?: string;
  /** Given name / first name */
  givenName?: string;
  /** Family name / last name */
  familyName?: string;
  /** Nickname */
  nickname?: string;
  /** URL to the user's profile picture */
  picture?: string;
  /** Arbitrary user metadata (stored in `user_metadata` on the Auth0 user) */
  userMetadata?: Record<string, string>;
  /** Database connection name (sent as `realm` to the API) */
  realm?: string;
  /** Organization ID or name to associate the user with */
  organization?: string;
}

/**
 * Options for requesting a passkey signup challenge.
 *
 * At least one user identifier (`email`, `username`, or `phoneNumber`) must be provided.
 * Which identifiers are accepted depends on what is configured on your database connection.
 */
export type PasskeySignupChallengeOptions = PasskeySignupChallengeBaseOptions & (
  | { /** Email address — include if email is configured as an identifier */ email: string; phoneNumber?: string; username?: string }
  | { /** Phone number — if Flexible Identifiers is enabled */ phoneNumber: string; email?: string; username?: string }
  | { /** Username — if Flexible Identifiers is enabled */ username: string; email?: string; phoneNumber?: string }
);

/**
 * Response from a passkey signup challenge request.
 */
export interface PasskeySignupChallengeResponse {
  authSession: string;
  authnParamsPublicKey: PasskeyCreationOptions;
}

/**
 * Options for requesting a passkey login challenge.
 */
export interface PasskeyLoginChallengeOptions {
  /** Database connection name (sent as `realm` to the API) */
  realm?: string;
  /** Organization ID or name (scopes tokens to the organization context) */
  organization?: string;
}

/**
 * Response from a passkey login challenge request.
 */
export interface PasskeyLoginChallengeResponse {
  authSession: string;
  authnParamsPublicKey: PasskeyRequestOptions;
}

/**
 * Options for exchanging a passkey credential response for tokens.
 */
export interface GetTokenByPasskeyOptions {
  /** Auth session ID returned from a signup or login challenge */
  authSession: string;
  /** Serialized credential response from the platform WebAuthn API */
  credential: PasskeyCredentialResponse;
  /** Database connection name (sent as `realm` to the API) */
  realm?: string;
  /** Requested OAuth scopes (e.g. 'openid profile email') */
  scope?: string;
  /** Target API audience */
  audience?: string;
  /** Organization ID or name (scopes tokens to the organization context) */
  organization?: string;
}

// ---------------------------------------------------------------------------
// Internal API response types (match Auth0 API response shape)
// ---------------------------------------------------------------------------

/**
 * @internal
 */
export interface PasskeySignupChallengeApiResponse {
  auth_session: string;
  authn_params_public_key: {
    challenge: string;
    rp: { id: string; name: string };
    user: { id: string; name: string; displayName: string };
    pubKeyCredParams: Array<{ type: string; alg: number }>;
    authenticatorSelection?: {
      residentKey?: string;
      userVerification?: string;
    };
    timeout?: number;
  };
}

/**
 * @internal
 */
export interface PasskeyLoginChallengeApiResponse {
  auth_session: string;
  authn_params_public_key: {
    challenge: string;
    rpId: string;
    timeout?: number;
    userVerification?: string;
  };
}
