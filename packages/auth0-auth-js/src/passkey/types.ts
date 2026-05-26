import type { TokenResponse } from '../types.js';

/**
 * Function signature for performing an OAuth grant request and returning a typed TokenResponse.
 * Injected by AuthClient to allow PasskeyClient to exchange credentials for tokens
 * via the token endpoint with proper client authentication and DPoP support.
 * @internal
 */
export type GrantRequestFn = (grantType: string, params: URLSearchParams) => Promise<TokenResponse>;

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
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
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
  allowCredentials?: Array<{
    id: string;
    type: string;
    transports?: string[];
  }>;
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
  userMetadata?: Record<string, unknown>;
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
    allowCredentials?: Array<{
      id: string;
      type: string;
      transports?: string[];
    }>;
  };
}
