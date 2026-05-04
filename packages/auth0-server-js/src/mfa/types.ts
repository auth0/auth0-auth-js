import type { StateStore } from '../types.js';
import type { AuthClient } from '@auth0/auth0-auth-js';

/**
 * MFA factor types for verifying MFA challenges.
 */
export type MfaFactorType = 'otp' | 'oob' | 'recovery-code';

/**
 * Options for verifying an MFA challenge with an OTP code.
 */
export interface MfaVerifyOtpOptions {
  /** MFA token from authentication response */
  mfaToken: string;
  /** Must be the OTP factor type */
  factorType: 'otp';
  /** The OTP code from the user's authenticator app */
  otp: string;
  /** Optional audience for the requested access token */
  audience?: string;
}

/**
 * Options for verifying an MFA challenge with an out-of-band code.
 */
export interface MfaVerifyOobOptions {
  /** MFA token from authentication response */
  mfaToken: string;
  /** Must be the OOB factor type */
  factorType: 'oob';
  /** The out-of-band code received from the MFA challenge */
  oobCode: string;
  /** Optional binding code entered by the user (for prompt-based OOB) */
  bindingCode?: string;
  /** Optional audience for the requested access token */
  audience?: string;
}

/**
 * Options for verifying an MFA challenge with a recovery code.
 */
export interface MfaVerifyRecoveryCodeOptions {
  /** MFA token from authentication response */
  mfaToken: string;
  /** Must be the recovery-code factor type */
  factorType: 'recovery-code';
  /** The recovery code */
  recoveryCode: string;
  /** Optional audience for the requested access token */
  audience?: string;
}

/**
 * Union type for all MFA verify options.
 */
export type MfaVerifyOptions = MfaVerifyOtpOptions | MfaVerifyOobOptions | MfaVerifyRecoveryCodeOptions;

/**
 * Response from a successful MFA verification.
 */
export interface MfaVerifyResponse {
  /** The access token */
  accessToken: string;
  /** The ID token (if openid scope was requested) */
  idToken?: string;
  /** The refresh token (if offline_access scope was requested) */
  refreshToken?: string;
  /** The token type (typically "Bearer") */
  tokenType: string;
  /** Token expiration time in seconds */
  expiresIn: number;
  /** The granted scopes */
  scope?: string;
  /** A new recovery code (only returned when verifying with a recovery code) */
  recoveryCode?: string;
}

/**
 * @internal
 * Raw API response from the token endpoint for MFA verification.
 */
export interface MfaVerifyApiResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  recovery_code?: string;
}

/**
 * @internal
 * Options for constructing a ServerMfaClient.
 */
export interface ServerMfaClientOptions<TStoreOptions = unknown> {
  authClient: AuthClient;
  domain: string;
  clientId: string;
  clientSecret?: string;
  customFetch: typeof fetch;
  stateStore: StateStore<TStoreOptions>;
  stateStoreIdentifier: string;
  defaultAudience: string;
}
