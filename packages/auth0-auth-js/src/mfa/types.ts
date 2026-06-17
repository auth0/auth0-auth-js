import type { Configuration } from 'openid-client';

/**
 * Configuration options for the MFA client.
 */
export interface MfaClientOptions {
  /**
   * The Auth0 domain to use for MFA operations.
   * @example 'example.auth0.com' (without https://)
   */
  domain: string;
  /**
   * The client ID of the application.
   */
  clientId: string;
  /**
   * The client secret of the application (confidential clients only).
   * When provided, it is included in the challenge request body.
   */
  clientSecret?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  /**
   * @internal
   * Callback to retrieve the openid-client Configuration for token endpoint requests.
   */
  getConfiguration?: () => Promise<Configuration>;
}

/**
 * Supported authenticator types returned by Auth0 API.
 * Note: Email authenticators use 'oob' type with oob_channel: 'email'
 */
export type AuthenticatorType = 'otp' | 'oob' | 'recovery-code';

/**
 * Out-of-band delivery channels.
 * Includes 'email' which is also delivered out-of-band.
 */
export type OobChannel = 'sms' | 'voice' | 'auth0' | 'email';

/**
 * Challenge types derived from authenticator_type and oob_channel.
 */
export type ChallengeType = 'otp' | 'recovery-code' | 'phone' | 'push-notification' | 'email';

/**
 * Represents an MFA authenticator enrolled by a user.
 */
export interface AuthenticatorResponse {
  /** Unique identifier for the authenticator */
  id: string;
  /** Type of authenticator */
  authenticatorType: AuthenticatorType;
  /** Whether the authenticator is active */
  active: boolean;
  /** Optional friendly name */
  name?: string;
  /** Delivery channels for OOB authenticators (only present for authenticatorType: 'oob') */
  oobChannels?: OobChannel[];
  /** Challenge type derived from authenticator_type and oob_channel */
  type?: ChallengeType;
}

/**
 * Options for listing MFA authenticators.
 */
export interface ListAuthenticatorsOptions {
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Options for deleting an MFA authenticator.
 */
export interface DeleteAuthenticatorOptions {
  /** ID of the authenticator to delete */
  authenticatorId: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Options for enrolling an OTP authenticator (TOTP apps like Google Authenticator).
 * * Refer - https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa/enroll-and-challenge-otp-authenticators
 */
export interface EnrollOtpOptions {
  /** Must be ['otp'] for OTP enrollment */
  authenticatorTypes: ['otp'];
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Options for enrolling an out-of-band authenticator (SMS, Voice, Push).
 */
export interface EnrollOobOptions {
  /** Must be ['oob'] for OOB enrollment */
  authenticatorTypes: ['oob'];
  /** Delivery channels to enable */
  oobChannels: OobChannel[];
  /** Phone number for SMS/Voice (E.164 format: +1234567890) */
  phoneNumber?: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Options for enrolling an email authenticator.
 * Refer - https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa/enroll-and-challenge-email-authenticators
 */
export interface EnrollEmailOptions {
  /** Must be ['oob'] for email enrollment */
  authenticatorTypes: ['oob'];
  /** Must be ['email'] for email delivery channel */
  oobChannels: ['email'];
  /** Email address (optional, uses user's email if not provided) */
  email?: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Union type for all enrollment options types.
 */
export type EnrollAuthenticatorOptions = EnrollOtpOptions | EnrollOobOptions | EnrollEmailOptions;

/**
 * Response when enrolling an OTP authenticator.
 */
export interface OtpEnrollmentResponse {
  /** Authenticator type */
  authenticatorType: 'otp';
  /** Base32-encoded secret for TOTP generation */
  secret: string;
  /** URI for generating QR code (otpauth://...) */
  barcodeUri: string;
  /** Recovery codes for account recovery */
  recoveryCodes?: string[];
  /** Authenticator ID */
  id?: string;
}

/**
 * Response when enrolling an OOB authenticator.
 */
export interface OobEnrollmentResponse {
  /** Authenticator type */
  authenticatorType: 'oob';
  /** Delivery channel used */
  oobChannel: OobChannel;
  /** Out-of-band code for verification */
  oobCode?: string;
  /** Binding method (e.g., 'prompt' for user code entry) */
  bindingMethod?: string;
  /** Authenticator ID */
  id?: string;
  /** URI for generating QR code (otpauth://...) */
  barcodeUri?: string;
  /** Recovery codes for account recovery */
  recoveryCodes?: string[];
}

/**
 * Union type for all enrollment response types.
 * Note: Email enrollments return OobEnrollmentResponse with oobChannel: 'email'
 */
export type EnrollmentResponse = OtpEnrollmentResponse | OobEnrollmentResponse;

/**
 * Options for initiating an MFA challenge.
 */
export interface ChallengeOptions {
  /** Type of challenge to initiate */
  challengeType: 'otp' | 'oob';
  /** Specific authenticator to challenge (optional) */
  authenticatorId?: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Response from initiating an MFA challenge.
 */
export interface ChallengeResponse {
  /** Type of challenge created */
  challengeType: 'otp' | 'oob';
  /** Out-of-band code (for OOB challenges) */
  oobCode?: string;
  /** Binding method for OOB (e.g., 'prompt') */
  bindingMethod?: string;
}

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


// Internal API Response Types (snake_case - matches Auth0 API)
/**
 * @internal
 * Internal API response for an authenticator (snake_case).
 */
export interface AuthenticatorApiResponse {
  id: string;
  authenticator_type: AuthenticatorType;
  active: boolean;
  name?: string;
  oob_channels?: OobChannel[];
  oob_channel?: OobChannel;
}

/**
 * @internal
 * API response when enrolling an OTP authenticator (snake_case).
 */
export interface OtpEnrollmentApiResponse {
  authenticator_type: 'otp';
  secret: string;
  barcode_uri: string;
  recovery_codes?: string[];
  id?: string;
}

/**
 * @internal
 * API response when enrolling an OOB authenticator (snake_case).
 */
export interface OobEnrollmentApiResponse {
  authenticator_type: 'oob';
  oob_channel: OobChannel;
  oob_code?: string;
  binding_method?: string;
  id?: string;
  barcode_uri?: string;
  recovery_codes?: string[];
}

/**
 * @internal
 * Union type for all enrollment API response types.
 * Note: Email enrollments return OobEnrollmentApiResponse with oob_channel: 'email'
 */
export type EnrollmentApiResponse = OtpEnrollmentApiResponse | OobEnrollmentApiResponse;

/**
 * @internal
 * API response from initiating an MFA challenge (snake_case).
 */
export interface ChallengeApiResponse {
  challenge_type: 'otp' | 'oob';
  oob_code?: string;
  binding_method?: string;
}
