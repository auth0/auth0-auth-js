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
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
}

/**
 * Represents an MFA authenticator enrolled by a user.
 */
export interface Authenticator {
  /** Unique identifier for the authenticator */
  id: string;
  /** Type of authenticator */
  authenticator_type: AuthenticatorType;
  /** Whether the authenticator is active */
  active: boolean;
  /** Optional friendly name */
  name?: string;
  /** ISO 8601 timestamp when created */
  created_at?: string;
  /** ISO 8601 timestamp of last authentication */
  last_auth?: string;
}

/**
 * Supported authenticator types.
 */
export type AuthenticatorType = 'otp' | 'oob' | 'recovery-code' | 'email';

/**
 * Out-of-band delivery channels.
 */
export type OobChannel = 'sms' | 'voice' | 'auth0';

/**
 * Parameters for listing MFA authenticators.
 */
export interface ListAuthenticatorsParams {
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Parameters for deleting an MFA authenticator.
 */
export interface DeleteAuthenticatorParams {
  /** ID of the authenticator to delete */
  authenticatorId: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Parameters for enrolling an OTP authenticator (TOTP apps like Google Authenticator).
 * * Refer - https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa/enroll-and-challenge-otp-authenticators
 */
export interface EnrollOtpParams {
  /** Must be ['otp'] for OTP enrollment */
  authenticator_types: ['otp'];
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Parameters for enrolling an out-of-band authenticator (SMS, Voice, Push).
 */
export interface EnrollOobParams {
  /** Must be ['oob'] for OOB enrollment */
  authenticator_types: ['oob'];
  /** Delivery channels to enable */
  oob_channels: OobChannel[];
  /** Phone number for SMS/Voice (E.164 format: +1234567890) */
  phone_number?: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Parameters for enrolling an email authenticator.
 * Refer - https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa/enroll-and-challenge-email-authenticators
 */
export interface EnrollEmailParams {
  /** Must be ['oob'] for email enrollment */
  authenticator_types: ['oob'],
  /** Must be ['email'] for email delivery channel */
  oob_channels: ['email'],
  /** Email address (optional, uses user's email if not provided) */
  email?: string;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Union type for all enrollment parameter types.
 */
export type EnrollAuthenticatorParams =
  | EnrollOtpParams
  | EnrollOobParams
  | EnrollEmailParams;

/**
 * Response when enrolling an OTP authenticator.
 */
export interface OtpEnrollmentResponse {
  /** Authenticator type */
  authenticator_type: 'otp';
  /** Base32-encoded secret for TOTP generation */
  secret: string;
  /** URI for generating QR code (otpauth://...) */
  barcode_uri: string;
  /** Recovery codes for account recovery */
  recovery_codes?: string[];
  /** Authenticator ID */
  id?: string;
}

/**
 * Response when enrolling an OOB authenticator.
 */
export interface OobEnrollmentResponse {
  /** Authenticator type */
  authenticator_type: 'oob';
  /** Delivery channel used */
  oob_channel: OobChannel;
  /** Out-of-band code for verification */
  oob_code?: string;
  /** Binding method (e.g., 'prompt' for user code entry) */
  binding_method?: string;
  /** Authenticator ID */
  id?: string;
}

/**
 * Response when enrolling an email authenticator.
 */
export interface EmailEnrollmentResponse {
  /** Authenticator type */
  authenticator_type: 'email';
  /** Email address enrolled */
  email: string;
  /** Authenticator ID */
  id?: string;
}

/**
 * Union type for all enrollment response types.
 */
export type EnrollmentResponse =
  | OtpEnrollmentResponse
  | OobEnrollmentResponse
  | EmailEnrollmentResponse;

/**
 * Parameters for initiating an MFA challenge.
 */
export interface ChallengeParams {
  /** Type of challenge to initiate */
  challenge_type: 'otp' | 'oob';
  /** Specific authenticator to challenge (optional) */
  authenticator_id?: string;
  /** OOB channel to use if challenge_type is 'oob' */
  oob_channel?: OobChannel;
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Response from initiating an MFA challenge.
 */
export interface ChallengeResponse {
  /** Type of challenge created */
  challenge_type: 'otp' | 'oob';
  /** Out-of-band code (for OOB challenges) */
  oob_code?: string;
  /** Binding method for OOB (e.g., 'prompt') */
  binding_method?: string;
}

