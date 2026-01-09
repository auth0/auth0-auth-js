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
 * Represents an MFA authenticator enrolled by a user.
 */
export interface Authenticator {
  /** Unique identifier for the authenticator */
  id: string;
  /** Type of authenticator */
  authenticatorType: AuthenticatorType;
  /** Whether the authenticator is active */
  active: boolean;
  /** Optional friendly name */
  name?: string;
  /** ISO 8601 timestamp when created */
  createdAt?: string;
  /** ISO 8601 timestamp of last authentication */
  lastAuth?: string;
  /** Additional type information */
  type?: string;
}

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
  authenticatorTypes: ['otp'];
  /** MFA token from authentication response */
  mfaToken: string;
}

/**
 * Parameters for enrolling an out-of-band authenticator (SMS, Voice, Push).
 */
export interface EnrollOobParams {
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
 * Parameters for enrolling an email authenticator.
 * Refer - https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa/enroll-and-challenge-email-authenticators
 */
export interface EnrollEmailParams {
  /** Must be ['oob'] for email enrollment */
  authenticatorTypes: ['oob'],
  /** Must be ['email'] for email delivery channel */
  oobChannels: ['email'],
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
}

/**
 * Union type for all enrollment response types.
 * Note: Email enrollments return OobEnrollmentResponse with oobChannel: 'email'
 */
export type EnrollmentResponse =
  | OtpEnrollmentResponse
  | OobEnrollmentResponse;

/**
 * Parameters for initiating an MFA challenge.
 */
export interface ChallengeParams {
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
  created_at?: string;
  last_auth?: string;
  type?: string;
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
}

/**
 * @internal
 * Union type for all enrollment API response types.
 * Note: Email enrollments return OobEnrollmentApiResponse with oob_channel: 'email'
 */
export type EnrollmentApiResponse =
  | OtpEnrollmentApiResponse
  | OobEnrollmentApiResponse;

/**
 * @internal
 * API response from initiating an MFA challenge (snake_case).
 */
export interface ChallengeApiResponse {
  challenge_type: 'otp' | 'oob';
  oob_code?: string;
  binding_method?: string;
}

