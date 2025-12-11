/**
 * Interface to represent an MFA API error response.
 */
export interface MfaApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Base class for MFA-related errors.
 */
abstract class MfaError extends Error {
  public cause?: MfaApiErrorResponse;
  public code: string;

  constructor(code: string, message: string, cause?: MfaApiErrorResponse) {
    super(message);

    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
    };
  }
}

/**
 * Error thrown when listing authenticators fails.
 */
export class MfaListAuthenticatorsError extends MfaError {
  constructor(message: string, cause?: MfaApiErrorResponse) {
    super('mfa_list_authenticators_error', message, cause);
    this.name = 'MfaListAuthenticatorsError';
  }
}

/**
 * Error thrown when enrolling an authenticator fails.
 */
export class MfaEnrollmentError extends MfaError {
  constructor(message: string, cause?: MfaApiErrorResponse) {
    super('mfa_enrollment_error', message, cause);
    this.name = 'MfaEnrollmentError';
  }
}

/**
 * Error thrown when deleting an authenticator fails.
 */
export class MfaDeleteAuthenticatorError extends MfaError {
  constructor(message: string, cause?: MfaApiErrorResponse) {
    super('mfa_delete_authenticator_error', message, cause);
    this.name = 'MfaDeleteAuthenticatorError';
  }
}

/**
 * Error thrown when initiating an MFA challenge fails.
 */
export class MfaChallengeError extends MfaError {
  constructor(message: string, cause?: MfaApiErrorResponse) {
    super('mfa_challenge_error', message, cause);
    this.name = 'MfaChallengeError';
  }
}

