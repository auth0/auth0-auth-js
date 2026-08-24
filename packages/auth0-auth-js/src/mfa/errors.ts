import { extractHttpMetadata } from '../errors.js';

/**
 * Interface to represent an MFA API error response.
 * Includes optional HTTP metadata fields (statusCode, headers, body).
 */
export interface MfaApiErrorResponse {
  error?: string;
  error_description?: string;
  message?: string;
  /**
   * HTTP status code from the error response (optional).
   */
  statusCode?: number;
  /**
   * Response headers from the error response (optional).
   */
  headers?: Headers;
  /**
   * Raw response body (optional).
   */
  body?: string;
}

/**
 * Base class for MFA-related errors (extends Error, not ApiError).
 * Captures optional HTTP metadata (status, headers, body) from error responses.
 */
abstract class MfaError extends Error {
  public cause?: MfaApiErrorResponse;
  public code: string;
  /**
   * HTTP status code from the error response (optional).
   */
  public statusCode?: number;
  /**
   * Response headers from the error response (optional).
   */
  public headers?: Headers;
  /**
   * Raw response body (optional).
   */
  public body?: string;

  constructor(code: string, message: string, cause?: MfaApiErrorResponse) {
    super(message);

    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
    };

    // Extract HTTP metadata from cause (additive, non-breaking)
    const meta = extractHttpMetadata(cause);
    this.statusCode = meta.statusCode;
    this.headers = meta.headers;
    this.body = meta.body;
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

/**
 * Error thrown when MFA verification fails (e.g., invalid OTP, invalid MFA token).
 */
export class MfaVerifyError extends MfaError {
  constructor(message: string, cause?: MfaApiErrorResponse) {
    super('mfa_verify_error', message, cause);
    this.name = 'MfaVerifyError';
  }
}
