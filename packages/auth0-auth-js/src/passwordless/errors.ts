import type { OAuth2Error } from '../errors.js';

/**
 * Interface to represent a Passwordless API error response (wire format).
 */
export interface PasswordlessApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Base class for Passwordless-related errors.
 *
 * Not exported: consumers branch on the concrete subclasses
 * ({@link PasswordlessStartError}, {@link PasswordlessVerifyError}) or on `err.code`.
 *
 * `cause` is typed as {@link OAuth2Error} so that a `403 mfa_required` token
 * response — carried on a {@link PasswordlessVerifyError} with `mfa_token` /
 * `mfa_requirements` — can be narrowed with `isMfaRequiredError`.
 */
abstract class PasswordlessError extends Error {
  public cause?: OAuth2Error;
  public code: string;

  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);

    // Restore the prototype chain so `instanceof` works when this class is
    // down-compiled to ES5 (Error breaks the chain under that target).
    Object.setPrototypeOf(this, new.target.prototype);

    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
      mfa_token: cause.mfa_token,
      mfa_requirements: cause.mfa_requirements,
    };
  }
}

/**
 * Error thrown when initiating a passwordless flow via `/passwordless/start` fails
 * (e.g. bad connection, invalid email/phone, sms provider error, rate limited).
 */
export class PasswordlessStartError extends PasswordlessError {
  constructor(message: string, cause?: OAuth2Error) {
    super('passwordless_start_error', message, cause);
    this.name = 'PasswordlessStartError';
  }
}

/**
 * Error thrown when exchanging a passwordless OTP code for a token fails
 * (e.g. invalid/expired code, too many requests).
 *
 * A `403 mfa_required` response is also surfaced as this error, carrying
 * `cause.error === 'mfa_required'` with the server's `mfa_token`. Narrow it with
 * `isMfaRequiredError` to drive the MFA challenge via `authClient.mfa`.
 */
export class PasswordlessVerifyError extends PasswordlessError {
  constructor(message: string, cause?: OAuth2Error) {
    super('passwordless_verify_error', message, cause);
    this.name = 'PasswordlessVerifyError';
  }
}

/**
 * Wire format for `/otp/challenge` error response with optional validation_errors.
 * @internal
 */
export interface ChallengeApiErrorResponse extends PasswordlessApiErrorResponse {
  validation_errors?: Array<{ field: string; message: string }>;
}

/**
 * Error thrown when an OTP challenge request fails.
 *
 * Extends the base PasswordlessError with HTTP status code and structured
 * field-level validation errors when present.
 *
 * Thrown by `challengeWithEmail` and `challengeWithPhoneNumber` on network
 * failures, server errors, or response validation failures.
 */
export class PasswordlessChallengeError extends PasswordlessError {
  /**
   * HTTP status code of the failed response. Set to 0 for network errors.
   */
  public statusCode: number;

  /**
   * Field-level validation errors from the server, if present in the response.
   * Format: `[{ field: string, message: string }, ...]`
   */
  public validationErrors?: Array<{ field: string; message: string }>;

  /**
   * Constructs a PasswordlessChallengeError.
   *
   * @param message - Human-readable error description
   * @param statusCode - HTTP response status, or 0 for network errors
   * @param cause - Optional structured error from server (OAuth2Error)
   * @param validationErrors - Optional field-level validation errors
   */
  constructor(
    message: string,
    statusCode: number,
    cause?: OAuth2Error,
    validationErrors?: Array<{ field: string; message: string }>
  ) {
    super('passwordless_challenge_error', message, cause);
    this.name = 'PasswordlessChallengeError';
    this.statusCode = statusCode;
    this.validationErrors = validationErrors;
  }
}
