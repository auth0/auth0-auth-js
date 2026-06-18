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
