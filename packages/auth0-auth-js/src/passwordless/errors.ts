import { extractHttpMetadata } from '../errors.js';
import type { OAuth2Error } from '../errors.js';

/**
 * Interface to represent a Passwordless API error response (wire format).
 * Includes optional HTTP metadata fields (statusCode, headers, body).
 */
export interface PasswordlessApiErrorResponse {
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
 * Base class for Passwordless-related errors (extends Error, not ApiError).
 * Captures optional HTTP metadata (status, headers, body) from error responses.
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

  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);

    // Restore the prototype chain so `instanceof` works when this class is
    // down-compiled to ES5 (Error breaks the chain under that target).
    Object.setPrototypeOf(this, new.target.prototype);

    this.code = code;
    // Only set cause if it has meaningful OAuth2Error fields (error or error_description)
    this.cause = cause && (cause.error || cause.error_description) ? {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
      mfa_token: cause.mfa_token,
      mfa_requirements: cause.mfa_requirements,
    } : undefined;

    // Extract HTTP metadata from cause (additive, non-breaking)
    const meta = extractHttpMetadata(cause);
    this.statusCode = meta.statusCode;
    this.headers = meta.headers;
    this.body = meta.body;
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
 * Error thrown when exchanging a database-connection OTP for tokens fails
 * (via `getTokenByPasswordlessDbConnection`): invalid/expired OTP, rate limiting,
 * a missing grant-request delegate, or a failed token exchange.
 *
 * This is distinct from {@link PasswordlessVerifyError} (the classic
 * email/SMS `verify()` flow) so callers can tell the two flows apart — mirroring
 * how the passkey SDK throws its own `PasskeyGetTokenError` for token exchange.
 *
 * A `403 mfa_required` response is surfaced as this error, carrying
 * `cause.error === 'mfa_required'` with the server's `mfa_token`. Narrow it with
 * `isMfaRequiredError` to drive the MFA challenge via `authClient.mfa`.
 */
export class PasswordlessDbGetTokenError extends PasswordlessError {
  // No manual `cause` re-copy needed: the base PasswordlessError constructor
  // already preserves `mfa_token`/`mfa_requirements` (unlike the passkey base,
  // which drops them and forces PasskeyGetTokenError to re-copy). Do not "align"
  // this with PasskeyGetTokenError by adding a cause override — it would be redundant.
  constructor(message: string, cause?: OAuth2Error) {
    super('passwordless_db_get_token_error', message, cause);
    this.name = 'PasswordlessDbGetTokenError';
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
 *
 * Note: The required ctor param `statusCode` and base optional field `statusCode?` align;
 * the param is authoritative when thrown, and the base field is set to the same value.
 */
export class PasswordlessChallengeError extends PasswordlessError {
  /**
   * HTTP status code of the failed response. Set to 0 for network errors.
   * This field is REQUIRED (set via ctor param); the base class optional `statusCode?`
   * is also set to this value for consistency.
   */
  public override statusCode: number;

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
