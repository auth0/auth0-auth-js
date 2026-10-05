import { extractHttpMetadata } from '../errors.js';
import type { MfaRequirements } from '../errors.js';

/**
 * Interface to represent a Passkey API error response.
 *
 * Optional HTTP metadata fields (`statusCode`, `headers`, `body`) may be supplied
 * so the thrown error can surface HTTP response context.
 */
export interface PasskeyApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
  /**
   * HTTP status code from the error response, when available.
   */
  statusCode?: number;
  /**
   * Response headers from the error response, when available. Native Fetch `Headers`.
   */
  headers?: Headers;
  /**
   * Raw response body text, when available.
   */
  body?: string;
}

/**
 * Passkey token exchange (`getTokenByPasskey`) error response.
 *
 * In addition to the common fields, an `mfa_required` response carries
 * `mfa_token` and `mfa_requirements` (mirroring {@link OAuth2Error}). Only the
 * token exchange can require MFA; the signup/login challenge requests cannot.
 * Use {@link isMfaRequiredError} to detect this case and continue with the MFA APIs.
 */
export interface PasskeyGetTokenApiErrorResponse extends PasskeyApiErrorResponse {
  mfa_token?: string;
  mfa_requirements?: MfaRequirements;
  /**
   * Identifiers that still require a valid OTP code. Present on retryable
   * `invalid_grant` (wrong code) and `invalid_request` (missing code) responses.
   * Absent on terminal failures.
   */
  verification_required?: string[];
  /**
   * The auth session token. Present when the session is still alive and the
   * caller may retry the token exchange with corrected OTP codes. Absent when
   * the session is terminal (exhausted, expired, or unknown).
   */
  auth_session?: string;
}

/**
 * Base class for Passkey-related errors (extends `Error`, not `ApiError`).
 * Optionally surfaces HTTP metadata (`statusCode`, `headers`, `body`) from the error response.
 */
export abstract class PasskeyError extends Error {
  public cause?: PasskeyApiErrorResponse;
  public code: string;
  /**
   * HTTP status code from the error response, when available.
   */
  public statusCode?: number;
  /**
   * Response headers from the error response, when available. Native Fetch `Headers`.
   */
  public headers?: Headers;
  /**
   * Raw response body text, when available.
   */
  public body?: string;

  constructor(code: string, message: string, cause?: PasskeyApiErrorResponse) {
    super(message);

    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
    };

    // Additive, non-breaking: surface HTTP metadata from the cause when present.
    const meta = extractHttpMetadata(cause);
    this.statusCode = meta.statusCode;
    this.headers = meta.headers;
    this.body = meta.body;
  }
}

/**
 * Error thrown when requesting a passkey register challenge fails.
 */
export class PasskeyRegisterError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_register_error', message, cause);
    this.name = 'PasskeyRegisterError';
  }
}

/**
 * Error thrown when requesting a passkey login challenge fails.
 */
export class PasskeyChallengeError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_challenge_error', message, cause);
    this.name = 'PasskeyChallengeError';
  }
}

/**
 * Error thrown when exchanging a passkey credential for tokens fails.
 *
 * Unlike the challenge errors, this carries `mfa_token` / `mfa_requirements` on
 * its `cause` when the server responds with `mfa_required`.
 *
 * When identifier verification is required, `isRetryable` indicates whether the
 * session is still alive. A retryable error means the caller should re-collect OTP
 * codes for the identifiers in `verificationRequired` and retry `getTokenByPasskey`
 * with the same credential and `authSession`. A non-retryable error means the session
 * is terminal and the caller must restart from `register()`.
 */
export class PasskeyGetTokenError extends PasskeyError {
  declare public cause?: PasskeyGetTokenApiErrorResponse;

  /**
   * `true` when the passkey session is still alive and the token exchange can be
   * retried with corrected OTP codes or after a transient server error.
   * `false` when the session is terminal (attempts exhausted, expired, or unknown).
   *
   * Branch on this field — never on HTTP status code or `error_description` text,
   * which are intentionally identical on retryable and terminal `invalid_grant` paths.
   */
  public readonly isRetryable: boolean;

  /**
   * Identifiers that still require a valid OTP code. Only present when `isRetryable`
   * is `true` and the failure was due to a wrong or missing OTP code.
   */
  public readonly verificationRequired?: string[];

  /**
   * The auth session token to use when retrying. Only present when `isRetryable`
   * is `true`.
   */
  public readonly authSession?: string;

  constructor(message: string, cause?: PasskeyGetTokenApiErrorResponse) {
    super('passkey_get_token_error', message, cause);
    this.name = 'PasskeyGetTokenError';

    // The base constructor intentionally drops `mfa_token` / `mfa_requirements`
    // (the challenge errors must not expose them). This error is the only one
    // that can carry them, so set the full cause here rather than relying on
    // the base's narrowed copy.
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
      mfa_token: cause.mfa_token,
      mfa_requirements: cause.mfa_requirements,
      verification_required: cause.verification_required,
      auth_session: cause.auth_session,
    };

    // A session is retryable when auth_session is present (wrong/missing OTP code)
    // or when the server returned a transient 5xx error.
    this.isRetryable =
      cause?.auth_session != null || cause?.error === 'server_error';
    this.verificationRequired = cause?.verification_required;
    this.authSession = cause?.auth_session;
  }
}
