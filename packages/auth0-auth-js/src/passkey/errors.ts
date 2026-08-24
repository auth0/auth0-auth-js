import { extractHttpMetadata } from '../errors.js';
import type { MfaRequirements } from '../errors.js';

/**
 * Interface to represent a Passkey API error response.
 * Includes optional HTTP metadata fields (statusCode, headers, body).
 */
export interface PasskeyApiErrorResponse {
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
}

/**
 * Base class for Passkey-related errors (extends Error, not ApiError).
 * Captures optional HTTP metadata (status, headers, body) from error responses.
 */
export abstract class PasskeyError extends Error {
  public cause?: PasskeyApiErrorResponse;
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

  constructor(code: string, message: string, cause?: PasskeyApiErrorResponse) {
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
 */
export class PasskeyGetTokenError extends PasskeyError {
  declare public cause?: PasskeyGetTokenApiErrorResponse;

  constructor(message: string, cause?: PasskeyGetTokenApiErrorResponse) {
    super('passkey_get_token_error', message, cause);
    this.name = 'PasskeyGetTokenError';

    // The base constructor intentionally drops `mfa_token` / `mfa_requirements`
    // (the challenge errors must not expose them). This error is the only one
    // that can carry them, so set the full cause here rather than relying on
    // the base's narrowed copy.
    const fullCause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
      mfa_token: cause.mfa_token,
      mfa_requirements: cause.mfa_requirements,
    };
    this.cause = fullCause;

    // Extract HTTP metadata from full cause (same as base)
    const meta = extractHttpMetadata(cause);
    this.statusCode = meta.statusCode;
    this.headers = meta.headers;
    this.body = meta.body;
  }
}
