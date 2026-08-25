import { extractHttpMetadata } from '../errors.js';

/** Wire format of an Auth0 Database API error response (snake_case fields as returned by `/dbconnections/*`).
 *
 * Optional HTTP metadata fields (`statusCode`, `headers`, `body`) may be supplied
 * so the thrown error can surface HTTP response context.
 */
export interface DatabaseApiErrorResponse {
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
 * Base class for Database-related errors (extends `Error`, not `ApiError`).
 * Optionally surfaces HTTP metadata (`statusCode`, `headers`, `body`) from the error response.
 */
abstract class DatabaseError extends Error {
  public cause?: DatabaseApiErrorResponse;
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

  constructor(code: string, message: string, cause?: DatabaseApiErrorResponse) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
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

export class SignUpError extends DatabaseError {
  constructor(message: string, cause?: DatabaseApiErrorResponse) {
    super('signup_error', message, cause);
    this.name = 'SignUpError';
  }
}

export class ChangePasswordError extends DatabaseError {
  constructor(message: string, cause?: DatabaseApiErrorResponse) {
    super('change_password_error', message, cause);
    this.name = 'ChangePasswordError';
  }
}
