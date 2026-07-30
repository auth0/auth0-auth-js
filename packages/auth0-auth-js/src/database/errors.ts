import { extractHttpMetadata } from '../errors.js';

/** Wire format of an Auth0 Database API error response (snake_case fields as returned by `/dbconnections/*`).
 * Includes optional HTTP metadata fields (statusCode, headers, body).
 */
export interface DatabaseApiErrorResponse {
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
 * Base class for Database-related errors (extends Error, not ApiError).
 * Captures optional HTTP metadata (status, headers, body) from error responses.
 */
abstract class DatabaseError extends Error {
  public cause?: DatabaseApiErrorResponse;
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

  constructor(code: string, message: string, cause?: DatabaseApiErrorResponse) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
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
