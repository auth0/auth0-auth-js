/**
 * Shape of an error response from Auth0 anonymous session endpoints.
 */
export interface AnonymousSessionApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Error codes that can be set on an {@link AnonymousSessionError}.
 *
 * Codes that map directly to Auth0 API error responses:
 * - `session_expired` — The session token has expired.
 * - `invalid_session_token` — The session token is malformed.
 * - `metadata_too_large` — The metadata payload at session creation exceeded 1 KB.
 * - `unauthorized_client` — The client ID is not enabled for anonymous sessions.
 * - `feature_not_enabled` — The tenant-level anonymous sessions flag is off.
 * - `invalid_client` — Client authentication failed.
 * - `invalid_target` — The resource server is not enabled for anonymous access.
 * - `invalid_request` — The request was malformed or the resource server is not enabled.
 * - `invalid_scope` — The requested scope is not granted to anonymous callers.
 * - `server_error` — An Auth0 infrastructure error occurred.
 */
export type AnonymousSessionErrorCode =
  | 'session_expired'
  | 'invalid_session_token'
  | 'metadata_too_large'
  | 'unauthorized_client'
  | 'feature_not_enabled'
  | 'invalid_client'
  | 'invalid_target'
  | 'invalid_request'
  | 'invalid_scope'
  | 'server_error'
  | string;

/**
 * Error thrown when an anonymous session operation fails.
 *
 * The `code` field identifies the specific failure reason. Codes `session_expired`
 * and `invalid_session_token` are handled silently by {@link AnonymousSessionClient.getTokenSilently}
 * and will never reach the caller from that method. All other codes are surfaced directly.
 */
export class AnonymousSessionError extends Error {
  /**
   * Machine-readable error code identifying the failure reason.
   * Maps to the `error` field in the Auth0 API response.
   */
  public code: AnonymousSessionErrorCode;
  /**
   * The raw error response from Auth0, if available.
   */
  public cause?: AnonymousSessionApiErrorResponse;

  constructor(code: AnonymousSessionErrorCode, message: string, cause?: AnonymousSessionApiErrorResponse) {
    super(message);
    this.name = 'AnonymousSessionError';
    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
    };
  }
}
