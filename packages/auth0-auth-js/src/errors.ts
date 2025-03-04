/**
 * Interface to represent an OAuth2 error.
 */
export interface OAuth2Error {
  error: string;
  error_description: string;
}

export enum NotSupportedErrorCode {
  PAR_NOT_SUPPORTED = 'par_not_supported',
}

/**
 * Error thrown when a feature is not supported.
 * For example, when trying to use Pushed Authorization Requests (PAR) but the Auth0 tenant was not configured to support it.
 */
export class NotSupportedError extends Error {
  public code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'NotSupportedError';
    this.code = code;
  }
}

export enum AccessTokenForConnectionErrorCode {
  FAILED_TO_RETRIEVE = 'failed_to_retrieve',
}

class ApiError extends Error {
  public cause?: OAuth2Error;
  public code: string;

  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);

    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
    };
  }
}

export enum AccessTokenErrorCode {
  FAILED_TO_REFRESH_TOKEN = 'failed_to_refresh_token',
  FAILED_TO_REQUEST_TOKEN = 'failed_to_request_token',
}

export class AccessTokenError extends ApiError {
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(code, message, cause);
    this.name = 'AccessTokenError';
  }
}

/**
 * Error thrown when trying to get an access token for a connection.
 */
export class AccessTokenForConnectionError extends ApiError {
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(code, message, cause);
    this.name = 'AccessTokenForConnectionError';
  }
}

/**
 * Error thrown when trying to use backchannel logout.
 */
export class BackchannelLogoutError extends Error {
  public code: string = 'backchannel_logout_error';

  constructor(message: string) {
    super(message);
    this.name = 'BackchannelLogoutError';
  }
}

export class LoginBackchannelError extends ApiError {
  public code: string = 'login_backchannel_error';

  constructor(cause?: OAuth2Error) {
    super(
      'login_backchannel_error',
      'There was an error when trying to use Client-Initiated Backchannel Authentication. Check the server logs for more information.',
      cause
    );
    this.name = 'LoginBackchannelError';
  }
}

export class BuildAuthorizationUrlError extends ApiError {
  constructor(cause?: OAuth2Error) {
    super(
      'build_authorization_url_error',
      'There was an error when trying to build the authorization URL. Check the server logs for more information.',
      cause
    );
    this.name = 'BuildAuthorizationUrlError';
  }
}