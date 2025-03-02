import { OAuth2Error } from '@auth0/auth0-auth-js';

export class MissingStateError extends Error {
  public code: string = 'missing_state_error';

  constructor(message?: string) {
    super(message ?? 'The state parameter is missing.');
    this.name = 'MissingStateError';
  }
}

export class InvalidStateError extends Error {
  public code: string = 'invalid_state_error';

  constructor(message?: string) {
    super(message ?? 'The state parameter is invalid.');
    this.name = 'InvalidStateError';
  }
}

export enum AccessTokenErrorCode {
  MISSING_SESSION = 'missing_session',
  MISSING_REFRESH_TOKEN = 'missing_refresh_token',
  FAILED_TO_REFRESH_TOKEN = 'failed_to_refresh_token',
  FAILED_TO_REQUEST_TOKEN = 'failed_to_request_token',
}

export class ApiError extends Error {
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

export enum AccessTokenForConnectionErrorCode {
  MISSING_REFRESH_TOKEN = 'missing_refresh_token',
  FAILED_TO_RETRIEVE = 'failed_to_retrieve',
}

export class AccessTokenForConnectionError extends ApiError {
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(code, message, cause);
    this.name = 'AccessTokenForConnectionError';
  }
}

export class MissingRequiredArgumentError extends Error {
  public code: string = 'missing_required_argument_error';

  constructor(argument: string) {
    super(`The argument '${argument}' is required but was not provided.`);
    this.name = 'MissingRequiredArgumentError';
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

export class BackchannelLogoutError extends Error {
  public code: string = 'backchannel_logout_error';

  constructor(message: string) {
    super(message);
    this.name = 'BackchannelLogoutError';
  }
}
