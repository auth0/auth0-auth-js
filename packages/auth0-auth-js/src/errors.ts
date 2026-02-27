/**
 * Interface to represent an OAuth2 error.
 */
export interface OAuth2Error {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Error codes used for {@link NotSupportedError}
 */
export enum NotSupportedErrorCode {
  PAR_NOT_SUPPORTED = 'par_not_supported_error',
  MTLS_WITHOUT_CUSTOMFETCH_NOT_SUPPORT = 'mtls_without_custom_fetch_not_supported',
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

/**
 * Base class for API errors, containing the error, error_description and message (if available).
 */
abstract class ApiError extends Error {
  public cause?: OAuth2Error;
  public code: string;

  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);

    this.code = code;
    this.cause = cause && {
      error: cause.error,
      error_description: cause.error_description,
      message: cause.message,
    };
  }
}

/**
 * Error thrown when trying to get an access token.
 */
export class TokenByCodeError extends ApiError {
  constructor(message: string, cause?: OAuth2Error) {
    super('token_by_code_error', message, cause);
    this.name = 'TokenByCodeError';
  }
}

/**
 * Error thrown when trying to get an access token.
 */
export class TokenByClientCredentialsError extends ApiError {
  constructor(message: string, cause?: OAuth2Error) {
    super('token_by_client_credentials_error', message, cause);
    this.name = 'TokenByClientCredentialsError';
  }
}

/**
 * Error thrown when trying to get an access token.
 */
export class TokenByRefreshTokenError extends ApiError {
  constructor(message: string, cause?: OAuth2Error) {
    super('token_by_refresh_token_error', message, cause);
    this.name = 'TokenByRefreshTokenError';
  }
}

/**
 * Error thrown when trying to get an access token for a connection.
 *
 * @deprecated Since v1.2.0, using {@link AuthClient#getTokenForConnection} is deprecated and we recommend to use {@link AuthClient#exchangeToken}.
 * When doing so, use {@link TokenExchangeError} instead of {@link TokenForConnectionError}.
 * This error class remains for backward compatibility and is planned for removal in v2.0.
 */
export class TokenForConnectionError extends ApiError {
  constructor(message: string, cause?: OAuth2Error) {
    super('token_for_connection_error', message, cause);
    // NOTE: The name is 'TokenForConnectionErrorCode' (not 'TokenForConnectionError')
    // for backward compatibility. Consumers may branch on err.name in their error handling.
    this.name = 'TokenForConnectionErrorCode';
  }
}

/**
 * Error thrown when a Token Exchange flow fails. This can occur due to misconfiguration,
 * an invalid subject_token, or if the exchange is denied by the server.
 */
export class TokenExchangeError extends ApiError {
  constructor(message: string, cause?: OAuth2Error) {
    super('token_exchange_error', message, cause);
    this.name = 'TokenExchangeError';
  }
}

/**
 * Error thrown when verifying the logout token.
 */
export class VerifyLogoutTokenError extends Error {
  public code: string = 'verify_logout_token_error';

  constructor(message: string) {
    super(message);
    this.name = 'VerifyLogoutTokenError';
  }
}

/**
 * Error thrown when trying to use Client-Initiated Backchannel Authentication.
 */
export class BackchannelAuthenticationError extends ApiError {
  public code: string = 'backchannel_authentication_error';

  constructor(cause?: OAuth2Error) {
    super(
      'backchannel_authentication_error',
      'There was an error when trying to use Client-Initiated Backchannel Authentication.',
      cause
    );
    this.name = 'BackchannelAuthenticationError';
  }
}

/**
 * Error thrown when trying to build the authorization URL.
 */
export class BuildAuthorizationUrlError extends ApiError {
  constructor(cause?: OAuth2Error) {
    super('build_authorization_url_error', 'There was an error when trying to build the authorization URL.', cause);
    this.name = 'BuildAuthorizationUrlError';
  }
}

/**
 * Error thrown when trying to build the Link User URL.
 */
export class BuildLinkUserUrlError extends ApiError {
  constructor(cause?: OAuth2Error) {
    super('build_link_user_url_error', 'There was an error when trying to build the Link User URL.', cause);
    this.name = 'BuildLinkUserUrlError';
  }
}

/**
 * Error thrown when trying to build the Unlink User URL.
 */
export class BuildUnlinkUserUrlError extends ApiError {
  constructor(cause?: OAuth2Error) {
    super('build_unlink_user_url_error', 'There was an error when trying to build the Unlink User URL.', cause);
    this.name = 'BuildUnlinkUserUrlError';
  }
}

/**
 * Error thrown when Client Secret or Client Assertion Signing Key is missing.
 */
export class MissingClientAuthError extends Error {
  public code: string = 'missing_client_auth_error';

  constructor() {
    super('The client secret or client assertion signing key must be provided.');
    this.name = 'MissingClientAuthError';
  }
}
