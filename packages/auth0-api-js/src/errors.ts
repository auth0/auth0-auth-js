/**
 * Error thrown when a required argument is missing.
 */
export class MissingRequiredArgumentError extends Error {
  public code: string = 'missing_required_argument_error';

  constructor(argument: string) {
    super(`The argument '${argument}' is required but was not provided.`);
    this.name = 'MissingRequiredArgumentError';
  }
}

/**
 * Error thrown when the SDK is misconfigured at instantiation time.
 */
export class InvalidConfigurationError extends Error {
  public code: string = 'invalid_configuration_error';
  constructor(message: string) {
    super(message);
    this.name = 'InvalidConfigurationError';
  }
}

/**
 * Base authentication error shape used across the SDK.
 */
export class AuthError extends Error {
  public code: string;
  public statusCode?: number;
  public headers?: Record<string, string | string[]>;
  public declare cause?: AuthErrorCause;

  constructor(message: string, code: string, statusCode?: number, headers?: Record<string, string | string[]>) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.headers = headers;
  }
}

export type AuthErrorCause = {
  code: string;
};

/**
 * Error thrown when the transaction is missing.
 */
export class MissingTransactionError extends AuthError {
  constructor(message?: string) {
    super(message ?? 'The transaction is missing.', 'missing_transaction_error');
  }
}

/**
 * Error thrown when verifying the access token.
 */
export class VerifyAccessTokenError extends AuthError {
  constructor(message: string, headers?: Record<string, string | string[]>) {
    super(message, 'verify_access_token_error', 401, headers);
  }
}

/**
 * Error thrown when the DPoP proof fails validation.
 */
export class InvalidDpopProofError extends AuthError {
  constructor(message = '', headers?: Record<string, string>) {
    super(message, 'invalid_dpop_proof', 400, headers);
  }
}

/**
 * Error thrown when request is missing a valid token or
 * multiple auth methods used
 */
export class InvalidRequestError extends AuthError {
  constructor(message: string, headers?: Record<string, string>) {
    super(message, 'invalid_request', 400, headers);
  }
}
