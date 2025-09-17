/**
 * Error thrown when the transaction is missing.
 */
export class MissingTransactionError extends Error {
  public code: string = 'missing_transaction_error';

  constructor(message?: string) {
    super(message ?? 'The transaction is missing.');
    this.name = 'MissingTransactionError';
  }
}

/**
 * Error thrown when verifying the access token.
 */
export class VerifyAccessTokenError extends Error {
  public code: string = 'verify_access_token_error';

  constructor(message: string) {
    super(message);
    this.name = 'VerifyAccessTokenError';
  }
}

/**
 * Error thrown when request is missing a valid token or
 * multiple auth methods used
 */
export class InvalidRequestError extends Error {
  public code: string = 'invalid_request';

  constructor(message: string) {
    super(message);
    this.name = 'InvalidRequestError';
  }
}

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
