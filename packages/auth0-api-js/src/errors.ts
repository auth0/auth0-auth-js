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
 * Error thrown when a required argument is missing.
 */
export class MissingRequiredArgumentError extends Error {
  public code: string = 'missing_required_argument_error';

  constructor(argument: string) {
    super(`The argument '${argument}' is required but was not provided.`);
    this.name = 'MissingRequiredArgumentError';
  }
}