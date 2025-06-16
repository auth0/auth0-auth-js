/**
 * Error thrown when there is no transaction available.
 */
export class MissingTransactionError extends Error {
  public code: string = 'missing_transaction_error';

  constructor(message?: string) {
    super(message ?? 'The transaction is missing.');
    this.name = 'MissingTransactionError';
  }
}


/**
 * Error thrown when backchannel logout fails.
 */
export class BackchannelLogoutError extends Error {
  public code: string = 'backchannel_logout_error';

  constructor(message: string) {
    super(message);
    this.name = 'BackchannelLogoutError';
  }
}

/**
 * Error thrown when starting the user-linking failed.
 */
export class StartLinkUserError extends Error {
  public code: string = 'start_link_user_error';

  constructor(message: string) {
    super(message);
    this.name = 'StartLinkUserError';
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

/**
 * Error thrown when a session is missing.
 */
export class MissingSessionError extends Error {
  public code: string = 'missing_session_error';

  constructor(message: string) {
    super(message);
    this.name = 'MissingSessionError';
  }
}