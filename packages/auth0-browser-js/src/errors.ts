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

/**
 * Error thrown when popup authentication times out.
 */
export class PopupTimeoutError extends Error {
  public code: string = 'popup_timeout_error';

  constructor(message?: string) {
    super(message ?? 'Popup timed out');
    this.name = 'PopupTimeoutError';
  }
}

/**
 * Error thrown when popup is closed by user before completing authentication.
 */
export class PopupCancelledError extends Error {
  public code: string = 'popup_cancelled_error';

  constructor() {
    super('Popup was closed by user');
    this.name = 'PopupCancelledError';
  }
}

/**
 * Error thrown when popup window fails to open.
 */
export class PopupOpenError extends Error {
  public code: string = 'popup_open_error';

  constructor(message?: string) {
    super(message ?? 'Failed to open popup window');
    this.name = 'PopupOpenError';
  }
}

/**
 * Error thrown when an operation times out.
 */
export class TimeoutError extends Error {
  public code: string = 'timeout_error';

  constructor(message: string) {
    super(message);
    this.name = 'TimeoutError';
  }
}
