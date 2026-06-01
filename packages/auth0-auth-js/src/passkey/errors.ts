/**
 * Interface to represent a Passkey API error response.
 */
export interface PasskeyApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Base class for Passkey-related errors.
 */
export abstract class PasskeyError extends Error {
  public cause?: PasskeyApiErrorResponse;
  public code: string;

  constructor(code: string, message: string, cause?: PasskeyApiErrorResponse) {
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
 * Error thrown when requesting a passkey register challenge fails.
 */
export class PasskeyRegisterError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_register_error', message, cause);
    this.name = 'PasskeyRegisterError';
  }
}

/**
 * Error thrown when requesting a passkey login challenge fails.
 */
export class PasskeyChallengeError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_challenge_error', message, cause);
    this.name = 'PasskeyChallengeError';
  }
}

/**
 * Error thrown when exchanging a passkey credential for tokens fails.
 */
export class PasskeyGetTokenError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_get_token_error', message, cause);
    this.name = 'PasskeyGetTokenError';
  }
}
