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
abstract class PasskeyError extends Error {
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
 * Error thrown when requesting a passkey signup challenge fails.
 */
export class PasskeySignupChallengeError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_signup_challenge_error', message, cause);
    this.name = 'PasskeySignupChallengeError';
  }
}

/**
 * Error thrown when requesting a passkey login challenge fails.
 */
export class PasskeyLoginChallengeError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_login_challenge_error', message, cause);
    this.name = 'PasskeyLoginChallengeError';
  }
}

/**
 * Error thrown when exchanging a passkey credential for tokens fails.
 * Accepts both PasskeyApiErrorResponse and OAuth2Error (same shape) as the cause,
 * since this error is thrown from AuthClient's token exchange.
 */
export class PasskeySigninError extends PasskeyError {
  constructor(message: string, cause?: PasskeyApiErrorResponse) {
    super('passkey_signin_error', message, cause);
    this.name = 'PasskeySigninError';
  }
}
