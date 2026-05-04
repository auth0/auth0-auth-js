import type { MfaApiErrorResponse } from '@auth0/auth0-auth-js';

/**
 * Error thrown when MFA verification fails.
 */
export class MfaVerifyError extends Error {
  public code: string = 'mfa_verify_error';
  public cause?: MfaApiErrorResponse;

  constructor(message: string, cause?: MfaApiErrorResponse) {
    super(message);
    this.name = 'MfaVerifyError';

    if (cause) {
      this.cause = {
        error: cause.error,
        error_description: cause.error_description,
        message: cause.message,
      };
    }
  }
}
