export interface DatabaseApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

abstract class DatabaseError extends Error {
  public cause?: DatabaseApiErrorResponse;
  public code: string;
  constructor(code: string, message: string, cause?: DatabaseApiErrorResponse) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.code = code;
    this.cause = cause;
  }
}

export class SignUpError extends DatabaseError {
  constructor(message: string, cause?: DatabaseApiErrorResponse) {
    super('signup_error', message, cause);
    this.name = 'SignUpError';
  }
}

export class ChangePasswordError extends DatabaseError {
  constructor(message: string, cause?: DatabaseApiErrorResponse) {
    super('change_password_error', message, cause);
    this.name = 'ChangePasswordError';
  }
}
