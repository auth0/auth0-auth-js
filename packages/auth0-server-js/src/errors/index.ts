export class ClientNotInitializedError extends Error {
  public code: string = 'client_not_initialized_error';

  constructor(message?: string) {
    super(message ?? 'The client was not initialized. Ensure to call `init()`.');

    this.name = 'ClientNotInitializedError';
  }
}

export class MissingStateError extends Error {
  public code: string = 'missing_state_error';

  constructor(message?: string) {
    super(message ?? 'The state parameter is missing.');
    this.name = 'MissingStateError';
  }
}

export class InvalidStateError extends Error {
  public code: string = 'invalid_state_error';

  constructor(message?: string) {
    super(message ?? 'The state parameter is invalid.');
    this.name = 'InvalidStateError';
  }
}

export enum AccessTokenErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",
  FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
}

export class AccessTokenError extends Error {
  public code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "AccessTokenError";
    this.code = code;
  }
}

export enum NotSupportedErrorCode {
  PAR_NOT_SUPPORTED = "par_not_supported",
}

export class NotSupportedError extends Error {
  public code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "NotSupportedError";
    this.code = code;
  }
}