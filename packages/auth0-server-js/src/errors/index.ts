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
