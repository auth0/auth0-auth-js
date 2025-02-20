export class ClientNotInitializedError extends Error {
  public code: string = 'client_not_initialized_error';

  constructor(message?: string) {
    super(message ?? 'The client was not initialized. Ensure to call `init()`.');

    this.name = 'ClientNotInitializedError';
  }
}
