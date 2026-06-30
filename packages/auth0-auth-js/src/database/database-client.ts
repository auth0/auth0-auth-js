import { SignUpError, ChangePasswordError } from './errors.js';
import type { DatabaseClientOptions, SignUpOptions, ChangePasswordOptions, SignUpResult } from './types.js';
import {
  requireFields, transformSignUpRequest, transformChangePasswordRequest,
  normalizeSignUpResult, parseErrorBody,
} from './utils.js';

export class DatabaseClient {
  #baseUrl: string;
  #clientId: string;
  #customFetch: typeof fetch;

  /** @internal */
  constructor(options: DatabaseClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#customFetch = options.customFetch ?? ((...args) => fetch(...args));
  }

  async signUp(options: SignUpOptions): Promise<SignUpResult> {
    requireFields(options, ['email', 'password', 'connection'], SignUpError);
    const body = { client_id: options.clientId ?? this.#clientId, ...transformSignUpRequest(options) };
    const response = await this.#post('/dbconnections/signup', body, SignUpError, 'Failed to sign up');
    const raw = (await response.json()) as Record<string, unknown>;
    return normalizeSignUpResult(raw);
  }

  async changePassword(options: ChangePasswordOptions): Promise<string> {
    requireFields(options, ['email', 'connection'], ChangePasswordError);
    const body = { client_id: options.clientId ?? this.#clientId, ...transformChangePasswordRequest(options) };
    const response = await this.#post(
      '/dbconnections/change_password', body, ChangePasswordError, 'Failed to request a password change'
    );
    return response.text();
  }

  async #post(
    path: string,
    body: Record<string, unknown>,
    ErrorClass: typeof SignUpError | typeof ChangePasswordError,
    failureMessage: string
  ): Promise<Response> {
    let response: Response;
    try {
      response = await this.#customFetch(`${this.#baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch {
      throw new ErrorClass(`${failureMessage}: a network error occurred.`);
    }
    if (response.ok) {
      return response;
    }
    const errorBody = await parseErrorBody(response);
    throw new ErrorClass(errorBody?.error_description || failureMessage, errorBody);
  }
}
