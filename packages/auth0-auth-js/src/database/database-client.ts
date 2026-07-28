import { SignUpError, ChangePasswordError } from './errors.js';
import type { DatabaseClientOptions, SignUpOptions, ChangePasswordOptions, SignUpResult } from './types.js';
import {
  requireFields, transformSignUpRequest, transformChangePasswordRequest,
  normalizeSignUpResult, parseErrorBody,
} from './utils.js';
import type { RequestOptions } from '../types.js';
import { composeRequestFetch } from '../request-fetch.js';
import { getTelemetryConfig, type TelemetryConfig } from '../telemetry.js';

export class DatabaseClient {
  #baseUrl: string;
  #clientId: string;
  #customFetch: typeof fetch;
  #telemetryConfig: TelemetryConfig;

  /** @internal */
  constructor(options: DatabaseClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#customFetch = options.customFetch ?? ((...args) => fetch(...args));
    this.#telemetryConfig = options.telemetryConfig ?? getTelemetryConfig();
  }

  async signUp(options: SignUpOptions, requestOptions?: RequestOptions): Promise<SignUpResult> {
    requireFields(options, ['email', 'password', 'connection'], SignUpError);
    const body = { client_id: options.clientId ?? this.#clientId, ...transformSignUpRequest(options) };
    const response = await this.#post('/dbconnections/signup', body, SignUpError, 'Failed to sign up', requestOptions);
    const raw = (await response.json()) as Record<string, unknown>;
    return normalizeSignUpResult(raw);
  }

  async changePassword(options: ChangePasswordOptions, requestOptions?: RequestOptions): Promise<string> {
    requireFields(options, ['connection'], ChangePasswordError);
    if (!options.email && !options.username) {
      throw new ChangePasswordError('Either "email" or "username" is required.');
    }
    const body = { client_id: options.clientId ?? this.#clientId, ...transformChangePasswordRequest(options) };
    const response = await this.#post(
      '/dbconnections/change_password', body, ChangePasswordError, 'Failed to request a password change', requestOptions
    );
    return response.text();
  }

  async #post(
    path: string,
    body: Record<string, unknown>,
    ErrorClass: typeof SignUpError | typeof ChangePasswordError,
    failureMessage: string,
    requestOptions?: RequestOptions
  ): Promise<Response> {
    const requestFetch = composeRequestFetch(this.#customFetch, requestOptions, this.#telemetryConfig);
    let response: Response;
    try {
      response = await requestFetch(`${this.#baseUrl}${path}`, {
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
