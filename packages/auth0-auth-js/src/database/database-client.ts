import { SignUpError, ChangePasswordError } from './errors.js';
import type { DatabaseClientOptions, SignUpOptions, ChangePasswordOptions, SignUpResult } from './types.js';
import {
  requireFields, transformSignUpRequest, transformChangePasswordRequest,
  normalizeSignUpResult, parseErrorBody,
} from './utils.js';
import type { RequestOptions, ApiResponse, FullResponseOption } from '../types.js';
import { composeRequestFetch } from '../request-fetch.js';
import { getTelemetryConfig, type TelemetryConfig } from '../telemetry.js';
import { filterSensitiveHeaders } from '../utils.js';

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

  /**
   * Registers a new user on a database connection via `POST /dbconnections/signup`.
   *
   * The endpoint is public: only `clientId` is sent in the request body, never a client
   * secret or assertion, so both public and confidential clients work. The result is
   * normalized to camelCase, with `id` resolved from whichever identifier the server
   * returns (`id`, `_id`, or `user_id`).
   *
   * @param options - Sign-up options. `email`, `password`, and `connection` are required.
   *   Pass `fullResponse: true` to receive an {@link ApiResponse} envelope containing the
   *   parsed result alongside the raw HTTP {@link Response}.
   * @param requestOptions - Optional per-request options (abort signal, extra headers, one-off fetch).
   * @throws {SignUpError} When required fields are missing, the request fails, or the server
   *   returns a non-2xx response. On an HTTP failure the error carries `statusCode`, `headers`, and `body`.
   * @returns The normalized {@link SignUpResult}, or an {@link ApiResponse} envelope when `fullResponse: true`.
   */
  async signUp(
    options: SignUpOptions & { fullResponse: true },
    requestOptions?: RequestOptions
  ): Promise<ApiResponse<SignUpResult>>;
  async signUp(options: SignUpOptions, requestOptions?: RequestOptions): Promise<SignUpResult>;
  async signUp(
    options: SignUpOptions & FullResponseOption,
    requestOptions?: RequestOptions
  ): Promise<SignUpResult | ApiResponse<SignUpResult>> {
    requireFields(options, ['email', 'password', 'connection'], SignUpError);
    const body = { client_id: options.clientId ?? this.#clientId, ...transformSignUpRequest(options) };
    const response = await this.#post('/dbconnections/signup', body, SignUpError, 'Failed to sign up', requestOptions);
    if (options.fullResponse) {
      const clone = response.clone();
      const raw = (await response.json()) as Record<string, unknown>;
      return { data: normalizeSignUpResult(raw), response: clone };
    }
    const raw = (await response.json()) as Record<string, unknown>;
    return normalizeSignUpResult(raw);
  }

  /**
   * Triggers a password-reset email via `POST /dbconnections/change_password`.
   *
   * The endpoint is public: only `clientId` is sent in the request body. For privacy the
   * server returns the same plain-text confirmation regardless of whether the identifier
   * matches an existing account, so the resolved value is that confirmation string, not JSON.
   *
   * @param options - Change-password options. `connection` is required, plus at least one of
   *   `email` or `username` (`username` is for username-only database connections). Pass
   *   `fullResponse: true` to receive an {@link ApiResponse} envelope containing the confirmation
   *   string alongside the raw HTTP {@link Response}.
   * @param requestOptions - Optional per-request options (abort signal, extra headers, one-off fetch).
   * @throws {ChangePasswordError} When required fields are missing, the request fails, or the server
   *   returns a non-2xx response. On an HTTP failure the error carries `statusCode`, `headers`, and `body`.
   * @returns The server's plain-text confirmation string, or an {@link ApiResponse} envelope when `fullResponse: true`.
   */
  async changePassword(
    options: ChangePasswordOptions & { fullResponse: true },
    requestOptions?: RequestOptions
  ): Promise<ApiResponse<string>>;
  async changePassword(options: ChangePasswordOptions, requestOptions?: RequestOptions): Promise<string>;
  async changePassword(
    options: ChangePasswordOptions & FullResponseOption,
    requestOptions?: RequestOptions
  ): Promise<string | ApiResponse<string>> {
    requireFields(options, ['connection'], ChangePasswordError);
    if (!options.email && !options.username) {
      throw new ChangePasswordError('Either "email" or "username" is required.');
    }
    const body = { client_id: options.clientId ?? this.#clientId, ...transformChangePasswordRequest(options) };
    const response = await this.#post(
      '/dbconnections/change_password', body, ChangePasswordError, 'Failed to request a password change', requestOptions
    );
    if (options.fullResponse) {
      const clone = response.clone();
      const text = await response.text();
      return { data: text, response: clone };
    }
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
    const bodyText = await response.clone().text();
    const errorBody = await parseErrorBody(response.clone());
    const err = new ErrorClass(
      errorBody?.error_description || failureMessage,
      errorBody ?? { error: 'unknown_error', error_description: failureMessage }
    );
    err.statusCode = response.status;
    // Snapshot headers, filtering Set-Cookie to avoid leaking session cookies into error objects.
    err.headers = filterSensitiveHeaders(response.headers);
    err.body = bodyText;
    throw err;
  }
}
