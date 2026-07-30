import { SignUpError, ChangePasswordError } from './errors.js';
import type { DatabaseClientOptions, SignUpOptions, ChangePasswordOptions, SignUpResult } from './types.js';
import {
  requireFields, transformSignUpRequest, transformChangePasswordRequest,
  normalizeSignUpResult, parseErrorBody,
} from './utils.js';
import type { RequestOptions } from '../types.js';
import { composeRequestFetch, type CapturingFetch } from '../request-fetch.js';
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

    // Build per-call fetch wrapper with getCapturedResponse property
    const requestFetch = composeRequestFetch(this.#customFetch, requestOptions, this.#telemetryConfig);

    try {
      const response = await requestFetch(`${this.#baseUrl}/dbconnections/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        // Error response: parse body and construct error manually
        const errorBody = await parseErrorBody(response);
        // Call getCapturedResponse() inline within catch-like path (still in try, but error case)
        const captured = (requestFetch as CapturingFetch).getCapturedResponse();
        throw new SignUpError(
          errorBody?.error_description || 'Failed to sign up',
          {
            ...errorBody,
            statusCode: captured.status,
            headers: captured.headers,
            body: captured.bodyText ? await captured.bodyText : undefined
          }
        );
      }

      // Success: parse response and attach httpResponse metadata
      const raw = (await response.json()) as Record<string, unknown>;
      const result = normalizeSignUpResult(raw);

      // Call getCapturedResponse() inline (per-call closure isolation)
      const captured = (requestFetch as CapturingFetch).getCapturedResponse();
      result.httpResponse = {
        status: captured.status!,
        statusText: captured.statusText!,
        headers: captured.headers!
      };

      return result;
    } catch (e) {
      // If it's already a SignUpError (from above), re-throw
      if (e instanceof SignUpError) throw e;

      // Network or other non-HTTP error
      const captured = (requestFetch as CapturingFetch).getCapturedResponse();
      throw new SignUpError(
        'Failed to sign up: a network error occurred.',
        {
          error: 'network_error',
          error_description: e instanceof Error ? e.message : String(e),
          statusCode: captured.status,
          headers: captured.headers,
          body: captured.bodyText ? await captured.bodyText : undefined
        }
      );
    }
  }

  async changePassword(options: ChangePasswordOptions, requestOptions?: RequestOptions): Promise<string> {
    requireFields(options, ['connection'], ChangePasswordError);
    if (!options.email && !options.username) {
      throw new ChangePasswordError('Either "email" or "username" is required.');
    }
    const body = { client_id: options.clientId ?? this.#clientId, ...transformChangePasswordRequest(options) };

    // Build per-call fetch wrapper with getCapturedResponse property
    const requestFetch = composeRequestFetch(this.#customFetch, requestOptions, this.#telemetryConfig);

    try {
      const response = await requestFetch(`${this.#baseUrl}/dbconnections/change_password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        // Error response: parse body and construct error manually
        const errorBody = await parseErrorBody(response);
        // Call getCapturedResponse() inline
        const captured = (requestFetch as CapturingFetch).getCapturedResponse();
        throw new ChangePasswordError(
          errorBody?.error_description || 'Failed to request a password change',
          {
            ...errorBody,
            statusCode: captured.status,
            headers: captured.headers,
            body: captured.bodyText ? await captured.bodyText : undefined
          }
        );
      }

      // Success: return raw text (no success metadata per O#3)
      return response.text();
    } catch (e) {
      // If it's already a ChangePasswordError (from above), re-throw
      if (e instanceof ChangePasswordError) throw e;

      // Network or other non-HTTP error
      const captured = (requestFetch as CapturingFetch).getCapturedResponse();
      throw new ChangePasswordError(
        'Failed to request a password change: a network error occurred.',
        {
          error: 'network_error',
          error_description: e instanceof Error ? e.message : String(e),
          statusCode: captured.status,
          headers: captured.headers,
          body: captured.bodyText ? await captured.bodyText : undefined
        }
      );
    }
  }
}
