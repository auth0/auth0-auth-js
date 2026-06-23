import { PasswordlessStartError, type PasswordlessApiErrorResponse } from './errors.js';
import type { PasswordlessClientOptions, SendEmailOptions, SendSmsOptions } from './types.js';
import {
  buildClientAuthBody,
  isE164PhoneNumber,
  transformSendEmailRequest,
  transformSendSmsRequest,
  type ClientAuthOptions,
} from './utils.js';

/**
 * Sub-client for the Auth0 Passwordless `/passwordless/start` endpoint.
 *
 * Exposed via `authClient.passwordless`. Unlike OAuth token endpoints, this is a
 * raw (non-`openid-client`) POST that requires client authentication on the request
 * body, so the client-auth options are passed to the constructor.
 */
export class PasswordlessClient {
  #baseUrl: string;
  #domain: string;
  #clientId: string;
  #customFetch: typeof fetch;
  #clientAuthOptions: ClientAuthOptions;

  /**
   * @internal
   */
  constructor(options: PasswordlessClientOptions) {
    this.#domain = options.domain;
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#customFetch = options.customFetch ?? ((...args) => fetch(...args));
    this.#clientAuthOptions = {
      clientSecret: options.clientSecret,
      clientAssertionSigningKey: options.clientAssertionSigningKey,
      clientAssertionSigningAlg: options.clientAssertionSigningAlg,
      useMtls: options.useMtls,
    };
  }

  /**
   * Sends a passwordless email containing either a one-time code (default) or a magic link.
   *
   * @param options - Send options. Omit `send` (or pass `send: 'code'`) to send a code;
   *   pass `send: 'link'` with `authParams` to send a magic link.
   * @throws {PasswordlessStartError} When the request fails or the server returns a non-2xx response.
   * @throws {MissingClientAuthError} When no client authentication method is configured.
   *
   * @example
   * ```typescript
   * // Send a one-time code (default)
   * await authClient.passwordless.sendEmail({ email: 'user@example.com' });
   *
   * // Send a magic link (completion is handled by the redirect/callback flow, not this method)
   * await authClient.passwordless.sendEmail({
   *   email: 'user@example.com',
   *   send: 'link',
   *   authParams: {
   *     redirect_uri: 'https://myapp.com/callback',
   *     response_type: 'code',
   *     scope: 'openid profile',
   *     state: 'caller_generated_state',
   *   },
   * });
   * ```
   */
  async sendEmail(options: SendEmailOptions): Promise<void> {
    await this.#start(transformSendEmailRequest(options), 'Failed to send passwordless email', options.language);
  }

  /**
   * Sends a passwordless SMS containing a one-time code. SMS does not support magic links.
   *
   * @param options - Send options. `phoneNumber` must be in E.164 format (e.g. `+14155550100`).
   * @throws {PasswordlessStartError} When the phone number is invalid, the request fails,
   *   or the server returns a non-2xx response.
   * @throws {MissingClientAuthError} When no client authentication method is configured.
   *
   * @example
   * ```typescript
   * await authClient.passwordless.sendSms({ phoneNumber: '+14155550100' });
   * ```
   */
  async sendSms(options: SendSmsOptions): Promise<void> {
    if (!isE164PhoneNumber(options.phoneNumber)) {
      throw new PasswordlessStartError('Phone number must be in E.164 format (e.g. +14155550100).');
    }
    await this.#start(transformSendSmsRequest(options), 'Failed to send passwordless SMS', options.language);
  }

  /**
   * Performs the `/passwordless/start` POST with client authentication and uniform
   * error handling. Accepts both `200 {}` and `204 No Content` as success; never
   * parses a body on `204`.
   */
  async #start(wireBody: Record<string, unknown>, failureMessage: string, language?: string): Promise<void> {
    const clientAuthBody = await buildClientAuthBody(this.#clientAuthOptions, this.#clientId, this.#domain);

    const finalBody = {
      client_id: this.#clientId,
      ...wireBody,
      ...clientAuthBody,
    };

    let response: Response;
    try {
      response = await this.#customFetch(`${this.#baseUrl}/passwordless/start`, {
        method: 'POST',
        // `x-request-language` is an HTTP header (not a body field) used to localize
        // the email/SMS template, matching node-auth0 / nextjs-auth0.
        headers: {
          'Content-Type': 'application/json',
          ...(language ? { 'x-request-language': language } : {}),
        },
        body: JSON.stringify(finalBody),
      });
    } catch {
      throw new PasswordlessStartError(`${failureMessage}: a network error occurred.`);
    }

    if (response.ok) {
      // 200 {} or 204 No Content — nothing to parse.
      return;
    }

    // Error path: 204 has no body, so only parse JSON when a body is expected.
    // When no structured body is available (204, or non-JSON), leave `cause`
    // undefined so callers can distinguish an OAuth-style error from an opaque one.
    let errorBody: PasswordlessApiErrorResponse | undefined;
    if (response.status !== 204) {
      try {
        errorBody = (await response.json()) as PasswordlessApiErrorResponse;
      } catch {
        errorBody = undefined;
      }
    }

    throw new PasswordlessStartError(errorBody?.error_description || failureMessage, errorBody);
  }
}
