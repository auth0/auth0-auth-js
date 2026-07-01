import {
  PasswordlessStartError,
  PasswordlessChallengeError,
  PasswordlessVerifyError,
  type PasswordlessApiErrorResponse,
  type ChallengeApiErrorResponse,
} from './errors.js';
import { type OAuth2Error, toOAuth2Error } from '../errors.js';
import type { TokenResponse } from '../types.js';
import type {
  PasswordlessClientOptions,
  SendEmailOptions,
  SendSmsOptions,
  ChallengeWithEmailOptions,
  ChallengeWithPhoneNumberOptions,
  PasswordlessChallenge,
  TokenByPasswordlessDbConnectionOptions,
  GrantRequestFn,
} from './types.js';
import {
  buildClientAuthBody,
  isE164PhoneNumber,
  transformSendEmailRequest,
  transformSendSmsRequest,
  transformChallengeEmailRequest,
  transformChallengePhoneRequest,
  type ClientAuthOptions,
} from './utils.js';

/**
 * Grant type for the Auth0 passwordless OTP token exchange.
 *
 * @internal
 */
export const PASSWORDLESS_OTP_GRANT_TYPE = 'http://auth0.com/oauth/grant-type/passwordless/otp';

/**
 * Sub-client for the Auth0 Passwordless endpoints.
 *
 * Exposed via `authClient.passwordless`. The `/passwordless/start` and `/otp/challenge`
 * endpoints are raw (non-`openid-client`) POSTs that require client authentication on the
 * request body, so the client-auth options are passed to the constructor. The OTP token
 * exchange (`getTokenByPasswordlessDbConnection`) is a standard OAuth grant and runs through
 * a `grantRequest` callback injected by `AuthClient`, reusing `openid-client`'s discovered
 * configuration for client authentication and DPoP support.
 */
export class PasswordlessClient {
  #baseUrl: string;
  #domain: string;
  #clientId: string;
  #customFetch: typeof fetch;
  #clientAuthOptions: ClientAuthOptions;
  #grantRequest?: GrantRequestFn;

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
    this.#grantRequest = options.grantRequest;
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
   * Requests a passwordless OTP challenge for email delivery against a database connection.
   *
   * Initiates a challenge on a database connection configured with `email_otp`.
   * On success, returns an opaque `auth_session` token for subsequent OTP verification
   * via the token endpoint.
   *
   * @param options - Challenge options
   * @throws {PasswordlessChallengeError} When validation fails, the request fails,
   *   or the server returns a non-2xx response
   * @throws {MissingClientAuthError} When no client authentication method is configured
   *
   * @example
   * ```typescript
   * const challenge = await authClient.passwordless.challengeWithEmail({
   *   email: 'user@example.com',
   *   connection: 'my-db-connection',
   *   allowSignup: true,
   * });
   * console.log(challenge.authSession); // Opaque string for subsequent OTP exchange
   * ```
   */
  async challengeWithEmail(options: ChallengeWithEmailOptions): Promise<PasswordlessChallenge> {
    // [Step 1] Transform options to wire format
    const wireBody = transformChallengeEmailRequest(options);

    // [Step 2] Call private #challenge helper with a descriptive failure message
    return this.#challenge(wireBody, 'Failed to request email OTP challenge');
  }

  /**
   * Requests a passwordless OTP challenge for phone delivery against a database connection.
   *
   * Initiates a challenge on a database connection configured with `phone_otp`.
   * On success, returns an opaque `auth_session` token for subsequent OTP verification
   * via the token endpoint.
   *
   * @param options - Challenge options
   * @throws {PasswordlessChallengeError} When the phone number is invalid, the request fails,
   *   or the server returns a non-2xx response
   * @throws {MissingClientAuthError} When no client authentication method is configured
   *
   * @example
   * ```typescript
   * const challenge = await authClient.passwordless.challengeWithPhoneNumber({
   *   phoneNumber: '+14155550100',
   *   connection: 'my-db-connection',
   *   deliveryMethod: 'voice',
   * });
   * ```
   */
  async challengeWithPhoneNumber(
    options: ChallengeWithPhoneNumberOptions
  ): Promise<PasswordlessChallenge> {
    // [Step 1] Validate E.164 phone format (synchronous guard, before any HTTP)
    if (!isE164PhoneNumber(options.phoneNumber)) {
      throw new PasswordlessChallengeError(
        'Phone number must be in E.164 format (e.g. +14155550100).',
        0,
        undefined,
        undefined
      );
    }

    // [Step 2] Transform options to wire format
    const wireBody = transformChallengePhoneRequest(options);

    // [Step 3] Call private #challenge helper with a descriptive failure message
    return this.#challenge(wireBody, 'Failed to request phone OTP challenge');
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

  /**
   * Performs the POST `/otp/challenge` request with client authentication
   * and uniform error handling. Returns PasswordlessChallenge on success.
   *
   * Note (D4 — language support deferred): this helper intentionally sends no
   * language hint — neither an `x-request-language` header nor a `language`
   * field in wireBody. This is a deliberate scope decision, not an omission.
   * The design leaves room to add an optional `language` passthrough later
   * without a breaking change; until then #challenge stays language-agnostic.
   */
  async #challenge(
    wireBody: Record<string, unknown>,
    failureMessage: string
  ): Promise<PasswordlessChallenge> {
    // [Step 1] Build client auth body (may throw MissingClientAuthError; propagate)
    const clientAuthBody = await buildClientAuthBody(
      this.#clientAuthOptions,
      this.#clientId,
      this.#domain
    );

    // [Step 2] Construct final request body
    const finalBody = {
      client_id: this.#clientId,
      ...wireBody,
      ...clientAuthBody,
    };
    // [Step 3] Issue HTTP POST
    let response: Response;
    try {
      response = await this.#customFetch(`${this.#baseUrl}/otp/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(finalBody),
      });
    } catch {
      // Network error (fetch threw)
      throw new PasswordlessChallengeError(
        'challenge error: a network error occurred.',
        0,
        undefined,
        undefined
      );
    }

    // [Step 4 & 5a] Check response status and handle success
    if (response.ok) {
      let responseBody: { auth_session?: string };
      try {
        responseBody = (await response.json()) as { auth_session?: string };
      } catch {
        responseBody = {};
      }

      // A 2xx without an `auth_session` is not actionable — the caller cannot
      // proceed to the token exchange. Surface it as an error rather than
      // returning an `authSession` that violates the `PasswordlessChallenge`
      // contract (and would only fail later, with a more confusing message).
      if (!responseBody.auth_session) {
        throw new PasswordlessChallengeError(
          `${failureMessage}: the response did not include an auth_session.`,
          response.status,
          undefined,
          undefined
        );
      }

      return { authSession: responseBody.auth_session };
    }

    // [Step 5b] Error path: non-2xx response
    let errorBody: ChallengeApiErrorResponse | undefined;
    try {
      errorBody = (await response.json()) as ChallengeApiErrorResponse;
    } catch {
      errorBody = undefined;
    }

    let cause: OAuth2Error | undefined;
    let validationErrors: Array<{ field: string; message: string }> | undefined;
    const errorMessage = errorBody?.error_description || failureMessage;

    if (errorBody) {
      cause = {
        error: errorBody.error,
        error_description: errorBody.error_description,
        message: errorBody.message,
      };
      validationErrors = errorBody.validation_errors;
    }

    throw new PasswordlessChallengeError(
      errorMessage,
      response.status,
      cause,
      validationErrors
    );
  }

  /**
   * Exchanges an OTP for tokens against a database connection (OTP grant).
   *
   * Completes the embedded passwordless DB-connection flow: pass the opaque `authSession`
   * returned by {@link challengeWithEmail}/{@link challengeWithPhoneNumber} together with the
   * user-entered `otp`. Posts to `/oauth/token` with grant type
   * `http://auth0.com/oauth/grant-type/passwordless/otp` and returns the resulting tokens.
   *
   * The exchange runs through `AuthClient`'s `openid-client` configuration, so it requires the
   * client to be authenticated (a `clientSecret`, `clientAssertionSigningKey`, or mTLS).
   *
   * @param options - The auth session, OTP, and optional scope/audience.
   *
   * @throws {PasswordlessVerifyError} If the code is invalid, expired, or rate-limited, or on a
   *   failed exchange. When the connection requires MFA the server responds with
   *   `403 mfa_required`; the thrown error carries `cause.error === 'mfa_required'` with the
   *   server's `mfa_token`. Narrow it with `isMfaRequiredError` and complete the challenge via
   *   `authClient.mfa` — this is not a distinct error type, mirroring the other token methods.
   *
   * @returns A Promise resolving to the TokenResponse as returned from Auth0.
   *
   * @example
   * ```typescript
   * const challenge = await authClient.passwordless.challengeWithEmail({
   *   email: 'user@example.com',
   *   connection: 'my-db-connection',
   * });
   * const tokens = await authClient.passwordless.getTokenByPasswordlessDbConnection({
   *   authSession: challenge.authSession,
   *   otp: '123456',
   *   scope: 'openid profile email', // include 'openid' for an id_token; SDK does not inject it
   * });
   * ```
   */
  async getTokenByPasswordlessDbConnection(
    options: TokenByPasswordlessDbConnectionOptions
  ): Promise<TokenResponse> {
    const params = new URLSearchParams({
      auth_session: options.authSession,
      otp: options.otp,
    });

    if (options.scope) {
      params.append('scope', options.scope);
    }

    if (options.audience) {
      params.append('audience', options.audience);
    }

    // `grantRequest` is injected by `AuthClient`. Constructing a bare
    // `PasswordlessClient` without it can only reach the `/passwordless/start`
    // and `/otp/challenge` paths; the OTP token exchange is unavailable.
    if (!this.#grantRequest) {
      throw new PasswordlessVerifyError(
        'Missing grant request delegate.',
        toOAuth2Error(new Error('missing grantRequest'))
      );
    }

    try {
      return await this.#grantRequest(PASSWORDLESS_OTP_GRANT_TYPE, params);
    } catch (e) {
      // `toOAuth2Error` lifts `mfa_token` / `mfa_requirements` from the nested
      // openid-client `cause` so `isMfaRequiredError` can detect an MFA requirement.
      throw new PasswordlessVerifyError('There was an error while trying to request a token.', toOAuth2Error(e));
    }
  }
}
