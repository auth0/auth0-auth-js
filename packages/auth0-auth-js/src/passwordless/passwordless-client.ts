import {
  PasswordlessStartError,
  PasswordlessChallengeError,
  PasswordlessDbGetTokenError,
  type PasswordlessApiErrorResponse,
  type ChallengeApiErrorResponse,
} from './errors.js';
import { toOAuth2Error, MissingCapturedResponseError } from '../errors.js';
import type { TokenResponse, RequestOptions, ApiResponse, FullResponseOption } from '../types.js';
import { composeRequestFetch } from '../request-fetch.js';
import { getTelemetryConfig, type TelemetryConfig } from '../telemetry.js';
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
  #telemetryConfig: TelemetryConfig;
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
    this.#telemetryConfig = options.telemetryConfig ?? getTelemetryConfig();
    this.#clientAuthOptions = {
      clientSecret: options.clientSecret,
      clientAssertionSigningKey: options.clientAssertionSigningKey,
      clientAssertionSigningAlg: options.clientAssertionSigningAlg,
      useMtls: options.useMtls,
    };
    this.#grantRequest = options.grantRequest;
  }

  /**
   * Builds the fetch used for a raw (non-`openid-client`) request, composing the
   * caller's {@link RequestOptions} over the sub-client's base fetch.
   */
  #fetchFor(requestOptions?: RequestOptions): typeof fetch {
    return composeRequestFetch(this.#customFetch, requestOptions, this.#telemetryConfig);
  }

  /**
   * Sends a passwordless email containing either a one-time code (default) or a magic link.
   *
   * @param options - Send options. Omit `send` (or pass `send: 'code'`) to send a code;
   *   pass `send: 'link'` with `authParams` to send a magic link. Pass `fullResponse: true`
   *   to receive an {@link ApiResponse}`<void>` envelope exposing the raw HTTP {@link Response}.
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
  async sendEmail(
    options: SendEmailOptions & { fullResponse: true },
    requestOptions?: RequestOptions
  ): Promise<ApiResponse<void>>;
  async sendEmail(options: SendEmailOptions, requestOptions?: RequestOptions): Promise<void>;
  async sendEmail(
    options: SendEmailOptions & FullResponseOption,
    requestOptions?: RequestOptions
  ): Promise<void | ApiResponse<void>> {
    const response = await this.#start(
      transformSendEmailRequest(options),
      'Failed to send passwordless email',
      options.language,
      requestOptions
    );
    if (options.fullResponse) {
      return { data: undefined, response };
    }
  }

  /**
   * Sends a passwordless SMS containing a one-time code. SMS does not support magic links.
   *
   * @param options - Send options. `phoneNumber` must be in E.164 format (e.g. `+14155550100`).
   *   Pass `fullResponse: true` to receive an {@link ApiResponse}`<void>` envelope exposing the
   *   raw HTTP {@link Response}.
   * @throws {PasswordlessStartError} When the phone number is invalid, the request fails,
   *   or the server returns a non-2xx response.
   * @throws {MissingClientAuthError} When no client authentication method is configured.
   *
   * @example
   * ```typescript
   * await authClient.passwordless.sendSms({ phoneNumber: '+14155550100' });
   * ```
   */
  async sendSms(
    options: SendSmsOptions & { fullResponse: true },
    requestOptions?: RequestOptions
  ): Promise<ApiResponse<void>>;
  async sendSms(options: SendSmsOptions, requestOptions?: RequestOptions): Promise<void>;
  async sendSms(
    options: SendSmsOptions & FullResponseOption,
    requestOptions?: RequestOptions
  ): Promise<void | ApiResponse<void>> {
    if (!isE164PhoneNumber(options.phoneNumber)) {
      throw new PasswordlessStartError('Phone number must be in E.164 format (e.g. +14155550100).');
    }
    const response = await this.#start(
      transformSendSmsRequest(options),
      'Failed to send passwordless SMS',
      options.language,
      requestOptions
    );
    if (options.fullResponse) {
      return { data: undefined, response };
    }
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
   * // `authSession` is opaque — store it and pass it to the OTP exchange; never log or inspect it.
   * const tokens = await authClient.passwordless.getTokenByPasswordlessDbConnection({
   *   authSession: challenge.authSession,
   *   otp: '123456',
   * });
   * ```
   */
  async challengeWithEmail(
    options: ChallengeWithEmailOptions,
    requestOptions?: RequestOptions
  ): Promise<PasswordlessChallenge> {
    // [Step 1] Transform options to wire format
    const wireBody = transformChallengeEmailRequest(options);

    // [Step 2] Call private #challenge helper with a descriptive failure message
    return this.#challenge(wireBody, 'Failed to request email OTP challenge', requestOptions);
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
    options: ChallengeWithPhoneNumberOptions,
    requestOptions?: RequestOptions
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
    return this.#challenge(wireBody, 'Failed to request phone OTP challenge', requestOptions);
  }

  /**
   * Performs the `/passwordless/start` POST with client authentication and uniform
   * error handling. Accepts both `200 {}` and `204 No Content` as success; never
   * parses a body on `204`.
   */
  async #start(
    wireBody: Record<string, unknown>,
    failureMessage: string,
    language?: string,
    requestOptions?: RequestOptions
  ): Promise<Response> {
    const clientAuthBody = await buildClientAuthBody(this.#clientAuthOptions, this.#clientId, this.#domain);

    const finalBody = {
      client_id: this.#clientId,
      ...wireBody,
      ...clientAuthBody,
    };

    let response: Response;
    try {
      response = await this.#fetchFor(requestOptions)(`${this.#baseUrl}/passwordless/start`, {
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
      // 200 {} or 204 No Content — nothing to parse. Return the live Response so
      // callers requesting `fullResponse` can inspect status/headers.
      return response;
    }

    // Error path: 204 has no body, so only parse JSON when a body is expected.
    // When no structured body is available (204, or non-JSON), pass a minimal cause
    // with metadata so extractHttpMetadata can lift statusCode/headers/body to the error instance.
    const bodyText = await response.clone().text();
    let errorBody: PasswordlessApiErrorResponse | undefined;
    if (response.status !== 204) {
      try {
        errorBody = JSON.parse(bodyText) as PasswordlessApiErrorResponse;
      } catch {
        errorBody = undefined;
      }
    }

    const cause = errorBody
      ? { ...errorBody, statusCode: response.status, headers: response.headers, body: bodyText }
      : { error: '', error_description: '', statusCode: response.status, headers: response.headers, body: bodyText };
    throw new PasswordlessStartError(errorBody?.error_description || failureMessage, cause);
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
    failureMessage: string,
    requestOptions?: RequestOptions
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
      response = await this.#fetchFor(requestOptions)(`${this.#baseUrl}/otp/challenge`, {
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
      let responseBody: { auth_session: string };
      try {
        responseBody = (await response.json()) as { auth_session: string };
      } catch {
        // A 2xx with a non-JSON body means an intermediary (WAF, maintenance
        // page, proxy) answered instead of Auth0 — `response.ok` says nothing
        // about the body. Surface it as a distinct, diagnosable error rather
        // than a misleading "missing auth_session" one, and keep the invariant
        // that every failure exit of #challenge is a PasswordlessChallengeError.
        throw new PasswordlessChallengeError(
          `${failureMessage}: could not parse the response body.`,
          response.status,
          undefined,
          undefined
        );
      }
      return { authSession: responseBody.auth_session };
    }

    // [Step 5b] Error path: non-2xx response
    const bodyText = await response.clone().text();
    let errorBody: ChallengeApiErrorResponse | undefined;
    try {
      errorBody = JSON.parse(bodyText) as ChallengeApiErrorResponse;
    } catch {
      errorBody = undefined;
    }

    // Pass the parsed wire body directly as the cause; the base
    // PasswordlessError constructor narrows it to the OAuth2Error fields
    // (same convention as #start). `validation_errors` is a
    // PasswordlessChallengeError-specific field, so it stays separate.
    // When errorBody is undefined (non-JSON), pass a minimal cause with metadata
    // so extractHttpMetadata can lift statusCode/headers/body to the error instance.
    const cause = errorBody
      ? { ...errorBody, statusCode: response.status, headers: response.headers, body: bodyText }
      : { error: '', error_description: '', statusCode: response.status, headers: response.headers, body: bodyText };
    throw new PasswordlessChallengeError(
      errorBody?.error_description || failureMessage,
      response.status,
      cause,
      errorBody?.validation_errors
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
   * @throws {PasswordlessDbGetTokenError} If the code is invalid, expired, or rate-limited, or on a
   *   failed exchange (also thrown if the client was constructed without a grant-request delegate).
   *   When the connection requires MFA the server responds with `403 mfa_required`; the thrown error
   *   carries `cause.error === 'mfa_required'` with the server's `mfa_token`. Narrow it with
   *   `isMfaRequiredError` and complete the challenge via `authClient.mfa`.
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
    options: TokenByPasswordlessDbConnectionOptions & { fullResponse: true },
    requestOptions?: RequestOptions
  ): Promise<ApiResponse<TokenResponse>>;
  async getTokenByPasswordlessDbConnection(
    options: TokenByPasswordlessDbConnectionOptions,
    requestOptions?: RequestOptions
  ): Promise<TokenResponse>;
  async getTokenByPasswordlessDbConnection(
    options: TokenByPasswordlessDbConnectionOptions & FullResponseOption,
    requestOptions?: RequestOptions
  ): Promise<TokenResponse | ApiResponse<TokenResponse>> {
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
      throw new PasswordlessDbGetTokenError(
        'Missing grant request delegate.',
        toOAuth2Error(new Error('missing grantRequest'))
      );
    }

    try {
      const result = await this.#grantRequest(PASSWORDLESS_OTP_GRANT_TYPE, params, requestOptions, options.fullResponse);
      return result;
    } catch (e) {
      if (e instanceof MissingCapturedResponseError) throw e;
      // `toOAuth2Error` lifts `mfa_token` / `mfa_requirements` from the nested
      // openid-client `cause` so `isMfaRequiredError` can detect an MFA requirement.
      throw new PasswordlessDbGetTokenError('There was an error while trying to request a token.', toOAuth2Error(e));
    }
  }
}
