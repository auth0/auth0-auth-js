import { updateStateData, applySessionExpiryAtLogin } from '../state/utils.js';
import type { ServerMfaClientOptions, MfaVerifyResponse } from './types.js';
import type {
  ListAuthenticatorsOptions,
  AuthenticatorResponse,
  EnrollAuthenticatorOptions,
  EnrollmentResponse,
  ChallengeOptions,
  ChallengeResponse,
  MfaVerifyOptions,
  RequestOptions,
} from '@auth0/auth0-auth-js';

export class ServerMfaClient<TStoreOptions = unknown> {
  readonly #options: ServerMfaClientOptions<TStoreOptions>;

  /**
   * @internal
   */
  constructor(options: ServerMfaClientOptions<TStoreOptions>) {
    this.#options = options;
  }

  /**
   * Lists all MFA authenticators enrolled by the user.
   *
   * @param options - Options for listing authenticators
   * @param requestOptions - Optional per-request options (signal, headers, customFetch).
   * @param storeOptions - Optional options used to resolve the domain in resolver (multi-tenant) mode.
   * @returns Promise resolving to an array of enrolled authenticators
   * @throws {MfaListAuthenticatorsError} When the request fails
   */
  async listAuthenticators(
    options: ListAuthenticatorsOptions,
    requestOptions?: RequestOptions,
    storeOptions?: TStoreOptions
  ): Promise<AuthenticatorResponse[]> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);
    return authClient.mfa.listAuthenticators(options, requestOptions);
  }

  /**
   * Enrolls a new MFA authenticator for the user.
   *
   * @param options - Enrollment options
   * @param requestOptions - Optional per-request options (signal, headers, customFetch).
   * @param storeOptions - Optional options used to resolve the domain in resolver (multi-tenant) mode.
   * @returns Promise resolving to enrollment response with authenticator details
   * @throws {MfaEnrollmentError} When enrollment fails
   */
  async enrollAuthenticator(
    options: EnrollAuthenticatorOptions,
    requestOptions?: RequestOptions,
    storeOptions?: TStoreOptions
  ): Promise<EnrollmentResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);
    return authClient.mfa.enrollAuthenticator(options, requestOptions);
  }

  /**
   * Initiates an MFA challenge for user verification.
   *
   * @param options - Challenge options
   * @param requestOptions - Optional per-request options (signal, headers, customFetch).
   * @param storeOptions - Optional options used to resolve the domain in resolver (multi-tenant) mode.
   * @returns Promise resolving to challenge response with challenge details
   * @throws {MfaChallengeError} When the challenge fails
   */
  async challengeAuthenticator(
    options: ChallengeOptions,
    requestOptions?: RequestOptions,
    storeOptions?: TStoreOptions
  ): Promise<ChallengeResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);
    return authClient.mfa.challengeAuthenticator(options, requestOptions);
  }

  /**
   * Verifies an MFA challenge and completes the authentication flow.
   *
   * Exchanges the MFA token and verification code for access, ID, and refresh tokens,
   * then saves them into the user's session automatically.
   *
   * @param options - The MFA token, factor type (otp / oob / recovery-code), and the code to verify
   * @param storeOptions - Optional options forwarded to the session store (and used to resolve the
   *   domain in resolver mode). Can be omitted when using the built-in stores in static mode; required
   *   if your custom store needs extra context (e.g. a request object) or you are in resolver mode.
   * @param requestOptions - Optional per-request options (signal, headers, customFetch).
   * @returns The tokens returned by Auth0 after successful verification
   * @throws {MfaVerifyError} When verification fails (e.g. invalid token, wrong code)
   */
  async verify(options: MfaVerifyOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<MfaVerifyResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    const tokenResponse = await authClient.mfa.verify(options, requestOptions);

    const audience = options.audience ?? this.#options.defaultAudience;
    const existingStateData = await this.#options.stateStore.get(
      this.#options.stateStoreIdentifier,
      storeOptions
    );

    const updatedStateData = applySessionExpiryAtLogin(
      updateStateData(audience, existingStateData, tokenResponse, {
        domain,
      }),
      tokenResponse.claims
    );

    await this.#options.stateStore.set(
      this.#options.stateStoreIdentifier,
      updatedStateData,
      true,
      storeOptions
    );

    const result: MfaVerifyResponse = {
      accessToken: tokenResponse.accessToken,
      tokenType: tokenResponse.tokenType ?? 'bearer',
      expiresAt: tokenResponse.expiresAt,
      scope: tokenResponse.scope,
    };

    if (tokenResponse.idToken) result.idToken = tokenResponse.idToken;
    if (tokenResponse.refreshToken) result.refreshToken = tokenResponse.refreshToken;
    if (tokenResponse.recoveryCode) result.recoveryCode = tokenResponse.recoveryCode;

    return result;
  }
}
