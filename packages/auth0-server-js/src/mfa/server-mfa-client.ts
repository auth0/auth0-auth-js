import { updateStateData, applySessionExpiryAtLogin } from '../state/utils.js';
import type { ServerMfaClientOptions, MfaVerifyResponse } from './types.js';
import type { TokenResponse } from '@auth0/auth0-auth-js';
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

/** @category Sub-clients */
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
   * @returns Promise resolving to an array of enrolled authenticators
   * @throws {MfaListAuthenticatorsError} When the request fails
   */
  async listAuthenticators(options: ListAuthenticatorsOptions, requestOptions?: RequestOptions): Promise<AuthenticatorResponse[]> {
    return this.#options.authClient.mfa.listAuthenticators(options, requestOptions);
  }

  /**
   * Enrolls a new MFA authenticator for the user.
   *
   * @param options - Enrollment options
   * @returns Promise resolving to enrollment response with authenticator details
   * @throws {MfaEnrollmentError} When enrollment fails
   */
  async enrollAuthenticator(options: EnrollAuthenticatorOptions, requestOptions?: RequestOptions): Promise<EnrollmentResponse> {
    return this.#options.authClient.mfa.enrollAuthenticator(options, requestOptions);
  }

  /**
   * Initiates an MFA challenge for user verification.
   *
   * @param options - Challenge options
   * @returns Promise resolving to challenge response with challenge details
   * @throws {MfaChallengeError} When the challenge fails
   */
  async challengeAuthenticator(options: ChallengeOptions, requestOptions?: RequestOptions): Promise<ChallengeResponse> {
    return this.#options.authClient.mfa.challengeAuthenticator(options, requestOptions);
  }

  /**
   * Verifies an MFA challenge and completes the authentication flow.
   *
   * Exchanges the MFA token and verification code for access, ID, and refresh tokens,
   * then saves them into the user's session automatically.
   *
   * @param options - The MFA token, factor type (otp / oob / recovery-code), and the code to verify
   * @param storeOptions - Optional options forwarded to the session store. Can be omitted when
   *   using the built-in stores; required if your custom store needs extra context (e.g. a request object).
   * @returns The tokens returned by Auth0 after successful verification
   * @throws {MfaVerifyError} When verification fails (e.g. invalid token, wrong code)
   * @throws {PoppyError} With the `poppy` option, when the login is refused: `invalid_poppy_guest`, `poppy_guest_not_supported` or `poppy_sign_in_required` (a guest is in the browser and the login is not a signed-in agent's). Nothing is persisted. A signed-in agent gets a session with the same deadline as the callback gives, and no refresh token.
   */
  async verify(options: MfaVerifyOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<MfaVerifyResponse> {
    const tokenResponse = await this.#options.authClient.mfa.verify(options, requestOptions);

    const audience = options.audience ?? this.#options.defaultAudience;

    // With the `poppy` option, the guard runs before anything is written. A login that it refuses throws, and a signed-in
    // agent is saved there, so there is no session to write here.
    const poppy = await this.#options.completePoppyLogin?.(
      tokenResponse,
      { audience, domain: this.#options.domain },
      storeOptions
    );

    if (!poppy) {
      await this.#saveSession(tokenResponse, audience, storeOptions);
    }

    const result: MfaVerifyResponse = {
      accessToken: tokenResponse.accessToken,
      tokenType: tokenResponse.tokenType ?? 'bearer',
      expiresAt: tokenResponse.expiresAt,
      scope: tokenResponse.scope,
    };

    if (tokenResponse.idToken) result.idToken = tokenResponse.idToken;
    // A signed-in agent session has no refresh token, so the caller gets none either.
    if (tokenResponse.refreshToken && !poppy) result.refreshToken = tokenResponse.refreshToken;
    if (tokenResponse.recoveryCode) result.recoveryCode = tokenResponse.recoveryCode;

    return result;
  }

  async #saveSession(tokenResponse: TokenResponse, audience: string, storeOptions?: TStoreOptions): Promise<void> {
    const existingStateData = await this.#options.stateStore.get(
      this.#options.stateStoreIdentifier,
      storeOptions
    );

    // The parent client can decide that the stored session is not built on, and then this login starts a new one.
    const baseStateData = this.#options.existingForLogin
      ? this.#options.existingForLogin(existingStateData)
      : existingStateData;

    const updatedStateData = applySessionExpiryAtLogin(
      updateStateData(audience, baseStateData, tokenResponse, {
        domain: this.#options.domain,
      }),
      tokenResponse.claims
    );

    await this.#options.stateStore.set(
      this.#options.stateStoreIdentifier,
      updatedStateData,
      true,
      storeOptions
    );

    // Verification is the point at which the login completes, so the anonymous session the
    // visitor may have had is over.
    await this.#options.onUserSessionEstablished?.(storeOptions);
  }
}
