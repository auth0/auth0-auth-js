import { updateStateData } from '../state/utils.js';
import type { ServerMfaClientOptions, MfaVerifyResponse } from './types.js';
import type {
  ListAuthenticatorsOptions,
  AuthenticatorResponse,
  EnrollAuthenticatorOptions,
  EnrollmentResponse,
  ChallengeOptions,
  ChallengeResponse,
  MfaVerifyOptions,
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
   * @returns Promise resolving to an array of enrolled authenticators
   * @throws {MfaListAuthenticatorsError} When the request fails
   */
  async listAuthenticators(options: ListAuthenticatorsOptions): Promise<AuthenticatorResponse[]> {
    return this.#options.authClient.mfa.listAuthenticators(options);
  }

  /**
   * Enrolls a new MFA authenticator for the user.
   *
   * @param options - Enrollment options
   * @returns Promise resolving to enrollment response with authenticator details
   * @throws {MfaEnrollmentError} When enrollment fails
   */
  async enrollAuthenticator(options: EnrollAuthenticatorOptions): Promise<EnrollmentResponse> {
    return this.#options.authClient.mfa.enrollAuthenticator(options);
  }

  /**
   * Initiates an MFA challenge for user verification.
   *
   * @param options - Challenge options
   * @returns Promise resolving to challenge response with challenge details
   * @throws {MfaChallengeError} When the challenge fails
   */
  async challengeAuthenticator(options: ChallengeOptions): Promise<ChallengeResponse> {
    return this.#options.authClient.mfa.challengeAuthenticator(options);
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
   */
  async verify(options: MfaVerifyOptions, storeOptions?: TStoreOptions): Promise<MfaVerifyResponse> {
    const tokenResponse = await this.#options.authClient.mfa.verify(options);

    const audience = options.audience ?? this.#options.defaultAudience;
    const existingStateData = await this.#options.stateStore.get(
      this.#options.stateStoreIdentifier,
      storeOptions
    );

    const updatedStateData = updateStateData(audience, existingStateData, tokenResponse, {
      domain: this.#options.domain,
    });

    await this.#options.stateStore.set(
      this.#options.stateStoreIdentifier,
      updatedStateData,
      true,
      storeOptions
    );

    const result: MfaVerifyResponse = {
      accessToken: tokenResponse.accessToken,
      tokenType: tokenResponse.tokenType ?? 'Bearer',
      expiresIn: tokenResponse.expiresIn ?? tokenResponse.expiresAt - Math.floor(Date.now() / 1000),
      scope: tokenResponse.scope,
    };

    if (tokenResponse.idToken) result.idToken = tokenResponse.idToken;
    if (tokenResponse.refreshToken) result.refreshToken = tokenResponse.refreshToken;
    if (tokenResponse.recoveryCode) result.recoveryCode = tokenResponse.recoveryCode;

    return result;
  }
}
