import type {
  MfaClientOptions,
  Authenticator,
  AuthenticatorApiResponse,
  ListAuthenticatorsParams,
  DeleteAuthenticatorParams,
  EnrollAuthenticatorParams,
  EnrollmentResponse,
  EnrollmentApiResponse,
  ChallengeParams,
  ChallengeResponse,
  ChallengeApiResponse,
} from './types.js';
import {
  MfaListAuthenticatorsError,
  MfaEnrollmentError,
  MfaDeleteAuthenticatorError,
  MfaChallengeError,
  type MfaApiErrorResponse,
} from './errors.js';
import {
  transformAuthenticatorResponse,
  transformEnrollmentResponse,
  transformChallengeResponse,
} from './utils.js';


export class MfaClient {
  #baseUrl: string;
  #clientId: string;
  #customFetch: typeof fetch;

  /**
   * @internal
   */
  constructor(options: MfaClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#customFetch = options.customFetch ?? ((...args) => fetch(...args));
  }

  /**
   * Lists all MFA authenticators enrolled by the user.
   *
   * Retrieves a list of all multi-factor authentication methods that have been
   * enrolled for the user, including OTP (TOTP), SMS, voice, email, and recovery codes.
   *
   * @param params - Parameters for listing authenticators
   * @param params.mfaToken - MFA token obtained from an MFA challenge response
   * @returns Promise resolving to an array of enrolled authenticators
   * @throws {MfaListAuthenticatorsError} When the request fails (e.g., invalid token, network error)
   *
   * @example
   * ```typescript
   * const authenticators = await authClient.mfa.listAuthenticators({
   *   mfaToken: 'your_mfa_token_here'
   * });
   *
   * // authenticators is an array of enrolled authenticators
   * // Each has: id, authenticatorType, active, name, createdAt, lastAuth
   * ```
   */
  async listAuthenticators(params: ListAuthenticatorsParams): Promise<Authenticator[]> {
    const url = `${this.#baseUrl}/mfa/authenticators`;
    const { mfaToken } = params;

    const response = await this.#customFetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaListAuthenticatorsError(
        error.error_description || 'Failed to list authenticators',
        error
      );
    }

    const apiResponse = (await response.json()) as AuthenticatorApiResponse[];
    return apiResponse.map(transformAuthenticatorResponse);
  }

  /**
   * Enrolls a new MFA authenticator for the user.
   *
   * Initiates the enrollment process for a new multi-factor authentication method.
   * Supports OTP (TOTP apps like Google Authenticator), SMS, voice, and email authenticators.
   *
   * For OTP enrollment, the response includes a secret and QR code URI that the user
   * can scan with their authenticator app. For SMS/voice enrollment, a phone number
   * must be provided. For email enrollment, an optional email address can be specified.
   *
   * @param params - Enrollment parameters (type depends on authenticator being enrolled)
   * @param params.mfaToken - MFA token obtained from an MFA challenge response
   * @param params.authenticatorTypes - Array with one authenticator type: 'otp', 'oob', or 'email'
   * @param params.oobChannels - (OOB only) Delivery channels: 'sms', 'voice', or 'auth0'
   * @param params.phoneNumber - (OOB only) Phone number in E.164 format (e.g., +1234567890)
   * @param params.email - (Email only) Email address (optional, uses user's email if not provided)
   * @returns Promise resolving to enrollment response with authenticator details
   * @throws {MfaEnrollmentError} When enrollment fails (e.g., invalid parameters, network error)
   *
   * @example
   * ```typescript
   * // Enroll OTP authenticator (Google Authenticator, etc.)
   * const otpEnrollment = await authClient.mfa.enrollAuthenticator({
   *   authenticatorTypes: ['otp'],
   *   mfaToken: 'your_mfa_token_here'
   * });
   * // otpEnrollment.secret - Base32-encoded secret for TOTP
   * // otpEnrollment.barcodeUri - URI for generating QR code
   *
   * // Enroll SMS authenticator
   * const smsEnrollment = await authClient.mfa.enrollAuthenticator({
   *   authenticatorTypes: ['oob'],
   *   oobChannels: ['sms'],
   *   phoneNumber: '+1234567890',
   *   mfaToken: 'your_mfa_token_here'
   * });
   * ```
   */
  async enrollAuthenticator(params: EnrollAuthenticatorParams): Promise<EnrollmentResponse> {
    const url = `${this.#baseUrl}/mfa/associate`;
    const { mfaToken, ...sdkParams } = params;

    // Transform camelCase SDK params to snake_case for API
    const apiParams: Record<string, unknown> = {
      authenticator_types: sdkParams.authenticatorTypes,
    };

    if ('oobChannels' in sdkParams) {
      apiParams.oob_channels = sdkParams.oobChannels;
    }

    if ('phoneNumber' in sdkParams && sdkParams.phoneNumber) {
      apiParams.phone_number = sdkParams.phoneNumber;
    }

    if ('email' in sdkParams && sdkParams.email) {
      apiParams.email = sdkParams.email;
    }

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(apiParams),
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaEnrollmentError(
        error.error_description || 'Failed to enroll authenticator',
        error
      );
    }

    const apiResponse = (await response.json()) as EnrollmentApiResponse;
    return transformEnrollmentResponse(apiResponse);
  }

  /**
   * Deletes an enrolled MFA authenticator.
   *
   * Removes a previously enrolled multi-factor authentication method from the user's account.
   * The authenticator ID can be obtained from the listAuthenticators() method.
   *
   * @param params - Parameters for deleting an authenticator
   * @param params.authenticatorId - ID of the authenticator to delete (e.g., 'totp|dev_abc123')
   * @param params.mfaToken - MFA token obtained from an MFA challenge response
   * @returns Promise that resolves when the authenticator is successfully deleted
   * @throws {MfaDeleteAuthenticatorError} When deletion fails (e.g., invalid ID, network error)
   *
   * @example
   * ```typescript
   * // First, list authenticators to get the ID
   * const authenticators = await authClient.mfa.listAuthenticators({
   *   mfaToken: 'your_mfa_token_here'
   * });
   *
   * // Delete a specific authenticator
   * await authClient.mfa.deleteAuthenticator({
   *   authenticatorId: authenticators[0].id,
   *   mfaToken: 'your_mfa_token_here'
   * });
   * ```
   */
  async deleteAuthenticator(params: DeleteAuthenticatorParams): Promise<void> {
    const { authenticatorId, mfaToken } = params;
    const url = `${this.#baseUrl}/mfa/authenticators/${encodeURIComponent(authenticatorId)}`;

    const response = await this.#customFetch(url, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaDeleteAuthenticatorError(
        error.error_description || 'Failed to delete authenticator',
        error
      );
    }
  }

  /**
   * Initiates an MFA challenge for user verification.
   *
   * Creates a challenge that the user must complete to verify their identity using
   * one of their enrolled MFA factors. For OTP challenges, the user enters a code
   * from their authenticator app. For OOB (out-of-band) challenges like SMS, a code
   * is sent to the user's device.
   *
   * @param params - Challenge parameters
   * @param params.mfaToken - MFA token obtained from an MFA challenge response
   * @param params.challengeType - Type of challenge: 'otp' for TOTP apps, 'oob' for SMS/voice/push
   * @param params.authenticatorId - (Optional) Specific authenticator to challenge
   * @returns Promise resolving to challenge response with challenge details
   * @throws {MfaChallengeError} When the challenge fails (e.g., invalid parameters, network error)
   *
   * @example
   * ```typescript
   * // Challenge with OTP (user enters code from their app)
   * const otpChallenge = await authClient.mfa.challengeAuthenticator({
   *   challengeType: 'otp',
   *   mfaToken: 'your_mfa_token_here'
   * });
   *
   * // Challenge with SMS (code sent to user's phone)
   * const smsChallenge = await authClient.mfa.challengeAuthenticator({
   *   challengeType: 'oob',
   *   authenticatorId: 'sms|dev_abc123',
   *   mfaToken: 'your_mfa_token_here'
   * });
   * // smsChallenge.oobCode - Out-of-band code for verification
   * ```
   */
  async challengeAuthenticator(params: ChallengeParams): Promise<ChallengeResponse> {
    const url = `${this.#baseUrl}/mfa/challenge`;
    const { mfaToken, ...challengeParams } = params;

    const body: Record<string, string | undefined> = {
      mfa_token: mfaToken,
      client_id: this.#clientId,
      challenge_type: challengeParams.challengeType,
    };

    if (challengeParams.authenticatorId) {
      body.authenticator_id = challengeParams.authenticatorId;
    }

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaChallengeError(
        error.error_description || 'Failed to challenge authenticator',
        error
      );
    }

    const apiResponse = (await response.json()) as ChallengeApiResponse;
    return transformChallengeResponse(apiResponse);
  }
}
