import { decodeJwt } from 'jose';
import { TokenResponse } from '@auth0/auth0-auth-js';
import type { MfaApiErrorResponse } from '@auth0/auth0-auth-js';
import { MfaChallengeError } from '@auth0/auth0-auth-js';
import { updateStateData } from '../state/utils.js';
import { MfaVerifyError } from './errors.js';
import type {
  ServerMfaClientOptions,
  MfaVerifyOptions,
  MfaVerifyResponse,
  MfaVerifyApiResponse,
} from './types.js';

import type {
  ListAuthenticatorsOptions,
  AuthenticatorResponse,
  EnrollAuthenticatorOptions,
  EnrollmentResponse,
  ChallengeOptions,
  ChallengeResponse,
} from '@auth0/auth0-auth-js';

const GRANT_TYPE_MAP = {
  otp: 'http://auth0.com/oauth/grant-type/mfa-otp',
  oob: 'http://auth0.com/oauth/grant-type/mfa-oob',
  'recovery-code': 'http://auth0.com/oauth/grant-type/mfa-recovery-code',
} as const;

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
    const url = `https://${this.#options.domain}/mfa/challenge`;
    const { mfaToken, ...challengeParams } = options;

    const body: Record<string, string | undefined> = {
      mfa_token: mfaToken,
      client_id: this.#options.clientId,
      challenge_type: challengeParams.challengeType,
    };

    if (this.#options.clientSecret) {
      body.client_secret = this.#options.clientSecret;
    }

    if (challengeParams.authenticatorId) {
      body.authenticator_id = challengeParams.authenticatorId;
    }

    const response = await this.#options.customFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaChallengeError(error.error_description || 'Failed to challenge authenticator', error);
    }

    const api = (await response.json()) as { challenge_type: string; oob_code?: string; binding_method?: string };
    return {
      challengeType: api.challenge_type as ChallengeResponse['challengeType'],
      oobCode: api.oob_code,
      bindingMethod: api.binding_method,
    } satisfies ChallengeResponse;
  }

  /**
   * Verifies an MFA challenge and completes the authentication flow.
   *
   * Calls the Auth0 token endpoint with the appropriate MFA grant type to exchange
   * the MFA token and verification code for access/ID/refresh tokens.
   *
   * After successful verification, the session state is updated via `updateStateData`
   * to persist the user, tokens, and token sets — following the same pattern as
   * `completeInteractiveLogin` and `loginBackchannel`.
   *
   * @param options - Verify options containing the MFA token and verification code
   * @param storeOptions - Optional options passed to the state store
   * @returns Promise resolving to the MFA verification response with tokens
   * @throws {MfaVerifyError} When verification fails (invalid token, wrong code, etc.)
   */
  async verify(options: MfaVerifyOptions, storeOptions?: TStoreOptions): Promise<MfaVerifyResponse> {
    const url = `https://${this.#options.domain}/oauth/token`;

    const body: Record<string, string> = {
      grant_type: GRANT_TYPE_MAP[options.factorType],
      client_id: this.#options.clientId,
      mfa_token: options.mfaToken,
    };

    if (this.#options.clientSecret) {
      body.client_secret = this.#options.clientSecret;
    }

    if (options.factorType === 'otp') {
      body.otp = options.otp;
    } else if (options.factorType === 'oob') {
      body.oob_code = options.oobCode;
      if (options.bindingCode) {
        body.binding_code = options.bindingCode;
      }
    } else if (options.factorType === 'recovery-code') {
      body.recovery_code = options.recoveryCode;
    }

    const response = await this.#options.customFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaVerifyError(error.error_description || 'Failed to verify MFA challenge', error);
    }

    const apiResponse = (await response.json()) as MfaVerifyApiResponse;

    // Decode ID token claims if present (for updateStateData to set user).
    // TokenResponse.claims expects openid-client's IDToken type, which is structurally
    // compatible with jose's JWTPayload for the fields used by updateStateData (sub, iss, etc.).
    const claims = apiResponse.id_token ? decodeJwt(apiResponse.id_token) : undefined;

    const tokenResponse = new TokenResponse(
      apiResponse.access_token,
      Math.floor(Date.now() / 1000) + apiResponse.expires_in,
      apiResponse.id_token,
      apiResponse.refresh_token,
      apiResponse.scope,
      claims as TokenResponse['claims']
    );

    // Update state data following the same pattern as completeInteractiveLogin and loginBackchannel
    const audience = options.audience ?? this.#options.defaultAudience;
    const existingStateData = await this.#options.stateStore.get(
      this.#options.stateStoreIdentifier,
      storeOptions
    );

    const updatedStateData = updateStateData(audience, existingStateData, tokenResponse);

    await this.#options.stateStore.set(
      this.#options.stateStoreIdentifier,
      updatedStateData,
      true,
      storeOptions
    );

    const result: MfaVerifyResponse = {
      accessToken: apiResponse.access_token,
      tokenType: apiResponse.token_type,
      expiresIn: apiResponse.expires_in,
      scope: apiResponse.scope,
    };

    if (apiResponse.id_token) {
      result.idToken = apiResponse.id_token;
    }

    if (apiResponse.refresh_token) {
      result.refreshToken = apiResponse.refresh_token;
    }

    if (apiResponse.recovery_code) {
      result.recoveryCode = apiResponse.recovery_code;
    }

    return result;
  }
}
