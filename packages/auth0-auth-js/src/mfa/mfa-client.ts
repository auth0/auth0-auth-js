import type {
  MfaClientOptions,
  Authenticator,
  EnrollAuthenticatorParams,
  EnrollmentResponse,
  ChallengeParams,
  ChallengeResponse,
} from './types.js';
import {
  MfaListAuthenticatorsError,
  MfaEnrollmentError,
  MfaDeleteAuthenticatorError,
  MfaChallengeError,
  type MfaApiErrorResponse,
} from './errors.js';


export class MfaClient {
  #baseUrl: string;
  #mfaToken?: string;
  #clientId: string;
  #customFetch: typeof fetch;

  /**
   * @internal
   * Constructor is internal - use AuthClient.createMfaClient() instead.
   */
  constructor(options: MfaClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#customFetch = options.customFetch || fetch;
  }

  public setMfaToken(token: string) {
    this.#mfaToken = token;
  }

  /**
   * Resolves the MFA token to use, with the provided token taking precedence.
   * @param mfaToken - Optional MFA token override
   * @returns The resolved MFA token
   */
  #resolveMfaToken(mfaToken?: string): string | undefined {
    return mfaToken ?? this.#mfaToken;
  }

 
  async listAuthenticators(mfaToken?: string): Promise<Authenticator[]> {
    const url = `${this.#baseUrl}/mfa/authenticators`;
    const token = this.#resolveMfaToken(mfaToken);

    const response = await this.#customFetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
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

    return (await response.json()) as Authenticator[];
  }

  
  async enrollAuthenticator(
    params: EnrollAuthenticatorParams,
    mfaToken?: string
  ): Promise<EnrollmentResponse> {
    const url = `${this.#baseUrl}/mfa/associate`;
    const token = this.#resolveMfaToken(mfaToken);

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
    });

    if (!response.ok) {
      const error = (await response.json()) as MfaApiErrorResponse;
      throw new MfaEnrollmentError(
        error.error_description || 'Failed to enroll authenticator',
        error
      );
    }

    return (await response.json()) as EnrollmentResponse;
  }

  
  async deleteAuthenticator(authenticatorId: string, mfaToken?: string): Promise<void> {
    const url = `${this.#baseUrl}/mfa/authenticators/${encodeURIComponent(authenticatorId)}`;
    const token = this.#resolveMfaToken(mfaToken);

    const response = await this.#customFetch(url, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
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


  async challengeAuthenticator(
    params: ChallengeParams,
    mfaToken?: string
  ): Promise<ChallengeResponse> {
    const url = `${this.#baseUrl}/mfa/challenge`;
    const token = this.#resolveMfaToken(mfaToken);

    const body: Record<string, string | undefined> = {
      mfa_token: token,
      client_id: this.#clientId,
      challenge_type: params.challenge_type,
    };

    if (params.authenticator_id) {
      body.authenticator_id = params.authenticator_id;
    }

    if (params.oob_channel) {
      body.oob_channel = params.oob_channel;
    }

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
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

    return (await response.json()) as ChallengeResponse;
  }
}
