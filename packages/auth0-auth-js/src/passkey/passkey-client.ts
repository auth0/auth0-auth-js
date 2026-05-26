import type {
  PasskeyClientOptions,
  PasskeySignupChallengeOptions,
  PasskeySignupChallengeResponse,
  PasskeySignupChallengeApiResponse,
  PasskeyLoginChallengeOptions,
  PasskeyLoginChallengeResponse,
  PasskeyLoginChallengeApiResponse,
  GetTokenByPasskeyOptions,
  GrantRequestFn,
} from './types.js';
import type { TokenResponse } from '../types.js';
import {
  PasskeyRegisterError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
  type PasskeyApiErrorResponse,
} from './errors.js';
import {
  transformSignupChallengeResponse,
  transformLoginChallengeResponse,
} from './utils.js';

const PASSKEY_GRANT_TYPE = 'urn:okta:params:oauth:grant-type:webauthn';

export class PasskeyClient {
  #baseUrl: string;
  #clientId: string;
  #customFetch: typeof fetch;
  #grantRequest: GrantRequestFn;

  /**
   * @internal
   */
  constructor(options: PasskeyClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#customFetch = options.customFetch ?? ((...args) => fetch(...args));
    this.#grantRequest = options.grantRequest;
  }

  async #parseErrorResponse(response: Response): Promise<PasskeyApiErrorResponse> {
    try {
      return (await response.json()) as PasskeyApiErrorResponse;
    } catch {
      return {
        error: 'unknown_error',
        error_description: `HTTP ${response.status} ${response.statusText}`,
      };
    }
  }

  /**
   * Requests a passkey signup challenge for a new user.
   *
   * Returns the WebAuthn public key creation options that should be passed to
   * the platform's credential manager (e.g., `navigator.credentials.create()`)
   * to register a new passkey.
   *
   * @param options - User profile data and optional realm
   * @returns Promise resolving to the signup challenge with auth session and public key creation options
   * @throws {PasskeyRegisterError} When the challenge request fails
   *
   * @example
   * ```typescript
   * const challenge = await authClient.passkey.register({
   *   email: 'user@example.com',
   *   name: 'Jane Doe',
   *   realm: 'Username-Password-Authentication'
   * });
   * ```
   */
  async register(options: PasskeySignupChallengeOptions): Promise<PasskeySignupChallengeResponse> {
    const url = `${this.#baseUrl}/passkey/register`;

    const body: Record<string, unknown> = {
      client_id: this.#clientId,
      user_profile: {
        ...(options.email && { email: options.email }),
        ...(options.name && { name: options.name }),
        ...(options.phoneNumber && { phone_number: options.phoneNumber }),
        ...(options.username && { username: options.username }),
      },
    };

    if (options.realm) body.realm = options.realm;

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await this.#parseErrorResponse(response);
      throw new PasskeyRegisterError(error.error_description || 'Failed to request signup challenge', error);
    }

    const apiResponse = (await response.json()) as PasskeySignupChallengeApiResponse;
    return transformSignupChallengeResponse(apiResponse);
  }

  /**
   * Requests a passkey login challenge for an existing user.
   *
   * Returns the WebAuthn public key request options that should be passed to
   * the platform's credential manager (e.g., `navigator.credentials.get()`)
   * to retrieve an existing passkey.
   *
   * @param options - Optional realm configuration
   * @returns Promise resolving to the login challenge with auth session and public key request options
   * @throws {PasskeyChallengeError} When the challenge request fails
   *
   * @example
   * ```typescript
   * const challenge = await authClient.passkey.challenge({
   *   realm: 'Username-Password-Authentication'
   * });
   * ```
   */
  async challenge(options?: PasskeyLoginChallengeOptions): Promise<PasskeyLoginChallengeResponse> {
    const url = `${this.#baseUrl}/passkey/challenge`;

    const body: Record<string, unknown> = {
      client_id: this.#clientId,
    };

    if (options?.realm) body.realm = options.realm;

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await this.#parseErrorResponse(response);
      throw new PasskeyChallengeError(error.error_description || 'Failed to request login challenge', error);
    }

    const apiResponse = (await response.json()) as PasskeyLoginChallengeApiResponse;
    return transformLoginChallengeResponse(apiResponse);
  }

  /**
   * Exchanges a passkey credential for tokens using the WebAuthn grant type.
   *
   * This method should be called after obtaining a credential response from the
   * platform's WebAuthn API (via `navigator.credentials.create()` for signup or
   * `navigator.credentials.get()` for login), using the challenge obtained from
   * `register()` or `challenge()`.
   *
   * @param options - The auth session and serialized credential response
   * @returns Promise resolving to a TokenResponse with access token, ID token, and optional refresh token
   * @throws {PasskeyGetTokenError} When the token exchange fails
   *
   * @example
   * ```typescript
   * const challenge = await authClient.passkey.challenge();
   * // Pass challenge.authnParamsPublicKey to navigator.credentials.get()
   * // Then serialize the credential response and exchange for tokens:
   * const tokens = await authClient.passkey.getTokenByPasskey({
   *   authSession: challenge.authSession,
   *   credential: serializedCredential,
   *   scope: 'openid profile email',
   *   audience: 'https://api.example.com',
   * });
   * ```
   */
  async getTokenByPasskey(options: GetTokenByPasskeyOptions): Promise<TokenResponse> {
    const params = new URLSearchParams({
      auth_session: options.authSession,
      authn_response: JSON.stringify(options.credential),
    });

    if (options.realm) params.append('realm', options.realm);
    if (options.scope) params.append('scope', options.scope);
    if (options.audience) params.append('audience', options.audience);

    try {
      return await this.#grantRequest(PASSKEY_GRANT_TYPE, params);
    } catch (e) {
      const cause = (e && typeof e === 'object' && 'error' in e && 'error_description' in e)
        ? e as PasskeyApiErrorResponse
        : undefined;
      throw new PasskeyGetTokenError('Failed to exchange passkey credential for tokens.', cause);
    }
  }
}
