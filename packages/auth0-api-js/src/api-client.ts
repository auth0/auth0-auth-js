import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, customFetch } from 'jose';
import { AuthClient, TokenForConnectionError, MissingClientAuthError } from '@auth0/auth0-auth-js';
import { AccessTokenForConnectionOptions, ApiClientOptions, ConnectionTokenSet, ExchangeProfileOptions, TokenExchangeProfileResult, VerifyAccessTokenOptions } from './types.js';
import {
  MissingRequiredArgumentError,
  VerifyAccessTokenError,
} from './errors.js';

export class ApiClient {
  #serverMetadata: oauth.AuthorizationServer | undefined;
  readonly #options: ApiClientOptions;
  #jwks?: ReturnType<typeof createRemoteJWKSet>;
  readonly #authClient: AuthClient | undefined;

  constructor(options: ApiClientOptions) {
    this.#options = options;

    if (options.clientId) {
      this.#authClient = new AuthClient({
        domain: options.domain,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        clientAssertionSigningKey: options.clientAssertionSigningKey,
        clientAssertionSigningAlg: options.clientAssertionSigningAlg,
        customFetch: options.customFetch,
      });
    }

    if (!this.#options.audience) {
      throw new MissingRequiredArgumentError('audience');
    }
  }

  /**
   * Initialized the SDK by performing Metadata Discovery.
   */
  async #discover() {
    if (this.#serverMetadata) {
      return {
        serverMetadata: this.#serverMetadata,
      };
    }

    const issuer = new URL(`https://${this.#options.domain}`);
    const response = await oauth.discoveryRequest(issuer, {
      [oauth.customFetch]: this.#options.customFetch,
    });

    this.#serverMetadata = await oauth.processDiscoveryResponse(
      issuer,
      response
    );

    return {
      serverMetadata: this.#serverMetadata,
    };
  }

  /**
   * Verifies the provided access token against the ApiClient's configured audience.
   *
   * This method validates the JWT signature using the Auth0 tenant's JWKS and verifies
   * standard claims including issuer, expiration, and issued-at time. The audience claim
   * is verified against the audience configured when constructing the ApiClient.
   *
   * @param options Options containing the access token and optional required claims.
   * @returns Promise resolving to the verified token payload containing all JWT claims.
   * @throws {VerifyAccessTokenError} When verification fails due to invalid signature,
   *                                   expired token, mismatched audience, or missing required claims.
   *
   * @example
   * ```typescript
   * const apiClient = new ApiClient({
   *   domain: 'example.auth0.com',
   *   audience: 'https://api.example.com', // This audience is used for verification
   *   clientId: 'client123',
   *   clientSecret: 'secret'
   * });
   *
   * const payload = await apiClient.verifyAccessToken({
   *   accessToken: 'eyJhbGc...'
   * });
   * ```
   */
  async verifyAccessToken(options: VerifyAccessTokenOptions) {
    const { serverMetadata } = await this.#discover();

    this.#jwks ||= createRemoteJWKSet(new URL(serverMetadata!.jwks_uri!), {
      [customFetch]: this.#options.customFetch,
    });

    try {
      const { payload } = await jwtVerify(options.accessToken, this.#jwks, {
        issuer: this.#serverMetadata!.issuer,
        audience: this.#options.audience,
        algorithms: ['RS256'],
        requiredClaims: ['iat', 'exp', ...(options.requiredClaims || [])],
      });
      return payload;
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      throw new VerifyAccessTokenError((e as any).message);
    }
  }

  /**
   * Retrieves an access token for a connection.
   *
   * @param options - Options for retrieving an access token for a connection.
   *
   * @throws {TokenForConnectionError} If there was an issue requesting the access token.
   *
   * @returns The Connection Token Set, containing the access token for the connection, as well as additional information.
   */
  public async getAccessTokenForConnection(options: AccessTokenForConnectionOptions): Promise<ConnectionTokenSet> {
    if (!this.#authClient) {
      throw new TokenForConnectionError(
        'Client credentials are required to use getAccessTokenForConnection'
      );
    }

    const tokenEndpointResponse = await this.#authClient.getTokenForConnection({
      connection: options.connection,
      loginHint: options.loginHint,
      accessToken: options.accessToken,
    });

    return {
      accessToken: tokenEndpointResponse.accessToken,
      scope: tokenEndpointResponse.scope,
      expiresAt: tokenEndpointResponse.expiresAt,
      connection: options.connection,
      loginHint: options.loginHint,
    };
  }

  /**
   * Exchanges a token via a Custom Token Exchange Profile for a different API audience while preserving user identity (RFC 8693).
   *
   * This method supports **Custom Token Exchange** for custom token types via a configured Token Exchange Profile.
   *
   * For **Access Token Exchange with Token Vault** (external provider's access tokens), use {@link getAccessTokenForConnection} instead.
   *
   * **Note**: This method requires a confidential client (client credentials must be configured).
   * While Custom Token Exchange Early Access technically permits public clients, this implementation
   * currently requires client authentication. Public client support may be added in a future release.
   *
   * @param subjectToken - The raw token to be exchanged (without "Bearer " prefix)
   * @param options - Configuration for the token exchange
   *
   * @returns A promise that resolves with the {@link TokenExchangeProfileResult}
   *
   * @throws {TokenExchangeError} When client credentials are not configured or exchange fails
   *
   * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Custom Token Exchange Documentation}
   *
   * @example
   * ```typescript
   * const result = await apiClient.getTokenByExchangeProfile(
   *   userToken,
   *   {
   *     subjectTokenType: 'urn:example:custom-token',
   *     audience: 'https://api.backend.com',
   *     scope: 'read:data write:data',
   *   }
   * );
   * ```
   */
  public async getTokenByExchangeProfile(
    subjectToken: string,
    options: ExchangeProfileOptions
  ): Promise<TokenExchangeProfileResult> {
    if (!this.#authClient) {
      throw new MissingClientAuthError();
    }

    const response = await this.#authClient.exchangeToken({
      subjectTokenType: options.subjectTokenType,
      subjectToken,
      audience: options.audience,
      scope: options.scope,
      requestedTokenType: options.requestedTokenType,
    });

    return {
      accessToken: response.accessToken,
      expiresAt: response.expiresAt,
      ...(response.scope && { scope: response.scope }),
      ...(response.idToken && { idToken: response.idToken }),
      ...(response.refreshToken && { refreshToken: response.refreshToken }),
      ...(response.tokenType && { tokenType: response.tokenType }),
      ...(response.issuedTokenType && { issuedTokenType: response.issuedTokenType }),
    };
  }
}
