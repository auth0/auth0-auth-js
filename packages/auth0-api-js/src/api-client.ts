import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, customFetch } from 'jose';
import { AuthClient, SUBJECT_TYPE_ACCESS_TOKEN } from '@auth0/auth0-auth-js';
import { 
  ApiClientOptions, 
  VerifyAccessTokenOptions,
  ConnectionTokenOptions,
  ConnectionTokenResult
} from './types.js';
import {
  MissingRequiredArgumentError,
  VerifyAccessTokenError,
  ClientAuthenticationError,
  ConnectionTokenError,
} from './errors.js';

export class ApiClient {
  #serverMetadata: oauth.AuthorizationServer | undefined;
  readonly #options: ApiClientOptions;
  #jwks?: ReturnType<typeof createRemoteJWKSet>;
  #authClient?: AuthClient; // AuthClient from @auth0/auth0-auth-js (optional)

  constructor(options: ApiClientOptions) {
    this.#options = options;

    if (!this.#options.audience) {
      throw new MissingRequiredArgumentError('audience');
    }

    // Initialize AuthClient if client credentials are provided
    if (this.#hasClientCredentials()) {
      this.#initializeAuthClient();
    }
  }

  /**
   * Check if client credentials are provided for enhanced functionality.
   */
  #hasClientCredentials(): boolean {
    return !!(this.#options.clientId && 
             (this.#options.clientSecret || this.#options.clientAssertionSigningKey));
  }

  /**
   * Initialize the AuthClient for enhanced operations.
   */
  #initializeAuthClient() {
    this.#authClient = new AuthClient({
      domain: this.#options.domain,
      clientId: this.#options.clientId!,
      clientSecret: this.#options.clientSecret,
      clientAssertionSigningKey: this.#options.clientAssertionSigningKey,
      clientAssertionSigningAlg: this.#options.clientAssertionSigningAlg,
      authorizationParams: this.#options.tokenEndpointParams,
      customFetch: this.#options.customFetch,
    });
  }

  /**
   * Validate that client authentication is available for the requested operation.
   */
  #requiresClientAuth() {
    if (!this.#authClient) {
      throw new ClientAuthenticationError(
        'This operation requires client credentials. Please provide clientId and clientSecret (or clientAssertionSigningKey) in the ApiClient options.'
      );
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
   * Verifies the provided access token.
   * @param options Options used to verify the logout token.
   * @returns
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
   * Retrieves an access token for a federated connection.
   * @param options Options for retrieving the connection token.
   * @returns A promise resolving to the connection token result.
   * @throws {ConnectionTokenError} If there was an issue retrieving the connection token.
   * @throws {ClientAuthenticationError} If client credentials are required but not provided.
   */
  async getTokenForConnection(options: ConnectionTokenOptions): Promise<ConnectionTokenResult> {
    this.#requiresClientAuth();

    try {
      // Use the enhanced AuthClient.getTokenForConnection with proper token type constants
      const tokenResponse = await this.#authClient!.getTokenForConnection({
        connection: options.connection,
        loginHint: options.loginHint,
        subjectToken: options.accessToken, // For API servers, this could be an access token
        subjectTokenType: SUBJECT_TYPE_ACCESS_TOKEN
      });

      return {
        accessToken: tokenResponse.accessToken,
        expiresAt: tokenResponse.expiresAt,
        scope: tokenResponse.scope,
        connection: options.connection,
        loginHint: options.loginHint,
      };
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      throw new ConnectionTokenError(`Failed to retrieve connection token: ${(e as any).message}`);
    }
  }
}
