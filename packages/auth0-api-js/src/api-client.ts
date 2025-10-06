import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, customFetch } from 'jose';
import { AuthClient, TokenForConnectionError } from '@auth0/auth0-auth-js';
import { AccessTokenForConnectionOptions, ApiClientOptions, ConnectionTokenSet, VerifyAccessTokenOptions } from './types.js';
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
        algorithms: options.algorithms ?? ['RS256', 'PS256'],
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
}
