import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, customFetch } from 'jose';
import { AuthClient } from '@auth0/auth0-auth-js';
import { ApiClientOptions, VerifyAccessTokenOptions } from './types.js';
import {
  MissingRequiredArgumentError,
  VerifyAccessTokenError,
} from './errors.js';

export class ApiClient {
  #serverMetadata: oauth.AuthorizationServer | undefined;
  readonly #options: ApiClientOptions;
  #jwks?: ReturnType<typeof createRemoteJWKSet>;

  /**
   * The underlying `authClient` instance that can be used to interact with the Auth0 Authentication API.
   */
  readonly authClient: AuthClient | undefined;

  constructor(options: ApiClientOptions) {
    this.#options = options;

    if (options.authClientOptions) {
      this.authClient = new AuthClient(options.authClientOptions);
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
        algorithms: ['RS256'],
        requiredClaims: ['iat', 'exp', ...(options.requiredClaims || [])],
      });
      return payload;
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      throw new VerifyAccessTokenError((e as any).message);
    }
  }
}
