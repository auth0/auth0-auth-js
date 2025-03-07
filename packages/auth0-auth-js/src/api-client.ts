import * as client from 'openid-client';
import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwksCache, JWKSCacheInput, jwtVerify } from 'jose';
import { ApiClientOptions, VerifyAccessTokenOptions } from './types.js';
import { MissingRequiredArgumentError, VerifyAccessTokenError } from './errors.js';

export class ApiClient {
  #serverMetadata: client.ServerMetadata | undefined;
  readonly #options: ApiClientOptions;
  readonly #jwksCache: JWKSCacheInput = {};

  constructor(options: ApiClientOptions) {
    this.#options = options;

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

    const response = await oauth.discoveryRequest(
      new URL(`https://${this.#options.domain}`),
      {
        [client.customFetch]: this.#options.customFetch,
      }
    );

    this.#serverMetadata = await response.json();

    return {
      serverMetadata: this.#serverMetadata,
    };
  }

  /**
   *  Verifies the provided access token.
   * @param options Options used to verify the logout token.
   * @returns
   */
  async verifyAccessToken(options: VerifyAccessTokenOptions) {
    const { serverMetadata } = await this.#discover();
    const keyInput = createRemoteJWKSet(new URL(serverMetadata!.jwks_uri!), {
      [jwksCache]: this.#jwksCache,
    });

    try {
      const { payload } = await jwtVerify(options.accessToken, keyInput, {
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
