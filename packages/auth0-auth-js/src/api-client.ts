import * as client from 'openid-client';
import * as oauth from 'oauth4webapi';
import {
  createRemoteJWKSet,
  jwksCache,
  JWKSCacheInput,
  exportSPKI,
} from 'jose';
import { ApiClientOptions } from './types.js';

export class ApiClient {
  #serverMetadata: client.ServerMetadata | undefined;
  readonly #options: ApiClientOptions;
  readonly #jwksCache: JWKSCacheInput = {};

  constructor(options: ApiClientOptions) {
    this.#options = options;
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
   * Retrieves the public key for the provided token.
   * @param token
   * @returns the public key for the provided token.
   */
  async getKeyForToken(token: { header: { kid: string } }): Promise<string> {
    const { serverMetadata } = await this.#discover();
    const keyInput = createRemoteJWKSet(new URL(serverMetadata!.jwks_uri!), {
      [jwksCache]: this.#jwksCache,
    });

    const key = await keyInput(token.header);
    // TODO: If we can get Fastify-jwt to support CryptoKey's, we can avoid exporting.
    return exportSPKI(key);
  }
}
