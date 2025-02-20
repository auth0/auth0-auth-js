import * as client from 'openid-client';
import { Auth0ClientOptions, BuildAuthorizationUrlOptions } from './types.js';
import { ClientNotInitializedError } from './errors/index.js';

export class Auth0Client {
  readonly #options: Auth0ClientOptions;
  #configuration: client.Configuration | undefined;
  #serverMetadata: client.ServerMetadata | undefined;

  constructor(options: Auth0ClientOptions) {
    this.#options = options;
  }

  /**
   * Initialized the SDK by performing Metadata Discovery.
   */
  public async init() {
    this.#configuration = await client.discovery(new URL(`https://${this.#options.domain}`), this.#options.clientId, {
      client_secret: this.#options.clientSecret,
    });

    this.#serverMetadata = this.#configuration.serverMetadata();
  }

  /**
   * Returns a URL to redirect the user-agent to to request authorization at Auth0.
   * @param param0
   * @returns {URL}
   */
  public async buildAuthorizationUrl(options: BuildAuthorizationUrlOptions) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    const params = new URLSearchParams({
      client_id: this.#options.clientId,
      client_secret: this.#options.clientSecret,
      scope: options.authorizationParams.scope ?? 'openid profile email offline_access',
      redirect_uri: options.authorizationParams.redirect_uri,
    });

    if (options.authorizationParams.audience) {
      params.append('audience', options.authorizationParams.audience);
    }

    return client.buildAuthorizationUrl(this.#configuration, params);
  }

  /**
   * Takes an URL, extract the Authorization Code flow query parameters and requests a token.
   * @returns The access token, as returned from Auth0.
   */
  public async handleCallback(url: URL) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    const tokenEndpointResponse = await client.authorizationCodeGrant(this.#configuration, url);

    return tokenEndpointResponse.access_token;
  }

  /**
   * Returns a URL to redirect the user-agent to after they log out.
   * @param param0
   * @returns {URL}
   */
  public async buildLogoutUrl({ returnTo }: { returnTo: string }) {
    if (!this.#configuration || !this.#serverMetadata) {
      throw new ClientNotInitializedError();
    }

    return client.buildEndSessionUrl(this.#configuration, {
      post_logout_redirect_uri: returnTo,
    });
  }
}
