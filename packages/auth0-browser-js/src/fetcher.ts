import type { BrowserClient } from './browser-client.js';
import type { FetcherConfig, FetchWithAuthParams, GetTokenSilentlyVerboseResponse } from './types.js';

/**
 * Authenticated HTTP client for making requests with automatic token injection
 */
export class Fetcher<TOutput = unknown> {
  #client: BrowserClient;
  #config: FetcherConfig<TOutput>;

  constructor(client: BrowserClient, config: FetcherConfig<TOutput> = {}) {
    this.#client = client;
    this.#config = config;
  }

  /**
   * Make an authenticated HTTP request with automatic token injection
   *
   * @param info - The request URL or Request object
   * @param init - Optional request initialization options
   * @param authParams - Optional parameters for token acquisition (audience, scope)
   * @returns The response from the fetch call
   */
  async fetchWithAuth(
    info: RequestInfo | URL,
    init?: RequestInit,
    authParams?: FetchWithAuthParams,
  ): Promise<TOutput> {
    // Get access token
    const tokenGetter = this.#config.getAccessToken ?? (() => this.#client.getTokenSilently({
      authorizationParams: {
        audience: authParams?.audience,
        scope: authParams?.scope,
      },
      detailedResponse: true,
    }));

    const tokenResult = await tokenGetter();
    const accessToken = typeof tokenResult === 'string'
      ? tokenResult
      : (tokenResult as GetTokenSilentlyVerboseResponse).access_token;

    // Build request URL
    const url = this.#buildUrl(info);
    const method = init?.method ?? 'GET';

    // Prepare headers
    const headers = new Headers(init?.headers);

    // Check if DPoP is enabled
    const isDpopEnabled = this.#isDpopEnabled();

    if (isDpopEnabled) {
      // Add DPoP authorization header
      headers.set('Authorization', `DPoP ${accessToken}`);

      // Generate and add DPoP proof
      try {
        const dpopProof = await this.#generateDpopProof(url.toString(), method, accessToken);
        headers.set('DPoP', dpopProof);
      } catch (error) {
        // Fall back to Bearer token if DPoP fails
        console.warn('DPoP proof generation failed, falling back to Bearer token:', error);
        headers.set('Authorization', `Bearer ${accessToken}`);
      }
    } else {
      // Standard Bearer token authorization
      headers.set('Authorization', `Bearer ${accessToken}`);
    }

    // Build request
    const request = new Request(url, {
      ...init,
      method,
      headers,
    });

    // Use custom fetch or default
    const fetchFn = this.#config.fetch;

    if (fetchFn) {
      // Use custom fetch function
      return fetchFn(request);
    }

    // Use standard fetch
    try {
      const response = await fetch(request);

      // Check for DPoP nonce error and retry
      if (isDpopEnabled && response.status === 401) {
        const dpopNonce = response.headers.get('DPoP-Nonce');
        if (dpopNonce) {
          // Store nonce and retry with new proof
          this.#client.setDpopNonce(dpopNonce, this.#config.dpopNonceId);
          return this.#retryWithDpopNonce(request, accessToken, dpopNonce) as TOutput;
        }
      }

      return response as TOutput;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Retry request with updated DPoP nonce
   */
  async #retryWithDpopNonce(request: Request, accessToken: string, nonce: string): Promise<TOutput> {
    const url = request.url;
    const method = request.method;

    // Generate new DPoP proof with nonce
    const dpopProof = await this.#generateDpopProof(url, method, accessToken, nonce);

    // Update DPoP header
    const headers = new Headers(request.headers);
    headers.set('DPoP', dpopProof);

    // Clone request with updated headers
    const retryRequest = new Request(url, {
      method: request.method,
      headers,
      body: request.body,
      mode: request.mode,
      credentials: request.credentials,
      cache: request.cache,
      redirect: request.redirect,
      referrer: request.referrer,
      integrity: request.integrity,
    });

    // Use custom fetch or default
    const fetchFn = this.#config.fetch ?? fetch;
    const response = await fetchFn(retryRequest);

    return response as TOutput;
  }

  /**
   * Build full URL from request info
   */
  #buildUrl(info: RequestInfo | URL): URL {
    let urlString: string;

    if (info instanceof URL) {
      urlString = info.toString();
    } else if (info instanceof Request) {
      urlString = info.url;
    } else {
      urlString = info;
    }

    // Prepend base URL if configured and URL is relative
    if (this.#config.baseUrl && !urlString.startsWith('http://') && !urlString.startsWith('https://')) {
      urlString = `${this.#config.baseUrl}${urlString.startsWith('/') ? '' : '/'}${urlString}`;
    }

    return new URL(urlString);
  }

  /**
   * Check if DPoP is enabled
   */
  #isDpopEnabled(): boolean {
    try {
      this.#client.getDpopNonce();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Generate DPoP proof
   */
  async #generateDpopProof(
    url: string,
    method: string,
    accessToken: string,
    nonce?: string,
  ): Promise<string> {
    const dpopNonce = nonce ?? this.#client.getDpopNonce(this.#config.dpopNonceId);

    return this.#client.generateDpopProof({
      url,
      method,
      nonce: dpopNonce,
      accessToken,
    });
  }
}
