import { DPOP_NONCE_HEADER } from './dpop/utils.js';
import { UseDpopNonceError } from './errors.js';
import type { AuthParams, FetcherConfig } from './types.js';
import {
  buildUrl,
  extractUrl,
  getHeader,
  hasUseDpopNonceError,
  retryOnError,
} from './utils.js';

export class Fetcher<
  TOutput extends Response = Response,
  TAuthParams = AuthParams
> {
  readonly #config: Omit<FetcherConfig<TOutput, TAuthParams>, 'fetch'> &
    Required<Pick<FetcherConfig<TOutput, TAuthParams>, 'fetch'>>;

    readonly #isDpopEnabled: boolean;

  constructor(config: FetcherConfig<TOutput, TAuthParams>) {
    this.#config = {
      ...config,
      fetch:
        config.fetch ||
        // For easier testing and constructor compatibility with SSR.
        ((typeof window === 'undefined'
          ? fetch
          : window.fetch.bind(window)) as unknown as () => Promise<TOutput>),
    };

    this.#isDpopEnabled = Boolean(this.#config.dpopProvider);
  }

  protected buildBaseRequest(
    info: RequestInfo | URL,
    init: RequestInit | undefined
  ): Request {
    // In the native `fetch()` behavior, `init` can override `info` and the result
    // is the merge of both. So let's replicate that behavior by passing those into
    // a fresh `Request` object.

    // No `baseUrl`? We can use `info` and `init` as is.
    if (!this.#config.baseUrl) {
      return new Request(info, init);
    }

    // But if `baseUrl` is present, first we have to build the final URL...
    const finalUrl = buildUrl(this.#config.baseUrl, extractUrl(info));

    // ... and then overwrite `info`'s URL with it, making sure we keep any other
    // properties that might be there already (headers, etc).
    const finalInfo =
      info instanceof Request ? new Request(finalUrl, info) : finalUrl;

    return new Request(finalInfo, init);
  }
  }

  /**
   * Sets the `Authorization` header on the request.
   *
   * @param request The request to set the header on.
   * @param accessToken The access token to set in the header.
   */
  protected setAuthorizationHeader(request: Request, accessToken: string) {
    request.headers.set(
      'authorization',
      `${this.#isDpopEnabled ? 'DPoP' : 'Bearer'} ${accessToken}`
    );
  }

  /**
   * Sets the DPoP proof header on the request if DPoP is enabled.
   * @param request The request to set the DPoP proof header on.
   * @param accessToken The access token to bind the DPoP proof to.
   */
  protected async setDpopProofHeader(
    request: Request,
    accessToken: string
  ): Promise<void> {
    // If we're not using DPoP, skip.
    if (!this.#isDpopEnabled) {
      return;
    }

    const dpopNonce = await this.#config.dpopProvider!.getNonce();

    const dpopProof = await this.#config.dpopProvider!.generateProof({
      accessToken,
      method: request.method,
      nonce: dpopNonce,
      url: request.url,
    });

    request.headers.set('dpop', dpopProof);
  }

  /**
   * Prepares the request by setting the `Authorization` header and
   * the DPoP proof if needed.
   * @param request The request to prepare.
   * @param authParams Optional parameters to pass to the access token factory.
   */
  protected async prepareRequest(request: Request, authParams?: TAuthParams) {
    const accessToken = await this.#config.tokenProvider(authParams);

    this.setAuthorizationHeader(request, accessToken);

    await this.setDpopProofHeader(request, accessToken);
  }

  /**
   * Handles the response by storing a new DPoP nonce if present and throwing
   * a `UseDpopNonceError` when the response `www-authentication` header contains
   * `use_dpop_nonce`.
   * @param response The fetch response.
   * @returns The same response if no `use_dpop_nonce` error is present.
   * @throws UseDpopNonceError when the response contains a `use_dpop_nonce` error.
   */
  protected async handleResponse(response: TOutput): Promise<TOutput> {
    const newDpopNonce = getHeader(response.headers, DPOP_NONCE_HEADER);

    if (newDpopNonce) {
      await this.#config.dpopProvider!.setNonce(newDpopNonce);
    }

    if (!hasUseDpopNonceError(response)) {
      return response;
    }

    throw new UseDpopNonceError(newDpopNonce);
  }

  /**
   * Internal fetch with auth method, to allow for retries on `use_dpop_nonce` errors.
   * @param info Request info, either a URL string or a `RequestInfo` object.
   * @param init Optional fetch init parameters.
   * @param authParams Optional parameters to pass to the access token factory.
   * @returns A promise resolving to the fetch response.
   */
  async #internalFetchWithAuth(
    info: RequestInfo | URL,
    init: RequestInit | undefined,
    authParams?: TAuthParams
  ): Promise<TOutput> {
    // Build the base request, applying `config.baseUrl` if needed.
    const request = this.buildBaseRequest(info, init);

    // Prepare the request by:
    // - setting the `Authorization` header
    // - setting the DPoP proof if needed.
    await this.prepareRequest(request, authParams);

    const response = await this.#config.fetch(request);

    // Handle the response by:
    // - storing a new DPoP nonce if present
    // - throwing a `UseDpopNonceError` when the response
    //   `www-authentication` header contains `use_dpop_nonce`.
    return this.handleResponse(response);
  }

  /**
   * Fetch with automatic Authorization header and DPoP support.
   * @param info Request info, either a URL string or a `RequestInfo` object.
   * @param init Optional fetch init parameters.
   * @param authParams Optional parameters to pass to the access token factory.
   * @returns A promise resolving to the fetch response.
   */
  public fetchWithAuth(
    info: RequestInfo | URL,
    init?: RequestInit,
    authParams?: TAuthParams
  ): Promise<TOutput> {
    return retryOnError(
      () => this.#internalFetchWithAuth(info, init, authParams),
      { shouldRetry: (e) => e instanceof UseDpopNonceError, maxRetries: 1 }
    );
  }
}
