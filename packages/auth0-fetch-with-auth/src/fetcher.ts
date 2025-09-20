import { DPOP_NONCE_HEADER } from './dpop/utils.js';
import { UseDpopNonceError } from './errors.js';
import type {
  CustomFetchMinimalOutput,
  FetcherConfig,
  FetcherHooks,
  FetchWithAuthCallbacks,
} from './types.js';
import { buildUrl, getHeader, hasUseDpopNonceError } from './utils.js';

export class Fetcher<
  TOutput extends CustomFetchMinimalOutput,
  TAuthParams = unknown
> {
  readonly config: Omit<FetcherConfig<TOutput>, 'fetch'> &
    Required<Pick<FetcherConfig<TOutput>, 'fetch'>>;
  readonly hooks: FetcherHooks<TAuthParams>;

  constructor(
    config: FetcherConfig<TOutput>,
    hooks: FetcherHooks<TAuthParams>
  ) {
    this.hooks = hooks;

    this.config = {
      ...config,
      fetch:
        config.fetch ||
        // For easier testing and constructor compatibility with SSR.
        ((typeof window === 'undefined'
          ? fetch
          : window.fetch.bind(window)) as () => Promise<any>),
    };
  }

  protected getAccessToken(authParams?: TAuthParams): Promise<string> {
    return this.config.getAccessToken
      ? this.config.getAccessToken(authParams)
      : this.hooks.getAccessToken(authParams);
  }

  protected buildBaseRequest(
    info: RequestInfo | URL,
    init: RequestInit | undefined
  ): Request {
    // In the native `fetch()` behavior, `init` can override `info` and the result
    // is the merge of both. So let's replicate that behavior by passing those into
    // a fresh `Request` object.
    const request = new Request(info, init);

    // No `baseUrl` config, use whatever the URL the `Request` came with.
    if (!this.config.baseUrl) {
      return request;
    }

    return new Request(buildUrl(this.config.baseUrl, request.url), request);
  }

  protected async setAuthorizationHeader(
    request: Request,
    accessToken: string
  ): Promise<void> {
    request.headers.set(
      'authorization',
      `${this.config.dpopNonceId ? 'DPoP' : 'Bearer'} ${accessToken}`
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
    if (!this.config.dpopNonceId) {
      return;
    }

    const dpopNonce = await this.hooks.getDpopNonce();

    const dpopProof = await this.hooks.generateDpopProof({
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
    const accessToken = await this.getAccessToken(authParams);

    this.setAuthorizationHeader(request, accessToken);

    await this.setDpopProofHeader(request, accessToken);
  }

  protected async handleResponse(
    response: TOutput,
    callbacks: FetchWithAuthCallbacks<TOutput>
  ): Promise<TOutput> {
    const newDpopNonce = getHeader(response.headers, DPOP_NONCE_HEADER);

    if (newDpopNonce) {
      await this.hooks.setDpopNonce(newDpopNonce);
    }

    if (!hasUseDpopNonceError(response)) {
      return response;
    }

    // After a `use_dpop_nonce` error, if we didn't get a new DPoP nonce or we
    // did but it still got rejected for the same reason, we have to give up.
    if (!newDpopNonce || !callbacks.onUseDpopNonceError) {
      throw new UseDpopNonceError(newDpopNonce);
    }

    return callbacks.onUseDpopNonceError();
  }

  async #internalFetchWithAuth(
    info: RequestInfo | URL,
    init: RequestInit | undefined,
    callbacks: FetchWithAuthCallbacks<TOutput>,
    authParams?: TAuthParams
  ): Promise<TOutput> {
    const request = this.buildBaseRequest(info, init);

    await this.prepareRequest(request, authParams);

    const response = await this.config.fetch(request);

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
    const callbacks: FetchWithAuthCallbacks<TOutput> = {
      onUseDpopNonceError: () =>
        this.#internalFetchWithAuth(
          info,
          init,
          {
            ...callbacks,
            // Retry on a `use_dpop_nonce` error, but just once.
            onUseDpopNonceError: undefined,
          },
          authParams
        ),
    };

    return this.#internalFetchWithAuth(info, init, callbacks, authParams);
  }
}
