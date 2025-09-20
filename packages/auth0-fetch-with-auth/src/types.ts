export type ResponseHeaders =
  | Record<string, string | null | undefined>
  | [string, string][]
  | { get(name: string): string | null | undefined };

export type CustomFetchMinimalOutput = {
  status: number;
  headers: ResponseHeaders;
};

export type CustomFetchImpl<TOutput extends CustomFetchMinimalOutput> = (
  req: Request
) => Promise<TOutput>;

export type AuthParams = {
  scope?: string[];
  audience?: string;
};

export type AccessTokenFactory<TAuthParams> = (
  authParams?: TAuthParams
) => Promise<string>;

export type FetcherConfig<TOutput extends CustomFetchMinimalOutput> = {
  baseUrl?: string;
  fetch?: CustomFetchImpl<TOutput>;
  dpopNonceId?: string;
};

export type FetcherHooks<TAuthParams = unknown> = {
  isDpopEnabled: () => boolean;
  getAccessToken: AccessTokenFactory<TAuthParams>;
  getDpopNonce: () => Promise<string | undefined>;
  setDpopNonce: (nonce: string) => Promise<void>;
  generateDpopProof: (params: {
    url: string;
    method: string;
    nonce?: string;
    accessToken: string;
  }) => Promise<string>;
};
