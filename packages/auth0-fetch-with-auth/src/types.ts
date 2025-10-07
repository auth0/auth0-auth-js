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

export interface DpopProvider {
    getNonce(): Promise<string | undefined>;
    setNonce(nonce: string): Promise<void>;
    generateProof(params: {
        url: string;
        method: string;
        nonce?: string;
        accessToken: string;
    }): Promise<string>;
}

export type AccessTokenFactory<TAuthParams> = (
  authParams?: TAuthParams
) => Promise<string>;

export type FetcherConfig<TOutput extends CustomFetchMinimalOutput, TAuthParams = unknown> = {
  baseUrl?: string;
  fetch?: CustomFetchImpl<TOutput>;
  dpopProvider?: DpopProvider;
  tokenProvider: AccessTokenFactory<TAuthParams>;
};
