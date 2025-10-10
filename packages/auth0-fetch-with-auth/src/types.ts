export type ResponseHeaders =
  | Record<string, string | null | undefined>
  | [string, string][]
  | { get(name: string): string | null | undefined };

export type CustomFetchImpl<TOutput extends Response> = (
  req: Request
) => Promise<TOutput>;

export type AuthParams = {
  scope?: string[];
  audience?: string;
};

export interface DpopProvider {
  getNonce(): Promise<string | undefined>;
  setNonce(nonce: string): Promise<void>;
  getPrivateKeyPair(): Promise<CryptoKeyPair>;
}

export type AccessTokenFactory<TAuthParams> = (
  authParams?: TAuthParams
) => Promise<string>;

export type FetcherConfig<TOutput extends Response = Response, TAuthParams = unknown> = {
  baseUrl?: string;
  fetch?: CustomFetchImpl<TOutput>;
  dpopProvider?: DpopProvider;
  tokenProvider: AccessTokenFactory<TAuthParams>;
};
