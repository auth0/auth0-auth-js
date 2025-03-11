import { AuthorizationParameters } from '@auth0/auth0-auth-js';

export interface ApiClientOptions {
  /**
   * The Auth0 domain to use for authentication.
   * @example 'example.auth0.com' (without https://)
   */
  domain: string;
  /**
   * The expected JWT Access Token audience ("aud") value.
   */
  audience: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
}

export interface ApiAuthClientOptions<TStoreOptions = unknown> {
  /**
   * The Auth0 domain.
   */
  domain: string;
  /**
   * The Auth0 audience.
   */
  audience: string;
  /**
   * The client ID.
   */
  clientId: string;
  /**
   * The client secret.
   */
  clientSecret?: string;
  /**
   * The client assertion signing key.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The client assertion signing algorithm.
   */
  clientAssertionSigningAlg?: string;
  /**
   * The authorization parameters.
   */
  authorizationParams?: AuthorizationParameters;
  /**
   * The custom fetch function.
   */
  customFetch?: typeof fetch;
  /**
   * The transaction store.
   */
  transactionStore: TransactionStore<TStoreOptions>;
  /**
   * The transaction identifier.
   */
  transactionIdentifier?: string;

  onUserLinked?: (
    sub: string,
    connection: string,
    refreshToken?: string
  ) => void;
}

export interface TransactionData {
  audience?: string;
  codeVerifier: string;
  [key: string]: unknown;
}

export interface AbstractDataStore<TData, TStoreOptions = unknown> {
  set(
    identifier: string,
    state: TData,
    options?: TStoreOptions
  ): Promise<void>;

  get(identifier: string, options?: TStoreOptions): Promise<TData | undefined>;

  delete(identifier: string, options?: TStoreOptions): Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface TransactionStore<TStoreOptions = unknown>
  extends AbstractDataStore<TransactionData, TStoreOptions> {}

export interface EncryptedStoreOptions {
  secret: string;
}

export interface StartLinkUserOptions<TAppState = unknown> {
  connection: string;
  connectionScope: string;
  appState?: TAppState;
  idToken: string;
  authorizationParams?: AuthorizationParameters;
}
