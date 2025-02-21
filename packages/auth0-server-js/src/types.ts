export interface Auth0ClientOptions {
  domain: string;
  clientId: string;
  clientSecret: string;

  transactionStore?: TransactionStore;
}

export interface UserClaims {
  sub: string;
  name?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  org_id?: string;

  [key: string]: unknown;
}

export interface AuthorizationParameters {
  scope?: string;
  audience?: string;
  redirect_uri: string;
}

export interface BuildAuthorizationUrlOptions {
  authorizationParams: AuthorizationParameters;
}

export interface TransactionData {
  state: string;
  audience?: string;
  [key: string]: unknown;
}

export interface AbstractDataStore<TData, TStoreOptions = unknown> {
  set(identifier: string, state: TData, options?: TStoreOptions): Promise<void>;

  get(identifier: string, options?: TStoreOptions): Promise<TData | undefined>;

  delete(identifier: string, options?: TStoreOptions): Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface TransactionStore<TStoreOptions = unknown>
  extends AbstractDataStore<TransactionData, TStoreOptions> {}
