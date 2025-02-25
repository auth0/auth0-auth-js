export interface Auth0ClientOptionsBase {
  domain: string;
  clientId: string;
  clientSecret: string;
  authorizationParams?: AuthorizationParameters;
}

export type Auth0ClientOptionsWithSecret = Auth0ClientOptionsBase & {
  secret: string;
}

export type Auth0ClientOptionsWithStore<TStoreOptions = unknown> = Auth0ClientOptionsBase & {
  transactionStore: TransactionStore<TStoreOptions>;
  stateStore: StateStore<TStoreOptions>;
}

export type Auth0ClientOptions<TStoreOptions = unknown> = Auth0ClientOptionsWithSecret | Auth0ClientOptionsWithStore<TStoreOptions>;

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

export interface TokenSet {
  audience: string;
  access_token: string;
  scope: string | undefined;
  expires_at: number;
}

export interface ConnectionTokenSet {
  access_token: string;
  scope: string | undefined;
  expires_at: number;
  connection: string;
  login_hint?: string;
}

export interface InternalStateData {
  sid: string;
  createdAt: number;
}

export interface StateData {
  user: UserClaims | undefined;
  id_token: string | undefined;
  refresh_token: string | undefined;
  tokenSets: TokenSet[];
  connectionTokenSets?: ConnectionTokenSet[];
  internal: InternalStateData;

  [key: string]: unknown;
}

export interface TransactionData {
  state: string;
  audience?: string;
  code_verifier: string;
  [key: string]: unknown;
}

export interface AbstractDataStore<TData, TStoreOptions = unknown> {
  set(identifier: string, state: TData, options?: TStoreOptions): Promise<void>;

  get(identifier: string, options?: TStoreOptions): Promise<TData | undefined>;

  delete(identifier: string, options?: TStoreOptions): Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface StateStore<TStoreOptions = unknown> extends AbstractDataStore<StateData, TStoreOptions> {}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface TransactionStore<TStoreOptions = unknown> extends AbstractDataStore<TransactionData, TStoreOptions> {}

export interface EncryptedStoreOptions {
  secret: string;
}

export interface StartLoginOptions {
  pushedAuthorizationRequests?: boolean;
}

export interface AccessTokenForConnectionOptions {
  connection: string;
  login_hint?: string;
}