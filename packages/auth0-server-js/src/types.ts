import { AuthorizationDetails } from '@auth0/auth0-auth-js';

export interface ServerClientOptions<TStoreOptions = unknown> {
  domain: string;
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  authorizationParams?: AuthorizationParameters;
  transactionIdentifier?: string;
  stateIdentifier?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  transactionStore: TransactionStore<TStoreOptions>;
  stateStore: StateStore<TStoreOptions>;
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
  redirect_uri?: string;

  [key: string]: unknown;
}

export interface TokenSet {
  audience: string;
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
}

export interface ConnectionTokenSet {
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
  connection: string;
  loginHint?: string;
}

export interface InternalStateData {
  sid: string;
  createdAt: number;
}

export interface StateData extends SessionData {
  internal: InternalStateData;
}

export interface SessionData {
  user: UserClaims | undefined;
  idToken: string | undefined;
  refreshToken: string | undefined;
  tokenSets: TokenSet[];
  connectionTokenSets?: ConnectionTokenSet[];

  [key: string]: unknown;
}

export interface TransactionData {
  audience?: string;
  codeVerifier: string;
  [key: string]: unknown;
}

export interface AbstractDataStore<TData, TStoreOptions = unknown> {
  set(identifier: string, state: TData, removeIfExists?: boolean, options?: TStoreOptions): Promise<void>;

  get(identifier: string, options?: TStoreOptions): Promise<TData | undefined>;

  delete(identifier: string, options?: TStoreOptions): Promise<void>;
}

export type LogoutTokenClaims = { sub?: string; sid?: string };

export interface StateStore<TStoreOptions = unknown> extends AbstractDataStore<StateData, TStoreOptions> {
  deleteByLogoutToken(claims: LogoutTokenClaims, options?: TStoreOptions): Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface TransactionStore<TStoreOptions = unknown> extends AbstractDataStore<TransactionData, TStoreOptions> {}

export interface EncryptedStoreOptions {
  secret: string;
}

export interface StartInteractiveLoginOptions<TAppState = unknown> {
  pushedAuthorizationRequests?: boolean;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

export interface LoginBackchannelOptions {
  bindingMessage: string;
  loginHint: {
    sub: string;
  };
  authorizationParams?: AuthorizationParameters;
}

export interface LoginBackchannelResult {
  authorizationDetails?: AuthorizationDetails[];
}

export interface AccessTokenForConnectionOptions {
  connection: string;
  loginHint?: string;
}

export interface LogoutOptions {
  returnTo: string;
}

export interface StartLinkUserOptions<TAppState = unknown> {
  connection: string;
  connectionScope: string;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}

export interface StartUnlinkUserOptions<TAppState = unknown> {
  connection: string;
  appState?: TAppState;
  authorizationParams?: AuthorizationParameters;
}