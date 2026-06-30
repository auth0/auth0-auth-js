export interface DatabaseClientOptions {
  domain: string;
  clientId: string;
  customFetch?: typeof fetch;
}

export interface SignUpOptions {
  email: string;
  password: string;
  connection: string;
  clientId?: string;
  username?: string;
  givenName?: string;
  familyName?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  userMetadata?: Record<string, unknown>;
}

export interface ChangePasswordOptions {
  email: string;
  connection: string;
  clientId?: string;
  organization?: string;
}

export interface SignUpResult {
  id?: string;
  email: string;
  emailVerified: boolean;
  username?: string;
  givenName?: string;
  familyName?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  userMetadata?: Record<string, unknown>;
}
