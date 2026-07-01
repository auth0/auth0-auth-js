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
  /**
   * Additional user metadata. Server constraints: values must be strings,
   * max 10 fields, field names ≤ 100 chars, values ≤ 500 chars, no dotted keys.
   */
  userMetadata?: Record<string, string>;
}

export interface ChangePasswordOptions {
  email: string;
  connection: string;
  clientId?: string;
  organization?: string;
}

export interface SignUpResult {
  /** Normalized user identifier (from `id`, `_id`, or `user_id`). May be undefined when the server response omits an identifier. */
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
