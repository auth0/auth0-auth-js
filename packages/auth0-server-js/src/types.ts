export interface Auth0ClientOptions {
  domain: string;
  clientId: string;
  clientSecret: string;
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