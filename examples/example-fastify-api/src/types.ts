export interface Auth0FastifyApiOptions {
  domain: string;
  audience: string;
}

export interface AuthRouteOptions {
  scopes?: string[];
}

export interface Token {
  sub?: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
}
