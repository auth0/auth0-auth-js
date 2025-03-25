export interface Auth0JwtModuleOptions {
  domain: string;
  audience: string;
  requiredClaims?: string[];
}

export interface Auth0ProtectedMetadata {
  scopes?: string[];
}

export const AUTH0_JWT_MODULE_OPTIONS = 'AUTH0_JWT_MODULE_OPTIONS';
export const AUTH0_API_CLIENT = 'AUTH0_API_CLIENT';