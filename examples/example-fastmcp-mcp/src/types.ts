import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type * as jose from "jose";

/**
 * Claims extracted from a validated Auth0 access token.
 *
 * This reflects Auth0's specific use of `azp`, `scope`, `aud`, and optional user profile fields.
 *
 * @public
 */
export interface AccessTokenClaims extends jose.JWTPayload {
  /** User identifier in Auth0. */
  sub: string;

  /** Standard OAuth 2.0 client_id claim that identifies the client application. */
  client_id?: string;

  /** Auth0-specific "authorized party" claim that identifies the client application. */
  azp?: string;

  /** Audience claim - identifies the intended recipient of the token. */
  aud?: string | string[];

  /** Token type - should be "Bearer" for access tokens. */
  typ?: string;

  /** Space-delimited list of OAuth scopes granted to the token. */
  scope?: string;

  /** User's full name from the Auth0 user profile. */
  name?: string;

  /** User's email address from the Auth0 user profile. */
  email?: string;
}

// FastMCP compatible AuthInfo type
export type FastMCPAuthSession = AuthInfo & { [key: string]: unknown };
