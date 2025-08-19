import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { JWTPayload } from "jose";
/**
 * Claims extracted from a validated Auth0 access token.
 *
 * This reflects Auth0's specific use of `azp`, `scope`, `aud`, and optional user profile fields.
 *
 * @public
 */
export interface AccessTokenClaims extends JWTPayload {
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

/**
 * Extended authentication information for Auth0-authenticated users.
 *
 * This interface extends the standard MCP AuthInfo with Auth0-specific user identity
 * claims extracted from JWT access tokens. It provides comprehensive user context
 * for MCP tool handlers and middleware.
 *
 **/
export interface Auth extends AuthInfo {
  extra: {
    /** User identifier from Auth0. */
    sub: string;

    /** Standard OAuth 2.0 client_id claim, if available. */
    client_id?: string;

    /** Auth0-specific azp (authorized party) claim, if available. */
    azp?: string;

    /** User's full name, if available. */
    name?: string;

    /** User's email address, if available. */
    email?: string;
  };
}
