/**
 * Auth0 authentication configuration for Express MCP server.
 */

import { type RequestHandler, type Router } from "express";
import { AUTH0_DOMAIN, AUDIENCE, MCP_SERVER_URL } from "./config.js";
import { AccessTokenClaims, Auth } from "./types.js";
import { SCOPES_SUPPORTED } from "./tools.js";
import { ApiClient, VerifyAccessTokenError } from "@auth0/auth0-api-js";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { discoverAuthorizationServerMetadata } from "@modelcontextprotocol/sdk/client/auth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

/**
 * Returns a router that includes MCP authorization metadata endpoints.
 */
export async function authMetadataRouter(): Promise<Router> {
  const oauthMetadata = await discoverAuthorizationServerMetadata(
    new URL(`https://${AUTH0_DOMAIN}`)
  );

  if (!oauthMetadata) {
    throw new Error(`Failed to fetch OAuth metadata from ${AUTH0_DOMAIN}`);
  }

  return mcpAuthMetadataRouter({
    resourceServerUrl: new URL(MCP_SERVER_URL),
    scopesSupported: SCOPES_SUPPORTED,
    oauthMetadata,
  });
}

/**
 * Returns a middleware that verifies the access token and extracts user information.
 */
export function authMiddleware(): RequestHandler {
  const apiClient = new ApiClient({
    domain: AUTH0_DOMAIN,
    audience: AUDIENCE,
  });

  const verify = async (token: string): Promise<Auth> => {
    try {
      const decoded = (await apiClient.verifyAccessToken({
        accessToken: token,
      })) as AccessTokenClaims;

      const clientId = decoded.client_id ?? decoded.azp;
      if (!clientId) {
        throw new Error(
          "Token is missing required client identification (client_id or azp claim)."
        );
      }

      return {
        token,
        clientId,
        scopes:
          typeof decoded.scope === "string"
            ? decoded.scope.split(" ").filter(Boolean)
            : [],
        ...(decoded.exp && { expiresAt: decoded.exp }),
        extra: {
          sub: decoded.sub,
          ...(decoded.client_id && { client_id: decoded.client_id }),
          ...(decoded.azp && { azp: decoded.azp }),
          ...(decoded.name && { name: decoded.name }),
          ...(decoded.email && { email: decoded.email }),
        },
      };
    } catch (error) {
      if (error instanceof VerifyAccessTokenError) {
        throw new InvalidTokenError(error.message);
      }
      throw error;
    }
  };

  return requireBearerAuth({
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(
      new URL(MCP_SERVER_URL)
    ),
    verifier: { verifyAccessToken: verify },
  });
}
