import type { IncomingMessage } from "http";
import { ApiClient, VerifyAccessTokenError } from "@auth0/auth0-api-js";
import {
  InsufficientScopeError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { AccessTokenClaims, FastMCPAuthSession } from "./types.js";
import { MCP_TOOL_SCOPES } from "./tools.js";

const PORT = parseInt(process.env.PORT ?? "3001", 10);
const MCP_SERVER_URL = process.env.MCP_SERVER_URL ?? `http://localhost:${PORT}`;
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN as string;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE as string;

const apiClient = new ApiClient({
  domain: AUTH0_DOMAIN,
  audience: AUTH0_AUDIENCE,
});

function validateScopes(
  token: AccessTokenClaims,
  requiredScopes: string[]
): boolean {
  let tokenScopes: string[] = [];

  if (token.scope) {
    tokenScopes =
      typeof token.scope === "string" ? token.scope.split(" ") : token.scope;
  }

  return requiredScopes.every((required) => tokenScopes.includes(required));
}

export const authenticate = async (
  request: IncomingMessage
): Promise<FastMCPAuthSession> => {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      throw new InvalidTokenError("Missing authorization header");
    }

    const [type, accessToken] = authHeader.split(" ");
    if (type?.toLocaleLowerCase() !== "bearer" || !accessToken) {
      throw new InvalidTokenError("Invalid authorization header");
    }
    const decoded = (await apiClient.verifyAccessToken({
      accessToken,
    })) as AccessTokenClaims;

    const clientId = decoded.client_id ?? decoded.azp;
    if (!clientId) {
      throw new InvalidTokenError(
        "Token is missing required client identification (client_id or azp claim)."
      );
    }

    const token = {
      token: accessToken,
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
    } satisfies FastMCPAuthSession;

    return token;
  } catch (error) {
    console.error(error);
    if (
      error instanceof VerifyAccessTokenError ||
      error instanceof InvalidTokenError
    ) {
      /**
       * WWW-Authenticate header is used for 401 responses as per spec.
       */
      const wwwAuthValue = `Bearer error="invalid_token", error_description="${
        error.message
      }", resource_metadata="${getOAuthProtectedResourceMetadataUrl(
        new URL(MCP_SERVER_URL)
      )}"`;
      throw new Response(null, {
        status: 401,
        statusText: "Unauthorized",
        headers: {
          "WWW-Authenticate": wwwAuthValue,
        },
      });
    } else if (error instanceof InsufficientScopeError) {
      throw new Response(null, {
        status: 403,
        statusText: "Forbidden",
      });
    } else {
      throw new Response(null, {
        status: 500,
        statusText: "Internal Server Error",
      });
    }
  }
};
