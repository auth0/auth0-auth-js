import { type XmcpConfig } from "xmcp";
import { AUTH0_DOMAIN, PORT, MCP_SERVER_URL } from "./src/config.ts";

const config: XmcpConfig = {
  http: {
    port: PORT,
    endpoint: "/",
    cors: {
      origin: [
        "*", // Allow all origins - adjust as needed for production
      ],
      exposedHeaders: ["Mcp-Session-Id"],
      allowedHeaders: ["Content-Type", "mcp-session-id"],
      credentials: true, // Allow auth headers for Auth0 authentication from MCP Inspector
    },
  },
  experimental: {
    oauth: {
      baseUrl: MCP_SERVER_URL,
      endpoints: {
        authorizationUrl: `https://${AUTH0_DOMAIN}/authorize`, // For authorization code
        tokenUrl: `https://${AUTH0_DOMAIN}/oauth/token`, // For token exchange
        registerUrl: `https://${AUTH0_DOMAIN}/oidc/register`, // For DCR
        userInfoUrl: `https://${AUTH0_DOMAIN}/userinfo`, // For XMCP token validation
      },
      issuerUrl: `https://${AUTH0_DOMAIN}/`,
      defaultScopes: [
        // OIDC scopes
        "openid",
        "profile",
        "email",

        // Tool scopes
        "tool:greet",
      ],
      pathPrefix: "/oauth2",
    },
  },
};

export default config;
