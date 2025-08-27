import { allowedMethods } from "@modelcontextprotocol/sdk/server/auth/middleware/allowedMethods.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import cors from "cors";
import express, {
  type Request,
  type Response,
  type Application,
} from "express";
import { createAuth0Mcp } from "./auth0.js";
import { registerTools } from "./tools.js";

const PORT = parseInt(process.env.PORT ?? "3001", 10);
const MCP_SERVER_RESOURCE_NAME = "Example Express MCP Server";
const MCP_SERVER_URL = process.env.MCP_SERVER_URL ?? `http://localhost:${PORT}`;
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN as string;
const AUDIENCE = process.env.AUTH0_AUDIENCE ?? MCP_SERVER_URL;

// Validate required environment variables
if (!AUTH0_DOMAIN) {
  throw new Error("AUTH0_DOMAIN environment variable is required");
}

const auth = createAuth0Mcp({
  resourceName: MCP_SERVER_RESOURCE_NAME,
  resourceServerUrl: new URL(MCP_SERVER_URL),
  domain: AUTH0_DOMAIN,
  audience: AUDIENCE,
});

/**
 * Set up MCP server and register tools.
 */
export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: MCP_SERVER_RESOURCE_NAME,
    version: "1.0.0",
  });

  registerTools(server, auth);

  return server;
}

/**
 * Create Express app with CORS, Auth0, and MCP handling.
 */
export async function createExpressApp(
  mcpServer: McpServer
): Promise<Application> {
  const app = express();

  // Enable CORS
  app.use(
    cors({
      origin: "http://localhost:6274", // MCP Inspector; adjust as needed for production
      exposedHeaders: ["Mcp-Session-Id"],
      allowedHeaders: ["Content-Type", "mcp-session-id"],
    })
  );

  app.use(express.json());

  // Add metadata routes
  app.use(await auth.authMetadataRouter());

  // Handle MCP requests
  app
    .route("/mcp")
    .post(auth.authMiddleware(), async (req: Request, res: Response) => {
      try {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
        });
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
        res.on("close", () => transport.close());
      } catch (error) {
        console.error("MCP request failed:", error);
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    })
    .all(allowedMethods(["POST"]));

  return app;
}
