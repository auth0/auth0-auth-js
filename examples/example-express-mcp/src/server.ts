/**
 * Express app with Auth0-based authentication and MCP transport.
 */

import express, { type Request, type Response } from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { allowedMethods } from "@modelcontextprotocol/sdk/server/auth/middleware/allowedMethods.js";
import { tools } from "./tools.js";
import { authMetadataRouter, authMiddleware } from "./auth.js";

/**
 * Set up MCP server and register tools.
 */
export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "Example Express MCP Server",
    version: "1.0.0",
  });

  for (const tool of tools) {
    server.registerTool(tool.name, tool.config, tool.handler);
  }

  return server;
}

/**
 * Create Express app with CORS, Auth0, and MCP handling.
 */
export async function createExpressApp(
  mcpServer: McpServer
): Promise<express.Application> {
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
  app.use(await authMetadataRouter());

  // Handle MCP requests
  app
    .route("/mcp")
    .post(authMiddleware(), async (req: Request, res: Response) => {
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
