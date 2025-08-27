/**
 * MCP tools with scope-based authorization.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createAuth0Mcp } from "./auth0.js";

export const MCP_TOOL_SCOPES = ["tool:greet", "tool:whoami"];

const greetToolInputSchema = {
  name: z
    .string()
    .optional()
    .describe("The name to greet (defaults to 'World')"),
} as const;

export const registerTools = (
  mcpServer: McpServer,
  auth0Mcp: ReturnType<typeof createAuth0Mcp>
) => {
  mcpServer.registerTool(
    "greet",
    {
      title: "Greet Tool",
      description: "Greets a user",
      inputSchema: greetToolInputSchema,
      annotations: { readOnlyHint: false },
    },
    auth0Mcp.requireScopes<typeof greetToolInputSchema>(
      ["tool:greet"],
      async (payload, { authInfo }) => {
        const name = payload.name || "World";
        const userId = authInfo.extra.sub;
        return {
          content: [
            {
              type: "text",
              text: `Hello, ${name}! You are authenticated as: ${userId}`,
            },
          ],
        };
      }
    )
  );

  mcpServer.registerTool(
    "whoami",
    {
      title: "Whoami Tool",
      description: "Returns the authenticated user's information",
      annotations: { readOnlyHint: false },
    },
    auth0Mcp.requireScopes(["tool:whoami"], async (_payload, { authInfo }) => {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                user: authInfo.extra,
                scopes: authInfo.scopes,
              },
              null,
              2
            ),
          },
        ],
      };
    })
  );
};
