/**
 * MCP tools with scope-based authorization.
 */

import { ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z, ZodRawShape } from "zod";
import { Auth } from "./types.js";

export const SCOPES_SUPPORTED = ["tool:whoami", "tool:greet"];

/**
 * Wraps a tool handler with scope validation.
 * This function ensures that the tool can only be executed if the user has the required OAuth scopes.
 */
export function requireScopes<T extends ZodRawShape>(
  requiredScopes: readonly string[],
  handler: (args: T, extra: { authInfo: Auth }) => Promise<CallToolResult>
): ToolCallback<T> {
  return (async (args, extra) => {
    // To support both context-only and payload+context handlers
    let context = extra;
    if (!extra) {
      context = args as Parameters<ToolCallback<T>>[1];
    }

    if (!context.authInfo) {
      throw new Error(
        "Authentication information is required to execute this tool."
      );
    }
    const userScopes = context.authInfo.scopes;
    const hasScopes = requiredScopes.every((scope) =>
      userScopes.includes(scope)
    );

    if (!hasScopes) {
      throw new Error(`Missing required scopes: ${requiredScopes.join(", ")}`);
    }

    return handler(args as T, { authInfo: context.authInfo as Auth });
  }) as ToolCallback<T>;
}

const greetToolInputSchema = {
  name: z
    .string()
    .optional()
    .describe("The name to greet (defaults to 'World')"),
} as const;

/**
 * Tool definitions
 */
export const tools = [
  {
    name: "greet",
    config: {
      title: "Greet Tool",
      description: "Greets a user",
      inputSchema: greetToolInputSchema,
      annotations: { readOnlyHint: false },
    },
    handler: requireScopes<typeof greetToolInputSchema>(
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
    ),
  },
  {
    name: "whoami",
    config: {
      title: "Whoami Tool",
      description: "Returns the authenticated user's information",
      annotations: { readOnlyHint: false },
    },
    handler: requireScopes(["tool:whoami"], async (_payload, { authInfo }) => {
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
    }),
  },
];
