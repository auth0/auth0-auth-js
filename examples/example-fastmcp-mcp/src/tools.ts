import { z } from "zod";
import { UserError, type Context } from "fastmcp";
import { FastMCPAuthSession } from "./types.js";

export const MCP_TOOL_SCOPES = ["tool:greet", "tool:whoami"];

/**
 * Wrapper for FastMCP tools that requires specific OAuth 2.0 scopes.
 */
export function requireScopes<T, R>(
  requiredScopes: readonly string[],
  toolFunction: (args: T, context: Context<FastMCPAuthSession>) => Promise<R>
): (args: T, context: Context<FastMCPAuthSession>) => Promise<R> {
  return async (args: T, context: Context<FastMCPAuthSession>) => {
    if (!context.session) {
      throw new UserError("Access Denied: This tool requires authentication.");
    }

    // Auth type has scopes as an array, no need to split
    const userScopes = context.session.scopes;
    const hasScopes = requiredScopes.every((scope) =>
      userScopes.includes(scope)
    );
    if (!hasScopes) {
      const missing = requiredScopes.filter(
        (scope) => !userScopes.includes(scope)
      );
      throw new UserError(
        `Access Denied: Missing required scopes: ${missing.join(", ")}.`
      );
    }

    return toolFunction(args, context);
  };
}

const greetParameters = z.object({
  name: z
    .string()
    .optional()
    .describe("The name of the person to greet (optional)."),
});

/**
 * Array of tool definitions for this MCP server, each wrapped with scope validation.
 */
export const tools = [
  {
    name: "greet",
    description:
      "Greet a user with personalized authentication information from Auth0.",
    annotations: {
      title: "Greet User (FastMCP)",
      readOnlyHint: true,
    },
    parameters: greetParameters,
    execute: requireScopes<z.infer<typeof greetParameters>, string>(
      ["tool:greet"],
      async (args, context) => {
        const { name } = args;
        const { session } = context;
        const userName = name ?? "there";

        console.log(`Greet tool invoked for user: ${session?.extra?.sub}`);

        return `
        Hello, ${userName} (${session?.extra?.sub})!

        FastMCP with Auth0 OAuth integration is working!
        Authentication and scope checks are working correctly.
        `.trim();
      }
    ),
  },
  {
    name: "whoami",
    description: "Returns information about the authenticated user",
    annotations: {
      title: "Who Am I? (FastMCP)",
      readOnlyHint: true,
    },
    parameters: undefined,
    execute: requireScopes(
      ["tool:whoami"],
      async (_args, { session: authInfo }) => {
        const info = { user: authInfo?.extra, scopes: authInfo?.scopes };
        return JSON.stringify(info, null, 2);
      }
    ),
  },
] as const;
