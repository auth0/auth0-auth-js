import { type ToolMetadata } from "xmcp";
import auth0Mcp from "../auth0";

/**
 * Metadata for the greet tool, following the XMCP tool export convention.
 */
export const metadata: ToolMetadata = {
  name: "whoami",
  description: "Returns information about the authenticated user",
  annotations: {
    title: "Who Am I?",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
  },
} as const;

/**
 * Whoami tool with Auth0 scope-based authorization, following the XMCP tool export convention.
 */
export default auth0Mcp.requireScopes(
  ["tool:whoami"],
  async (_payload, { authInfo }) => {
    return {
      content: [
        {
          type: "text",
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
  }
);
