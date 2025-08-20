import "dotenv/config";

export const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN as string;
export const PORT = parseInt(process.env.PORT ?? "3001", 10);
export const MCP_SERVER_URL =
  process.env.MCP_SERVER_URL ?? `http://localhost:${PORT}`;
export const AUDIENCE = process.env.AUTH0_AUDIENCE ?? MCP_SERVER_URL;

// Validate required environment variables
if (!AUTH0_DOMAIN) {
  throw new Error("AUTH0_DOMAIN environment variable is required");
}
