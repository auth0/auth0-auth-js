import type { JsonRpcRequest, JsonRpcSuccessResponse, JsonRpcErrorResponse } from './types.js';

// Standard JSON-RPC 2.0 error codes
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

// MCP-specific error codes
export const MCP_UNAUTHORIZED = -32001;
export const MCP_FORBIDDEN = -32003;
export const MCP_TOOL_NOT_FOUND = -32004;
export const MCP_UPSTREAM_ERROR = -32005;
export const MCP_AGENT_BLOCKED = -32006;
export const MCP_CONFIRMATION_REQUIRED = -32007;

export class JsonRpcParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JsonRpcParseError';
  }
}

export function parseRequest(body: unknown): JsonRpcRequest {
  if (!body || typeof body !== 'object') {
    throw new JsonRpcParseError('Request body must be an object');
  }

  const obj = body as Record<string, unknown>;

  if (obj.jsonrpc !== '2.0') {
    throw new JsonRpcParseError('Invalid or missing "jsonrpc" field (must be "2.0")');
  }

  if (typeof obj.method !== 'string' || !obj.method) {
    throw new JsonRpcParseError('Invalid or missing "method" field');
  }

  if (obj.params !== undefined && (typeof obj.params !== 'object' || obj.params === null)) {
    throw new JsonRpcParseError('"params" must be an object when provided');
  }

  return {
    jsonrpc: '2.0',
    id: (obj.id as string | number | null) ?? null,
    method: obj.method,
    params: obj.params as Record<string, unknown> | undefined,
  };
}

export function success(id: string | number | null, result: unknown): JsonRpcSuccessResponse {
  return { jsonrpc: '2.0', id, result };
}

export function error(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcErrorResponse {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message, ...(data !== undefined && { data }) },
  };
}

export function errorForParseFailure(message: string): JsonRpcErrorResponse {
  return error(null, PARSE_ERROR, message);
}
