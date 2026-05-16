import type { ApiClient } from '../api-client.js';
import type { VerifiedAccessTokenClaims } from '../types.js';

// -----------------------------------------------------------------------------
// HTTP
// -----------------------------------------------------------------------------

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

// -----------------------------------------------------------------------------
// JSON Schema (subset relevant for MCP tool input schemas)
// -----------------------------------------------------------------------------

export interface JsonSchema {
  type?: string;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  required?: string[];
  enum?: unknown[];
  description?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  default?: unknown;
  oneOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  allOf?: JsonSchema[];
  $ref?: string;
}

// -----------------------------------------------------------------------------
// Tool definitions
// -----------------------------------------------------------------------------

export interface ToolEndpoint {
  method: HttpMethod;
  path: string;
}

export type CallerType = 'human' | 'agent';

export interface ToolAuthContext {
  claims: VerifiedAccessTokenClaims;
  scopes: string[];
  token: string;
  caller: CallerType;
  agentId?: string;
}

export interface MappedRequest {
  pathParams?: Record<string, string>;
  query?: Record<string, string>;
  body?: unknown;
  headers?: Record<string, string>;
}

export interface ToolDefinition<TInput = Record<string, unknown>> {
  name: string;
  description: string;
  endpoint: ToolEndpoint;
  schema: JsonSchema;
  scopes?: string[];
  agentPolicy?: AgentPolicy;
  mapInput?: (ctx: { input: TInput; auth: ToolAuthContext }) => MappedRequest;
}

// -----------------------------------------------------------------------------
// API group (multi-upstream routing)
// -----------------------------------------------------------------------------

export interface ApiUpstreamOptions {
  baseUrl: string;
  audience: string;
  scope?: string;
  customFetch?: typeof fetch;
}

export interface ApiGroupOptions {
  baseUrl: string;
  audience: string;
  scope?: string;
  customFetch?: typeof fetch;
  tools: ToolDefinition[];
  agentPolicy?: ApiAgentPolicy;
}

// -----------------------------------------------------------------------------
// Agent policy
// -----------------------------------------------------------------------------

export interface AgentPolicy {
  allowedAgents?: string[];
  requireConfirmation?: boolean;
}

export interface ApiAgentPolicy extends AgentPolicy {
  byOperation?: Record<string, AgentPolicy>;
}

// -----------------------------------------------------------------------------
// Gateway configuration
// -----------------------------------------------------------------------------

interface McpGatewayCommonOptions {
  serverName: string;
  serverVersion?: string;
  resource: string;
  customFetch?: typeof fetch;
  onAuditEvent?: (event: McpAuditEvent) => void | Promise<void>;
}

export type McpGatewayOptions = McpGatewayCommonOptions & (
  | {
      apiClient: ApiClient;
      domain?: never;
      clientId?: never;
      clientSecret?: never;
      clientAssertionSigningKey?: never;
      clientAssertionSigningAlg?: never;
    }
  | {
      apiClient?: never;
      domain: string;
      clientId: string;
      clientSecret?: string;
      clientAssertionSigningKey?: string | CryptoKey;
      clientAssertionSigningAlg?: string;
    }
);

// -----------------------------------------------------------------------------
// Local tool handler (gateway's own tools)
// -----------------------------------------------------------------------------

export interface McpToolContent {
  type: 'text' | 'image' | 'resource';
  text?: string;
  mimeType?: string;
  data?: string;
  uri?: string;
}

export interface McpToolResult {
  content: McpToolContent[];
  isError?: boolean;
}

export interface LocalToolDefinition<TInput = Record<string, unknown>> {
  name: string;
  description: string;
  schema: JsonSchema;
  scopes?: string[];
  agentPolicy?: AgentPolicy;
  handler: (ctx: { input: TInput; auth: ToolAuthContext }) => Promise<McpToolResult> | McpToolResult;
}

// -----------------------------------------------------------------------------
// MCP protocol types
// -----------------------------------------------------------------------------

export interface McpRequestContext {
  body: JsonRpcRequest | unknown;
  headers: Record<string, string | string[] | undefined>;
  url?: string;
}

export interface McpResponseEnvelope {
  status: number;
  headers: Record<string, string>;
  body: JsonRpcResponse | Record<string, unknown>;
}

export interface McpServerCapabilities {
  tools?: Record<string, never>;
}

export interface McpServerInfo {
  name: string;
  version: string;
}

export interface McpInitializeResult {
  protocolVersion: string;
  capabilities: McpServerCapabilities;
  serverInfo: McpServerInfo;
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: JsonSchema;
}

// -----------------------------------------------------------------------------
// Audit events
// -----------------------------------------------------------------------------

export type McpAuditEventType =
  | 'mcp.tool.invoked'
  | 'mcp.tool.completed'
  | 'mcp.tool.blocked'
  | 'mcp.tool.failed'
  | 'mcp.agent.blocked'
  | 'mcp.agent.confirmation_required';

export interface McpAuditEvent {
  type: McpAuditEventType;
  toolName: string;
  sub?: string;
  status: 'success' | 'failed' | 'blocked';
  reason?: string;
  durationMs?: number;
  timestamp: string;
}

// -----------------------------------------------------------------------------
// JSON-RPC 2.0
// -----------------------------------------------------------------------------

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export type JsonRpcSuccessResponse = {
  jsonrpc: '2.0';
  id: string | number | null;
  result: unknown;
};

export type JsonRpcErrorResponse = {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
};

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

// -----------------------------------------------------------------------------
// OpenAPI spec types (minimal for parsing)
// -----------------------------------------------------------------------------

export interface OpenApiParameter {
  name: string;
  in: 'path' | 'query' | 'header' | 'cookie';
  required?: boolean;
  description?: string;
  schema?: JsonSchema;
}

export interface OpenApiRequestBody {
  required?: boolean;
  content?: Record<string, { schema?: JsonSchema }>;
}

export interface OpenApiOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  parameters?: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
  security?: Record<string, string[]>[];
}

export interface OpenApiPathItem {
  get?: OpenApiOperation;
  post?: OpenApiOperation;
  put?: OpenApiOperation;
  patch?: OpenApiOperation;
  delete?: OpenApiOperation;
  parameters?: OpenApiParameter[];
}

export interface OpenApiSpec {
  openapi?: string;
  info?: { title?: string; version?: string };
  paths?: Record<string, OpenApiPathItem>;
  components?: { schemas?: Record<string, JsonSchema> };
}

export interface OpenApiToolsOptions {
  include?: string[];
  exclude?: string[];
  scopeOverrides?: Record<string, string[]>;
  descriptionOverrides?: Record<string, string>;
}
