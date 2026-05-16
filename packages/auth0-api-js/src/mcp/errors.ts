export class McpError extends Error {
  public code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'McpError';
    this.code = code;
  }
}

export class McpToolNotFoundError extends McpError {
  public toolName: string;

  constructor(toolName: string) {
    super(`Tool not found: ${toolName}`, 'mcp_tool_not_found');
    this.name = 'McpToolNotFoundError';
    this.toolName = toolName;
  }
}

export class McpScopeMismatchError extends McpError {
  public requiredScopes: string[];
  public presentScopes: string[];

  constructor(required: string[], present: string[]) {
    super('Missing required scope', 'mcp_scope_mismatch');
    this.name = 'McpScopeMismatchError';
    this.requiredScopes = required;
    this.presentScopes = present;
  }
}

export class McpInputValidationError extends McpError {
  constructor(message: string) {
    super(message, 'mcp_input_validation_error');
    this.name = 'McpInputValidationError';
  }
}

export class McpUpstreamError extends McpError {
  public upstreamStatus: number;
  public upstreamBody?: string;

  constructor(status: number, body?: string) {
    super(`Upstream API returned ${status}`, 'mcp_upstream_error');
    this.name = 'McpUpstreamError';
    this.upstreamStatus = status;
    this.upstreamBody = body;
  }
}
