import { describe, expect, test } from 'vitest';
import * as mcp from './mcp.js';

describe('mcp subpath exports', () => {
  test('exports McpGateway', () => {
    expect(mcp.McpGateway).toBeDefined();
    expect(typeof mcp.McpGateway).toBe('function');
  });

  test('exports toolsFromOpenApiSpec', () => {
    expect(mcp.toolsFromOpenApiSpec).toBeDefined();
    expect(typeof mcp.toolsFromOpenApiSpec).toBe('function');
  });

  test('exports MCP error classes', () => {
    expect(mcp.McpError).toBeDefined();
    expect(mcp.McpToolNotFoundError).toBeDefined();
    expect(mcp.McpScopeMismatchError).toBeDefined();
    expect(mcp.McpInputValidationError).toBeDefined();
    expect(mcp.McpUpstreamError).toBeDefined();
  });
});
