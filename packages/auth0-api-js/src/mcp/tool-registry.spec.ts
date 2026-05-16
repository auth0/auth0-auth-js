import { describe, expect, test } from 'vitest';
import { ToolRegistry } from './tool-registry.js';
import type { ToolDefinition, LocalToolDefinition, ApiUpstreamOptions } from './types.js';

const upstream: ApiUpstreamOptions = {
  baseUrl: 'https://api.example.com',
  audience: 'https://api',
};

describe('ToolRegistry', () => {
  describe('registerRemote', () => {
    test('registers a remote tool', () => {
      const registry = new ToolRegistry();
      const tool: ToolDefinition = {
        name: 'listItems',
        description: 'List items',
        endpoint: { method: 'GET', path: '/items' },
        schema: { type: 'object' },
        scopes: ['items:read'],
      };

      registry.registerRemote(tool, upstream);

      const registered = registry.get('listItems');
      expect(registered).toBeDefined();
      expect(registered!.isLocal).toBe(false);
      expect(registered!.upstream).toBe(upstream);
    });

    test('throws on duplicate name', () => {
      const registry = new ToolRegistry();
      const tool: ToolDefinition = {
        name: 'myTool',
        description: 'Tool',
        endpoint: { method: 'GET', path: '/t' },
        schema: { type: 'object' },
      };

      registry.registerRemote(tool, upstream);
      expect(() => registry.registerRemote(tool, upstream)).toThrow('already registered');
    });

    test('throws on empty name', () => {
      const registry = new ToolRegistry();
      expect(() => registry.registerRemote({
        name: '',
        description: 'Bad',
        endpoint: { method: 'GET', path: '/' },
        schema: { type: 'object' },
      }, upstream)).toThrow('non-empty');
    });
  });

  describe('registerLocal', () => {
    test('registers a local tool', () => {
      const registry = new ToolRegistry();
      const tool: LocalToolDefinition = {
        name: 'whoami',
        description: 'Identity',
        schema: { type: 'object' },
        handler: async () => ({ content: [{ type: 'text', text: 'ok' }] }),
      };

      registry.registerLocal(tool);

      const registered = registry.get('whoami');
      expect(registered).toBeDefined();
      expect(registered!.isLocal).toBe(true);
      expect(registered!.upstream).toBeUndefined();
    });
  });

  describe('list', () => {
    test('returns all tools in MCP format', () => {
      const registry = new ToolRegistry();
      registry.registerRemote({
        name: 'toolA',
        description: 'Tool A',
        endpoint: { method: 'GET', path: '/a' },
        schema: { type: 'object', properties: { x: { type: 'string' } } },
      }, upstream);
      registry.registerLocal({
        name: 'toolB',
        description: 'Tool B',
        schema: { type: 'object' },
        handler: async () => ({ content: [] }),
      });

      const tools = registry.list();
      expect(tools).toHaveLength(2);
      expect(tools[0]).toEqual({
        name: 'toolA',
        description: 'Tool A',
        inputSchema: { type: 'object', properties: { x: { type: 'string' } } },
      });
      expect(tools[1]!.name).toBe('toolB');
    });
  });

  describe('listForScopes', () => {
    test('includes tools whose scopes are satisfied', () => {
      const registry = new ToolRegistry();
      registry.registerRemote({
        name: 'readTool',
        description: 'Read',
        endpoint: { method: 'GET', path: '/r' },
        schema: { type: 'object' },
        scopes: ['data:read'],
      }, upstream);
      registry.registerRemote({
        name: 'writeTool',
        description: 'Write',
        endpoint: { method: 'POST', path: '/w' },
        schema: { type: 'object' },
        scopes: ['data:write'],
      }, upstream);
      registry.registerLocal({
        name: 'noScopeLocal',
        description: 'No scope',
        schema: { type: 'object' },
        handler: async () => ({ content: [] }),
      });

      const tools = registry.listForScopes(['data:read']);
      expect(tools.map((t) => t.name)).toEqual(['readTool', 'noScopeLocal']);
    });

    test('tool with multiple required scopes needs all of them', () => {
      const registry = new ToolRegistry();
      registry.registerRemote({
        name: 'adminTool',
        description: 'Admin',
        endpoint: { method: 'POST', path: '/admin' },
        schema: { type: 'object' },
        scopes: ['admin:read', 'admin:write'],
      }, upstream);

      expect(registry.listForScopes(['admin:read'])).toHaveLength(0);
      expect(registry.listForScopes(['admin:read', 'admin:write'])).toHaveLength(1);
    });
  });

  describe('allScopes', () => {
    test('returns deduplicated scopes from all tools', () => {
      const registry = new ToolRegistry();
      registry.registerRemote({
        name: 'a',
        description: 'A',
        endpoint: { method: 'GET', path: '/a' },
        schema: { type: 'object' },
        scopes: ['read', 'write'],
      }, upstream);
      registry.registerRemote({
        name: 'b',
        description: 'B',
        endpoint: { method: 'GET', path: '/b' },
        schema: { type: 'object' },
        scopes: ['read', 'admin'],
      }, upstream);

      const scopes = registry.allScopes();
      expect(scopes.sort()).toEqual(['admin', 'read', 'write']);
    });
  });

  describe('get', () => {
    test('returns undefined for unknown tool', () => {
      const registry = new ToolRegistry();
      expect(registry.get('nonexistent')).toBeUndefined();
    });
  });
});
