import { describe, expect, test } from 'vitest';
import { buildUpstreamRequest } from './endpoint-mapper.js';
import type { ToolDefinition, ToolAuthContext, ApiUpstreamOptions } from './types.js';

const mockAuth: ToolAuthContext = {
  claims: { sub: 'user_1', iss: 'https://auth0.local/', aud: 'https://api' },
  scopes: ['read'],
  token: 'test-token-123',
};

const upstream: ApiUpstreamOptions = {
  baseUrl: 'https://api.example.com',
  audience: 'https://api',
};

describe('buildUpstreamRequest', () => {
  describe('auto-mapping', () => {
    test('GET with query params', () => {
      const tool: ToolDefinition = {
        name: 'list',
        description: 'List items',
        endpoint: { method: 'GET', path: '/items' },
        schema: { type: 'object' },
      };

      const { url, init } = buildUpstreamRequest(tool, { status: 'active', limit: '10' }, mockAuth, upstream);

      expect(url).toBe('https://api.example.com/items?status=active&limit=10');
      expect(init.method).toBe('GET');
      expect((init.headers as Record<string, string>).authorization).toBe('Bearer test-token-123');
      expect(init.body).toBeUndefined();
    });

    test('GET with path params', () => {
      const tool: ToolDefinition = {
        name: 'get',
        description: 'Get item',
        endpoint: { method: 'GET', path: '/items/{itemId}' },
        schema: { type: 'object' },
      };

      const { url } = buildUpstreamRequest(tool, { itemId: 'abc' }, mockAuth, upstream);
      expect(url).toBe('https://api.example.com/items/abc');
    });

    test('GET with both path and query params', () => {
      const tool: ToolDefinition = {
        name: 'getWithFilter',
        description: 'Get items in category',
        endpoint: { method: 'GET', path: '/categories/{catId}/items' },
        schema: { type: 'object' },
      };

      const { url } = buildUpstreamRequest(tool, { catId: 'electronics', sort: 'price' }, mockAuth, upstream);
      expect(url).toBe('https://api.example.com/categories/electronics/items?sort=price');
    });

    test('POST with body', () => {
      const tool: ToolDefinition = {
        name: 'create',
        description: 'Create item',
        endpoint: { method: 'POST', path: '/items' },
        schema: { type: 'object' },
      };

      const { url, init } = buildUpstreamRequest(tool, { name: 'Widget', price: 9.99 }, mockAuth, upstream);

      expect(url).toBe('https://api.example.com/items');
      expect(init.method).toBe('POST');
      expect(init.body).toBe(JSON.stringify({ name: 'Widget', price: 9.99 }));
      expect((init.headers as Record<string, string>)['content-type']).toBe('application/json');
    });

    test('POST with path params extracts them from body', () => {
      const tool: ToolDefinition = {
        name: 'update',
        description: 'Update item',
        endpoint: { method: 'POST', path: '/items/{id}/approve' },
        schema: { type: 'object' },
      };

      const { url, init } = buildUpstreamRequest(tool, { id: 'item_1', comment: 'LGTM' }, mockAuth, upstream);

      expect(url).toBe('https://api.example.com/items/item_1/approve');
      expect(JSON.parse(init.body as string)).toEqual({ comment: 'LGTM' });
    });

    test('DELETE with path params only', () => {
      const tool: ToolDefinition = {
        name: 'delete',
        description: 'Delete item',
        endpoint: { method: 'DELETE', path: '/items/{id}' },
        schema: { type: 'object' },
      };

      const { url, init } = buildUpstreamRequest(tool, { id: 'item_1' }, mockAuth, upstream);

      expect(url).toBe('https://api.example.com/items/item_1');
      expect(init.method).toBe('DELETE');
      expect(init.body).toBeUndefined();
    });

    test('skips null/undefined query params', () => {
      const tool: ToolDefinition = {
        name: 'list',
        description: 'List',
        endpoint: { method: 'GET', path: '/items' },
        schema: { type: 'object' },
      };

      const { url } = buildUpstreamRequest(tool, { status: 'active', empty: null, undef: undefined }, mockAuth, upstream);
      expect(url).toBe('https://api.example.com/items?status=active');
    });

    test('encodes path params', () => {
      const tool: ToolDefinition = {
        name: 'get',
        description: 'Get',
        endpoint: { method: 'GET', path: '/items/{id}' },
        schema: { type: 'object' },
      };

      const { url } = buildUpstreamRequest(tool, { id: 'has spaces/slash' }, mockAuth, upstream);
      expect(url).toBe('https://api.example.com/items/has%20spaces%2Fslash');
    });
  });

  describe('custom mapInput', () => {
    test('uses mapInput result', () => {
      const tool: ToolDefinition = {
        name: 'custom',
        description: 'Custom mapping',
        endpoint: { method: 'POST', path: '/tasks/{taskId}' },
        schema: { type: 'object' },
        mapInput: ({ input }) => ({
          pathParams: { taskId: input.id as string },
          body: { title: input.title, assignee: input.assignee },
          headers: { 'x-custom': 'value' },
        }),
      };

      const { url, init } = buildUpstreamRequest(
        tool,
        { id: 'task_1', title: 'Fix bug', assignee: 'alice' },
        mockAuth,
        upstream
      );

      expect(url).toBe('https://api.example.com/tasks/task_1');
      expect(JSON.parse(init.body as string)).toEqual({ title: 'Fix bug', assignee: 'alice' });
      expect((init.headers as Record<string, string>)['x-custom']).toBe('value');
    });

    test('mapInput receives auth context', () => {
      let receivedAuth: ToolAuthContext | undefined;
      const tool: ToolDefinition = {
        name: 'authAware',
        description: 'Auth-aware mapping',
        endpoint: { method: 'GET', path: '/me' },
        schema: { type: 'object' },
        mapInput: ({ auth }) => {
          receivedAuth = auth;
          return { query: { sub: auth.claims.sub as string } };
        },
      };

      buildUpstreamRequest(tool, {}, mockAuth, upstream);
      expect(receivedAuth?.claims.sub).toBe('user_1');
      expect(receivedAuth?.token).toBe('test-token-123');
    });
  });

  describe('baseUrl normalization', () => {
    test('strips trailing slashes from baseUrl', () => {
      const tool: ToolDefinition = {
        name: 'get',
        description: 'Get',
        endpoint: { method: 'GET', path: '/items' },
        schema: { type: 'object' },
      };

      const { url } = buildUpstreamRequest(tool, {}, mockAuth, {
        ...upstream,
        baseUrl: 'https://api.example.com///',
      });

      expect(url).toBe('https://api.example.com/items');
    });
  });
});
