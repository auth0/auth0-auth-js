import { describe, expect, test, beforeAll, afterAll, afterEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from '../test-utils/tokens.js';
import { McpGateway } from './gateway.js';
import type { McpRequestContext, McpAuditEvent, JsonRpcResponse } from './types.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const resource = 'https://gateway.example.com/mcp';
const expensesBaseUrl = 'https://expenses.example.com';
const hrBaseUrl = 'https://hr.example.com';

const mockOidcConfig = {
  issuer: `https://${domain}/`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
  token_endpoint: `https://${domain}/oauth/token`,
};

const server = setupServer(
  http.get(`https://${domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json(mockOidcConfig)
  ),
  http.get(`https://${domain}/.well-known/jwks.json`, () =>
    HttpResponse.json({ keys: jwks })
  ),

  // Expenses API mock
  http.get(`${expensesBaseUrl}/expenses`, ({ request }) => {
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    const expenses = [
      { id: 'exp_1', amount: 250, status: 'pending' },
      { id: 'exp_2', amount: 89, status: 'approved' },
    ];
    const filtered = status ? expenses.filter((e) => e.status === status) : expenses;
    return HttpResponse.json({ expenses: filtered, total: filtered.length });
  }),
  http.get(`${expensesBaseUrl}/expenses/:id`, ({ params }) => {
    return HttpResponse.json({ id: params.id, amount: 250, status: 'pending' });
  }),
  http.post(`${expensesBaseUrl}/expenses/:id/approve`, ({ params }) => {
    return HttpResponse.json({ id: params.id, status: 'approved' });
  }),

  // HR API mock
  http.get(`${hrBaseUrl}/employees`, () => {
    return HttpResponse.json({
      employees: [{ id: 'emp_1', name: 'Alice' }],
      total: 1,
    });
  }),
  http.get(`${hrBaseUrl}/employees/:id`, ({ params }) => {
    return HttpResponse.json({ id: params.id, name: 'Alice', department: 'Engineering' });
  }),

  // OBO token exchange mock
  http.post(`https://${domain}/oauth/token`, async ({ request }) => {
    const body = await request.text();
    const params = new URLSearchParams(body);
    const audience = params.get('audience');
    return HttpResponse.json({
      access_token: `obo-token-for-${audience}`,
      token_type: 'Bearer',
      expires_in: 3600,
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

function createGateway(overrides?: { onAuditEvent?: (e: McpAuditEvent) => void }) {
  const gateway = new McpGateway({
    domain,
    clientId,
    clientSecret,
    serverName: 'Test Gateway',
    resource,
    onAuditEvent: overrides?.onAuditEvent,
  });

  // Register expenses API
  gateway.api('expenses', {
    baseUrl: expensesBaseUrl,
    audience: 'https://expenses-api',
    tools: [
      {
        name: 'listExpenses',
        description: 'List expenses',
        endpoint: { method: 'GET', path: '/expenses' },
        scopes: ['expenses:read'],
        schema: {
          type: 'object',
          properties: { status: { type: 'string' } },
        },
      },
      {
        name: 'getExpense',
        description: 'Get an expense',
        endpoint: { method: 'GET', path: '/expenses/{id}' },
        scopes: ['expenses:read'],
        schema: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
        },
      },
      {
        name: 'approveExpense',
        description: 'Approve an expense',
        endpoint: { method: 'POST', path: '/expenses/{id}/approve' },
        scopes: ['expenses:approve'],
        schema: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
        },
      },
    ],
  });

  // Register HR API
  gateway.api('hr', {
    baseUrl: hrBaseUrl,
    audience: 'https://hr-api',
    tools: [
      {
        name: 'listEmployees',
        description: 'List employees',
        endpoint: { method: 'GET', path: '/employees' },
        scopes: ['hr:read'],
        schema: { type: 'object', properties: {} },
      },
      {
        name: 'getEmployee',
        description: 'Get employee details',
        endpoint: { method: 'GET', path: '/employees/{id}' },
        scopes: ['hr:read'],
        schema: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
        },
      },
    ],
  });

  // Register local tool
  gateway.tool({
    name: 'whoami',
    description: 'Returns user identity',
    schema: { type: 'object', properties: {} },
    handler: async ({ auth }) => ({
      content: [{ type: 'text', text: JSON.stringify({ sub: auth.claims.sub, scopes: auth.scopes }) }],
    }),
  });

  return gateway;
}

async function makeRequest(
  gateway: McpGateway,
  method: string,
  params?: Record<string, unknown>,
  token?: string
): Promise<{ status: number; body: JsonRpcResponse }> {
  const handler = gateway.requestHandler();
  const ctx: McpRequestContext = {
    body: { jsonrpc: '2.0' as const, id: 1, method, params },
    headers: {
      ...(token && { authorization: `Bearer ${token}` }),
      'content-type': 'application/json',
    },
  };
  const result = await handler(ctx);
  return { status: result.status, body: result.body as JsonRpcResponse };
}

describe('McpGateway', () => {
  describe('constructor', () => {
    test('throws on missing domain', () => {
      expect(() => new McpGateway({
        domain: '',
        clientId,
        serverName: 'Test',
        resource,
      })).toThrow('"domain"');
    });

    test('throws on missing clientId', () => {
      expect(() => new McpGateway({
        domain,
        clientId: '',
        serverName: 'Test',
        resource,
      })).toThrow('"clientId"');
    });

    test('throws on missing serverName', () => {
      expect(() => new McpGateway({
        domain,
        clientId,
        serverName: '',
        resource,
      })).toThrow('"serverName"');
    });

    test('throws on missing resource', () => {
      expect(() => new McpGateway({
        domain,
        clientId,
        serverName: 'Test',
        resource: '',
      })).toThrow('"resource"');
    });
  });

  describe('initialize', () => {
    test('returns server info and capabilities', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource);
      const { body } = await makeRequest(gateway, 'initialize', {}, token);

      expect(body).toHaveProperty('result');
      const result = (body as { result: Record<string, unknown> }).result;
      expect(result.protocolVersion).toBe('2025-03-26');
      expect(result.capabilities).toEqual({ tools: {} });
      expect((result.serverInfo as Record<string, unknown>).name).toBe('Test Gateway');
    });
  });

  describe('tools/list', () => {
    test('returns all tools when authenticated with full scopes', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read expenses:approve hr:read',
      });

      const { body } = await makeRequest(gateway, 'tools/list', {}, token);
      const result = (body as { result: { tools: unknown[] } }).result;
      // 3 expenses + 2 hr + 1 local = 6
      expect(result.tools).toHaveLength(6);
    });

    test('returns all tools regardless of token scopes (scope enforced at tools/call)', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/list', {}, token);
      const result = (body as { result: { tools: { name: string }[] } }).result;
      const names = result.tools.map((t) => t.name);
      expect(names).toContain('listExpenses');
      expect(names).toContain('getExpense');
      expect(names).toContain('approveExpense');
      expect(names).toContain('listEmployees');
      expect(names).toContain('whoami');
      expect(result.tools).toHaveLength(6);
    });

    test('returns 401 when unauthenticated', async () => {
      const gateway = createGateway();
      const handler = gateway.requestHandler();
      const result = await handler({
        body: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
        headers: {},
      });
      expect(result.status).toBe(401);
      expect(result.body).toHaveProperty('error', 'Unauthorized');
    });
  });

  describe('tools/call — local tools', () => {
    test('executes local tool handler', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'whoami',
        arguments: {},
      }, token);

      expect(body).toHaveProperty('result');
      const result = (body as { result: { content: { text: string }[] } }).result;
      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.sub).toBe('user_1');
      expect(parsed.scopes).toContain('expenses:read');
    });
  });

  describe('tools/call — remote tools (multi-API routing)', () => {
    test('routes to expenses API with OBO', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'listExpenses',
        arguments: { status: 'pending' },
      }, token);

      expect(body).toHaveProperty('result');
      const result = (body as { result: { content: { text: string }[] } }).result;
      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.expenses).toBeDefined();
      expect(parsed.expenses[0].status).toBe('pending');
    });

    test('routes to HR API with different OBO audience', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'hr:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'getEmployee',
        arguments: { id: 'emp_1' },
      }, token);

      expect(body).toHaveProperty('result');
      const result = (body as { result: { content: { text: string }[] } }).result;
      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.id).toBe('emp_1');
      expect(parsed.name).toBe('Alice');
    });

    test('handles path params correctly', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'getExpense',
        arguments: { id: 'exp_42' },
      }, token);

      const result = (body as { result: { content: { text: string }[] } }).result;
      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.id).toBe('exp_42');
    });

    test('handles POST with body', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:approve',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'approveExpense',
        arguments: { id: 'exp_1' },
      }, token);

      const result = (body as { result: { content: { text: string }[] } }).result;
      const parsed = JSON.parse(result.content[0]!.text);
      expect(parsed.status).toBe('approved');
    });
  });

  describe('authorization', () => {
    test('returns 401 when no token', async () => {
      const gateway = createGateway();
      const handler = gateway.requestHandler();
      const result = await handler({
        body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'listExpenses', arguments: {} } },
        headers: {},
      });
      expect(result.status).toBe(401);
      expect(result.body).toHaveProperty('error', 'Unauthorized');
    });

    test('returns forbidden when missing required scope', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'approveExpense',
        arguments: { id: 'exp_1' },
      }, token);

      expect(body).toHaveProperty('error');
      const err = (body as { error: { code: number; data: { missingScopes: string[] } } }).error;
      expect(err.code).toBe(-32003);
      expect(err.data.missingScopes).toEqual(['expenses:approve']);
    });

    test('returns tool not found for unknown tool', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource);

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'nonExistent',
      }, token);

      const err = (body as { error: { code: number } }).error;
      expect(err.code).toBe(-32004);
    });

    test('returns invalid params when tool name is missing', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource);

      const { body } = await makeRequest(gateway, 'tools/call', {}, token);

      const err = (body as { error: { code: number } }).error;
      expect(err.code).toBe(-32602);
    });
  });

  describe('JSON-RPC protocol', () => {
    test('returns method not found for unknown method', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource);
      const { body } = await makeRequest(gateway, 'resources/list', {}, token);

      const err = (body as { error: { code: number } }).error;
      expect(err.code).toBe(-32601);
    });

    test('returns parse error for invalid body', async () => {
      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource);
      const handler = gateway.requestHandler();

      const result = await handler({
        body: { not: 'valid' } as never,
        headers: { authorization: `Bearer ${token}` },
      });

      expect(result.status).toBe(400);
      const err = (result.body as { error: { code: number } }).error;
      expect(err.code).toBe(-32700);
    });
  });

  describe('resource metadata', () => {
    test('returns protected resource metadata with all scopes', () => {
      const gateway = createGateway();
      const metadata = gateway.resourceMetadata();

      expect(metadata.resource).toBe(resource);
      expect(metadata.authorization_servers).toEqual([`https://${domain}/`]);
      expect(metadata.scopes_supported).toEqual(
        expect.arrayContaining(['expenses:read', 'expenses:approve', 'hr:read'])
      );
    });
  });

  describe('audit events', () => {
    test('emits invoked and completed events on success', async () => {
      const events: McpAuditEvent[] = [];
      const gateway = createGateway({ onAuditEvent: (e) => { events.push(e); } });
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      await makeRequest(gateway, 'tools/call', {
        name: 'listExpenses',
        arguments: {},
      }, token);

      expect(events).toHaveLength(2);
      expect(events[0]!.type).toBe('mcp.tool.invoked');
      expect(events[0]!.toolName).toBe('listExpenses');
      expect(events[1]!.type).toBe('mcp.tool.completed');
      expect(events[1]!.durationMs).toBeGreaterThanOrEqual(0);
    });

    test('emits blocked event on scope mismatch', async () => {
      const events: McpAuditEvent[] = [];
      const gateway = createGateway({ onAuditEvent: (e) => { events.push(e); } });
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      await makeRequest(gateway, 'tools/call', {
        name: 'approveExpense',
        arguments: { id: 'exp_1' },
      }, token);

      expect(events).toHaveLength(1);
      expect(events[0]!.type).toBe('mcp.tool.blocked');
      expect(events[0]!.status).toBe('blocked');
    });

    test('does not throw when audit callback throws', async () => {
      const gateway = createGateway({
        onAuditEvent: () => { throw new Error('audit failure'); },
      });
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'listExpenses',
        arguments: {},
      }, token);

      expect(body).toHaveProperty('result');
    });
  });

  describe('upstream error handling', () => {
    test('returns upstream error when API returns 4xx', async () => {
      server.use(
        http.get(`${expensesBaseUrl}/expenses`, () =>
          HttpResponse.json({ error: 'forbidden' }, { status: 403 })
        ),
      );

      const gateway = createGateway();
      const token = await generateToken(domain, 'user_1', resource, undefined, undefined, undefined, {
        scope: 'expenses:read',
      });

      const { body } = await makeRequest(gateway, 'tools/call', {
        name: 'listExpenses',
        arguments: {},
      }, token);

      const err = (body as { error: { code: number; data: { upstreamStatus: number } } }).error;
      expect(err.code).toBe(-32005);
      expect(err.data.upstreamStatus).toBe(403);
    });
  });

  describe('chaining', () => {
    test('api() and tool() return this for chaining', () => {
      const gateway = new McpGateway({
        domain,
        clientId,
        clientSecret,
        serverName: 'Test',
        resource,
      });

      const result = gateway
        .api('a', {
          baseUrl: 'http://a.example.com',
          audience: 'https://a-api',
          tools: [{
            name: 'toolA',
            description: 'A',
            endpoint: { method: 'GET', path: '/a' },
            schema: { type: 'object' },
          }],
        })
        .tool({
          name: 'localTool',
          description: 'Local',
          schema: { type: 'object' },
          handler: async () => ({ content: [{ type: 'text', text: 'ok' }] }),
        });

      expect(result).toBe(gateway);
    });
  });

  describe('tool registration validation', () => {
    test('throws on duplicate tool name', () => {
      const gateway = new McpGateway({
        domain,
        clientId,
        clientSecret,
        serverName: 'Test',
        resource,
      });

      gateway.tool({
        name: 'myTool',
        description: 'First',
        schema: { type: 'object' },
        handler: async () => ({ content: [{ type: 'text', text: 'ok' }] }),
      });

      expect(() => gateway.tool({
        name: 'myTool',
        description: 'Duplicate',
        schema: { type: 'object' },
        handler: async () => ({ content: [{ type: 'text', text: 'ok' }] }),
      })).toThrow('already registered');
    });

    test('throws on missing API namespace', () => {
      const gateway = new McpGateway({
        domain,
        clientId,
        clientSecret,
        serverName: 'Test',
        resource,
      });

      expect(() => gateway.api('', {
        baseUrl: 'http://example.com',
        audience: 'https://api',
        tools: [],
      })).toThrow('namespace');
    });
  });
});
