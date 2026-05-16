import { describe, expect, test } from 'vitest';
import { toolsFromOpenApiSpec } from './openapi.js';
import type { OpenApiSpec } from './types.js';

const sampleSpec: OpenApiSpec = {
  openapi: '3.0.3',
  info: { title: 'Test API', version: '1.0.0' },
  paths: {
    '/expenses': {
      get: {
        operationId: 'listExpenses',
        summary: 'List all expenses',
        parameters: [
          { name: 'status', in: 'query', schema: { type: 'string', enum: ['pending', 'approved'] }, description: 'Filter by status' },
          { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100 } },
        ],
        security: [{ oauth2: ['expenses:read'] }],
      },
      post: {
        operationId: 'createExpense',
        summary: 'Create an expense',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  amount: { type: 'number', description: 'Amount in cents' },
                  description: { type: 'string' },
                },
                required: ['amount'],
              },
            },
          },
        },
        security: [{ oauth2: ['expenses:write'] }],
      },
    },
    '/expenses/{expenseId}': {
      parameters: [
        { name: 'expenseId', in: 'path', required: true, schema: { type: 'string' } },
      ],
      get: {
        operationId: 'getExpense',
        summary: 'Get a single expense',
      },
      delete: {
        operationId: 'deleteExpense',
        description: 'Delete an expense permanently',
      },
    },
  },
  components: {
    schemas: {
      Expense: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          amount: { type: 'number' },
        },
      },
    },
  },
};

describe('toolsFromOpenApiSpec', () => {
  test('generates tools for all operations with operationId', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    expect(tools).toHaveLength(4);
    expect(tools.map((t) => t.name)).toEqual([
      'listExpenses',
      'createExpense',
      'getExpense',
      'deleteExpense',
    ]);
  });

  test('maps HTTP methods correctly', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    expect(tools.find((t) => t.name === 'listExpenses')?.endpoint.method).toBe('GET');
    expect(tools.find((t) => t.name === 'createExpense')?.endpoint.method).toBe('POST');
    expect(tools.find((t) => t.name === 'deleteExpense')?.endpoint.method).toBe('DELETE');
  });

  test('uses summary as description', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    expect(tools.find((t) => t.name === 'listExpenses')?.description).toBe('List all expenses');
  });

  test('falls back to description when no summary', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    expect(tools.find((t) => t.name === 'deleteExpense')?.description).toBe('Delete an expense permanently');
  });

  test('extracts query parameters into schema', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    const listTool = tools.find((t) => t.name === 'listExpenses')!;
    expect(listTool.schema.properties?.status).toBeDefined();
    expect(listTool.schema.properties?.status?.enum).toEqual(['pending', 'approved']);
    expect(listTool.schema.properties?.limit).toBeDefined();
  });

  test('extracts path-level parameters', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    const getTool = tools.find((t) => t.name === 'getExpense')!;
    expect(getTool.schema.properties?.expenseId).toBeDefined();
    expect(getTool.schema.required).toContain('expenseId');
  });

  test('extracts request body into schema', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    const createTool = tools.find((t) => t.name === 'createExpense')!;
    expect(createTool.schema.properties?.amount).toBeDefined();
    expect(createTool.schema.properties?.description).toBeDefined();
    expect(createTool.schema.required).toContain('amount');
  });

  test('extracts scopes from security', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec);
    expect(tools.find((t) => t.name === 'listExpenses')?.scopes).toEqual(['expenses:read']);
    expect(tools.find((t) => t.name === 'createExpense')?.scopes).toEqual(['expenses:write']);
  });

  test('filters with include option', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec, { include: ['listExpenses', 'getExpense'] });
    expect(tools).toHaveLength(2);
    expect(tools.map((t) => t.name)).toEqual(['listExpenses', 'getExpense']);
  });

  test('filters with exclude option', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec, { exclude: ['deleteExpense'] });
    expect(tools).toHaveLength(3);
    expect(tools.map((t) => t.name)).not.toContain('deleteExpense');
  });

  test('applies scope overrides', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec, {
      scopeOverrides: { getExpense: ['admin:read'] },
    });
    expect(tools.find((t) => t.name === 'getExpense')?.scopes).toEqual(['admin:read']);
  });

  test('applies description overrides', () => {
    const tools = toolsFromOpenApiSpec(sampleSpec, {
      descriptionOverrides: { listExpenses: 'Custom description' },
    });
    expect(tools.find((t) => t.name === 'listExpenses')?.description).toBe('Custom description');
  });

  test('resolves $ref in components', () => {
    const specWithRef: OpenApiSpec = {
      paths: {
        '/items': {
          post: {
            operationId: 'createItem',
            requestBody: {
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Item' },
                },
              },
            },
          },
        },
      },
      components: {
        schemas: {
          Item: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              quantity: { type: 'number' },
            },
            required: ['name'],
          },
        },
      },
    };

    const tools = toolsFromOpenApiSpec(specWithRef);
    const tool = tools[0]!;
    expect(tool.schema.properties?.name).toEqual({ type: 'string' });
    expect(tool.schema.required).toContain('name');
  });

  test('returns empty array for spec with no paths', () => {
    const tools = toolsFromOpenApiSpec({});
    expect(tools).toEqual([]);
  });

  test('skips operations without operationId', () => {
    const spec: OpenApiSpec = {
      paths: {
        '/health': {
          get: { summary: 'No operation ID' },
        },
      },
    };
    const tools = toolsFromOpenApiSpec(spec);
    expect(tools).toHaveLength(0);
  });
});
