# Federated MCP Gateway

A single MCP endpoint that unifies multiple upstream APIs. Auto-generates tools from OpenAPI specs, handles OAuth consent, per-API On-Behalf-Of token exchange, scope enforcement, and agent governance.

```
npm install @auth0/auth0-api-js
```

```typescript
import { McpGateway } from '@auth0/auth0-api-js/mcp';
```

---

## Quick Start

```typescript
import { McpGateway } from '@auth0/auth0-api-js/mcp';
import express from 'express';

const gateway = new McpGateway({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  serverName: 'My Gateway',
  resource: 'https://gateway.example.com/mcp',
});

// Auto-generate tools from OpenAPI spec
gateway.apiFromSpec('expenses', {
  baseUrl: 'https://expenses.internal',
  audience: 'https://expenses-api',
  spec: expensesOpenApiSpec,
});

// Serve it
const app = express();
app.use(express.json());

const handler = gateway.requestHandler();
app.post('/mcp', async (req, res) => {
  const result = await handler({
    body: req.body,
    headers: req.headers,
    url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
  });
  res.status(result.status).set(result.headers).json(result.body);
});

app.get('/.well-known/oauth-protected-resource', (_, res) => {
  res.json(gateway.resourceMetadata());
});

app.listen(3000);
```

---

## Constructor

```typescript
new McpGateway(options)
```

Accepts either raw credentials or a pre-configured `ApiClient` instance.

### With credentials

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `domain` | `string` | Yes | Auth0 tenant domain |
| `clientId` | `string` | Yes | Application client ID (for OBO) |
| `clientSecret` | `string` | * | Client secret |
| `clientAssertionSigningKey` | `string \| CryptoKey` | * | Private key for client assertions |
| `clientAssertionSigningAlg` | `string` | No | Assertion algorithm (default: RS256) |
| `serverName` | `string` | Yes | MCP server name |
| `serverVersion` | `string` | No | Server version (default: "1.0.0") |
| `resource` | `string` | Yes | Gateway's resource identifier (audience) |
| `customFetch` | `typeof fetch` | No | Custom fetch implementation |
| `onAuditEvent` | `(event: McpAuditEvent) => void` | No | Audit callback |

\* One of `clientSecret` or `clientAssertionSigningKey` is required.

### With ApiClient

```typescript
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new ApiClient({ domain, clientId, clientSecret, audience });

const gateway = new McpGateway({
  apiClient,
  serverName: 'My Gateway',
  resource: 'https://gateway.example.com/mcp',
});
```

---

## Methods

### `gateway.api(namespace, options)`

Register an upstream API with manually-defined tools.

```typescript
gateway.api('payments', {
  baseUrl: 'https://payments.internal',
  audience: 'https://payments-api',
  tools: [
    {
      name: 'chargeCard',
      description: 'Charge a credit card',
      endpoint: { method: 'POST', path: '/charges' },
      schema: {
        type: 'object',
        properties: {
          amount: { type: 'number' },
          currency: { type: 'string' },
        },
        required: ['amount'],
      },
      scopes: ['payments:write'],
    },
  ],
});
```

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `baseUrl` | `string` | Yes | Upstream API base URL |
| `audience` | `string` | Yes | API audience for OBO exchange |
| `scope` | `string` | No | Default scopes for OBO (used when tool has no `scopes`) |
| `tools` | `ToolDefinition[]` | Yes | Tool definitions |
| `customFetch` | `typeof fetch` | No | Custom fetch for this API |

Returns `this` (chainable).

---

### `gateway.apiFromSpec(namespace, options)`

Auto-generate tools from an OpenAPI 3.x specification.

```typescript
import spec from './openapi.json';

gateway.apiFromSpec('crm', {
  baseUrl: 'https://crm.internal',
  audience: 'https://crm-api',
  spec,
  toolOptions: {
    include: ['listContacts', 'getContact'],
    scopeOverrides: { getContact: ['crm:read'] },
    descriptionOverrides: { listContacts: 'Search CRM contacts' },
  },
});
```

Each operation with an `operationId` becomes a tool. Path/query parameters and request body become tool input properties. Security scopes are extracted automatically.

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `baseUrl` | `string` | Yes | Upstream API base URL |
| `audience` | `string` | Yes | API audience for OBO |
| `spec` | `OpenApiSpec` | Yes | OpenAPI 3.x spec object |
| `toolOptions.include` | `string[]` | No | Only include these operationIds |
| `toolOptions.exclude` | `string[]` | No | Exclude these operationIds |
| `toolOptions.scopeOverrides` | `Record<string, string[]>` | No | Override scopes per operation |
| `toolOptions.descriptionOverrides` | `Record<string, string>` | No | Override descriptions |

Returns `this` (chainable).

---

### `gateway.tool(definition)`

Register a local tool with a custom handler. Executes in-process — no upstream call, no OBO.

```typescript
gateway.tool({
  name: 'whoami',
  description: 'Returns caller identity',
  schema: { type: 'object', properties: {} },
  scopes: ['profile'],
  handler: async ({ input, auth }) => ({
    content: [{ type: 'text', text: `Hello ${auth.claims.sub}` }],
  }),
});
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Tool name |
| `description` | `string` | Yes | Description shown to AI agents |
| `schema` | `JsonSchema` | Yes | Input schema (JSON Schema) |
| `scopes` | `string[]` | No | Required scopes |
| `agentPolicy` | `AgentPolicy` | No | Agent governance policy |
| `handler` | `(ctx) => McpToolResult` | Yes | Handler function |

The handler receives `{ input, auth }` where `auth` contains:
- `auth.claims` — Verified JWT claims
- `auth.scopes` — Token scopes as array
- `auth.token` — Raw Bearer token
- `auth.caller` — `'human'` or `'agent'`
- `auth.agentId` — Agent identifier (from `act.sub` claim)

Returns `this` (chainable).

---

### `gateway.requestHandler()`

Returns a framework-agnostic request handler.

```typescript
const handler = gateway.requestHandler();
// handler: (ctx: McpRequestContext) => Promise<McpResponseEnvelope>
```

**McpRequestContext:**
```typescript
{
  body: unknown;          // Parsed JSON-RPC request body
  headers: Record<string, string | string[] | undefined>;
  url?: string;           // Full request URL (for token verification)
}
```

**McpResponseEnvelope:**
```typescript
{
  status: number;         // HTTP status code
  headers: Record<string, string>;
  body: JsonRpcResponse;  // JSON-RPC 2.0 response
}
```

---

### `gateway.resourceMetadata()`

Returns OAuth 2.0 Protected Resource Metadata (RFC 9728). Includes all registered scopes.

```typescript
app.get('/.well-known/oauth-protected-resource', (_, res) => {
  res.json(gateway.resourceMetadata());
});
```

---

## How It Works

When an AI agent calls a tool:

1. **Authenticate** — Verify the Bearer JWT against the gateway's audience
2. **Find tool** — Look up the tool name in the registry
3. **Check scopes** — Ensure the token has the tool's required scopes
4. **Agent policy** — If caller is an agent (`act` claim present), enforce governance rules
5. **Emit audit** — Fire `mcp.tool.invoked` event
6. **Execute** — Local tools run the handler; remote tools do OBO + upstream proxy

For remote tools, the On-Behalf-Of exchange swaps the gateway token for a token scoped to the target API's audience. Each API gets exactly the permissions it needs.

OBO is skipped when:
- The upstream audience matches the gateway's own resource (self-routing)
- The token is a client_credentials grant (M2M, no user to act on behalf of)

---

## Agent Governance

When a token contains an `act` claim, the gateway identifies the caller as an agent. You can enforce policies per-tool:

```typescript
gateway.tool({
  name: 'deleteAccount',
  description: 'Permanently delete a user account',
  schema: { type: 'object', properties: { userId: { type: 'string' } }, required: ['userId'] },
  agentPolicy: {
    allowedAgents: ['trusted-agent-client-id'],
    requireConfirmation: true,
  },
  handler: async ({ input }) => { /* ... */ },
});
```

| Field | Type | Description |
|-------|------|-------------|
| `allowedAgents` | `string[]` | Only these agent IDs (from `act.sub`) are allowed |
| `requireConfirmation` | `boolean` | Require human confirmation before execution |

Blocked agents receive JSON-RPC error `-32006`. Confirmation-required returns `-32007`.

---

## Audit Events

```typescript
const gateway = new McpGateway({
  // ...
  onAuditEvent: (event) => console.log(event),
});
```

Event types:
- `mcp.tool.invoked` — Tool execution started
- `mcp.tool.completed` — Tool execution succeeded
- `mcp.tool.blocked` — Scope check failed
- `mcp.tool.failed` — Execution error
- `mcp.agent.blocked` — Agent not in allowlist
- `mcp.agent.confirmation_required` — Human confirmation needed

Each event includes: `type`, `toolName`, `sub`, `status`, `reason`, `durationMs`, `timestamp`.

---

## Exports

```typescript
import {
  McpGateway,
  toolsFromOpenApiSpec,
  McpError,
  McpToolNotFoundError,
  McpScopeMismatchError,
  McpInputValidationError,
  McpUpstreamError,
} from '@auth0/auth0-api-js/mcp';

import type {
  McpGatewayOptions,
  McpRequestContext,
  McpResponseEnvelope,
  ToolDefinition,
  ToolAuthContext,
  LocalToolDefinition,
  AgentPolicy,
  ApiGroupOptions,
  OpenApiSpec,
  OpenApiToolsOptions,
  McpAuditEvent,
} from '@auth0/auth0-api-js/mcp';
```

---

## Example

See [`examples/example-mcp-gateway/`](../../examples/example-mcp-gateway/) for a full working setup with three APIs, OpenAPI specs, OAuth consent, and Claude Desktop integration.
