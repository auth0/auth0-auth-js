# Federated MCP Gateway Example

A complete working example of `McpGateway` from `@auth0/auth0-api-js/mcp`. One MCP endpoint unifies three APIs — tools are auto-generated from OpenAPI specs, authentication uses OAuth with consent, and each upstream API receives its own scoped token via On-Behalf-Of exchange.

## Architecture

```
Claude Desktop / AI Agent
        │
        │  JSON-RPC + Bearer Token
        ▼
┌─────────────────────────────────────────────┐
│         MCP Gateway (:3000)                 │
│                                             │
│  12 tools (auto-generated from specs)       │
│  JWT verification → Scope check → OBO       │
└─────┬────────────────┬────────────────┬─────┘
      │                │                │
      ▼                ▼                ▼
┌───────────┐   ┌───────────┐   ┌───────────┐
│ Expenses  │   │  HR API   │   │  Gateway  │
│ API :4000 │   │   :5000   │   │ API :3000 │
└───────────┘   └───────────┘   └───────────┘
```

## Prerequisites

- Node.js 18+
- An Auth0 tenant

## Auth0 Setup

### 1. Create APIs

Create three APIs in **Applications → APIs**:

| Name | Identifier | Permissions |
|------|-----------|-------------|
| MCP Gateway | `http://localhost:3000/mcp` | `expenses:read`, `expenses:write`, `expenses:approve`, `hr:read`, `policies:read` |
| Expenses API | `https://expenses-api.example.com` | — |
| HR API | `https://hr-api.example.com` | — |

On the MCP Gateway API:
- Enable **RBAC**
- Enable **Add Permissions in the Access Token**

### 2. Create Applications

Create two applications in **Applications → Applications**:

| Name | Type | Purpose |
|------|------|---------|
| MCP Gateway (Server) | Machine to Machine | Gateway performs OBO exchange |
| MCP Client (Native) | Native | `mcp-remote` uses this for the OAuth flow |

For the **MCP Gateway** M2M app:
- Authorize it to access all three APIs (Expenses, HR, MCP Gateway)
- Note the Client ID and Client Secret

For the **MCP Client** Native app:
- Set Allowed Callback URLs: `http://localhost:4208/oauth/callback`
- Note the Client ID

### 3. Enable Token Exchange

In **Applications → APIs → MCP Gateway API → Permissions**, ensure Token Exchange (OBO) is enabled for the MCP Gateway M2M application.

### 4. Assign Permissions to User

1. **User Management → Roles** → Create a role (e.g., "MCP User")
2. Add all permissions from the MCP Gateway API to this role
3. **User Management → Users** → Assign the role to your user

## Installation

```bash
cd examples/example-mcp-gateway

# Install all three services
cd gateway && npm install && cd ..
cd expenses-api && npm install && cd ..
cd hr-api && npm install && cd ..
```

## Configuration

Copy `.env.example` to `.env` in each directory and fill in your values:

```bash
cp gateway/.env.example gateway/.env
cp expenses-api/.env.example expenses-api/.env
cp hr-api/.env.example hr-api/.env
```

### gateway/.env

```
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=<MCP Gateway M2M client ID>
AUTH0_CLIENT_SECRET=<MCP Gateway M2M client secret>
MCP_CLIENT_ID=<MCP Client Native app client ID>
GATEWAY_RESOURCE=http://localhost:3000/mcp
GATEWAY_PORT=3000
EXPENSES_API_PORT=4000
EXPENSES_API_AUDIENCE=https://expenses-api.example.com
HR_API_PORT=5000
HR_API_AUDIENCE=https://hr-api.example.com
```

### expenses-api/.env

```
AUTH0_DOMAIN=your-tenant.auth0.com
EXPENSES_API_AUDIENCE=https://expenses-api.example.com
EXPENSES_API_PORT=4000
```

### hr-api/.env

```
AUTH0_DOMAIN=your-tenant.auth0.com
HR_API_AUDIENCE=https://hr-api.example.com
HR_API_PORT=5000
```

## Running

Start all three services (each in a separate terminal):

```bash
# Terminal 1 — Gateway
cd gateway && npm run dev

# Terminal 2 — Expenses API
cd expenses-api && npm run dev

# Terminal 3 — HR API
cd hr-api && npm run dev
```

## Connecting with Claude Desktop

Add to your Claude Desktop MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "acme-gateway": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:3000/mcp"]
    }
  }
}
```

On first connection, your browser will open for OAuth consent. After granting permissions, Claude Desktop has access to all 12 tools.

### Token Caching

If Claude Desktop times out during the first auth flow, run `mcp-remote` standalone to cache the token:

```bash
npx mcp-remote http://localhost:3000/mcp
```

Complete the browser auth, then Ctrl+C and restart Claude Desktop. It will reuse the cached token.

## Available Tools

| Tool | Source | Scope Required |
|------|--------|---------------|
| `listExpenses` | Expenses API (OpenAPI) | `expenses:read` |
| `getExpense` | Expenses API (OpenAPI) | `expenses:read` |
| `submitExpense` | Expenses API (OpenAPI) | `expenses:write` |
| `approveExpense` | Expenses API (OpenAPI) | `expenses:approve` |
| `listEmployees` | HR API (OpenAPI) | `hr:read` |
| `getEmployee` | HR API (OpenAPI) | `hr:read` |
| `listDepartments` | HR API (OpenAPI) | `hr:read` |
| `getDepartment` | HR API (OpenAPI) | `hr:read` |
| `listPolicies` | Gateway API (OpenAPI) | `policies:read` |
| `getPolicy` | Gateway API (OpenAPI) | `policies:read` |
| `whoami` | Local handler | — |
| `gatewayStatus` | Local handler | — |

## Testing with curl

```bash
TOKEN="<your-jwt>"

# List all tools
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq

# Call a remote tool (triggers OBO exchange)
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"listExpenses","arguments":{"status":"pending"}}}' | jq

# Call a local tool
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' | jq
```
