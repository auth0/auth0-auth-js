import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { McpGateway } from '@auth0/auth0-api-js/mcp';
import type { OpenApiSpec } from '@auth0/auth0-api-js/mcp';
import { createRoutes } from './routes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN!;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID!;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET!;
const GATEWAY_RESOURCE = process.env.GATEWAY_RESOURCE!;
const PORT = Number(process.env.GATEWAY_PORT ?? 3000);

// ---------------------------------------------------------------------------
// Create the gateway
// ---------------------------------------------------------------------------

const gateway = new McpGateway({
  domain: AUTH0_DOMAIN,
  clientId: AUTH0_CLIENT_ID,
  clientSecret: AUTH0_CLIENT_SECRET,
  serverName: 'Acme AI Gateway',
  serverVersion: '1.0.0',
  resource: GATEWAY_RESOURCE,
  onAuditEvent: (event) => {
    console.log(`[Audit] ${event.type} tool=${event.toolName} status=${event.status}${event.reason ? ` reason="${event.reason}"` : ''}${event.durationMs ? ` (${event.durationMs}ms)` : ''}`);
  },
});

// ---------------------------------------------------------------------------
// Register upstream APIs from OpenAPI specs
// ---------------------------------------------------------------------------

const expensesSpec: OpenApiSpec = JSON.parse(
  readFileSync(resolve(__dirname, '../_specs/expenses-api.json'), 'utf-8')
);

gateway.apiFromSpec('expenses', {
  baseUrl: `http://localhost:${process.env.EXPENSES_API_PORT ?? '4000'}`,
  audience: process.env.EXPENSES_API_AUDIENCE!,
  spec: expensesSpec,
});

const hrSpec: OpenApiSpec = JSON.parse(
  readFileSync(resolve(__dirname, '../_specs/hr-api.json'), 'utf-8')
);

gateway.apiFromSpec('hr', {
  baseUrl: `http://localhost:${process.env.HR_API_PORT ?? '5000'}`,
  audience: process.env.HR_API_AUDIENCE!,
  spec: hrSpec,
});

// Gateway's own REST endpoints exposed as tools (OBO skipped — same audience)
const gatewaySpec: OpenApiSpec = JSON.parse(
  readFileSync(resolve(__dirname, '../_specs/gateway-api.json'), 'utf-8')
);

gateway.apiFromSpec('gateway', {
  baseUrl: `http://localhost:${PORT}`,
  audience: GATEWAY_RESOURCE,
  spec: gatewaySpec,
});

// ---------------------------------------------------------------------------
// Local tools — run in-process, no upstream call
// ---------------------------------------------------------------------------

gateway.tool({
  name: 'whoami',
  description: 'Returns the authenticated user identity and granted scopes',
  schema: { type: 'object', properties: {} },
  handler: async ({ auth }) => ({
    content: [{
      type: 'text',
      text: JSON.stringify({
        sub: auth.claims.sub,
        scopes: auth.scopes,
        caller: auth.caller,
        agentId: auth.agentId,
        iss: auth.claims.iss,
      }, null, 2),
    }],
  }),
});

gateway.tool({
  name: 'gatewayStatus',
  description: 'Returns the gateway health status and connected APIs',
  schema: { type: 'object', properties: {} },
  handler: async () => ({
    content: [{
      type: 'text',
      text: JSON.stringify({
        status: 'healthy',
        uptime: process.uptime(),
        connectedApis: ['expenses', 'hr', 'gateway'],
      }, null, 2),
    }],
  }),
});

// ---------------------------------------------------------------------------
// Express server
// ---------------------------------------------------------------------------

const policies = JSON.parse(readFileSync(resolve(__dirname, 'data/policies.json'), 'utf-8'));

const app = express();
app.use(express.json());

const handler = gateway.requestHandler();

app.post('/mcp', async (req, res) => {
  const result = await handler({
    body: req.body,
    headers: req.headers as Record<string, string | string[] | undefined>,
    url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
  });
  res.status(result.status).set(result.headers).json(result.body);
});

app.use(createRoutes(policies));

// OAuth protected resource metadata (RFC 9728)
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json(gateway.resourceMetadata());
});

// OAuth authorization server metadata (RFC 8414)
// Proxies Auth0 OIDC metadata with audience/scope baked into the authorization URL
// and registration_endpoint pointing back to this gateway for DCR.
app.get('/.well-known/oauth-authorization-server', async (req, res) => {
  const gatewayOrigin = `${req.protocol}://${req.get('host')}`;
  try {
    const response = await fetch(`https://${AUTH0_DOMAIN}/.well-known/openid-configuration`);
    const oidc = await response.json() as Record<string, unknown>;

    const authzEndpoint = new URL(oidc.authorization_endpoint as string);
    authzEndpoint.searchParams.set('audience', GATEWAY_RESOURCE);
    authzEndpoint.searchParams.set('scope', 'openid profile expenses:read expenses:write expenses:approve hr:read policies:read');

    res.json({
      issuer: oidc.issuer,
      authorization_endpoint: authzEndpoint.toString(),
      token_endpoint: oidc.token_endpoint,
      registration_endpoint: `${gatewayOrigin}/register`,
      response_types_supported: oidc.response_types_supported,
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: oidc.scopes_supported,
    });
  } catch {
    res.status(502).json({ error: 'Failed to fetch authorization server metadata' });
  }
});

// Dynamic Client Registration (RFC 7591)
// Returns a static response using the pre-registered Auth0 Native app.
const MCP_CLIENT_ID = process.env.MCP_CLIENT_ID ?? AUTH0_CLIENT_ID;

app.post('/register', (req, res) => {
  const body = req.body as Record<string, unknown>;
  res.status(201).json({
    client_id: MCP_CLIENT_ID,
    client_name: body.client_name ?? 'MCP Remote Client',
    redirect_uris: body.redirect_uris ?? ['http://127.0.0.1/callback'],
    grant_types: body.grant_types ?? ['authorization_code'],
    response_types: body.response_types ?? ['code'],
    token_endpoint_auth_method: 'none',
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0,
  });
});

app.listen(PORT, () => {
  console.log(`[MCP Gateway] listening on http://localhost:${PORT}`);
  console.log(`  MCP endpoint:     POST http://localhost:${PORT}/mcp`);
  console.log(`  Metadata:         GET  http://localhost:${PORT}/.well-known/oauth-protected-resource`);
  console.log(`  Tools: 12 (4 expenses + 4 hr + 2 gateway + 2 local)`);
});
