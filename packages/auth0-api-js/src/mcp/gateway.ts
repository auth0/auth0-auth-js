import { ApiClient } from '../api-client.js';
import { getToken } from '../token.js';
import { ProtectedResourceMetadataBuilder } from '../protected-resource-metadata.js';
import { VerifyAccessTokenError, InvalidRequestError } from '../errors.js';
import type { VerifiedAccessTokenClaims } from '../types.js';

import { ToolRegistry } from './tool-registry.js';
import { buildUpstreamRequest, executeUpstreamRequest } from './endpoint-mapper.js';
import {
  success,
  error,
  parseRequest,
  JsonRpcParseError,
  errorForParseFailure,
  METHOD_NOT_FOUND,
  INVALID_PARAMS,
  INTERNAL_ERROR,
  MCP_UNAUTHORIZED,
  MCP_FORBIDDEN,
  MCP_TOOL_NOT_FOUND,
  MCP_UPSTREAM_ERROR,
  MCP_AGENT_BLOCKED,
  MCP_CONFIRMATION_REQUIRED,
} from './json-rpc.js';
import { McpUpstreamError } from './errors.js';
import { toolsFromOpenApiSpec } from './openapi.js';

import type {
  McpGatewayOptions,
  McpRequestContext,
  McpResponseEnvelope,
  McpInitializeResult,
  McpAuditEvent,
  ToolAuthContext,
  ToolDefinition,
  LocalToolDefinition,
  AgentPolicy,
  ApiGroupOptions,
  ApiUpstreamOptions,
  JsonRpcResponse,
  OpenApiSpec,
  OpenApiToolsOptions,
} from './types.js';

const MCP_PROTOCOL_VERSION = '2025-03-26';

/**
 * A federated MCP server gateway that unifies multiple upstream APIs behind a
 * single MCP endpoint. Handles per-API token exchange (OBO), scope-based
 * authorization, agent governance, and request routing automatically.
 */
export class McpGateway {
  readonly #apiClient: ApiClient;
  readonly #registry: ToolRegistry;
  readonly #options: McpGatewayOptions;
  readonly #fetchFn: typeof fetch;

  constructor(options: McpGatewayOptions) {
    if (!options.serverName) {
      throw new Error('The "serverName" option is required');
    }
    if (!options.resource) {
      throw new Error('The "resource" option is required');
    }

    this.#options = options;
    this.#registry = new ToolRegistry();
    this.#fetchFn = options.customFetch ?? fetch;

    if (options.apiClient) {
      this.#apiClient = options.apiClient;
    } else {
      if (!options.domain) {
        throw new Error('The "domain" option is required');
      }
      if (!options.clientId) {
        throw new Error('The "clientId" option is required');
      }
      this.#apiClient = new ApiClient({
        domain: options.domain,
        audience: options.resource,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        clientAssertionSigningKey: options.clientAssertionSigningKey,
        clientAssertionSigningAlg: options.clientAssertionSigningAlg,
        customFetch: options.customFetch,
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API registration — remote upstream tools
  // ---------------------------------------------------------------------------

  api(namespace: string, options: ApiGroupOptions): this {
    if (!namespace || typeof namespace !== 'string') {
      throw new Error('API namespace must be a non-empty string');
    }
    if (!options.baseUrl) {
      throw new Error(`API "${namespace}" requires a "baseUrl"`);
    }
    if (!options.audience) {
      throw new Error(`API "${namespace}" requires an "audience"`);
    }

    const upstream: ApiUpstreamOptions = {
      baseUrl: options.baseUrl,
      audience: options.audience,
      scope: options.scope,
      customFetch: options.customFetch,
    };

    for (const tool of options.tools) {
      this.#registry.registerRemote(tool, upstream);
    }

    return this;
  }

  // ---------------------------------------------------------------------------
  // API registration — from OpenAPI spec
  // ---------------------------------------------------------------------------

  apiFromSpec(
    namespace: string,
    options: { baseUrl: string; audience: string; scope?: string; customFetch?: typeof fetch; spec: OpenApiSpec; toolOptions?: OpenApiToolsOptions }
  ): this {
    const tools = toolsFromOpenApiSpec(options.spec, options.toolOptions);
    return this.api(namespace, {
      baseUrl: options.baseUrl,
      audience: options.audience,
      scope: options.scope,
      customFetch: options.customFetch,
      tools,
    });
  }

  // ---------------------------------------------------------------------------
  // Local tool registration — gateway's own handlers
  // ---------------------------------------------------------------------------

  tool<TInput = Record<string, unknown>>(definition: LocalToolDefinition<TInput>): this {
    this.#registry.registerLocal(definition as LocalToolDefinition);
    return this;
  }

  // ---------------------------------------------------------------------------
  // Protected resource metadata (RFC 9728)
  // ---------------------------------------------------------------------------

  resourceMetadata(): Record<string, unknown> {
    const allScopes = this.#registry.allScopes();
    const builder = new ProtectedResourceMetadataBuilder(
      this.#options.resource,
      [`https://${this.#options.domain}/`]
    );

    if (allScopes.length > 0) {
      builder.withScopesSupported(allScopes);
    }

    return builder.build().toJSON() as unknown as Record<string, unknown>;
  }

  // ---------------------------------------------------------------------------
  // Request handler (framework-agnostic)
  // ---------------------------------------------------------------------------

  requestHandler(): (ctx: McpRequestContext) => Promise<McpResponseEnvelope> {
    return async (ctx: McpRequestContext): Promise<McpResponseEnvelope> => {
      return this.#handleRequest(ctx);
    };
  }

  // ---------------------------------------------------------------------------
  // Internal: request routing
  // ---------------------------------------------------------------------------

  async #handleRequest(ctx: McpRequestContext): Promise<McpResponseEnvelope> {
    // Check for Bearer token upfront. If missing, return HTTP 401 to trigger OAuth.
    // This ensures mcp-remote authenticates before establishing the MCP session.
    if (!this.#hasToken(ctx)) {
      return {
        status: 401,
        headers: {
          'content-type': 'application/json',
          'www-authenticate': `Bearer resource_metadata="${this.#options.resource}/.well-known/oauth-protected-resource"`,
        },
        body: { error: 'Unauthorized' },
      };
    }

    let request;
    try {
      request = parseRequest(ctx.body);
    } catch (err) {
      if (err instanceof JsonRpcParseError) {
        return this.#envelope(400, errorForParseFailure(err.message));
      }
      return this.#envelope(400, errorForParseFailure('Invalid JSON-RPC request'));
    }

    const id = request.id ?? null;

    switch (request.method) {
      case 'initialize':
        return this.#envelope(200, success(id, this.#initializeResult()));

      case 'notifications/initialized':
        return this.#envelope(200, success(id, {}));

      case 'tools/list':
        return this.#handleToolsList(id, ctx);

      case 'tools/call':
        return this.#handleToolsCall(id, request.params, ctx);

      default:
        return this.#envelope(200, error(id, METHOD_NOT_FOUND, `Method not found: ${request.method}`));
    }
  }

  // ---------------------------------------------------------------------------
  // MCP initialize
  // ---------------------------------------------------------------------------

  #initializeResult(): McpInitializeResult {
    return {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: {
        name: this.#options.serverName,
        version: this.#options.serverVersion ?? '1.0.0',
      },
    };
  }

  // ---------------------------------------------------------------------------
  // tools/list — scope-aware discovery
  // ---------------------------------------------------------------------------

  async #handleToolsList(
    id: string | number | null,
    _ctx: McpRequestContext
  ): Promise<McpResponseEnvelope> {
    const tools = this.#registry.list();
    return this.#envelope(200, success(id, { tools }));
  }

  // ---------------------------------------------------------------------------
  // tools/call — the core gateway flow
  // ---------------------------------------------------------------------------

  async #handleToolsCall(
    id: string | number | null,
    params: Record<string, unknown> | undefined,
    ctx: McpRequestContext
  ): Promise<McpResponseEnvelope> {
    const toolName = params?.name as string | undefined;
    if (!toolName || typeof toolName !== 'string') {
      return this.#envelope(200, error(id, INVALID_PARAMS, 'Missing required parameter: "name"'));
    }

    const input = (params?.arguments ?? {}) as Record<string, unknown>;
    const startTime = Date.now();

    // 1. Authenticate
    let auth: ToolAuthContext;
    try {
      auth = await this.#authenticate(ctx);
    } catch (err) {
      await this.#emitAudit('mcp.tool.blocked', toolName, undefined, 'blocked', this.#errorMessage(err));
      if (err instanceof InvalidRequestError) {
        // No token present — return HTTP 401 with WWW-Authenticate to trigger OAuth flow
        return {
          status: 401,
          headers: {
            'content-type': 'application/json',
            'www-authenticate': `Bearer resource_metadata="${this.#options.resource}/.well-known/oauth-protected-resource"`,
          },
          body: error(id, MCP_UNAUTHORIZED, 'Unauthorized', {
            reason: err.message,
          }),
        };
      }
      if (err instanceof VerifyAccessTokenError) {
        return this.#envelope(200, error(id, MCP_UNAUTHORIZED, 'Unauthorized', {
          reason: err.message || 'Invalid access token',
        }));
      }
      return this.#envelope(200, error(id, MCP_UNAUTHORIZED, 'Unauthorized'));
    }

    // 2. Find tool
    const registered = this.#registry.get(toolName);
    if (!registered) {
      await this.#emitAudit('mcp.tool.blocked', toolName, auth.claims.sub, 'failed', 'Tool not found');
      return this.#envelope(200, error(id, MCP_TOOL_NOT_FOUND, `Tool not found: ${toolName}`));
    }

    // 3. Check scopes
    const requiredScopes = registered.definition.scopes;
    if (requiredScopes && requiredScopes.length > 0) {
      const scopeSet = new Set(auth.scopes);
      const missingScopes = requiredScopes.filter((s) => !scopeSet.has(s));
      if (missingScopes.length > 0) {
        await this.#emitAudit('mcp.tool.blocked', toolName, auth.claims.sub, 'blocked', 'Missing required scope');
        return this.#envelope(200, error(id, MCP_FORBIDDEN, 'Forbidden', {
          reason: 'Missing required scope',
          requiredScopes,
          missingScopes,
        }));
      }
    }

    // 4. Enforce agent policy
    const policy = this.#resolveAgentPolicy(registered);
    const enforcement = this.#enforceAgentPolicy(policy, auth);

    if (enforcement.blocked) {
      await this.#emitAudit('mcp.agent.blocked', toolName, auth.claims.sub, 'blocked', enforcement.reason);
      return this.#envelope(200, error(id, MCP_AGENT_BLOCKED, 'Agent not allowed', {
        reason: enforcement.reason,
        agentId: auth.agentId,
      }));
    }

    if (enforcement.confirmationRequired) {
      await this.#emitAudit('mcp.agent.confirmation_required', toolName, auth.claims.sub, 'blocked', 'Human confirmation required');
      return this.#envelope(200, error(id, MCP_CONFIRMATION_REQUIRED, 'Human confirmation required', {
        toolName,
        agentId: auth.agentId,
      }));
    }

    // 5. Emit invoked event
    await this.#emitAudit('mcp.tool.invoked', toolName, auth.claims.sub, 'success');

    // 6. Execute — local handler or upstream proxy
    if (registered.isLocal) {
      return this.#executeLocal(id, registered.definition as LocalToolDefinition, input, auth, toolName, startTime);
    }

    return this.#executeRemote(id, registered.definition as ToolDefinition, input, auth, registered.upstream!, toolName, startTime);
  }

  // ---------------------------------------------------------------------------
  // Local tool execution
  // ---------------------------------------------------------------------------

  async #executeLocal(
    id: string | number | null,
    definition: LocalToolDefinition,
    input: Record<string, unknown>,
    auth: ToolAuthContext,
    toolName: string,
    startTime: number
  ): Promise<McpResponseEnvelope> {
    try {
      const result = await definition.handler({ input, auth });
      const durationMs = Date.now() - startTime;
      await this.#emitAudit('mcp.tool.completed', toolName, auth.claims.sub, 'success', undefined, durationMs);
      return this.#envelope(200, success(id, result));
    } catch (err) {
      const durationMs = Date.now() - startTime;
      await this.#emitAudit('mcp.tool.failed', toolName, auth.claims.sub, 'failed', this.#errorMessage(err), durationMs);
      return this.#envelope(200, error(id, INTERNAL_ERROR, 'Internal error'));
    }
  }

  // ---------------------------------------------------------------------------
  // Remote tool execution (upstream proxy with OBO)
  // ---------------------------------------------------------------------------

  async #executeRemote(
    id: string | number | null,
    definition: ToolDefinition,
    input: Record<string, unknown>,
    auth: ToolAuthContext,
    upstream: ApiUpstreamOptions,
    toolName: string,
    startTime: number
  ): Promise<McpResponseEnvelope> {
    try {
      // OBO token exchange for the target API's audience.
      // Skip OBO when:
      // - The upstream audience matches the gateway's own resource (self-routing)
      // - The token is a client_credentials grant (no user to act on behalf of)
      let upstreamToken = auth.token;
      const gty = (auth.claims as Record<string, unknown>)['gty'];
      const isM2M = gty === 'client-credentials';

      if (upstream.audience !== this.#options.resource && !isM2M) {
        const oboResult = await this.#apiClient.getTokenOnBehalfOf(auth.token, {
          audience: upstream.audience,
          scope: definition.scopes?.join(' ') ?? upstream.scope,
        });
        upstreamToken = oboResult.accessToken;
      }

      const upstreamAuth: ToolAuthContext = { ...auth, token: upstreamToken };
      const fetchFn = upstream.customFetch ?? this.#fetchFn;
      const { url, init } = buildUpstreamRequest(definition, input, upstreamAuth, upstream);
      const result = await executeUpstreamRequest(url, init, fetchFn);

      const durationMs = Date.now() - startTime;
      await this.#emitAudit('mcp.tool.completed', toolName, auth.claims.sub, 'success', undefined, durationMs);

      let text: string;
      if (result.contentType && result.contentType.includes('application/json')) {
        try {
          const parsed = JSON.parse(result.body);
          text = JSON.stringify(parsed, null, 2);
        } catch {
          text = result.body;
        }
      } else {
        text = result.body;
      }

      return this.#envelope(200, success(id, {
        content: [{ type: 'text', text }],
      }));
    } catch (err) {
      const durationMs = Date.now() - startTime;

      if (err instanceof McpUpstreamError) {
        await this.#emitAudit('mcp.tool.failed', toolName, auth.claims.sub, 'failed', err.message, durationMs);
        return this.#envelope(200, error(id, MCP_UPSTREAM_ERROR, err.message, {
          upstreamStatus: err.upstreamStatus,
          ...(err.upstreamBody && { upstreamBody: err.upstreamBody }),
        }));
      }

      const errMsg = this.#errorMessage(err);
      await this.#emitAudit('mcp.tool.failed', toolName, auth.claims.sub, 'failed', errMsg, durationMs);
      return this.#envelope(200, error(id, INTERNAL_ERROR, 'Internal error'));
    }
  }

  // ---------------------------------------------------------------------------
  // Authentication + agent detection
  // ---------------------------------------------------------------------------

  async #authenticate(ctx: McpRequestContext): Promise<ToolAuthContext> {
    const headers = ctx.headers as Record<string, string | string[] | undefined> & {
      authorization?: string;
    };

    const token = getToken(headers as Parameters<typeof getToken>[0]);

    const claims = await this.#apiClient.verifyAccessToken({
      accessToken: token,
      scheme: 'bearer',
      headers: ctx.headers,
      httpUrl: ctx.url,
    });

    const scopes = extractScopes(claims);
    const act = (claims as Record<string, unknown>)['act'] as { sub?: string } | undefined;
    const caller = act ? 'agent' as const : 'human' as const;
    const agentId = act?.sub;

    return { claims, scopes, token, caller, agentId };
  }

  // ---------------------------------------------------------------------------
  // Agent policy enforcement
  // ---------------------------------------------------------------------------

  #resolveAgentPolicy(registered: { definition: ToolDefinition | LocalToolDefinition; upstream?: ApiUpstreamOptions }): AgentPolicy | undefined {
    return registered.definition.agentPolicy;
  }

  #enforceAgentPolicy(
    policy: AgentPolicy | undefined,
    auth: ToolAuthContext
  ): { blocked: boolean; confirmationRequired: boolean; reason?: string } {
    if (!policy || auth.caller === 'human') {
      return { blocked: false, confirmationRequired: false };
    }

    if (policy.allowedAgents && policy.allowedAgents.length > 0) {
      if (!auth.agentId || !policy.allowedAgents.includes(auth.agentId)) {
        return {
          blocked: true,
          confirmationRequired: false,
          reason: `Agent "${auth.agentId ?? 'unknown'}" is not in the allowed agents list`,
        };
      }
    }

    if (policy.requireConfirmation) {
      return { blocked: false, confirmationRequired: true };
    }

    return { blocked: false, confirmationRequired: false };
  }

  // ---------------------------------------------------------------------------
  // Audit
  // ---------------------------------------------------------------------------

  async #emitAudit(
    type: McpAuditEvent['type'],
    toolName: string,
    sub?: string,
    status: McpAuditEvent['status'] = 'success',
    reason?: string,
    durationMs?: number
  ): Promise<void> {
    if (!this.#options.onAuditEvent) return;

    const event: McpAuditEvent = {
      type,
      toolName,
      ...(sub && { sub }),
      status,
      ...(reason && { reason }),
      ...(durationMs !== undefined && { durationMs }),
      timestamp: new Date().toISOString(),
    };

    try {
      await this.#options.onAuditEvent(event);
    } catch {
      // Audit failures must never break the request flow
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  #envelope(status: number, body: JsonRpcResponse | Record<string, unknown>): McpResponseEnvelope {
    return {
      status,
      headers: { 'content-type': 'application/json' },
      body,
    };
  }

  #errorMessage(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
  }

  #hasToken(ctx: McpRequestContext): boolean {
    const authHeader = (ctx.headers as Record<string, string | string[] | undefined>)['authorization'];
    return typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ');
  }
}

function extractScopes(claims: VerifiedAccessTokenClaims): string[] {
  const scopeClaim = (claims as Record<string, unknown>)['scope'];
  if (typeof scopeClaim === 'string') {
    return scopeClaim.split(' ').filter(Boolean);
  }
  if (Array.isArray(scopeClaim)) {
    return scopeClaim.filter((s): s is string => typeof s === 'string');
  }
  return [];
}
